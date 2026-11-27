"""Guards for scripts/unifi-os-version-metric.sh (issue #244): the read-only UniFi OS Server version
collector. Fake `uosserver` binaries live in a scratch directory under the worktree
(.test-scratch/, git-ignored, removed by exact path after each test). The shipped script has no
test hooks: every test runs a scratch copy in which only the fixed constant lines are rewritten
(Env.build). Every guard has a clean-mutant revert proof at the bottom: the scratch copy is mutated at
one marked line and the same hostile fixture must then behave differently (the guard bites).
The collector reports versions only; nothing here asserts or implies an update is pending.
"""
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "unifi-os-version-metric.sh"
DOC = REPO_ROOT / "docs" / "unifi-os-version-collector.md"
SCRATCH_ROOT = REPO_ROOT / ".test-scratch"

CANARY = "CANARY-RAW-STATUS-LINE-7731"

STATUS_OK = f"""CONTAINER ID  IMAGE            COMMAND  STATUS
abc123def456  uosserver:5.1.42 /init    Up 3 days {CANARY}

Host service status:
● uosserver.service - UniFi OS Server
     Loaded: loaded (/etc/systemd/system/uosserver.service; enabled)
     Active: active (running)

Container service status:
● mongodb.service - MongoDB
     Loaded: loaded (/lib/systemd/system/mongodb.service; enabled)
     Status: {{"state":"running","version":"7.0.14"}}
● unifi.service - UniFi Network
     Loaded: loaded (/lib/systemd/system/unifi.service; enabled)
     Active: active (running)
     Status: {{"state":"running","version":"10.6.109","uptime":12}}
● other.service - Other
     Status: {{"version":"9.9.9"}}
"""


def status_with(status_json, extra_after=""):
    return (
        "Container service status:\n"
        "● unifi.service - UniFi Network\n"
        "     Active: active (running)\n"
        f"     Status: {status_json}\n" + extra_after
    )


FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> {rec}
/usr/bin/env >> {rec}.env
case "$1" in
    version) cat {vfix}; exit "$(cat {vrc})" ;;
    status) {status_cmd}; exit "$(cat {src})" ;;
esac
exit 64
"""


class Env:
    def __init__(self, scratch):
        self.tmp = scratch
        self.bin = scratch / "bin"
        self.bin.mkdir()
        self.vfix = scratch / "version.fix"
        self.sfix = scratch / "status.fix"
        self.vrc = scratch / "version.rc"
        self.src = scratch / "status.rc"
        self.rec = scratch / "calls.txt"
        self.vfix.write_text("5.1.42\n", encoding="utf-8")
        self.sfix.write_text(STATUS_OK, encoding="utf-8")
        self.vrc.write_text("0\n")
        self.src.write_text("0\n")
        self.uos = self.bin / "uosserver"
        self.write_fake()
        # the collector refuses uid 0, so the tests never depend on who runs them
        self.id_user = self.bin / "id-user"
        self.id_user.write_text("#!/bin/sh\necho 1000\n", encoding="utf-8")
        self.id_user.chmod(0o755)
        # generous command limit: a loaded CI worker must not time the fake out. Only the tests that
        # prove the time bound use env.fast (1 second).
        self.script = self.build("script.sh")
        self.fast = self.build("fast.sh", rewrites={"cmd_timeout": "1"})

    def write_fake(self, status_cmd=None):
        status_cmd = status_cmd or f"cat {shlex.quote(str(self.sfix))}"
        self.uos.write_text(
            FAKE.format(rec=shlex.quote(str(self.rec)), vfix=shlex.quote(str(self.vfix)),
                        vrc=shlex.quote(str(self.vrc)), src=shlex.quote(str(self.src)),
                        status_cmd=status_cmd), encoding="utf-8")
        self.uos.chmod(0o755)

    def build(self, name, marks=None, rewrites=None):
        """Scratch copy of the shipped script: constants rewritten, optional one-line mutations."""
        rw = {"uos_bin": str(self.uos), "cmd_timeout": "30", "id_bin": str(self.id_user)}
        rw.update(rewrites or {})
        lines = SCRIPT.read_text(encoding="utf-8").splitlines(keepends=True)
        for var, value in rw.items():
            hits = [i for i, ln in enumerate(lines) if re.match(rf"\s*{var}=", ln)]
            assert len(hits) == 1, f"default line for {var} found {len(hits)} times"
            lines[hits[0]] = f"{var}={shlex.quote(value)}\n"
        for marker, replacement in (marks or {}).items():
            hits = [i for i, ln in enumerate(lines) if ln.rstrip().endswith(f"# MUTATE:{marker}")]
            assert len(hits) == 1, f"marker {marker} found {len(hits)} times"
            indent = re.match(r"\s*", lines[hits[0]]).group(0)
            lines[hits[0]] = indent + replacement + "\n"
        p = self.tmp / name
        p.write_text("".join(lines), encoding="utf-8")
        return p

    def run(self, args=(), label="pi-a", script=None, stdout_to=None, timeout=60, env_extra=None):
        env = {"PATH": "/usr/bin:/bin", "FOREIGN_LEAK": "1"}
        if label is not None:
            env["HOST_LABEL"] = label
        env.update(env_extra or {})
        kw = {"stdout": stdout_to} if stdout_to is not None else {"stdout": subprocess.PIPE}
        return subprocess.run(["/bin/sh", str(script or self.script), *args], env=env,
                              stderr=subprocess.PIPE, timeout=timeout, **kw)


@pytest.fixture
def env():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="t244-", dir=SCRATCH_ROOT))
    try:
        yield Env(scratch)
    finally:
        shutil.rmtree(scratch)  # exact path made above


def text(r):
    return r.stdout.decode("utf-8", "replace") if r.stdout else ""


def etext(r):
    return r.stderr.decode("utf-8", "replace")


LINE_RE = (r'^unifi_os_version,host=pi-a os_version="5\.1\.42",network_version="{net}",'
           r'collected_ts=(\d+)i,result="{res}"\n$')


def assert_ok(r, net="10\\.6\\.109", res="ok"):
    assert r.returncode == 0, etext(r)
    m = re.match(LINE_RE.format(net=net, res=res), text(r))
    assert m, text(r)
    assert abs(int(m.group(1)) - time.time()) < 120


def assert_failed_clean(r, *hostile):
    assert r.returncode != 0
    assert r.stdout == b"", r.stdout
    for h in (CANARY, *hostile):
        assert h not in text(r) and h not in etext(r)


# ------------------------------------------------------------------ happy path and fixed environment
def test_happy_path(env):
    assert_ok(env.run())


def test_label_as_argument(env):
    env.run()
    r = env.run(args=("pi-a",), label=None)
    assert_ok(r)


def test_no_raw_status_text_on_success(env):
    r = env.run()
    assert CANARY not in text(r) and CANARY not in etext(r)
    assert "mongodb" not in text(r) and "7.0.14" not in text(r) and "9.9.9" not in text(r)


def test_only_two_fixed_commands_run_with_fixed_environment(env):
    env.run()
    calls = env.rec.read_text().split("\n")
    assert [c for c in calls if c] == ["version", "status"]
    envtxt = (env.tmp / "calls.txt.env").read_text()
    assert "FOREIGN_LEAK" not in envtxt and "HOST_LABEL" not in envtxt
    assert "PATH=/usr/bin:/bin" in envtxt and "LC_ALL=C" in envtxt


@pytest.mark.parametrize("label", [None, "", "a b", "-x", "x" * 33, "a;b", "a=b", "a,b", "host\nx"])
def test_bad_label_fails_without_output(env, label):
    r = env.run(label=label)
    assert r.returncode != 0 and r.stdout == b""


def test_label_conflict_fails(env):
    r = env.run(args=("other",), label="pi-a")
    assert r.returncode != 0 and r.stdout == b""


def test_extra_arguments_fail(env):
    r = env.run(args=("pi-a", "x"))
    assert r.returncode != 0 and r.stdout == b""


# ------------------------------------------------------------------ OS version is strict, and fatal
BAD_OS = [
    "", "\n", "5.1.42 extra\n", "v5.1.42\n", "5.1.42\n6.0.0\n", "5.1.42\x1b[0m\n", "5.1..2\n", ".5.1\n",
    "5.1.\n", "a.b.c\n", "5.1.42;id\n", "5.1.42\x00\n", "5" * 65 + ".1\n", "5.1.42 \n", " 5.1.42\n",
    "5.1.42\r\n", "$(id)\n", "5.1.42-rc1\n", "5,1,42\n", "٥.1.42\n",
]


@pytest.mark.parametrize("bad", BAD_OS)
def test_odd_os_version_fails_and_prints_nothing(env, bad):
    env.vfix.write_bytes(bad.encode("utf-8"))
    r = env.run()
    assert_failed_clean(r, "id)", "[0m")


def test_oversized_os_version_output_fails(env):
    env.vfix.write_bytes(b"5.1.42\n" + b"A" * (6 * 1024 * 1024))
    r = env.run()
    assert_failed_clean(r)


def test_hostile_os_version_never_echoed(env):
    env.vfix.write_text(f"{CANARY} `reboot` $(id)\n", encoding="utf-8")
    r = env.run()
    assert_failed_clean(r, "reboot", "$(id)")


def test_os_version_nonzero_exit_fails(env):
    env.vrc.write_text("3\n")
    r = env.run()
    assert_failed_clean(r)


def test_os_version_without_trailing_newline_is_accepted(env):
    env.vfix.write_text("5.1.42", encoding="utf-8")
    assert_ok(env.run())


def test_missing_uosserver_fails(env):
    env.uos.unlink()
    assert_failed_clean(env.run())


def test_hanging_version_is_bounded(env):
    env.uos.write_text("#!/bin/sh\nsleep 300\n", encoding="utf-8")
    start = time.time()
    r = env.run(script=env.fast)
    assert time.time() - start < 20
    assert_failed_clean(r)


def test_hanging_version_with_pipe_holding_child_is_bounded(env):
    env.uos.write_text("#!/bin/sh\nsleep 300 &\nsleep 300\n", encoding="utf-8")
    start = time.time()
    r = env.run(script=env.fast)
    assert time.time() - start < 20
    assert_failed_clean(r)


def test_write_failure_exits_nonzero(env):
    with open("/dev/full", "wb") as full:
        r = env.run(stdout_to=full)
    assert r.returncode != 0


# ------------------------------------------------------------------ Network app version: strict, never guessed
def net_unknown(r):
    assert_ok(r, net="unknown", res="network_unknown")
    assert CANARY not in text(r) and CANARY not in etext(r)


def test_network_version_missing_is_unknown_not_error(env):
    env.sfix.write_text(status_with('{"state":"running"}'), encoding="utf-8")
    net_unknown(env.run())


def test_two_top_level_version_fields_are_not_guessed(env):
    env.sfix.write_text(status_with('{"version":"10.6.109","other":1,"version":"1.2.3"}'), encoding="utf-8")
    net_unknown(env.run())


def test_nested_only_version_is_not_the_network_version(env):
    env.sfix.write_text(status_with('{"metadata":{"version":"1.2.3"}}'), encoding="utf-8")
    net_unknown(env.run())


def test_nested_member_list_with_version_is_not_the_network_version(env):
    env.sfix.write_text(status_with('{"meta":{"a":1,"version":"1.2.3"}}'), encoding="utf-8")
    net_unknown(env.run())


def test_nested_version_before_the_real_top_level_one_is_ignored(env):
    env.sfix.write_text(status_with('{"meta":{"version":"1.2.3"},"list":[{"version":"2.2.2"}],'
                                    '"version":"10.6.109"}'), encoding="utf-8")
    assert_ok(env.run())


def test_version_text_inside_a_string_value_is_ignored(env):
    js = '{"note":"x \\"version\\":\\"1.1.1\\" y","version":"10.6.109"}'
    env.sfix.write_text(status_with(js), encoding="utf-8")
    assert_ok(env.run())


def test_version_text_only_inside_a_string_value_is_unknown(env):
    env.sfix.write_text(status_with('{"note":"\\"version\\":\\"1.1.1\\""}'), encoding="utf-8")
    net_unknown(env.run())


@pytest.mark.parametrize("js", ['{"version":"10.6.109"} trailing', '{"version":"10.6.109"', '"version":"10.6.109"',
                                '{"version":"10.6.109"}}', '[{"version":"10.6.109"}]', '{"a":1 "version":"10.6.109"}',
                                '{"version":{"x":"10.6.109"}}', '{"version":["10.6.109"]}'])
def test_malformed_status_json_is_unknown(env, js):
    env.sfix.write_text(status_with(js), encoding="utf-8")
    net_unknown(env.run())


def test_oversized_status_json_is_unknown(env):
    env.sfix.write_text(status_with('{"pad":"' + "x" * 9000 + '","version":"10.6.109"}'), encoding="utf-8")
    net_unknown(env.run())


# the parse is bounded in size (the walker never sees more than the cap) and so in time
HOSTILE_JSON = {
    "pad-just-over-cap": '{"pad":"' + "x" * 3000 + '","version":"10.6.109"}',
    "pad-8k": '{"pad":"' + "x" * 8150 + '","version":"10.6.109"}',
    "deep-in-cap": '{"a":' + "[" * 1500 + "]" * 1500 + ',"version":"10.6.109"}',
    "deep-huge": '{"a":' + "[" * 200000 + "]" * 200000 + ',"version":"10.6.109"}',
    "opens-only": "{" + '"a":{' * 3000,
    "one-mebibyte": '{"pad":"' + "x" * 1000000 + '","version":"10.6.109"}',
}


@pytest.mark.parametrize("name", sorted(HOSTILE_JSON))
def test_hostile_status_json_is_bounded_in_time_and_unknown(env, name):
    env.sfix.write_text(status_with(HOSTILE_JSON[name]), encoding="utf-8")
    start = time.time()
    r = env.run(timeout=60)
    assert time.time() - start < 10
    net_unknown(r)


def test_status_line_of_over_8k_anywhere_is_unknown_and_fast(env):
    env.sfix.write_text("x" * 3000000 + "\n" + status_with('{"version":"10.6.109"}'), encoding="utf-8")
    start = time.time()
    r = env.run(timeout=60)
    assert time.time() - start < 10
    net_unknown(r)


def test_normal_status_still_parses_and_is_quick(env):
    start = time.time()
    assert_ok(env.run())
    assert time.time() - start < 10


@pytest.mark.parametrize("js", ['{,"version":"10.6.109"}', '{"version":"10.6.109",}', '{"a":1,,"version":"10.6.109"}',
                                '{"version":"10.6.109",,}', '{"note":"bad\\q","version":"10.6.109"}',
                                '{"note":"bad\\u12G4","version":"10.6.109"}', '{"note":"bad\\u12","version":"10.6.109"}'])
def test_malformed_json_grammar_is_unknown(env, js):
    env.sfix.write_text(status_with(js), encoding="utf-8")
    net_unknown(env.run())


def test_valid_escapes_are_accepted(env):
    js = '{"note":"a\\"b\\\\c\\/d\\n\\t\\u00e9\\uABCD","a":[1,2,{"b":null}],"version":"10.6.109"}'
    env.sfix.write_text(status_with(js), encoding="utf-8")
    assert_ok(env.run())


def test_empty_object_is_unknown(env):
    env.sfix.write_text(status_with("{}"), encoding="utf-8")
    net_unknown(env.run())


def test_mutant_json_cap_guard_bites(env):
    env.sfix.write_text(status_with(HOSTILE_JSON["pad-just-over-cap"]), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-json-cap", ":")
    assert 'network_version="10.6.109"' in text(env.run(script=m, timeout=120))


def test_mutant_line_cap_guard_bites(env):
    env.sfix.write_text(status_with('{"version":"10.6.109"}', "y" * 9000 + "\n"), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-line-cap", ":")
    assert 'network_version="10.6.109"' in text(env.run(script=m))


def test_mutant_comma_guard_bites(env):
    env.sfix.write_text(status_with('{"version":"10.6.109",}'), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-comma", '",") st=k; continue ;;')
    assert 'network_version="10.6.109"' in text(env.run(script=m))


def test_mutant_escape_guard_bites(env):
    env.sfix.write_text(status_with('{"note":"bad\\q","version":"10.6.109"}'), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-escape", "*) ;;")
    assert 'network_version="10.6.109"' in text(env.run(script=m))


def test_doc_cron_line_does_not_deliver_an_empty_line(env):
    body = doc_cron_command()
    deliver = env.bin / "deliver2"
    got = env.tmp / "delivered2.txt"
    deliver.write_text(f"#!/bin/sh\ncat >> {shlex.quote(str(got))}\n", encoding="utf-8")
    deliver.chmod(0o755)
    empty = env.bin / "collector-empty"
    empty.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    empty.chmod(0o755)
    cmd = body.replace("/opt/siem/scripts/unifi-os-version-metric.sh", str(empty))
    cmd = cmd.replace("/opt/siem/deliver-metrics", str(deliver))
    r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=30)
    assert r.returncode != 0 and not got.exists()


# ------------------------------------------------------------------ root is refused; no detached survivor holds the run
def fake_id(env, out, name="id"):
    p = env.bin / name
    p.write_text(f"#!/bin/sh\necho {out}\n", encoding="utf-8")
    p.chmod(0o755)
    return p


def test_root_is_refused(env):
    s = env.build("root.sh", rewrites={"id_bin": str(fake_id(env, "0", "id0"))})
    assert_failed_clean(env.run(script=s))
    assert "root" in etext(env.run(script=s))


@pytest.mark.parametrize("out", ["", "abc", "-1", "01", "1000 0"])
def test_unreadable_user_id_fails(env, out):
    s = env.build("badid.sh", rewrites={"id_bin": str(fake_id(env, f"'{out}'", "idx"))})
    assert_failed_clean(env.run(script=s))


def test_ordinary_user_runs(env):
    s = env.build("user.sh", rewrites={"id_bin": str(fake_id(env, "1000", "id1"))})
    assert_ok(env.run(script=s))


SURVIVOR = "#!/bin/sh\nsetsid sh -c 'sleep 14' </dev/null &\nsleep 300\n"


def test_detached_survivor_cannot_hold_the_run_open(env):
    env.uos.write_text(SURVIVOR, encoding="utf-8")
    s = env.build("slack.sh", rewrites={"cmd_timeout": "1", "reader_slack": "2"})
    start = time.time()
    r = env.run(script=s)
    assert time.time() - start < 9
    assert_failed_clean(r)


def test_detached_survivor_in_status_only_gives_unknown_in_time(env):
    env.write_fake(status_cmd="setsid sh -c 'sleep 14' </dev/null & sleep 300")
    s = env.build("slack2.sh", rewrites={"cmd_timeout": "1", "reader_slack": "2"})
    start = time.time()
    r = env.run(script=s)
    assert time.time() - start < 9
    net_unknown(r)


def test_two_status_lines_in_unifi_block_are_not_guessed(env):
    env.sfix.write_text(status_with('{"version":"10.6.109"}',
                                    '     Status: {"version":"10.7.1"}\n'), encoding="utf-8")
    net_unknown(env.run())


def test_version_of_another_service_is_not_used(env):
    env.sfix.write_text(
        "● mongodb.service - MongoDB\n     Status: {\"version\":\"7.0.14\"}\n"
        "● unifi.service - UniFi\n     Active: active\n", encoding="utf-8")
    net_unknown(env.run())


def test_no_unifi_block_is_unknown(env):
    env.sfix.write_text(f"nothing here {CANARY}\n", encoding="utf-8")
    net_unknown(env.run())


@pytest.mark.parametrize("js", [
    '{"version":"10.6.109; rm -rf /"}', '{"version":"10.6.x"}', '{"version":""}', '{"version":"10..6"}',
    '{"version":".6.1"}', '{"version":"10.6."}', "{'version':'10.6.109'}", '{"app_version":"10.6.109"}',
    '{"version":10.6}', '{"version":"1' + "0" * 70 + '.1"}', '{"version":"10.6.109\\u0041"}',
    '{"version":"٥.1"}', '{"version" "10.6.109"}', '{"Version":"10.6.109"}',
])
def test_odd_network_version_is_unknown(env, js):
    env.sfix.write_text(status_with(js), encoding="utf-8")
    net_unknown(env.run())


def test_version_field_with_spaces_is_accepted(env):
    env.sfix.write_text(status_with('{ "version" : "10.6.109" }'), encoding="utf-8")
    assert_ok(env.run())


def test_status_nonzero_exit_makes_network_unknown_only(env):
    env.src.write_text("5\n")
    net_unknown(env.run())


def test_status_hostile_garbage_is_unknown_and_not_echoed(env):
    env.sfix.write_bytes((CANARY + " \x1b[31m\x00 unifi.service Status: {\"version\":\"1.1.1\"}").encode() * 50)
    net_unknown(env.run())


def test_oversized_status_output_is_unknown_and_bounded(env):
    env.write_fake(status_cmd="head -c 20000000 /dev/zero")
    start = time.time()
    r = env.run()
    assert time.time() - start < 30
    net_unknown(r)


def test_status_with_too_many_lines_is_unknown(env):
    body = status_with('{"version":"10.6.109"}') + "x\n" * 60000
    env.sfix.write_text(body, encoding="utf-8")
    net_unknown(env.run())


def test_hanging_status_is_bounded_and_network_unknown(env):
    env.write_fake(status_cmd="sleep 300")
    start = time.time()
    r = env.run(script=env.fast)
    assert time.time() - start < 20
    net_unknown(r)


def test_failed_run_prints_no_status_text_at_all(env):
    env.vrc.write_text("1\n")
    r = env.run()
    assert_failed_clean(r, "10.6.109", "7.0.14", "mongodb", "unifi.service")


# ------------------------------------------------------------------ shipped file and docs
def test_shipped_script_shape():
    src = SCRIPT.read_text(encoding="utf-8")
    assert src.startswith("#!/bin/sh\n")
    consts = dict(re.findall(r"^(\w+_bin)=(\S+)$", src, re.M))
    assert consts and all(v.startswith("/") for v in consts.values()), consts
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    for banned in ("sudo", "curl", "wget", "eval ", "source ", "uosserver shell", "uosserver support"):
        assert banned not in code


def test_shipped_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)


def test_docs_wording_and_scope():
    doc = DOC.read_text(encoding="utf-8")
    assert "UniFi OS Server <version>, Network <version>: check for updates in the UI" in doc
    assert "no update-available signal" in doc.lower()
    assert "never pages" in doc.lower()
    assert "uosserver-version-metric" not in doc
    assert "unifi-os-version-metric.sh" in doc


def doc_cron_command():
    doc = DOC.read_text(encoding="utf-8")
    m = re.search(r"^\S+ \S+ \S+ \S+ \S+ HOST_LABEL=\S+ timeout --kill-after=30s 2m sh -c '(.+)'$", doc, re.M)
    assert m, "the cron line is missing from the doc"
    return m.group(1)


def test_doc_cron_line_does_not_mask_a_collector_failure(env):
    body = doc_cron_command()
    assert "set -o pipefail" not in body and not re.search(r"metric\.sh\s*\|", body)
    deliver = env.bin / "deliver"
    got = env.tmp / "delivered.txt"
    deliver.write_text(f"#!/bin/sh\ncat >> {shlex.quote(str(got))}\n", encoding="utf-8")
    deliver.chmod(0o755)
    bad = env.bin / "collector-bad"
    bad.write_text("#!/bin/sh\necho partial\nexit 1\n", encoding="utf-8")
    bad.chmod(0o755)
    good = env.bin / "collector-good"
    good.write_text("#!/bin/sh\necho line-ok\n", encoding="utf-8")
    good.chmod(0o755)

    def run_with(collector):
        cmd = body.replace("/opt/siem/scripts/unifi-os-version-metric.sh", str(collector))
        cmd = cmd.replace("/opt/siem/deliver-metrics", str(deliver))
        assert str(collector) in cmd and str(deliver) in cmd
        return subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=30)

    r = run_with(bad)
    assert r.returncode != 0 and not got.exists()
    r = run_with(good)
    assert r.returncode == 0 and got.read_text() == "line-ok\n"


def test_doc_says_root_is_refused_and_gives_unprivileged_install():
    doc = DOC.read_text(encoding="utf-8")
    assert "refuses to run as root" in doc
    assert "never as root" in doc or "ordinary user" in doc
    assert "crontab" in doc and "sudo install -m 0755" in doc
    assert "as the owner's user or as root" not in doc


# ------------------------------------------------------------------ clean-mutant revert proofs
def mutant(env, marker, replacement, name="mut.sh", rewrites=None):
    return env.build(name, marks={marker: replacement}, rewrites=rewrites)


def test_mutant_os_charset_guard_bites(env):
    env.vfix.write_text("5.1.4a2\n", encoding="utf-8")
    assert env.run().returncode != 0
    m = mutant(env, "charset", ":")
    assert env.run(script=m).returncode == 0


def test_mutant_os_rc_guard_bites(env):
    env.vrc.write_text("3\n")
    assert env.run().returncode != 0
    m = mutant(env, "os-rc", ":")
    assert env.run(script=m).returncode == 0


def test_mutant_net_status_count_guard_bites(env):
    env.sfix.write_text(status_with('{"version":"10.6.109"}', '     Status: {"version":"10.7.1"}\n'),
                        encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-status-count", ":")
    assert 'network_version="unknown"' not in text(env.run(script=m))


def test_mutant_net_version_count_guard_bites(env):
    env.sfix.write_text(status_with('{"version":"10.6.109","x":1,"version":"1.2.3"}'), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-version-count", ":")
    assert 'network_version="unknown"' not in text(env.run(script=m))


def test_mutant_net_depth_guard_bites(env):
    env.sfix.write_text(status_with('{"meta":{"a":1,"version":"1.2.3"}}'), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-depth", "top=1")
    assert 'network_version="1.2.3"' in text(env.run(script=m))


def test_mutant_root_guard_bites(env):
    s = env.build("root.sh", rewrites={"id_bin": str(fake_id(env, "0", "id0"))})
    assert env.run(script=s).returncode != 0
    m = env.build("rootmut.sh", marks={"root": ":"}, rewrites={"id_bin": str(fake_id(env, "0", "id0"))})
    assert env.run(script=m).returncode == 0


def test_mutant_reader_bound_guard_bites(env):
    env.uos.write_text(SURVIVOR, encoding="utf-8")
    rw = {"cmd_timeout": "1", "reader_slack": "2"}
    m = env.build("rb.sh", marks={"reader-bound": '"$head_bin" -c "$1"'}, rewrites=rw)
    start = time.time()
    env.run(script=m)
    assert time.time() - start >= 12


def test_mutant_net_block_scope_guard_bites(env):
    env.sfix.write_text(
        "● mongodb.service - MongoDB\n     Status: {\"version\":\"7.0.14\"}\n"
        "● unifi.service - UniFi\n     Active: active\n", encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "net-block-scope", "*.service) in_block=1 ;;")
    assert 'network_version="7.0.14"' in text(env.run(script=m))


def test_mutant_net_charset_guard_bites(env):
    env.sfix.write_text(status_with('{"version":"10.6.1x9"}'), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "charset", ":")
    assert 'network_version="unknown"' not in text(env.run(script=m))


def test_mutant_timeout_guard_bites(env):
    env.uos.write_text("#!/bin/sh\nsleep 6\n", encoding="utf-8")
    assert env.run(script=env.fast).returncode != 0
    m = mutant(env, "run-cmd", '"$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C "$uos_bin" "$1" </dev/null 2>/dev/null',
               rewrites={"cmd_timeout": "1"})
    start = time.time()
    env.run(script=m)
    assert time.time() - start >= 5


def test_mutant_output_check_guard_bites(env):
    with open("/dev/full", "wb") as full:
        assert env.run(stdout_to=full).returncode != 0
    m = mutant(env, "output-check", 'printf "%s\\n" "$payload"')
    with open("/dev/full", "wb") as full:
        assert env.run(script=m, stdout_to=full).returncode == 0


def pad_then_unifi_block():
    pad = ("x" * 99 + "\n") * 12000  # about 1.2 MB, 12000 lines: past the read bound, under the line cap
    return pad + status_with('{"version":"10.6.109"}')


def test_status_read_bound_hides_data_past_it(env):
    env.sfix.write_text(pad_then_unifi_block(), encoding="utf-8")
    net_unknown(env.run())


def test_mutant_status_bound_guard_bites(env):
    env.sfix.write_text(pad_then_unifi_block(), encoding="utf-8")
    net_unknown(env.run())
    m = mutant(env, "status-bound",
               "} | bounded_read 100000000 |\"$tr_bin\" '\\000' '?' | net_version) || net_ver=unknown")
    assert 'network_version="10.6.109"' in text(env.run(script=m))


def test_mutant_env_guard_bites(env):
    m = mutant(env, "run-cmd", '"$timeout_bin" -k 5 "$cmd_timeout" "$uos_bin" "$1" </dev/null 2>/dev/null')
    env.run(script=m)
    assert "FOREIGN_LEAK=1" in (env.tmp / "calls.txt.env").read_text()
