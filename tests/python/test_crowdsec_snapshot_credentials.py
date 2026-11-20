"""The CrowdSec smoke test, the pfSense ingest test and the snapshot setup keep every password out of every
child's argument list and environment, and out of every shell trace.

Same design as test_verify_policy_credentials.py: each script runs in a box where every external command
is a recording wrapper (argument list and environment read from /proc) and curl is a fake that records its
standard input too. A sentinel password must reach curl on standard input only (as a curl config); no child
may carry it in its argument list or environment, and no shell trace may print it.

What is NOT guaranteed (the documented limit in docs/container-engine.md): a name that already existed
before the .env ran keeps an export the file gives it, the environment the script was itself started with
holds whatever its launcher exported, and the .env is trusted shell code.
"""
import os
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPTS = REPO_ROOT / "scripts"
PATH_LINE = "PATH=/usr/local/sbin:"
ABS_TOOLS = ("readlink", "dirname", "id", "stat", "mktemp", "rm", "env")
PLAIN_TOOLS = ("jq", "grep", "head", "tail", "tr", "sort", "awk", "cat", "date", "python3", "dirname")
SENTINEL = "S3ntinel-Pw-9f2c"
OTHER_SECRET = "Other-Secret-7d41"

SMOKE = {"script": "08-crowdsec-smoketest.sh", "vars": ["OPENSEARCH_ADMIN_PASSWORD", "GRAFANA_PASS"],
         "args": [], "done": "CrowdSec smoke test passed", "os_calls": 3, "grafana_calls": 2}
INGEST = {"script": "09-test-crowdsec-pfsense-ingest.sh", "vars": ["OPENSEARCH_ADMIN_PASSWORD"],
          "args": [], "done": "CrowdSec pfSense ingestion test passed", "os_calls": 2, "grafana_calls": 0}
SNAPSHOT = {"script": "10-snapshot-setup.sh", "vars": ["OPENSEARCH_ADMIN_PASSWORD"],
            "args": ["https://localhost:9200"], "done": "Snapshot Setup Complete", "os_calls": None,
            "grafana_calls": 0}

FAKE_CURL = r"""#!/bin/bash
REC='@REC@'
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > "$REC/curl-$id-argv"
cat /proc/$$/environ > "$REC/curl-$id-environ"
cfg=0
url=
prev=
method=GET
for a in "$@"; do
    [ "$prev" = -K ] && [ "$a" = - ] && cfg=1
    [ "$prev" = -X ] && method=$a
    case "$a" in http*) url=$a ;; esac
    prev=$a
done
printf '%s' "$url" > "$REC/curl-$id-url"
printf '%s' "$method" > "$REC/curl-$id-method"
if [ "$cfg" = 1 ]; then cat > "$REC/curl-$id-stdin"; fi
case "$url" in
    *_count*) printf '{"count":1}' ;;
    *_search*) printf '{"hits":{"total":{"value":1}}}' ;;
    *alert-rules*) printf '[{"title":"CrowdSec Ban Decision Surge"}]' ;;
    *api/search*) printf '[{"uid":"crowdsec-overview"}]' ;;
    *_cluster/health*) printf '{"status":"green"}' ;;
    *_plugins/_sm/policies*)
        if [ "$method" = GET ] && [ -e "$REC/no-policy" ]; then printf '{"error":"not found"}'; exit 0; fi
        printf '{"_seq_no":1,"_primary_term":1,"sm_policy":{"creation":{"schedule":{"cron":{"expression":"0 3 * * *"}}},"deletion":{"condition":{"max_age":"14d"}}}}' ;;
    *_verify*) printf '{"nodes":{"n1":{}}}' ;;
    *_cat/snapshots*) printf 'id status\n' ;;
    *) printf '{"acknowledged":true}' ;;
esac
exit 0
"""
PROBE = r"""#!/bin/sh
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > '@REC@/@TOOL@-'$id'-argv'
/usr/bin/cat /proc/$$/environ > '@REC@/@TOOL@-'$id'-environ'
exec @REAL@ "$@"
"""
FAKE_NC = r"""#!/bin/sh
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > '@REC@/nc-'$id'-argv'
/usr/bin/cat /proc/$$/environ > '@REC@/nc-'$id'-environ'
/usr/bin/cat > /dev/null
"""
FAKE_SLEEP = "#!/bin/sh\nexit 0\n"


def _exe(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


class Box:
    def __init__(self, tmp_path, spec):
        self.spec = spec
        self.script = spec["script"]
        self.root = tmp_path / "box"
        self.scripts = self.root / "scripts"
        self.scripts.mkdir(parents=True)
        self.scripts.chmod(0o755)
        self.rec = tmp_path / "rec"
        self.rec.mkdir()
        bindir = tmp_path / "probe-bin"
        bindir.mkdir()
        _exe(bindir / "curl", FAKE_CURL.replace("@REC@", str(self.rec)))
        for tool in set(PLAIN_TOOLS) | set(ABS_TOOLS):
            real = shutil.which(tool, path="/usr/bin:/bin")
            if real:
                _exe(bindir / tool, PROBE.replace("@REC@", str(self.rec)).replace("@TOOL@", tool)
                     .replace("@REAL@", real))
        _exe(bindir / "nc", FAKE_NC.replace("@REC@", str(self.rec)))
        _exe(bindir / "sleep", FAKE_SLEEP)
        self.bindir = bindir
        text = (SCRIPTS / self.script).read_text(encoding="utf-8")
        text = text.replace("/opt/siem/.env", str(tmp_path / "no-such-env"))
        if PATH_LINE in text:
            text = text.replace(PATH_LINE, f"PATH={bindir}:/usr/local/sbin:", 1)
        text = self._probe_absolute(text)
        (self.scripts / self.script).write_text(text, encoding="utf-8")
        (self.scripts / self.script).chmod(0o755)
        for helper in ("lib-container-engine.sh", "lib-secrets.sh"):
            lib = self._probe_absolute((SCRIPTS / helper).read_text(encoding="utf-8"))
            (self.scripts / helper).write_text(lib, encoding="utf-8")
            (self.scripts / helper).chmod(0o644)
        self.fixture = tmp_path / "fixture.log"
        self.fixture.write_text("<14>1 2026-01-01T00:00:00Z pfsense crowdsec - - - test line\n", encoding="utf-8")

    def _probe_absolute(self, text):
        return re.sub(r"(?<![A-Za-z0-9_])/(?:usr/)?bin/(" + "|".join(ABS_TOOLS) + r")\b",
                      lambda m: f"{self.bindir}/{m.group(1)}", text)

    def run(self, passwords=None, via="env", env_text=None, bash_args=(), extra_env=None, extra_file=""):
        pw = {v: (passwords or {}).get(v, SENTINEL) for v in self.spec["vars"]}
        env = {"PATH": f"{self.bindir}:/usr/bin:/bin", "HOME": str(self.rec.parent),
               "FIXTURE": str(self.fixture), **(extra_env or {})}
        if via == "env":
            env.update(pw)
        else:
            text = env_text(pw) if env_text else (
                "".join(f"{k}='{v}'\n" for k, v in pw.items()) + f"OTHER_SECRET='{OTHER_SECRET}'\n")
            (self.root / ".env").write_text(text + extra_file, encoding="utf-8")
            (self.root / ".env").chmod(0o600)
        return subprocess.run(["bash", *bash_args, str(self.scripts / self.script), *self.spec["args"]], env=env,
                              text=True, capture_output=True, timeout=120, stdin=subprocess.DEVNULL)

    def recorded(self, suffix):
        return {p.name: p.read_bytes().decode("utf-8", errors="replace")
                for p in self.rec.iterdir() if p.name.endswith(suffix)}

    def curl_stdins(self):
        return [v for k, v in self.recorded("-stdin").items() if k.startswith("curl-")]

    def curl_calls(self):
        return [n for n in self.recorded("-argv") if n.startswith("curl-")]

    def calls(self):
        out = []
        for name in self.recorded("-url"):
            cid = name[:-len("-url")]
            stdin_file = self.rec / f"{cid}-stdin"
            out.append({"url": (self.rec / name).read_text(),
                        "method": (self.rec / f"{cid}-method").read_text(),
                        "argv": (self.rec / f"{cid}-argv").read_text().split("\n"),
                        "stdin": stdin_file.read_text() if stdin_file.exists() else None})
        return out


def ran(proc, spec):
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert spec["done"] in proc.stdout, proc.stdout + proc.stderr
    return proc


def escaped(cred):
    return cred.replace("\\", "\\\\").replace('"', '\\"')


SPECS = pytest.mark.parametrize("spec", [SMOKE, INGEST, SNAPSHOT], ids=["smoke", "ingest", "snapshot"])


@SPECS
@pytest.mark.parametrize("via", ["env", "file"])
def test_no_child_sees_a_password_in_argv_or_environ(tmp_path, spec, via):
    box = Box(tmp_path, spec)
    proc = box.run(via=via)
    ran(proc, spec)
    assert box.curl_calls(), "curl never ran"
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"
            assert OTHER_SECRET not in data, f"another .env secret in {name}"
            for v in spec["vars"] + ["GRAFANA_ADMIN_PASS"]:
                assert f"{v}=" not in data, f"{v} inherited by {name}"
    assert SENTINEL not in proc.stdout + proc.stderr


@SPECS
def test_sentinel_reaches_curl_on_stdin_as_a_config_and_no_argv_has_dash_u(tmp_path, spec):
    box = Box(tmp_path, spec)
    ran(box.run(), spec)
    stdins = box.curl_stdins()
    assert stdins, "no curl call read a config from stdin"
    assert all(re.fullmatch(r'user = "[^"\n]*"\n', s) for s in stdins), stdins
    assert any(f"admin:{SENTINEL}" in s for s in stdins)
    for name, argv in box.recorded("-argv").items():
        if name.startswith("curl-"):
            lines = argv.split("\n")
            assert "-u" not in lines and "--user" not in lines, f"-u in {name}"
            assert not any(re.match(r"-[a-zA-Z]*u$", x) for x in lines), f"-u cluster in {name}"
            assert "-K" in lines and lines[lines.index("-K") + 1] == "-", f"no -K - in {name}"
    for tool in ("nc",):
        for name, argv in box.recorded("-argv").items():
            if name.startswith(tool + "-"):
                assert SENTINEL not in argv


@SPECS
@pytest.mark.parametrize("pw_text", ["plain", "hostile"])
def test_every_credentialed_call_gets_its_own_credential(tmp_path, spec, pw_text):
    """Each service gets its own password (all different), so a swap, an empty or a missing config on any one
    call fails here. Replacing `-K -` by `-u` leaves no stdin at all and fails too."""
    suffix = "" if pw_text == "plain" else 'q"b\\s'
    pws = {v: f"{SENTINEL}-{i}{suffix}" for i, v in enumerate(spec["vars"])}
    box = Box(tmp_path, spec)
    ran(box.run(passwords=pws, extra_env={"GRAFANA_USER": "gf-user"}), spec)
    calls = box.calls()
    assert calls
    os_calls = [c for c in calls if ":9200" in c["url"]]
    gf_calls = [c for c in calls if ":3000" in c["url"]]
    assert len(os_calls) + len(gf_calls) == len(calls), calls
    os_cfg = f'user = "admin:{escaped(pws["OPENSEARCH_ADMIN_PASSWORD"])}"\n'
    for c in os_calls:
        assert c["stdin"] == os_cfg, c
        assert "-u" not in c["argv"], c
    if spec["os_calls"] is not None:
        assert len(os_calls) == spec["os_calls"]
    else:
        assert len(os_calls) >= 6
    assert len(gf_calls) == spec["grafana_calls"]
    for c in gf_calls:
        assert c["stdin"] == f'user = "gf-user:{escaped(pws["GRAFANA_PASS"])}"\n', c
        assert "-u" not in c["argv"], c


def test_smoke_test_grafana_admin_pass_alias_goes_on_stdin_only(tmp_path):
    box = Box(tmp_path, SMOKE)
    proc = box.run(passwords={"OPENSEARCH_ADMIN_PASSWORD": SENTINEL, "GRAFANA_PASS": ""})
    assert proc.returncode != 0 and not box.curl_calls()  # no password and no alias: refused, nothing requested
    sub = tmp_path / "alias"
    sub.mkdir()
    box = Box(sub, SMOKE)
    proc = subprocess.run(["bash", str(box.scripts / box.script)],
                          env={"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(sub),
                               "OPENSEARCH_ADMIN_PASSWORD": SENTINEL, "GRAFANA_ADMIN_PASS": OTHER_SECRET},
                          text=True, capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
    ran(proc, SMOKE)
    gf = [c for c in box.calls() if ":3000" in c["url"]]
    assert gf and all(c["stdin"] == f'user = "admin:{OTHER_SECRET}"\n' for c in gf)
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert OTHER_SECRET not in data and SENTINEL not in data, name
    assert OTHER_SECRET not in proc.stdout + proc.stderr


@SPECS
@pytest.mark.parametrize("style", ["export_assign", "declare_gx", "set_a", "export_alias", "set_a_alias"])
def test_an_env_file_that_exports_cannot_reach_children(tmp_path, spec, style):
    first = spec["vars"][0]

    def text(pw):
        plain = "".join(f"{k}='{v}'\n" for k, v in pw.items())
        if style == "export_assign":
            return "".join(f"export {k}='{v}'\n" for k, v in pw.items()) + f"export OTHER_SECRET='{OTHER_SECRET}'\n"
        if style == "declare_gx":
            return "".join(f"declare -gx {k}='{v}'\n" for k, v in pw.items()) + f"declare -gx OTHER_SECRET='{OTHER_SECRET}'\n"
        if style == "set_a":
            return "set -a\n" + plain + f"OTHER_SECRET='{OTHER_SECRET}'\n"
        if style == "export_alias":
            return plain + f'export BACKUP_PASSWORD="${first}"\nexport OTHER_SECRET=\'{OTHER_SECRET}\'\n'
        return "set -a\n" + plain + f'BACKUP_PASSWORD="${first}"\nOTHER_SECRET=\'{OTHER_SECRET}\'\n'

    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=text)
    ran(proc, spec)
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"
            assert OTHER_SECRET not in data, f"another .env secret in {name}"
            assert "BACKUP_PASSWORD=" not in data, f"alias inherited by {name}"
            for v in spec["vars"]:
                assert f"{v}=" not in data, f"{v} inherited by {name}"


@SPECS
@pytest.mark.parametrize("how", ["bash_x", "shellopts", "env_file_set_x", "env_file_set_x_after"])
@pytest.mark.parametrize("via", ["env", "file"])
def test_no_trace_ever_prints_a_password(tmp_path, spec, how, via):
    if how.startswith("env_file") and via == "env":
        pytest.skip("needs the file route")
    box = Box(tmp_path, spec)
    kw = {"via": via}
    if how == "bash_x":
        kw["bash_args"] = ("-x",)
    elif how == "shellopts":
        kw["extra_env"] = {"SHELLOPTS": "xtrace"}
    elif how == "env_file_set_x":
        kw["env_text"] = lambda pw: "set -x\n" + "".join(f"{k}='{v}'\n" for k, v in pw.items())
    else:
        kw["env_text"] = lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items()) + "set -x\n"
    proc = box.run(**kw)
    ran(proc, spec)
    assert SENTINEL not in proc.stdout + proc.stderr, "a password in the shell trace"


def trace_hijacks(first):
    plain = lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())  # noqa: E731
    ps4 = f'PS4="${first} "\n'
    return {
        "ps4_then_set_x": lambda pw: plain(pw) + ps4 + "set -x\n",
        "set_x_then_ps4": lambda pw: "set -x\n" + plain(pw) + ps4,
        "exported_ps4": lambda pw: plain(pw) + f'export PS4="${first} "\nset -x\n',
        "debug_trap_stdout": lambda pw: plain(pw) + f"trap 'printf \"%s\\n\" \"${first}\"' DEBUG\n",
        "debug_trap_stderr": lambda pw: plain(pw) + f"trap 'printf \"%s\\n\" \"${first}\" >&2' DEBUG\n",
        "return_trap": lambda pw: plain(pw) + f"trap 'printf \"%s\\n\" \"${first}\"' RETURN\nset -T\n",
    }


@SPECS
@pytest.mark.parametrize("how", ["ps4_then_set_x", "set_x_then_ps4", "exported_ps4", "debug_trap_stdout",
                                 "debug_trap_stderr", "return_trap"])
def test_an_env_file_cannot_make_the_trace_or_a_trap_print_a_password(tmp_path, spec, how):
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=trace_hijacks(spec["vars"][0])[how])
    ran(proc, spec)
    assert SENTINEL not in proc.stdout + proc.stderr, "a password printed through the trace or a trap"
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"


@SPECS
@pytest.mark.parametrize("bad", ["false\n", "if then\n", "return 1\n"])
def test_a_failing_env_file_stops_the_script_before_any_request(tmp_path, spec, bad):
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items()) + bad)
    assert proc.returncode != 0, proc.stdout
    assert spec["done"] not in proc.stdout
    assert not box.curl_calls(), "a request was made after a failed .env load"
    assert not [n for n in box.recorded("-argv") if n.startswith("nc-")], "the replay started"
    out = proc.stdout + proc.stderr
    assert "failed to load" in out and ".env" in out, out
    assert SENTINEL not in out


@SPECS
def test_started_by_path_the_privileged_shebang_ignores_a_startup_file(tmp_path, spec):
    box = Box(tmp_path, spec)
    assert (box.scripts / box.script).read_text().startswith("#!/bin/bash -p\n")
    startup = tmp_path / "startup.sh"
    marker = tmp_path / "startup-ran"
    startup.write_text(f'printf x > {marker}\nprintf "%s" "$OPENSEARCH_ADMIN_PASSWORD" >&2\n', encoding="utf-8")
    env = {"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(tmp_path), "BASH_ENV": str(startup),
           "FIXTURE": str(box.fixture), **{v: SENTINEL for v in spec["vars"]}}
    proc = subprocess.run([str(box.scripts / box.script), *spec["args"]], env=env, text=True, capture_output=True,
                          timeout=60, stdin=subprocess.DEVNULL)
    assert not marker.exists(), "the startup file ran"
    assert SENTINEL not in proc.stdout + proc.stderr


@SPECS
def test_refuses_an_untrusted_env_file(tmp_path, spec):
    for kind in ("symlink", "world_writable"):
        sub = tmp_path / kind
        sub.mkdir()
        box = Box(sub, spec)
        marker = sub / "ran"
        body = f"OPENSEARCH_ADMIN_PASSWORD='{SENTINEL}'\ntouch '{marker}'\n"
        if kind == "symlink":
            real = sub / "real.env"
            real.write_text(body, encoding="utf-8")
            real.chmod(0o600)
            (box.root / ".env").symlink_to(real)
        else:
            (box.root / ".env").write_text(body, encoding="utf-8")
            (box.root / ".env").chmod(0o666)
        env = {"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(sub), "FIXTURE": str(box.fixture)}
        proc = subprocess.run(["bash", str(box.scripts / box.script), *spec["args"]], env=env, text=True,
                              capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        assert proc.returncode != 0, kind
        assert not marker.exists(), f"{kind}: the file was sourced"
        assert not box.curl_calls(), kind


@SPECS
def test_inherited_allexport_does_not_export_later_assignments(tmp_path, spec):
    box = Box(tmp_path, spec)
    proc = box.run(via="file", bash_args=("-a",))
    ran(proc, spec)
    for name, data in {**box.recorded("-argv"), **box.recorded("-environ")}.items():
        assert SENTINEL not in data, f"secret in {name}"


@SPECS
def test_hostile_password_stays_one_config_line(tmp_path, spec):
    hostile = 'a"b\\c;d e$f'
    box = Box(tmp_path, spec)
    ran(box.run(passwords={v: hostile for v in spec["vars"]}), spec)
    stdins = box.curl_stdins()
    assert stdins
    for s in stdins:
        assert s.count("\n") == 1, s
        assert s.rstrip("\n").endswith(':a\\"b\\\\c;d e$f"'), s


@SPECS
@pytest.mark.parametrize("bad", ["a\nb", "a\rb"])
def test_line_break_in_a_credential_is_refused_before_any_call(tmp_path, spec, bad):
    for var in spec["vars"]:
        sub = tmp_path / var
        sub.mkdir()
        box = Box(sub, spec)
        proc = box.run(passwords={var: bad})
        assert proc.returncode != 0, proc.stdout
        assert not box.curl_calls(), "curl ran with a refused credential"
        assert not [n for n in box.recorded("-argv") if n.startswith("nc-")], "the replay started"
        assert var in proc.stdout + proc.stderr
        assert bad not in proc.stdout + proc.stderr


def test_smoke_test_line_break_in_the_grafana_user_is_refused(tmp_path):
    box = Box(tmp_path, SMOKE)
    proc = box.run(extra_env={"GRAFANA_USER": "a\nb"})
    assert proc.returncode != 0
    assert not box.curl_calls()
    assert "GRAFANA_USER" in proc.stdout + proc.stderr


@SPECS
def test_inherited_exported_passwords_are_unexported_before_the_first_command(tmp_path, spec):
    """Even a password the launcher exported is not handed on: the very first child (readlink) has none."""
    box = Box(tmp_path, spec)
    ran(box.run(via="env"), spec)
    first = {n: d for n, d in box.recorded("-environ").items() if n.startswith(("readlink-", "dirname-"))}
    assert first
    for name, data in first.items():
        for v in spec["vars"]:
            assert f"{v}=" not in data, f"{v} inherited by {name}"


def policy_calls(box):
    return [c for c in box.calls() if "_plugins/_sm/policies" in c["url"] and c["method"] != "GET"]


def test_snapshot_policy_update_path_is_a_put_with_the_sequence_guard(tmp_path):
    box = Box(tmp_path, SNAPSHOT)
    ran(box.run(), SNAPSHOT)
    writes = policy_calls(box)
    assert len(writes) == 1, writes
    c = writes[0]
    assert c["method"] == "PUT"
    assert c["url"] == "https://localhost:9200/_plugins/_sm/policies/siem-daily?if_seq_no=1&if_primary_term=1"
    assert c["stdin"] == f'user = "admin:{SENTINEL}"\n'
    assert "-K" in c["argv"] and c["argv"][c["argv"].index("-K") + 1] == "-" and "-u" not in c["argv"]


def test_snapshot_policy_create_path_is_a_post_with_its_own_credential(tmp_path):
    box = Box(tmp_path, SNAPSHOT)
    (box.rec / "no-policy").write_text("x", encoding="utf-8")
    pw = 'q"b\\s' + SENTINEL
    ran(box.run(passwords={"OPENSEARCH_ADMIN_PASSWORD": pw}), SNAPSHOT)
    writes = policy_calls(box)
    assert len(writes) == 1, writes
    c = writes[0]
    assert c["method"] == "POST"
    assert c["url"] == "https://localhost:9200/_plugins/_sm/policies/siem-daily"
    assert c["stdin"] == f'user = "admin:{escaped(pw)}"\n'
    assert "-K" in c["argv"] and c["argv"][c["argv"].index("-K") + 1] == "-" and "-u" not in c["argv"]
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"


PASTE_BEGIN = "# --- paste begin"
PASTE_END = "# --- paste end"


def printed_hint(tmp_path):
    box = Box(tmp_path, SNAPSHOT)
    out = ran(box.run(), SNAPSHOT).stdout
    assert PASTE_BEGIN in out and PASTE_END in out, out
    return out.split(PASTE_BEGIN, 1)[1].split(PASTE_END, 1)[0]


def run_hint(tmp_path, hint, password):
    """Run the printed hint in a fresh shell, with the fake curl first on PATH and the password in the
    shell variable the hint names (the owner's own shell, not exported)."""
    box = Box(tmp_path / "hint-run", SNAPSHOT)
    proc = subprocess.run(["bash", "-c", "OPENSEARCH_ADMIN_PASSWORD=$PW\n" + hint],
                          env={"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(tmp_path), "PW": password},
                          text=True, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    return box, proc


def test_the_printed_manual_snapshot_hint_has_no_dash_u_and_no_raw_credential_printf(tmp_path):
    hint = printed_hint(tmp_path)
    assert "-u admin" not in hint and "-u " not in hint
    assert "-K -" in hint


@pytest.mark.parametrize("pw", ['plain-pw', 'q"b\\s', 'a"b\\c;d e$f', '\\"', 'tail\\'])
def test_the_printed_manual_snapshot_hint_sends_one_correct_escaped_config_line(tmp_path, pw):
    hint = printed_hint(tmp_path / "p")
    box, proc = run_hint(tmp_path, hint, pw)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    stdins = box.curl_stdins()
    assert stdins == [f'user = "admin:{escaped(pw)}"\n']
    argv = next(v for k, v in box.recorded("-argv").items() if k.startswith("curl-"))
    assert pw not in argv
    assert "-X\nPUT" in argv and "/_snapshot/siem-snapshots/manual-" in argv
    assert re.search(r"/manual-\d{8}\?wait_for_completion=false", argv)


@pytest.mark.parametrize("pw", ["a\nb", "a\rb", 'x"\nuser = "evil'])
def test_the_printed_manual_snapshot_hint_refuses_a_line_break(tmp_path, pw):
    hint = printed_hint(tmp_path / "p")
    box, proc = run_hint(tmp_path, hint, pw)
    assert proc.returncode != 0
    assert not box.curl_calls(), "curl ran with a refused credential"
    assert "evil" not in proc.stdout + proc.stderr
