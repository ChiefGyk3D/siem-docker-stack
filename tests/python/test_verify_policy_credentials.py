"""The verify and ISM policy scripts keep a password out of every child's argument list and environment.

Each script runs in a box where every external command is a recording wrapper (argument list and
environment read from /proc) and curl is a fake that records its standard input too. A sentinel
password must reach curl on standard input only (as a curl config); no child may carry it in its
argument list or environment, and no shell trace may print it.

What is verified: the named password variables, and any variable the .env file creates (plain, exported,
declared with -x, set -a, or an exported alias), are not in a child's environment. What is NOT
guaranteed: a name that already existed before the file ran keeps an export the file gives it (the
documented limit in docs/container-engine.md), and the environment the script was itself started with
holds whatever its launcher exported. The .env is trusted shell code.
"""
import os
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPTS = REPO_ROOT / "scripts"
PATH_LINE = "PATH=/usr/local/sbin:"  # start of the fixed PATH assignment in the verify script
ABS_TOOLS = ("readlink", "dirname", "id", "stat", "mktemp", "rm", "env")  # called by absolute path
PLAIN_TOOLS = ("jq", "grep", "tail", "tr", "sort", "awk", "df", "whoami", "mountpoint", "sleep", "dirname")
SENTINEL = "S3ntinel-Pw-9f2c"
OTHER_SECRET = "Other-Secret-7d41"

VERIFY = {
    "script": "05-verify.sh",
    "vars": ["OPENSEARCH_ADMIN_PASSWORD", "WAZUH_INDEXER_PASSWORD", "INFLUXDB_ADMIN_PASSWORD"],
}
POLICY = {
    "script": "04-apply-ism-policy.sh",
    "vars": ["OPENSEARCH_ADMIN_PASSWORD"],
}

# The fake curl: records argv, environ and (only when a config is read from it) stdin, then answers
# like the services would: an authenticated request gets 200, the anonymous one gets 401.
FAKE_CURL = r"""#!/bin/bash
REC='@REC@'
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > "$REC/curl-$id-argv"
cat /proc/$$/environ > "$REC/curl-$id-environ"
cfg=0
want_code=0
url=
prev=
for a in "$@"; do
    [ "$prev" = -K ] && [ "$a" = - ] && cfg=1
    [ "$a" = -w ] && want_code=1
    case "$a" in http*) url=$a ;; esac
    prev=$a
done
printf '%s' "$url" > "$REC/curl-$id-url"
if [ "$cfg" = 1 ]; then cat > "$REC/curl-$id-stdin"; fi
if [ "$want_code" = 1 ]; then
    case "$url" in
        *:9200*) [ "$cfg" = 1 ] && printf 200 || printf 401 ;;
        *:9202*) printf 200 ;;
        *:443*) printf 200 ;;
        *:5601*) printf 302 ;;
        *:8086/ping*) printf 204 ;;
        *:9090*) printf 401 ;;
        *) printf 200 ;;
    esac
    exit 0
fi
case "$url" in
    *_cluster/health) printf '{"status":"green","number_of_nodes":1,"number_of_data_nodes":1}' ;;
    *nodeattrs*) printf 'node temp hot\n' ;;
    *_ism/policies) printf '{"total_policies":0,"policies":[]}' ;;
    *_index_template) printf '{"index_templates":[]}' ;;
    *8086/query*) printf '{"results":[{"series":[{"values":[["db"]]}]}]}' ;;
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
        self.bindir = bindir
        text = (SCRIPTS / self.script).read_text(encoding="utf-8")
        text = text.replace("/opt/siem/.env", str(tmp_path / "no-such-env"))  # never read the host's file
        if PATH_LINE in text:
            text = text.replace(PATH_LINE, f"PATH={bindir}:/usr/local/sbin:", 1)
        text = self._probe_absolute(text)
        (self.scripts / self.script).write_text(text, encoding="utf-8")
        (self.scripts / self.script).chmod(0o755)
        lib = (SCRIPTS / "lib-container-engine.sh").read_text(encoding="utf-8")
        lib = self._probe_absolute(lib)
        lib += "\nce_resolve() { return 1; }\n"  # no engine is ever started
        (self.scripts / "lib-container-engine.sh").write_text(lib, encoding="utf-8")
        (self.scripts / "lib-container-engine.sh").chmod(0o644)
        src = REPO_ROOT / "docker" / "opensearch"
        shutil.copytree(src, self.root / "docker" / "opensearch", ignore=shutil.ignore_patterns("security"))

    def _probe_absolute(self, text):
        return re.sub(r"(?<![A-Za-z0-9_])/(?:usr/)?bin/(" + "|".join(ABS_TOOLS) + r")\b",
                      lambda m: f"{self.bindir}/{m.group(1)}", text)

    def run(self, passwords=None, via="env", env_text=None, bash_args=(), umask=0o022, extra_env=None):
        pw = {v: (passwords or {}).get(v, SENTINEL) for v in self.spec["vars"]}
        env = {"PATH": f"{self.bindir}:/usr/bin:/bin", "HOME": str(self.rec.parent), **(extra_env or {})}
        if via == "env":
            env.update(pw)
        else:
            text = env_text(pw) if env_text else (
                "".join(f"{k}='{v}'\n" for k, v in pw.items()) + f"OTHER_SECRET='{OTHER_SECRET}'\n")
            (self.root / ".env").write_text(text, encoding="utf-8")
            (self.root / ".env").chmod(0o600)
        args = [] if self.script.startswith("05") else ["https://localhost:9200"]
        return subprocess.run(["bash", *bash_args, str(self.scripts / self.script), *args], env=env, text=True,
                              capture_output=True, timeout=120, stdin=subprocess.DEVNULL,
                              preexec_fn=lambda: os.umask(umask))

    def recorded(self, suffix):
        return {p.name: p.read_bytes().decode("utf-8", errors="replace")
                for p in self.rec.iterdir() if p.name.endswith(suffix)}

    def curl_stdins(self):
        return list(self.recorded("-stdin").values())

    def curl_calls(self):
        return [n for n in self.recorded("-argv") if n.startswith("curl-")]


def ran(proc, spec):
    """The script ran to its end. The verify script exits 1 here on purpose: no container engine exists in
    the box, so its container checks fail; it is the summary line that shows it got through."""
    if spec is VERIFY:
        assert "Passed:" in proc.stdout, proc.stdout + proc.stderr
    else:
        assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


SPECS = pytest.mark.parametrize("spec", [VERIFY, POLICY], ids=["verify", "policy"])


@SPECS
@pytest.mark.parametrize("via", ["env", "file"])
def test_no_child_sees_a_password_in_argv_or_environ(tmp_path, spec, via):
    box = Box(tmp_path, spec)
    proc = box.run(via=via)
    ran(proc, spec)
    assert box.curl_calls(), "curl never ran"
    names = sorted(p.name for p in box.rec.iterdir())
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"
            assert OTHER_SECRET not in data, f"another .env secret in {name}"
            for v in spec["vars"]:
                assert f"{v}=" not in data, f"{v} inherited by {name}"
    assert any(n.startswith("curl-") and n.endswith("-environ") for n in names)
    assert SENTINEL not in proc.stdout + proc.stderr


@SPECS
def test_sentinel_reaches_curl_on_stdin_as_a_config(tmp_path, spec):
    box = Box(tmp_path, spec)
    ran(box.run(), spec)
    stdins = box.curl_stdins()
    assert stdins, "no curl call read a config from stdin"
    assert all(re.fullmatch(r'user = "[^"\n]*"\n', s) for s in stdins), stdins
    assert any(f"admin:{SENTINEL}" in s for s in stdins)
    for name, argv in box.recorded("-argv").items():
        if name.startswith("curl-"):
            assert "-u" not in argv.split("\n"), f"-u in {name}"


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
        if style == "export_alias":  # a new exported name that holds a password value
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
    elif how == "env_file_set_x":  # the file turns tracing on before it assigns
        kw["env_text"] = lambda pw: "set -x\n" + "".join(f"{k}='{v}'\n" for k, v in pw.items())
    else:  # the file turns tracing on after it assigns and leaves it on
        kw["env_text"] = lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items()) + "set -x\n"
    proc = box.run(**kw)
    ran(proc, spec)
    assert SENTINEL not in proc.stdout + proc.stderr, "a password in the shell trace"


def escaped(cred):
    return cred.replace("\\", "\\\\").replace('"', '\\"')


@SPECS
@pytest.mark.parametrize("pw_text", ["plain", "hostile"])
def test_every_credentialed_call_gets_its_own_credential(tmp_path, spec, pw_text):
    """Per call: the URL and the stdin config recorded together. Each service gets its own password (all
    different), so a swap, an empty config or a missing config on any one call fails here. Replacing
    `-K -` by `-u` leaves no stdin at all and fails too."""
    suffix = "" if pw_text == "plain" else 'q"b\\s'
    pws = {v: f"{SENTINEL}-{i}{suffix}" for i, v in enumerate(spec["vars"])}
    box = Box(tmp_path, spec)
    ran(box.run(passwords=pws), spec)
    calls = {}
    for name in box.recorded("-url"):
        cid = name[:-len("-url")]
        argv = (box.rec / f"{cid}-argv").read_text().split("\n")
        stdin_file = box.rec / f"{cid}-stdin"
        calls[cid] = {"url": (box.rec / name).read_text(), "argv": argv,
                      "stdin": stdin_file.read_text() if stdin_file.exists() else None}
    assert calls
    os_cfg = f'user = "admin:{escaped(pws["OPENSEARCH_ADMIN_PASSWORD"])}"\n'
    anonymous = 0
    for c in calls.values():
        assert "-u" not in c["argv"], c
        if ":9202" in c["url"]:
            assert c["stdin"] == f'user = "admin:{escaped(pws["WAZUH_INDEXER_PASSWORD"])}"\n', c
        elif ":8086/query" in c["url"]:
            assert c["stdin"] == f'user = "admin:{escaped(pws["INFLUXDB_ADMIN_PASSWORD"])}"\n', c
        elif ":9200" in c["url"] and c["stdin"] is None:
            anonymous += 1  # the one deliberate 401 check
        elif ":9200" in c["url"]:
            assert c["stdin"] == os_cfg, c
            assert "-K" in c["argv"] and c["argv"][c["argv"].index("-K") + 1] == "-"
        else:
            assert c["stdin"] is None, c  # services that take no credential get none
    assert anonymous == (1 if spec is VERIFY else 0)
    if spec is VERIFY:
        assert sum(1 for c in calls.values() if c["stdin"]) == 6


@SPECS
@pytest.mark.parametrize("bad", ["false\n", "if then\n", "return 1\n"])
def test_a_failing_env_file_stops_the_script_before_any_request(tmp_path, spec, bad):
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items()) + bad)
    assert proc.returncode != 0, proc.stdout
    assert "Passed:" not in proc.stdout
    assert not box.curl_calls(), "a request was made after a failed .env load"
    out = proc.stdout + proc.stderr
    assert "failed to load" in out and ".env" in out, out
    assert SENTINEL not in out


def all_text_files():
    out = [REPO_ROOT / "README.md", REPO_ROOT / "change-passwords.sh"]
    for pattern in ("scripts/*.sh", "docs/**/*.md"):
        out += sorted(REPO_ROOT.glob(pattern))
    return [p for p in out if p.is_file()]


HARDENED = ("04-apply-ism-policy.sh", "05-verify.sh", "08b-init-opensearch-security.sh",
            "08-crowdsec-smoketest.sh", "09-test-crowdsec-pfsense-ingest.sh", "10-snapshot-setup.sh")


def test_no_text_tells_anyone_to_start_a_hardened_script_through_bash():
    """Run as root, `bash script` runs BASH_ENV, imported functions, SHELLOPTS and BASHOPTS before line 1 and
    bypasses the privileged shebang. Usage lines, emitted next-step commands and the docs say to run
    these scripts by their path (sudo scripts/...)."""
    hits = []
    for path in all_text_files():
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if via_interpreter(line):
                hits.append(f"{path.relative_to(REPO_ROOT)}:{n}: {line.strip()}")
    assert not hits, "\n".join(hits)


# any shell interpreter, then anything (options, options with operands such as `-o pipefail`, `-c '`),
# then a relative or absolute path to one of the scripts; sudo options and variables before it are
# covered because only the interpreter token has to match
INTERPRETER_PATTERN = re.compile(r"\b(?:ba|da|z|k|a)?sh\b(?:\s+\S+)*?\s+[\"']?(?:\S*/)?(?:"
                                 + "|".join(re.escape(h) for h in HARDENED) + r")\b")


def via_interpreter(line):
    return bool(INTERPRETER_PATTERN.search(line))


@pytest.mark.parametrize("line", [
    "bash scripts/05-verify.sh",
    "sudo bash scripts/05-verify.sh localhost",
    "bash -o pipefail scripts/05-verify.sh",
    "bash -x -e scripts/04-apply-ism-policy.sh https://h:9200",
    "sudo -u root bash -c 'scripts/05-verify.sh'",
    'sudo -E -u root bash -c "scripts/08b-init-opensearch-security.sh"',
    "sudo env A=1 sh /opt/siem/scripts/05-verify.sh",
    "dash -c /opt/siem/scripts/04-apply-ism-policy.sh",
    "SIEM_USER=x bash /path/to/scripts/05-verify.sh 10.0.0.1",
    "echo '  2. Run: bash scripts/08b-init-opensearch-security.sh'",
    "bash scripts/10-snapshot-setup.sh https://h:9200",
    "sudo bash scripts/08-crowdsec-smoketest.sh",
    "echo '  5. Snapshots: bash scripts/09-test-crowdsec-pfsense-ingest.sh'",
])
def test_the_interpreter_scan_catches_every_spelling(line):
    assert via_interpreter(line), line


@pytest.mark.parametrize("line", [
    "sudo scripts/05-verify.sh",
    "sudo -u root scripts/04-apply-ism-policy.sh https://h:9200",
    "sudo SIEM_DEPLOY_DIR=/opt/siem scripts/08b-init-opensearch-security.sh",
    "`05-verify.sh` needs WAZUH_INDEXER_PASSWORD in the .env",
    "bash scripts/03-deploy.sh local",
])
def test_the_interpreter_scan_leaves_direct_execution_alone(line):
    assert not via_interpreter(line), line


CANONICAL = {
    "scripts/04-apply-ism-policy.sh": ["sudo scripts/04-apply-ism-policy.sh"],
    "scripts/05-verify.sh": ["sudo scripts/05-verify.sh"],
    "scripts/08b-init-opensearch-security.sh": ["sudo scripts/08b-init-opensearch-security.sh",
                                                "sudo scripts/04-apply-ism-policy.sh", "sudo scripts/05-verify.sh"],
    "scripts/08-crowdsec-smoketest.sh": ["sudo scripts/08-crowdsec-smoketest.sh"],
    "scripts/09-test-crowdsec-pfsense-ingest.sh": ["sudo scripts/09-test-crowdsec-pfsense-ingest.sh"],
    "scripts/10-snapshot-setup.sh": ["sudo scripts/10-snapshot-setup.sh"],
    "scripts/03-deploy.sh": ["sudo scripts/08b-init-opensearch-security.sh", "sudo scripts/04-apply-ism-policy.sh",
                             "sudo scripts/05-verify.sh", "sudo scripts/10-snapshot-setup.sh"],
    "README.md": ["sudo scripts/04-apply-ism-policy.sh", "sudo scripts/05-verify.sh",
                  "sudo scripts/08-crowdsec-smoketest.sh"],
    "docs/phase-f-testing.md": ["sudo scripts/08b-init-opensearch-security.sh", "sudo scripts/04-apply-ism-policy.sh",
                                "sudo scripts/05-verify.sh", "sudo scripts/08-crowdsec-smoketest.sh",
                                "sudo scripts/09-test-crowdsec-pfsense-ingest.sh", "sudo scripts/10-snapshot-setup.sh"],
    "docs/backup-restore.md": ["sudo scripts/10-snapshot-setup.sh"],
    "docs/crowdsec.md": ["sudo scripts/09-test-crowdsec-pfsense-ingest.sh"],
    "docs/maintenance.md": ["sudo /path/to/scripts/05-verify.sh"],
    "docs/container-engine.md": ["sudo scripts/05-verify.sh"],
}


@pytest.mark.parametrize("relpath", sorted(CANONICAL))
def test_the_direct_execution_commands_are_present(relpath):
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    for command in CANONICAL[relpath]:
        assert command in text, f"{relpath} does not show `{command}`"


def trace_hijacks(first):
    plain = lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())  # noqa: E731
    ps4 = f'PS4="${first} "\n'
    debug = f"trap 'printf \"%s\\n\" \"${first}\"' DEBUG\n"
    return {
        "ps4_then_set_x": lambda pw: plain(pw) + ps4 + "set -x\n",
        "set_x_then_ps4": lambda pw: "set -x\n" + plain(pw) + ps4,
        "exported_ps4": lambda pw: plain(pw) + f'export PS4="${first} "\nset -x\n',
        "debug_trap_stdout": lambda pw: plain(pw) + debug,
        "debug_trap_stderr": lambda pw: plain(pw) + f"trap 'printf \"%s\\n\" \"${first}\" >&2' DEBUG\n",
        "return_trap": lambda pw: plain(pw) + f"trap 'printf \"%s\\n\" \"${first}\"' RETURN\nset -T\n",
    }


@SPECS
@pytest.mark.parametrize("how", ["ps4_then_set_x", "set_x_then_ps4", "exported_ps4", "debug_trap_stdout",
                                 "debug_trap_stderr", "return_trap"])
def test_an_env_file_cannot_make_the_trace_or_a_trap_print_a_password(tmp_path, spec, how):
    """The file is shell code: `PS4="$PASSWORD "; set -x` makes bash expand the password in every trace line
    (the line for the `set +x` that ends tracing included), and a DEBUG or RETURN trap can print it. Tracing,
    PS4 and those traps are neutralized while the loader's output is still discarded."""
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=trace_hijacks(spec["vars"][0])[how])
    ran(proc, spec)
    assert SENTINEL not in proc.stdout + proc.stderr, "a password printed through the trace or a trap"
    for suffix in ("-argv", "-environ"):
        for name, data in box.recorded(suffix).items():
            assert SENTINEL not in data, f"secret in {name}"


@SPECS
def test_known_limit_env_exit_trap_still_fires_and_prints_the_password(tmp_path, spec):
    """DOCUMENTED LIMIT (docs/container-engine.md): the .env is trusted shell code. The loader clears the
    DEBUG, RETURN and ERR traps and tracing, but not an EXIT or signal trap: one the file installs runs
    at exit with the script's variables. This test asserts the limit as it is; when the loader learns to
    close it, flip this test to assert the sentinel is absent."""
    first = spec["vars"][0]
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())
                   + f"trap 'printf \"%s\\n\" \"${first}\"' EXIT\n")
    ran(proc, spec)
    assert SENTINEL in proc.stdout, "the documented limit no longer holds: close the docs note and flip this test"


@SPECS
def test_known_limit_env_function_shadowing_a_helper_is_not_blocked(tmp_path, spec):
    """DOCUMENTED LIMIT (docs/container-engine.md): a function the .env defines runs in place of the
    command of the same name, with the script's variables. This test asserts the limit as it is; when the
    loader learns to close it, flip this test to assert the sentinel is absent."""
    first = spec["vars"][0]
    box = Box(tmp_path, spec)
    proc = box.run(via="file", env_text=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())
                   + f"jq() {{ cat > /dev/null; printf '%s\\n' \"${first}\"; }}\n")
    ran(proc, spec)
    assert SENTINEL in proc.stdout, "the documented limit no longer holds: close the docs note and flip this test"


def test_only_the_final_status_of_the_env_file_decides_the_load(tmp_path):
    """DOCUMENTED LIMIT: the loader reports the status of the complete file. A command that fails in the
    middle but is followed by one that succeeds does not make the load fail."""
    box = Box(tmp_path, POLICY)
    proc = box.run(via="file", env_text=lambda pw: "false\n" + "".join(f"{k}='{v}'\n" for k, v in pw.items()))
    ran(proc, POLICY)
    assert box.curl_calls()


@pytest.mark.parametrize("spec", [VERIFY, POLICY], ids=["verify", "policy"])
def test_started_by_path_the_privileged_shebang_ignores_a_startup_file(tmp_path, spec):
    """The script started by its path runs under `#!/bin/bash -p`: BASH_ENV is not processed. (This does not
    fake root: it checks the shebang option the root launch depends on.)"""
    box = Box(tmp_path, spec)
    startup = tmp_path / "startup.sh"
    marker = tmp_path / "startup-ran"
    startup.write_text(f'printf x > {marker}\nprintf "%s" "$OPENSEARCH_ADMIN_PASSWORD" >&2\n', encoding="utf-8")
    pw = {v: SENTINEL for v in spec["vars"]}
    env = {"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(tmp_path), "BASH_ENV": str(startup), **pw}
    args = [] if spec is VERIFY else ["https://localhost:9200"]
    proc = subprocess.run([str(box.scripts / box.script), *args], env=env, text=True, capture_output=True,
                          timeout=60, stdin=subprocess.DEVNULL)
    assert not marker.exists(), "the startup file ran"
    assert SENTINEL not in proc.stdout + proc.stderr


def test_policy_script_refuses_an_untrusted_env_file(tmp_path):
    """The ISM script loads .env through the same trusted loader as the others: a link or a world writable
    file is refused before anything in it runs, and before any request."""
    for kind in ("symlink", "world_writable"):
        sub = tmp_path / kind
        sub.mkdir()
        box = Box(sub, POLICY)
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
        env = {"PATH": f"{box.bindir}:/usr/bin:/bin", "HOME": str(sub)}
        proc = subprocess.run(["bash", str(box.scripts / box.script), "https://localhost:9200"], env=env, text=True,
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
def test_line_break_in_a_password_is_refused_before_any_call(tmp_path, spec, bad):
    for var in spec["vars"]:
        sub = tmp_path / var
        sub.mkdir()
        box = Box(sub, spec)
        proc = box.run(passwords={var: bad})
        assert proc.returncode != 0, proc.stdout
        assert not box.curl_calls(), "curl ran with a refused password"
        assert var in proc.stdout + proc.stderr
        assert bad not in proc.stdout + proc.stderr  # the value is never echoed
