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


@SPECS
def test_stdin_config_is_what_authenticates_every_credentialed_call(tmp_path, spec):
    """Replacing `-K -` by `-u` (or dropping it) must fail here: every credentialed call has the config on
    stdin and `-K -` in its argument list, and no call has -u."""
    box = Box(tmp_path, spec)
    ran(box.run(), spec)
    argvs = {n: a.split("\n") for n, a in box.recorded("-argv").items() if n.startswith("curl-")}
    with_cfg = [n for n, a in argvs.items() if "-K" in a and a[a.index("-K") + 1] == "-"]
    assert len(with_cfg) == len(box.curl_stdins())
    expected = 6 if spec is VERIFY else len(argvs)  # verify: 3 credentialed checks plus 3 reads
    assert len(with_cfg) == expected, sorted(argvs.values())
    assert all("-u" not in a for a in argvs.values())


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
