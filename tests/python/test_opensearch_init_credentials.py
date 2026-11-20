"""The OpenSearch security init script never exposes a password in an argument or an environment.

The script runs against a stub engine that records the engine client's argument list, environment and
standard input, and that then RUNS the inner command (the `bash -c` payload) against a fake hash tool, so
what a process inside the container would see is observed too. The host-side children of the script
(grep, tail, python3) go through probe wrappers that record their own argument list and environment from
/proc. A sentinel secret must reach the engine on standard input only.

Documented residual exposure (not asserted away): the password is, by necessity, in the environment of
the hashing tool inside the container (the pinned tool reads it from a named variable or an argument, and
its console mode needs a terminal). An environment is readable only by the owner and root, an argument by
everyone. The test pins that choice: the tool gets `-env`, never `-p`. The launching process's own
environment is set by whoever starts the script and is out of the script's hands.
"""
import hashlib
import json
import os
import re
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPTS = REPO_ROOT / "scripts"
SCRIPT = "08b-init-opensearch-security.sh"
SECURITY_SRC = REPO_ROOT / "docker" / "opensearch" / "security"
PATH_LINE = "PATH=/usr/local/sbin:"  # start of the script's fixed PATH assignment

SENTINEL = "S3ntinel-Pw-9f2c"  # recognizable, no shell or curl-config special characters
PASS_VARS = ["OPENSEARCH_ADMIN_PASSWORD", "OPENSEARCH_LOGSTASH_PASSWORD",
             "OPENSEARCH_READONLY_PASSWORD", "OPENSEARCH_DASHBOARDS_PASSWORD"]
ABS_TOOLS = ("readlink", "dirname", "id", "stat", "mktemp", "rm", "env")  # called by absolute path
OTHER_SECRET = "Other-Secret-7d41"  # another value in the same .env, which no child may inherit

# The engine stub: records the client call, then plays the container for `exec ... bash -c PAYLOAD`.
STUB = r"""
n=$(ls "$REC" | wc -l)
n=$((n + 1))
d="$REC/call-$n"
mkdir "$d"
for a in "$@"; do printf '%s\n' "$a"; done > "$d/argv"
/usr/bin/env > "$d/env"
cat > "$d/stdin"
case " $* " in
    *" bash -c "*)
        # exec [-i] CONTAINER bash -c PAYLOAD ...: run the payload with the recorded stdin
        shift
        [ "$1" != -i ] || shift
        shift  # the container name
        shift  # bash
        shift  # -c
        payload=$1
        # what the image's own environment holds: where its java lives
        OPENSEARCH_JAVA_HOME="$INNER/jdk"
        export OPENSEARCH_JAVA_HOME
        cd "$INNER" && /bin/bash -c "$payload" < "$d/stdin"
        ;;
    *" curl "*)
        case " $* " in
            *" -u "* | *" -K "*) printf 200 ;;
            *"/_cluster/health"*) printf 401 ;;
            *) printf 200 ;;
        esac
        ;;
esac
exit 0
"""

# The fake hashing tool: understands -p VALUE and -env NAME like the real one, records what it was
# given, and answers a "bcrypt" line derived from the whole password so any change to it shows.
# It has the shape of the pinned tools/hash.sh: unrelated helper children first (path discovery), then
# `"$BIN_PATH" $JAVA_OPTS -cp ... Hasher "$@"` as a CHILD, where BIN_PATH is $OPENSEARCH_JAVA_HOME/bin/java,
# else $JAVA_HOME/bin/java, else plain java.
HASH_TOOL = r"""#!/bin/bash
helper=$(/usr/bin/env > "$INNERREC/helper-$$-environ"; /usr/bin/dirname "$0")
BIN_PATH="java"
if [ ! -z "$OPENSEARCH_JAVA_HOME" ]; then
    BIN_PATH="$OPENSEARCH_JAVA_HOME/bin/java"
elif [ ! -z "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/java"
fi
"$BIN_PATH" $JAVA_OPTS -cp "$helper/../*" org.opensearch.security.tools.Hasher "$@"
"""
# The fake java: understands -p VALUE and -env NAME like the real Hasher, records what it was given, and
# answers a "bcrypt" line derived from the whole password so any change to it shows.
JAVA_TOOL = r"""#!/bin/bash
pw=
id=$$
printf '%s\n' "$@" > "$INNERREC/java-$id-argv"
cat /proc/$$/environ > "$INNERREC/java-$id-environ"
while [ $# -gt 0 ]; do
    case "$1" in
        -p) pw=$2; shift ;;
        -env) pw=${!2}; shift ;;
    esac
    shift
done
printf '$2a$12$%s\n' "$(printf '%s' "$pw" | sha256sum | cut -c1-53)"
"""
PROBE = r"""#!/bin/sh
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > '@PROBES@/@TOOL@-'$id'-argv'
/usr/bin/cat /proc/$$/environ > '@PROBES@/@TOOL@-'$id'-environ'
exec /usr/bin/@TOOL@ "$@"
"""

# python3 probe: records argv/environ, and every file the render step creates under the security dir.
PY_SHIM = r"""
import builtins, json, os, sys
probes = "@PROBES@"
pid = os.getpid()
with open(f"{probes}/python3-{pid}-argv", "w") as f:
    f.write("\n".join(sys.argv[1:]))
with open(f"{probes}/python3-{pid}-environ", "wb") as f:
    f.write(open("/proc/self/environ", "rb").read())
events = open(f"{probes}/creates.jsonl", "a")
real_open, real_os_open = builtins.open, os.open
def log(kind, path, extra):
    if "internal_users" in str(path):
        events.write(json.dumps({"kind": kind, "path": str(path), **extra}) + "\n")
        events.flush()
def my_open(file, mode="r", *a, **k):
    if isinstance(file, (str, bytes, os.PathLike)) and any(c in mode for c in "wax+"):
        log("builtin_open", file, {"mode": mode})
    return real_open(file, mode, *a, **k)
def my_os_open(path, flags, mode=0o777, **k):
    if flags & os.O_CREAT:
        log("os_open", path, {"mode": mode})
    return real_os_open(path, flags, mode, **k)
builtins.open = my_open
os.open = my_os_open
if os.path.exists(f"{probes}/fail-replace"):  # a test asks for the final rename to fail
    def boom(*a, **k):
        raise OSError("forced failure")
    os.replace = boom
code = sys.stdin.read()
sys.argv = sys.argv[1:]
exec(compile(code, "<stdin>", "exec"), {"__name__": "__main__"})
"""


class Box:
    def __init__(self, tmp_path, script_text=None, hash_tool=HASH_TOOL):
        self.root = tmp_path / "box"
        self.scripts = self.root / "scripts"
        self.scripts.mkdir(parents=True)
        self.scripts.chmod(0o755)
        self.rec = tmp_path / "rec"
        self.inner_rec = tmp_path / "inner-rec"
        self.probes = tmp_path / "probes"
        self.inner = tmp_path / "inner"
        for d in (self.rec, self.inner_rec, self.probes):
            d.mkdir()
        tools = self.inner / "plugins" / "opensearch-security" / "tools"
        tools.mkdir(parents=True)
        self._exe(tools / "hash.sh", self._with_vars(hash_tool))
        self._exe(tools / "securityadmin.sh", "#!/bin/sh\necho applied\n")
        (self.inner / "jdk" / "bin").mkdir(parents=True)
        self._exe(self.inner / "jdk" / "bin" / "java", self._with_vars(JAVA_TOOL))
        stub = tmp_path / "engine-stub"
        self._exe(stub, "#!/bin/sh\n" + self._with_vars(STUB))
        bindir = tmp_path / "probe-bin"
        bindir.mkdir()
        for tool in ("grep", "tail") + ABS_TOOLS:
            self._exe(bindir / tool, PROBE.replace("@PROBES@", str(self.probes)).replace("@TOOL@", tool))
        shim = tmp_path / "pyshim.py"
        shim.write_text(PY_SHIM.replace("@PROBES@", str(self.probes)), encoding="utf-8")
        self._exe(bindir / "python3", f"#!/bin/sh\nexec /usr/bin/python3 -I '{shim}' \"$@\"\n")
        text = script_text if script_text is not None else (SCRIPTS / SCRIPT).read_text(encoding="utf-8")
        assert PATH_LINE in text
        text = text.replace(PATH_LINE, f"PATH={bindir}:/usr/local/sbin:", 1)
        text = self._probe_absolute(text, bindir)
        (self.scripts / SCRIPT).write_text(text, encoding="utf-8")
        (self.scripts / SCRIPT).chmod(0o755)
        lib = (SCRIPTS / "lib-container-engine.sh").read_text(encoding="utf-8")
        lib = self._probe_absolute(lib, bindir)
        lib += f"\nce_init() {{ CE_NAME=docker; CE_BIN='{stub}'; }}\n"
        (self.scripts / "lib-container-engine.sh").write_text(lib, encoding="utf-8")
        (self.scripts / "lib-container-engine.sh").chmod(0o644)
        self.deploy = self.root / "deploy"
        self.sec = self.deploy / "opensearch" / "security"
        self.sec.mkdir(parents=True)
        (self.sec / "internal_users.yml.template").write_text(
            (SECURITY_SRC / "internal_users.yml.template").read_text(encoding="utf-8"), encoding="utf-8")

    @staticmethod
    def _probe_absolute(text, bindir):
        """The scripts call these by absolute path; point each at the recording wrapper."""
        return re.sub(r"(?<![A-Za-z0-9_])/(?:usr/)?bin/(" + "|".join(ABS_TOOLS) + r")\b",
                      lambda m: f"{bindir}/{m.group(1)}", text)

    def _with_vars(self, text):
        # ce_run starts the engine with an empty environment, so the directories are written into the text
        head = f"REC='{self.rec}'\nINNER='{self.inner}'\nINNERREC='{self.inner_rec}'\n"
        if text.startswith("#!"):
            first, rest = text.split("\n", 1)
            return first + "\n" + head + rest
        return head + text

    @staticmethod
    def _exe(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def run(self, passwords=None, via="env", extra_env=None, umask=0o022, bash_args=(), env_style=None):
        """via='env': passwords in the launching environment; via='file': in the deploy dir .env."""
        pw = {v: (passwords or {}).get(v, SENTINEL) for v in PASS_VARS}
        env = {"PATH": "/usr/bin:/bin", "SIEM_DEPLOY_DIR": str(self.deploy), "HOME": str(self.rec.parent)}
        if via == "env":
            env.update(pw)
        else:
            lines = [f"{k}='{v}'" for k, v in pw.items()] + [f"OTHER_SECRET='{OTHER_SECRET}'"]
            text = "\n".join(lines) + "\n"
            if env_style is not None:
                text = env_style(pw)
            (self.deploy / ".env").write_text(text, encoding="utf-8")
            (self.deploy / ".env").chmod(0o600)
        env.update(extra_env or {})
        return subprocess.run(["bash", *bash_args, str(self.scripts / SCRIPT)], env=env, text=True, capture_output=True,
                              timeout=120, preexec_fn=lambda: os.umask(umask))

    def engine_calls(self):
        out = []
        for d in sorted(self.rec.iterdir(), key=lambda p: int(p.name.split("-")[1])):
            out.append({k: (d / k).read_text(encoding="utf-8", errors="replace") for k in ("argv", "env", "stdin")})
        return out

    def files(self, directory, suffix):
        return {p.name: p.read_bytes().decode("utf-8", errors="replace")
                for p in directory.iterdir() if p.name.endswith(suffix)}


def fake_hash(password):
    return "$2a$12$" + hashlib.sha256(password.encode()).hexdigest()[:53]


def make(tmp_path, **kw):
    return Box(tmp_path, **kw)


@pytest.mark.parametrize("via", ["env", "file"])
def test_sentinel_never_in_engine_argv_or_environment(tmp_path, via):
    box = make(tmp_path)
    proc = box.run(via=via)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    recorded = box.engine_calls()
    assert len(recorded) >= 7  # one probe, four hashes, securityadmin, two verify calls
    for c in recorded:
        assert SENTINEL not in c["argv"], f"secret in an argument list:\n{c['argv']}"
        assert SENTINEL not in c["env"], "secret in an environment"
    assert SENTINEL not in proc.stdout + proc.stderr


@pytest.mark.parametrize("via", ["env", "file"])
def test_no_host_child_sees_a_secret_in_argv_or_environ(tmp_path, via):
    """Every external the script runs (the bootstrap commands too, not only grep, tail and python3) is a
    recording wrapper: none may inherit a password or another secret the .env set, or get one in its
    arguments."""
    box = make(tmp_path)
    assert box.run(via=via).returncode == 0
    assert_children_clean(box, EVERY_TOOL)


EVERY_TOOL = ("grep", "tail", "python3") + ABS_TOOLS


def assert_children_clean(box, tools):
    names = sorted(p.name for p in box.probes.iterdir())
    for tool in tools:  # the probes really ran
        assert any(n.startswith(f"{tool}-") and n.endswith("-environ") for n in names), (tool, names)
    for p in box.probes.iterdir():
        if p.name.endswith(("-argv", "-environ")):
            data = p.read_bytes().decode("utf-8", errors="replace")
            assert SENTINEL not in data, f"secret in {p.name}"
            assert OTHER_SECRET not in data, f"another .env secret in {p.name}"
            for v in PASS_VARS:
                assert f"{v}=" not in data, f"{v} inherited by {p.name}"


ENV_STYLES = {
    "export_assign": lambda pw: "".join(f"export {k}='{v}'\n" for k, v in pw.items())
                                + f"export OTHER_SECRET='{OTHER_SECRET}'\n",
    "declare_gx": lambda pw: "".join(f"declare -gx {k}='{v}'\n" for k, v in pw.items())
                             + f"declare -gx OTHER_SECRET='{OTHER_SECRET}'\n",
    "set_a_then_plain": lambda pw: "set -a\n" + "".join(f"{k}='{v}'\n" for k, v in pw.items())
                                   + f"OTHER_SECRET='{OTHER_SECRET}'\n",
    "other_secret_only": lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())
                                    + f"export OTHER_SECRET='{OTHER_SECRET}'\n",
    "export_after_plain": lambda pw: "".join(f"{k}='{v}'\nexport {k}\n" for k, v in pw.items())
                                     + f"OTHER_SECRET='{OTHER_SECRET}'\nexport OTHER_SECRET\n",
}


@pytest.mark.parametrize("style", sorted(ENV_STYLES))
def test_an_env_file_that_exports_cannot_reach_children(tmp_path, style):
    """The .env is shell code. Whatever export form it uses (export NAME=v, declare -x, set -a, export
    after assignment), no host child may inherit a password or another secret it defined, and allexport
    is off again afterwards."""
    box = make(tmp_path)
    proc = box.run(via="file", env_style=ENV_STYLES[style])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert_children_clean(box, EVERY_TOOL)
    for c in box.engine_calls():
        assert SENTINEL not in c["env"] and OTHER_SECRET not in c["env"]


def test_known_limit_env_file_can_export_through_a_name_that_already_existed(tmp_path):
    """DOCUMENTED LIMIT (docs/container-engine.md): the .env is trusted shell code. A name that existed
    before it ran (here CE_TRUSTED_DIRS, a variable of the script's own helper) keeps an export given
    by the file, so a password put in it reaches host children. This test asserts the limit as it is;
    when the script learns to close it, this test must be flipped to assert the opposite."""
    box = make(tmp_path)
    proc = box.run(via="file", env_style=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items())
                   + f"CE_HOME_BASES='/run /var/tmp /tmp {OTHER_SECRET}'\nexport CE_HOME_BASES\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    leaked = [p.name for p in box.probes.iterdir()
              if p.name.endswith("-environ") and OTHER_SECRET in p.read_bytes().decode("utf-8", errors="replace")]
    assert leaked, "the documented limit no longer holds: close the docs note and flip this test"


def test_declare_x_in_an_env_file_is_local_to_the_loader_and_leaks_nothing(tmp_path):
    """Plain `declare -x` inside the sourcing function is function-local: the passwords are then unset
    and the script refuses to run, still without any secret reaching a child."""
    box = make(tmp_path)
    proc = box.run(via="file", env_style=lambda pw: "".join(f"declare -x {k}='{v}'\n" for k, v in pw.items()))
    assert proc.returncode != 0
    for p in box.probes.iterdir():
        assert SENTINEL not in p.read_bytes().decode("utf-8", errors="replace"), p.name
    assert SENTINEL not in proc.stdout + proc.stderr


@pytest.mark.parametrize("how", ["bash_a", "shellopts", "both"])
@pytest.mark.parametrize("via", ["env", "file"])
def test_inherited_allexport_does_not_export_later_assignments(tmp_path, how, via):
    """A shell started with allexport (bash -a, or SHELLOPTS=allexport in the environment) would export
    every later assignment, such as the admin credential string: the script switches it off first."""
    box = make(tmp_path)
    kw = {}
    if how in ("bash_a", "both"):
        kw["bash_args"] = ("-a",)
    if how in ("shellopts", "both"):
        kw["extra_env"] = {"SHELLOPTS": "allexport"}
    proc = box.run(via=via, **kw)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert_children_clean(box, EVERY_TOOL)
    for c in box.engine_calls():  # the client environment too (it is built with env -i)
        assert SENTINEL not in c["env"]
    # the credential string the script builds for the admin check is never exported to a child either
    assert "ADMIN_CRED" not in "".join(p.read_text(errors="replace") for p in box.probes.iterdir()
                                       if p.name.endswith("-environ"))


def test_exported_functions_run_with_no_password_exported(tmp_path):
    """A function inherited through the environment runs inside the shell, and a child it starts gets the
    shell's exported variables. Shadow grep, pwd and compgen with functions that dump a child's
    environment: nothing secret may be in it at any of those points."""
    box = make(tmp_path)
    dump = box.probes / "fn-env.txt"
    fns = {}
    for name in ("grep", "pwd", "compgen"):
        fns[f"BASH_FUNC_{name}%%"] = (f"() {{  /usr/bin/env >> '{dump}'\n"
                                     f" builtin {name} \"$@\" 2>/dev/null || /usr/bin/{name} \"$@\"\n}}")
    proc = box.run(extra_env=fns)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = dump.read_text(errors="replace") if dump.exists() else ""
    assert SENTINEL not in text and OTHER_SECRET not in text
    for v in PASS_VARS:
        assert f"{v}=" not in text


def test_hash_tool_gets_the_password_by_name_not_by_argument(tmp_path):
    """The pinned Hasher takes -p VALUE (an argument: visible to everyone) or -env NAME (an environment).
    Only the second is acceptable."""
    box = make(tmp_path)
    assert box.run().returncode == 0
    argvs = box.files(box.inner_rec, "-argv")
    java = {n: d for n, d in argvs.items() if n.startswith("java-")}
    assert len(java) == 4
    for name, data in java.items():
        assert SENTINEL not in data, name
        assert "-p\n" not in data and not data.startswith("-p"), f"{name}: password argument option"
        assert data.splitlines()[-2:] == ["-env", "HASH_PASS"], name


def test_only_the_hasher_process_has_the_password_in_its_environment(tmp_path):
    """The wrapper (hash.sh) runs unrelated helper children before it starts java. The password is handed
    to the java process alone: not to the wrapper, not to any helper."""
    box = make(tmp_path)
    assert box.run().returncode == 0
    envs = box.files(box.inner_rec, "-environ")
    helpers = {n: d for n, d in envs.items() if n.startswith("helper-")}
    javas = {n: d for n, d in envs.items() if n.startswith("java-")}
    assert len(helpers) == 4 and len(javas) == 4
    for name, data in helpers.items():
        assert SENTINEL not in data, f"a helper child of the wrapper inherited the password: {name}"
        assert "\x00HASH_PASS=" not in "\x00" + data, name  # (the function text names it; a variable would be NAME=)
    for name, data in javas.items():
        assert SENTINEL in data, f"the hasher process did not get the password: {name}"
    # the engine client never sees it, nor does anything on the host (see the other tests)
    for c in box.engine_calls():
        assert SENTINEL not in c["env"]


def test_temp_file_is_removed_when_the_final_rename_fails(tmp_path):
    box = make(tmp_path)
    (box.sec / "internal_users.yml").write_text("old\n", encoding="utf-8")
    (box.probes / "fail-replace").write_text("", encoding="utf-8")
    proc = box.run()
    assert proc.returncode != 0
    assert "forced failure" in proc.stdout + proc.stderr
    assert sorted(p.name for p in box.sec.iterdir() if "tmp" in p.name) == []
    assert (box.sec / "internal_users.yml").read_text(encoding="utf-8") == "old\n"


def test_hash_derives_from_the_whole_password(tmp_path):
    """A leading or trailing space, a backslash and a tab all survive the trip to the hash tool."""
    box = make(tmp_path)
    secrets = {"OPENSEARCH_ADMIN_PASSWORD": "  lead and trail  ",
               "OPENSEARCH_LOGSTASH_PASSWORD": "back\\slash\\\\x",
               "OPENSEARCH_READONLY_PASSWORD": "tab\there",
               "OPENSEARCH_DASHBOARDS_PASSWORD": 'quo"te $HOME `id`'}
    proc = box.run(secrets)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rendered = (box.sec / "internal_users.yml").read_text(encoding="utf-8")
    for pw in secrets.values():
        assert fake_hash(pw) in rendered, pw
    # and no two accounts share a hash: a truncation would collapse them
    assert len({fake_hash(p) for p in secrets.values()}) == 4


def test_sentinel_reaches_the_engine_on_stdin(tmp_path):
    """The fix moves the secret, it does not drop it: hashing and the admin check both get it on stdin."""
    box = make(tmp_path)
    assert box.run().returncode == 0
    with_secret = [c for c in box.engine_calls() if SENTINEL in c["stdin"]]
    assert len(with_secret) == 5  # four hash calls and the admin check
    admin = [c for c in with_secret if "-K\n-\n" in c["argv"]]
    assert len(admin) == 1
    assert admin[0]["stdin"] == f'user = "admin:{SENTINEL}"\n'


def test_distinct_secrets_do_not_cross_into_argv(tmp_path):
    box = make(tmp_path)
    secrets = {v: f"Zq{i}-unique-{v[11:15]}" for i, v in enumerate(PASS_VARS)}
    assert box.run(secrets).returncode == 0
    for c in box.engine_calls():
        for s in secrets.values():
            assert s not in c["argv"]
            assert s not in c["env"]
    for p in box.probes.iterdir():
        data = p.read_bytes().decode("utf-8", errors="replace")
        for s in secrets.values():
            assert s not in data, p.name


@pytest.mark.parametrize("hostile", [
    'pa"ss\\word',                # quote and backslash, escaped in the curl config
    "pw$(touch /nonexistent)`id`",  # shell metacharacters
    "pw -o /etc/x",               # looks like options
])
def test_hostile_password_stays_one_config_line(tmp_path, hostile):
    box = make(tmp_path)
    proc = box.run({"OPENSEARCH_ADMIN_PASSWORD": hostile})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    admin = [c for c in box.engine_calls() if "-K\n-\n" in c["argv"]]
    assert len(admin) == 1
    stdin = admin[0]["stdin"]
    escaped = hostile.replace("\\", "\\\\").replace('"', '\\"')
    assert stdin == f'user = "admin:{escaped}"\n'
    for c in box.engine_calls():
        assert hostile not in c["argv"] and hostile not in c["env"]


@pytest.mark.parametrize("var", PASS_VARS)
@pytest.mark.parametrize("bad", ['pw\noutput = /tmp/owned', "pw\rx"])
def test_line_break_in_a_password_is_refused_before_any_engine_call(tmp_path, var, bad):
    box = make(tmp_path)
    proc = box.run({var: bad})
    assert proc.returncode != 0
    assert var in proc.stderr
    assert "/tmp/owned" not in proc.stdout + proc.stderr
    assert list(box.rec.iterdir()) == []


def test_internal_users_file_is_never_created_wider_than_final_mode(tmp_path):
    """The rendered file holds password hashes: it is created with its final restrictive mode from the
    start (no create-then-chmod window), even under a permissive umask."""
    box = make(tmp_path)
    assert box.run(umask=0o000).returncode == 0
    events = [json.loads(line) for line in (box.probes / "creates.jsonl").read_text().splitlines()]
    assert events, "the render step created no file under the probe (test would pass vacuously)"
    for e in events:
        assert e["kind"] == "os_open", f"created through a umask-governed open: {e}"
        assert e["mode"] & ~0o640 == 0, f"created with mode {oct(e['mode'])}: {e}"
    final = box.sec / "internal_users.yml"
    assert final.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in box.sec.iterdir() if "tmp" in p.name) == []  # no leftover temporary file


@pytest.mark.parametrize("bad", ["false\n", "if then\n", "return 1\n"])
def test_a_failing_env_file_is_reported_and_stops_before_any_engine_call(tmp_path, bad):
    """A .env whose load fails (a failing command, a syntax error) must not look like success: the script
    exits non-zero with a value-free diagnostic naming the load, and calls the engine zero times."""
    box = make(tmp_path)
    proc = box.run(via="file", env_style=lambda pw: "".join(f"{k}='{v}'\n" for k, v in pw.items()) + bad)
    assert proc.returncode != 0, proc.stdout
    out = proc.stdout + proc.stderr
    assert "failed to load" in out and ".env" in out, out
    assert SENTINEL not in out
    assert box.engine_calls() == []
