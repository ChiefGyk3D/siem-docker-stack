"""Tests for scripts/twingate-connector-update.sh (issue #220).

The script runs against a FAKE `docker` (and a fake `curl`). The shipped script
has no test seam: the harness writes a TEST-ONLY COPY of it in which exactly
four fixed lines (PATH, LOCK_BASE, RUN_BASE, TRUSTED_UID) are rewritten to point at the
fakes and at scratch dirs. Both fakes record their arguments and never touch a
real engine, network or Twingate account. Tokens below are placeholders.
(A fourth line, TRUSTED_UID=0, is rewritten to the test user's uid because the
tests do not run as root; a fake `find` reports chosen paths as owned by
someone else to model an attacker-owned path.)
"""
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "twingate-connector-update.sh"
LAUNCHER = REPO_ROOT / "scripts" / "twingate-connector-update-launcher.sh"
NAME = "connector-a"
OLD_ID = "sha256:" + "a" * 64
NEW_ID = "sha256:" + "b" * 64
SECRET = "FAKE-SECRET-TOKEN-not-real-9f8e7d"
WEBHOOK = "https://hooks.example.invalid/notify/FAKE-WEBHOOK-PATH-123"
HOOK = {"NOTIFY_WEBHOOK_URL": WEBHOOK, "NOTIFY_WEBHOOK_ALLOWED_HOSTS": "hooks.example.invalid"}
API_KEY = "FAKE-API-KEY-not-real-4455"

FAKE_DOCKER = r'''#!/bin/sh
D="$(cd "$(dirname "$0")/.." && pwd)/fake"
[ ! -f "$D/fakeenv" ] || . "$D/fakeenv"
echo "$*" >>"$D/log"
env >>"$D/envdump"
[ -z "$DOCKER_CONFIG" ] || ls -A "$DOCKER_CONFIG" >>"$D/cfgls" 2>/dev/null
hold() { touch "$D/$1"; i=0; while [ ! -f "$D/go" ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i+1)); done; }
case "$1" in
  inspect)
    [ -f "$D/inspect.json" ] || exit 1
    cat "$D/inspect.json" ;;
  image)
    case "$*" in
      *--format*) cat "$D/new_id" ;;
      *)
        [ -z "$FAKE_OLD_MISSING" ] || exit 1
        [ ! -f "$D/old_gone" ] || exit 1
        cat "$D/image.json" ;;
    esac ;;
  info) echo "json-file" ;;
  tag) [ -z "$FAKE_TAG_FAIL" ] || exit 1 ;;
  pull)
    [ -z "$FAKE_PULL_FAIL" ] || { echo "pull failed $FAKE_SECRET" >&2; exit 1; }
    [ -z "$FAKE_PULL_HOLD" ] || hold in_pull
    exit 0 ;;
  exec)
    [ -f "$D/version" ] || exit 1
    cat "$D/version" ;;
  stop) exit 0 ;;
  rm) [ -z "$FAKE_OLD_VANISH" ] || touch "$D/old_gone"; exit 0 ;;
  ps) cat "$D/state" 2>/dev/null ;;
  run)
    if [ "$2" = "--rm" ]; then
      [ -z "$FAKE_NEWVER_FAIL" ] || exit 1
      echo "Connector 1.96.0"; exit 0
    fi
    # run -d ... --env-file F ... IMAGE
    n=$(wc -l <"$D/log")
    prev=""; envf=""; last=""
    for a in "$@"; do
      [ "$prev" = "--env-file" ] && envf="$a"
      prev="$a"; last="$a"
    done
    stat -c '%a %n' "$(dirname "$envf")" "$envf" >>"$D/stat"
    cp "$envf" "$D/env_seen_$n"
    python3 -I "$(dirname "$0")/envparse.py" "$envf" >"$D/env_parsed_$n"
    case "$last" in
      twingate/connector:1)
        [ ! -f "$D/hold" ] || hold in_run
        echo "${FAKE_NEW_STATUS:-Up 2 seconds}" >"$D/state"
        echo "Connector 1.96.0" >"$D/version" ;;
      twingate/connector:rollback-*)
        [ -z "$FAKE_ROLLBACK_RUN_FAIL" ] || { echo "rollback run failed" >&2; exit 1; }
        echo "${FAKE_OLD_STATUS:-Up 2 seconds}" >"$D/state"
        echo "Connector 1.95.0" >"$D/version" ;;
    esac
    exit 0 ;;
esac
exit 0
'''

FAKE_CURL = r'''#!/bin/sh
D="$(cd "$(dirname "$0")/.." && pwd)/fake"
[ ! -f "$D/fakeenv" ] || . "$D/fakeenv"
echo "$*" >>"$D/curl.argv"
env >>"$D/envdump"
cat >>"$D/curl.stdin"
printf '\n---\n' >>"$D/curl.stdin"
n=$(wc -l <"$D/curl.argv")
[ -z "$FAKE_CURL_FAIL" ] || exit 7
out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
emit() {
  if [ -f "$D/curl.out.$n" ]; then cat "$D/curl.out.$n"
  elif [ -f "$D/curl.out" ]; then cat "$D/curl.out"
  else printf '{}'; fi
}
if [ -n "$out" ]; then emit >"$out"; else emit; fi
# a complete, valid body and THEN a transfer failure
[ -z "$FAKE_CURL_FAIL_AFTER" ] || exit 7
'''

IMAGE_ENV = ["PATH=/usr/bin", "LANG=C.UTF-8"]

# Fake `find`: a path listed in the fake dir/foreign is reported as owned by another user.
FAKE_FIND = r'''#!/bin/sh
FD="$(cd "$(dirname "$0")/.." && pwd)/fake"
# fake/gw lists paths reported as group- or world-writable (a "-perm /022" query).
for a in "$@"; do
  case "$a" in
    /*) if [ -f "$FD/gw" ] && grep -qxF "$a" "$FD/gw"; then exit 0; fi ;;
  esac
done
for a in "$@"; do
  case "$a" in
    /*) if [ -f "$FD/foreign" ] && grep -qxF "$a" "$FD/foreign"; then exit 0; fi ;;
  esac
done
# fake/mnt names a directory modelled as a nested mount: a one-filesystem
# (-xdev) listing does not descend into it.
case " $* " in
  *" -xdev "*) if [ -f "$FD/mnt" ]; then exec /usr/bin/find "$@" ! -path "$(cat "$FD/mnt")/*"; fi ;;
esac
# The test tree is not root-owned, so a trust query is answered "trusted" here;
# the lists above model the attacker-controlled ones.
case " $* " in
  *" /022 "*) for a in "$@"; do case "$a" in /*) echo "$a"; exit 0 ;; esac; done ;;
esac
exec /usr/bin/find "$@"
'''

# Fake `ls`: a path listed in fake/acl gets the plus sign after its mode, as GNU ls
# shows for an extended ACL. Everything else is the real ls.
FAKE_LS = r'''#!/bin/sh
FD="$(cd "$(dirname "$0")/.." && pwd)/fake"
for last in "$@"; do :; done
if [ -f "$FD/acl" ] && grep -qxF "$last" "$FD/acl"; then
  /bin/ls "$@" | sed 's/^\(.\{10\}\)/\1+/'
  exit 0
fi
exec /bin/ls "$@"
'''

# Fake `getfacl`: a path listed in fake/getfacl reports a named-user entry.
FAKE_GETFACL = r'''#!/bin/sh
FD="$(cd "$(dirname "$0")/.." && pwd)/fake"
for last in "$@"; do :; done
if [ -f "$FD/getfacl_fail" ]; then exit 1; fi
printf 'user::rwx\n'
if [ -f "$FD/getfacl" ] && grep -qxF "$last" "$FD/getfacl"; then printf 'user:someone:rwx\nmask::rwx\n'; fi
printf 'group::r-x\nother::r-x\n'
'''

# Fake `cat` and `sed`: they record their arguments (the help test proves that no
# program is handed the updater's path) and otherwise behave as the real ones. A
# file fake/mountinfo replaces the kernel mount table for the starting-point
# mount test.
FAKE_CAT = r'''#!/bin/sh
FD="$(cd "$(dirname "$0")/.." && pwd)/fake"
printf '%s\n' "$*" >>"$FD/cat.args"
if [ "$1" = /proc/self/mountinfo ] && [ -f "$FD/mountinfo" ]; then exec /bin/cat "$FD/mountinfo"; fi
exec /bin/cat "$@"
'''

FAKE_SED = r'''#!/bin/sh
FD="$(cd "$(dirname "$0")/.." && pwd)/fake"
printf '%s\n' "$*" >>"$FD/sed.args"
exec /bin/sed "$@"
'''

# A model of how `docker run --env-file` reads a file. It is deliberately
# conservative: it trims leading whitespace of a line, skips blank and '#' lines,
# splits at the first '=', trims trailing whitespace of the value and strips one
# pair of matching surrounding quotes. Docker's own grammar may differ in some of
# these points; the script must therefore accept only values that every such
# reading returns unchanged.
ENV_PARSER = r'''
import json, sys
out = []
for line in open(sys.argv[1], encoding="utf-8").read().split("\n"):
    line = line.lstrip()
    if not line or line.startswith("#"):
        continue
    k, sep, v = line.partition("=")
    if sep:
        v = v.rstrip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
    out.append(k + sep + v)
print(json.dumps(out))
'''

PATH_LINE = 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'


def make_test_copy(dest, bin_dir, lock_base, run_base):
    """Write a test-only copy of the script with three fixed lines rewritten."""
    lines = SCRIPT.read_text().splitlines(keepends=True)
    out, hits = [], {"path": 0, "lock": 0, "run": 0, "uid": 0}
    for line in lines:
        if line.rstrip("\n") == PATH_LINE:
            line = f'PATH="{bin_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'
            hits["path"] += 1
        elif line.startswith("LOCK_BASE="):
            line = f'LOCK_BASE="{lock_base}"\n'
            hits["lock"] += 1
        elif line.startswith("RUN_BASE="):
            line = f'RUN_BASE="{run_base}"\n'
            hits["run"] += 1
        elif line.rstrip("\n") == "TRUSTED_UID=0":
            line = f"TRUSTED_UID={os.getuid()}\n"
            hits["uid"] += 1
        out.append(line)
    assert hits == {"path": 1, "lock": 1, "run": 1, "uid": 1}, hits
    dest.write_text("".join(out))
    return dest


def make_launcher_copy(dest, bin_dir, updater):
    """Test-only copy of the launcher: PATH, TRUSTED_UID and UPDATER are rewritten."""
    out, hits = [], {"path": 0, "uid": 0, "updater": 0, "find": 0, "ls": 0, "getfacl": 0}
    for line in LAUNCHER.read_text().splitlines(keepends=True):
        if line.rstrip("\n") == PATH_LINE:
            line = f'PATH="{bin_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'
            hits["path"] += 1
        elif line.rstrip("\n") == "TRUSTED_UID=0":
            line = f"TRUSTED_UID={os.getuid()}\n"
            hits["uid"] += 1
        elif line.startswith("UPDATER="):
            line = f'UPDATER="{updater}"\n'
            hits["updater"] += 1
        elif line.rstrip("\n") in ("FIND=/usr/bin/find", "LS=/usr/bin/ls", "GETFACL=/usr/bin/getfacl"):
            # the fakes in the test bin directory, by absolute path (never found through PATH)
            name = line.split("=")[0].lower()
            line = f"{name.upper()}={bin_dir}/{name}\n"
            hits[name] += 1
        out.append(line)
    assert hits == {"path": 1, "uid": 1, "updater": 1, "find": 1, "ls": 1, "getfacl": 1}, hits
    dest.write_text("".join(out))
    return dest


def inspect_json(host=None, cfg=None, mounts=None):
    c = {
        "Id": "abcdef123456" + "0" * 52,
        "Image": OLD_ID,
        "Config": {"Image": "twingate/connector:1",
                   "Env": ["PATH=/usr/bin", "LANG=C.UTF-8",
                           f"TWINGATE_ACCESS_TOKEN={SECRET}", "TWINGATE_NETWORK=example-net"]},
        "HostConfig": {"NetworkMode": "host", "Binds": None,
                       "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                       "Privileged": False},
        "Mounts": mounts or [],
    }
    c["HostConfig"].update(host or {})
    c["Config"].update(cfg or {})
    return json.dumps([c])


def image_json(cfg=None):
    conf = {"Env": IMAGE_ENV}
    conf.update(cfg or {})
    return json.dumps([{"Id": OLD_ID, "Config": conf}])


def node(name=NAME, state="ALIVE", rn="rn1", nid=None, version="1.96.0"):
    return {"id": nid or f"id-{name}", "name": name, "state": state, "version": version,
            "remoteNetwork": {"id": rn}}


def gql(nodes, more=False, cursor=None):
    return json.dumps({"data": {"connectors": {
        "pageInfo": {"hasNextPage": more, "endCursor": cursor},
        "edges": [{"node": n} for n in nodes]}}})


class Env:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.d = tmp_path / "fake"
        self.bin = tmp_path / "bin"
        self.tmp = tmp_path / "tmp"
        self.run_dir = tmp_path / "run"
        self.lock_base = tmp_path / "lock"
        self.hostile = tmp_path / "hostile"
        for p in (self.d, self.bin, self.tmp, self.run_dir, self.lock_base, self.hostile):
            p.mkdir()
        self.script = make_test_copy(tmp_path / "script-under-test.sh", self.bin, self.lock_base, self.run_dir)
        self.launcher = make_launcher_copy(tmp_path / "launcher-under-test.sh", self.bin, self.script)
        (self.bin / "envparse.py").write_text(ENV_PARSER)
        for n, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL), ("find", FAKE_FIND),
                        ("ls", FAKE_LS), ("getfacl", FAKE_GETFACL), ("cat", FAKE_CAT), ("sed", FAKE_SED)):
            f = self.bin / n
            f.write_text(body)
            f.chmod(0o755)
        (self.d / "inspect.json").write_text(inspect_json())
        (self.d / "image.json").write_text(image_json())
        (self.d / "new_id").write_text(NEW_ID + "\n")
        (self.d / "version").write_text("Connector 1.95.0\n")
        (self.d / "state").write_text("Up 3 days\n")

    def environ(self, **env):
        # TMPDIR and XDG_RUNTIME_DIR point at HOSTILE dirs: the script must never use them.
        e = {"PATH": os.environ["PATH"],
             "FAKE_SECRET": SECRET, "TMPDIR": str(self.tmp), "HOME": str(self.root),
             "XDG_RUNTIME_DIR": str(self.tmp),
             "HOST_LABEL": "host-test", "TWINGATE_UPDATE_WAIT_SECS": "2",
             "TWINGATE_UPDATE_POLL_SECS": "1"}
        e.update(env)
        # FAKE_* settings go to the fakes through a file, not the environment,
        # because the script clears its environment before it runs them.
        fake = {k: v for k, v in e.items() if k.startswith("FAKE_")}
        (self.d / "fakeenv").write_text("".join(f"{k}={shlex.quote(v)}\n" for k, v in fake.items()))
        return {k: v for k, v in e.items() if not k.startswith("FAKE_")}

    def run(self, *args, stdin="", original=False, **env):
        script = LAUNCHER if original else self.launcher
        return subprocess.run(["sh", str(script), *args], input=stdin, capture_output=True,
                              text=True, env=self.environ(**env), timeout=60,
                              cwd=str(self.root))

    def start(self, *args, **env):
        return subprocess.Popen(["sh", str(self.launcher), *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=self.environ(**env), cwd=str(self.root))

    def envdump(self):
        p = self.d / "envdump"
        return p.read_text() if p.exists() else ""

    def wait_for(self, name, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if (self.d / name).exists():
                return
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {name}")

    def release(self):
        (self.d / "go").write_text("")

    def leftovers(self):
        found = []
        for base in (self.tmp, self.run_dir, self.lock_base):
            for p in base.rglob("*"):
                found.append(str(p.relative_to(self.root)))
        return found

    def log(self):
        p = self.d / "log"
        return p.read_text().splitlines() if p.exists() else []

    def verbs(self):
        return [l.split()[0] for l in self.log()]

    def runs_d(self):
        return [l for l in self.log() if l.startswith("run -d")]

    def curl_argv(self):
        p = self.d / "curl.argv"
        return p.read_text() if p.exists() else ""

    def curl_stdin(self):
        p = self.d / "curl.stdin"
        return p.read_text() if p.exists() else ""


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


CHANGING = ("pull", "stop", "rm", "tag")


def changed(env):
    return [l for l in env.log() if l.split()[0] in CHANGING or l.startswith("run -d")]


def set_inspect(env, **kw):
    (env.d / "inspect.json").write_text(inspect_json(**kw))


# --- happy path --------------------------------------------------------------

def test_update_happy_path(env):
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert "result=updated" in r.stdout
    assert "Connector 1.95.0" in r.stdout and "Connector 1.96.0" in r.stdout
    log = env.log()
    assert "pull twingate/connector:1" in log
    assert "stop " + NAME in log and "rm " + NAME in log
    assert log.index("stop " + NAME) < log.index("rm " + NAME)
    runs = env.runs_d()
    assert len(runs) == 1
    assert runs[0].startswith("run -d --network host --env-file ")
    assert f"--name {NAME} --restart=unless-stopped twingate/connector:1" in runs[0]
    assert "prune" not in " ".join(log)
    envfile = next(env.d.glob("env_seen_*")).read_text().splitlines()
    assert f"TWINGATE_ACCESS_TOKEN={SECRET}" in envfile
    assert envfile and all(l.startswith("TWINGATE_") for l in envfile)
    # new version is read with no network and a fixed entrypoint
    assert any(l.startswith("run --rm --network none --entrypoint ./connectord ") for l in log)
    assert env.leftovers() == []


# --- finding 8: absolute PATH; r2 finding 2: no test seam in production -------

def test_inherited_path_and_cwd_are_not_used(env):
    # a fake docker sits first on the INHERITED PATH and in the cwd; the shipped
    # script must not use either
    shutil.copy(env.bin / "docker", env.root / "docker")
    r = env.run("--dry-run", NAME, original=True, PATH=f"{env.bin}::{os.environ['PATH']}")
    assert r.returncode == 2
    assert env.log() == []


def test_no_bin_dir_seam_is_honored_by_the_shipped_script(env):
    # r2 finding 2: an env var must never put a directory in front of the trusted PATH
    r = env.run("--dry-run", NAME, original=True, TWINGATE_UPDATE_BIN_DIR=str(env.bin))
    assert env.log() == [] and env.curl_argv() == ""
    assert "TWINGATE_UPDATE_BIN_DIR" not in SCRIPT.read_text() + LAUNCHER.read_text()


def test_test_copy_differs_from_the_shipped_script_in_four_lines_only(env):
    a = SCRIPT.read_text().splitlines()
    b = env.script.read_text().splitlines()
    assert len(a) == len(b)
    assert len([1 for x, y in zip(a, b) if x != y]) == 4
    # the launcher copy differs in six lines only: PATH, TRUSTED_UID, UPDATER and
    # the absolute paths of the three fakes (FIND, LS, GETFACL)
    a = LAUNCHER.read_text().splitlines()
    b = env.launcher.read_text().splitlines()
    assert len(a) == len(b)
    assert len([1 for x, y in zip(a, b) if x != y]) == 6


# --- finding 5: layout allowlist ----------------------------------------------

REFUSALS = [
    ("host", {"NetworkMode": "bridge"}),
    ("host", {"NetworkMode": "container:abc"}),
    ("host", {"Binds": ["/etc/x:/etc/x"]}),
    ("mounts", [{"Type": "bind", "Source": "/a", "Destination": "/b"}]),
    ("host", {"RestartPolicy": {"Name": "always"}}),
    ("host", {"RestartPolicy": {"Name": "no"}}),
    ("host", {"Privileged": True}),
    ("host", {"CapAdd": ["NET_ADMIN"]}),
    ("host", {"CapDrop": ["ALL"]}),
    ("host", {"SecurityOpt": ["seccomp=unconfined"]}),
    ("host", {"PidMode": "host"}),
    ("host", {"UsernsMode": "host"}),
    ("host", {"ReadonlyRootfs": True}),
    ("host", {"Memory": 536870912}),
    ("host", {"CpuShares": 512}),
    ("host", {"LogConfig": {"Type": "syslog", "Config": {}}}),
    ("host", {"LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}}}),
    ("host", {"Dns": ["192.0.2.53"]}),
    ("host", {"ExtraHosts": ["db:192.0.2.9"]}),
    ("host", {"Tmpfs": {"/run": ""}}),
    ("host", {"Ulimits": [{"Name": "nofile", "Soft": 1, "Hard": 2}]}),
    ("host", {"Devices": [{"PathOnHost": "/dev/net/tun", "PathInContainer": "/dev/net/tun"}]}),
    ("host", {"Sysctls": {"net.ipv4.ping_group_range": "0 2147483647"}}),
    ("host", {"GroupAdd": ["docker"]}),
    ("host", {"AutoRemove": True}),
    ("cfg", {"WorkingDir": "/srv"}),
    ("cfg", {"Tty": True}),
    ("cfg", {"User": "root"}),
    ("cfg", {"User": "1000:1000"}),
    ("cfg", {"Entrypoint": ["/bin/sh", "-c"]}),
    ("cfg", {"Cmd": ["--debug"]}),
    ("cfg", {"Labels": {"owner": "me"}}),
    ("cfg", {"Healthcheck": {"Test": ["CMD", "true"]}}),
    ("cfg", {"Env": ["TWINGATE_NETWORK=x", "EXTRA_VAR=1"]}),
]


@pytest.mark.parametrize("kind,val", REFUSALS, ids=[f"{k}-{json.dumps(v)[:40]}" for k, v in REFUSALS])
def test_layout_refusal_changes_nothing(env, kind, val):
    if kind == "mounts":
        set_inspect(env, mounts=val)
    else:
        set_inspect(env, **{kind: val})
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "layout differs" in r.stderr
    assert changed(env) == []
    assert env.leftovers() == []


def test_layout_accepts_settings_inherited_from_the_image(env):
    img = {"User": "node", "Entrypoint": ["/connectord"], "Cmd": ["run"], "Labels": {"v": "1"},
           "Healthcheck": {"Test": ["CMD", "true"]}}
    (env.d / "image.json").write_text(image_json(img))
    set_inspect(env, cfg=img)
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


def test_layout_refusal_wrong_image(env):
    d = json.loads(inspect_json())
    d[0]["Config"]["Image"] = "twingate/connector:latest"
    (env.d / "inspect.json").write_text(json.dumps(d))
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []


def test_missing_container_refused(env):
    (env.d / "inspect.json").unlink()
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []


# --- finding 7: env file ------------------------------------------------------

@pytest.mark.parametrize("entry", [
    "TWINGATE_X=a\nPATH=/evil",
    "TWINGATE_X=a\nTWINGATE_ACCESS_TOKEN=attacker",
    "TWINGATE_NOEQUALS",
    "NOEQUALS",
])
def test_env_injection_refused(env, entry):
    set_inspect(env, cfg={"Env": ["PATH=/usr/bin", f"TWINGATE_ACCESS_TOKEN={SECRET}", entry]})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "malformed environment" in r.stderr
    assert changed(env) == []


def test_no_twingate_env_refused(env):
    set_inspect(env, cfg={"Env": ["PATH=/usr/bin"]})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []


# --- equal image no-op -------------------------------------------------------

def test_equal_image_is_noop(env):
    (env.d / "new_id").write_text(OLD_ID + "\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0
    assert "already up to date" in r.stdout
    assert [l for l in env.log() if l.startswith(("stop", "rm", "run", "tag"))] == []
    assert env.leftovers() == []


# --- finding 1: rollback safety ----------------------------------------------

def test_old_image_must_exist_before_anything_changes(env):
    r = env.run("--yes", NAME, FAKE_OLD_MISSING="1")
    assert r.returncode == 2
    assert "not present on this host" in r.stderr
    assert changed(env) == []


def test_old_image_is_tagged_before_the_stop(env):
    r = env.run("--yes", NAME)
    assert r.returncode == 0
    log = env.log()
    tags = [l for l in log if l.startswith("tag ")]
    assert len(tags) == 1
    assert re.fullmatch(rf"tag {OLD_ID} twingate/connector:rollback-\d+", tags[0])
    assert log.index(tags[0]) < log.index("stop " + NAME)
    assert not any(l.startswith(("rmi", "image rm", "image prune")) for l in log)


def test_tag_failure_refuses_before_the_stop(env):
    r = env.run("--yes", NAME, FAKE_TAG_FAIL="1")
    assert r.returncode == 2 and "cannot tag" in r.stderr
    assert not any(l.startswith(("stop", "rm", "run -d")) for l in env.log())
    assert env.leftovers() == []


def test_rollback_on_unhealthy(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)")
    assert r.returncode == 1
    assert "result=rolled-back" in r.stdout
    assert "Rolling back" in r.stderr
    runs = env.runs_d()
    assert len(runs) == 2
    assert runs[0].endswith(" twingate/connector:1")
    assert re.search(r" twingate/connector:rollback-\d+$", runs[1])
    assert "--network host" in runs[1] and f"--name {NAME}" in runs[1]
    seen = sorted(env.d.glob("env_seen_*"))
    assert len(seen) == 2 and seen[0].read_text() == seen[1].read_text()
    assert "prune" not in " ".join(env.log())
    assert env.leftovers() == []


def kept_files(env):
    return sorted(env.run_dir.rglob("connector-env-*.env"))


def test_rollback_run_failure_is_loud_and_keeps_the_env_file(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)", FAKE_ROLLBACK_RUN_FAIL="1")
    assert r.returncode == 2
    assert "ROLLBACK FAILED" in r.stderr and "result=rollback-failed" in r.stdout
    kept = kept_files(env)
    assert len(kept) == 1
    assert stat.S_IMODE(kept[0].stat().st_mode) == 0o600
    assert f"TWINGATE_ACCESS_TOKEN={SECRET}" in kept[0].read_text()
    assert str(kept[0]) in r.stderr and "shred" in r.stderr
    assert SECRET not in r.stdout + r.stderr
    # only the kept file remains; the temp dir is gone and the lock is released
    assert list(env.tmp.iterdir()) == []
    assert [p for p in env.run_dir.rglob("*") if p.is_file()] == kept


def test_rollback_failure_when_unhealthy_too(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)", FAKE_OLD_STATUS="Up 1 second (unhealthy)")
    assert r.returncode == 2
    assert "ROLLBACK FAILED" in r.stderr and "result=rollback-failed" in r.stdout
    assert len(env.runs_d()) == 2 and len(kept_files(env)) == 1


def test_failed_rollback_never_claims_a_missing_image_is_kept(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)",
                FAKE_ROLLBACK_RUN_FAIL="1", FAKE_OLD_VANISH="1")
    assert r.returncode == 2
    assert "NOT present" in r.stderr
    assert "still on this host" not in r.stderr and "(kept)" not in r.stderr
    assert len(kept_files(env)) == 1


def test_failed_rollback_says_image_kept_when_it_is(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)", FAKE_ROLLBACK_RUN_FAIL="1")
    assert re.search(r"still on this host as twingate/connector:rollback-\d+", r.stderr)


# --- finding 2: signals in the window -----------------------------------------

SIGS = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGPIPE]


@pytest.mark.parametrize("sig", SIGS, ids=[s.name for s in SIGS])
def test_signal_during_recreate_still_completes_the_update(env, sig):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    try:
        env.wait_for("in_run")
        os.kill(p.pid, sig)
        env.release()
        out, err = p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert p.returncode == 0, (out, err)
    assert "result=updated" in out
    assert len(env.runs_d()) == 1
    assert env.leftovers() == []


def test_signal_during_recreate_still_rolls_back_a_bad_update(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)")
    try:
        env.wait_for("in_run")
        os.kill(p.pid, signal.SIGTERM)
        env.release()
        out, err = p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert p.returncode == 1, (out, err)
    assert "result=rolled-back" in out
    assert len(env.runs_d()) == 2


def test_closed_stdout_during_recreate_still_completes_the_update(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    try:
        p.stdout.readline()
        env.wait_for("in_run")
        p.stdout.close()
        env.release()
        p.wait(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        p.stderr.close()
    assert p.returncode == 0
    assert len(env.runs_d()) == 1
    assert env.leftovers() == []


@pytest.mark.parametrize("sig", SIGS, ids=[s.name for s in SIGS])
def test_signal_before_the_window_changes_nothing_and_cleans_up(env, sig):
    p = env.start("--yes", NAME, FAKE_PULL_HOLD="1")
    try:
        env.wait_for("in_pull")
        os.kill(p.pid, sig)
        env.release()
        p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert p.returncode != 0
    assert not any(l.startswith(("stop", "rm", "tag", "run -d")) for l in env.log())
    assert env.leftovers() == []


# --- finding 3: secrets at rest ------------------------------------------------

def test_only_a_twingate_env_file_exists_during_the_window(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    try:
        env.wait_for("in_run")
        files = [f for f in list(env.tmp.rglob("*")) + list(env.run_dir.rglob("*")) if f.is_file()]
        names = sorted(f.name for f in files)
        assert "connector.env" in names
        for f in files:
            if f.name in ("pid", "start", "ident", "rundir"):  # the lock state
                continue
            text = f.read_text()
            assert "HostConfig" not in text and "{" not in text, f.name
            assert text.splitlines() and all(l.startswith("TWINGATE_") for l in text.splitlines())
        assert not any(f.suffix == ".json" for f in files)
        env.release()
        p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert env.leftovers() == []


def test_head_n_1_leaves_no_secret_file_behind(env):
    cmd = f'sh "{env.launcher}" --yes {NAME} | head -n 1'
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=60,
                       env=env.environ(), cwd=str(env.root))
    assert len(r.stdout.splitlines()) == 1
    stops = [l for l in env.log() if l.startswith("stop")]
    # either nothing was touched, or the update ran to the end (never half way)
    assert (not stops) or len(env.runs_d()) >= 1
    assert env.leftovers() == []
    assert SECRET not in r.stdout + r.stderr


# --- secret handling ---------------------------------------------------------

@pytest.mark.parametrize("scenario", ["ok", "rollback", "pullfail", "dry"])
def test_secret_never_printed(env, scenario):
    extra = {}
    args = ["--yes", NAME]
    if scenario == "rollback":
        extra["FAKE_NEW_STATUS"] = "Up 1 second (unhealthy)"
    if scenario == "pullfail":
        extra["FAKE_PULL_FAIL"] = "1"
    if scenario == "dry":
        args = ["--dry-run", NAME]
    r = env.run(*args, **extra)
    assert SECRET not in r.stdout + r.stderr
    assert SECRET not in "\n".join(env.log())
    assert SECRET not in env.curl_argv()


# --- trap cleanup ------------------------------------------------------------

def test_tmp_private_and_removed_after_success(env):
    r = env.run("--yes", NAME)
    assert r.returncode == 0
    lines = (env.d / "stat").read_text().splitlines()
    assert lines[0].startswith("700 ") and lines[1].startswith("600 ")
    assert env.leftovers() == []


@pytest.mark.parametrize("extra,rc", [
    ({"FAKE_PULL_FAIL": "1"}, 1),
    ({"FAKE_NEW_STATUS": "Up 1 second (unhealthy)"}, 1),
])
def test_tmp_removed_on_error(env, extra, rc):
    r = env.run("--yes", NAME, **extra)
    assert r.returncode == rc
    assert env.leftovers() == []


def test_tmp_removed_on_layout_refusal(env):
    set_inspect(env, host={"NetworkMode": "bridge"})
    env.run("--yes", NAME)
    assert env.leftovers() == []


# --- finding 10: lock and filter escaping -------------------------------------

def test_two_runs_cannot_overlap(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    try:
        env.wait_for("in_run")
        n_before = len(env.log())
        r2 = env.run("--yes", NAME)
        assert r2.returncode == 2 and "in progress" in r2.stderr
        assert len(env.log()) == n_before
        env.release()
        p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert p.returncode == 0
    assert env.leftovers() == []


def test_stale_lock_is_taken_over(env):
    dead = subprocess.Popen(["sh", "-c", "exit 0"])
    dead.wait()
    lock = env.lock_base / "twingate-connector-update.lock.d"
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0 and "stale lock" in r.stdout
    assert env.leftovers() == []


def test_unreadable_lock_is_not_stolen(env):
    lock = env.lock_base / "twingate-connector-update.lock.d"
    lock.mkdir()
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []


def test_name_is_escaped_in_the_docker_filter(env):
    r = env.run("--yes", "conn.a")
    assert r.returncode == 0
    ps = [l for l in env.log() if l.startswith("ps ")]
    assert ps and all("name=^conn\\.a$" in l for l in ps)


# --- dry run, args, confirmation --------------------------------------------

def test_dry_run_runs_only_read_only_commands(env):
    r = env.run("--dry-run", NAME)
    assert r.returncode == 0
    assert "DRY-RUN would" in r.stdout
    assert set(env.verbs()) <= {"inspect", "image", "exec", "info"}
    assert env.curl_argv() == ""
    assert env.leftovers() == []


@pytest.mark.parametrize("bad", ["../x", "a b", "-x", "a;b", "a$(id)", "", "x" * 64])
def test_name_regex_strict(env, bad):
    r = env.run("--yes", bad)
    assert r.returncode == 2
    assert env.log() == []


def test_two_names_refused(env):
    r = env.run("--yes", NAME, "other")
    assert r.returncode == 2 and env.log() == []


def test_confirmation_declined(env):
    r = env.run(NAME, stdin="no\n")
    assert r.returncode == 3
    assert [l for l in changed(env) if not l.startswith("pull")] == []


def test_confirmation_accepted(env):
    r = env.run(NAME, stdin="yes\n")
    assert r.returncode == 0 and len(env.runs_d()) == 1


def test_unknown_version_needs_yes(env):
    r = env.run(NAME, stdin="yes\n", FAKE_NEWVER_FAIL="1")
    assert r.returncode == 3 and "--yes" in r.stderr and env.runs_d() == []
    r = env.run("--yes", NAME, FAKE_NEWVER_FAIL="1")
    assert r.returncode == 0


# --- webhook notice ----------------------------------------------------------

def test_webhook_notice(env):
    r = env.run("--yes", NAME, **HOOK)
    assert r.returncode == 0 and "notice sent" in r.stdout
    assert "FAKE-WEBHOOK-PATH" not in env.curl_argv()
    assert "FAKE-WEBHOOK-PATH" not in r.stdout + r.stderr
    assert "--max-time 5" in env.curl_argv() and "--proto =https" in env.curl_argv()
    body = json.loads(env.curl_argv().split("--data ", 1)[1].strip())
    assert body == {"host-label": "host-test", "connector": NAME, "from": "Connector 1.95.0",
                    "to": "Connector 1.96.0", "result": "updated"}
    assert SECRET not in env.curl_argv() + env.curl_stdin()


def test_webhook_http_refused(env):
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL="http://hooks.example.invalid/x")
    assert r.returncode == 0 and env.curl_argv() == ""


def test_webhook_failure_never_fails_update(env):
    r = env.run("--yes", NAME, FAKE_CURL_FAIL="1", **HOOK)
    assert r.returncode == 0 and "notice failed" in r.stdout


def test_no_webhook_in_dry_run(env):
    env.run("--dry-run", NAME, **HOOK)
    assert env.curl_argv() == ""


# --- Twingate Admin API ------------------------------------------------------

API = {"TWINGATE_API_KEY": API_KEY, "TWINGATE_NETWORK_URL": "https://example-net.twingate.com"}


def curl_out(env, nodes, n=None, **kw):
    name = "curl.out" if n is None else f"curl.out.{n}"
    (env.d / name).write_text(gql(nodes, **kw))


def test_precheck_reminder_without_api(env):
    r = env.run("--dry-run", NAME)
    assert "REMINDER" in r.stdout and env.curl_argv() == ""


def test_precheck_ok_when_another_connector_in_the_same_network_is_alive(env):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--dry-run", NAME, **API)
    assert "1 other Connector(s) ALIVE" in r.stdout and "WARNING" not in r.stdout
    assert API_KEY not in env.curl_argv() + r.stdout + r.stderr
    assert API_KEY in env.curl_stdin()
    assert "https://example-net.twingate.com/api/graphql/" in env.curl_stdin()


def test_precheck_warns_when_the_other_connector_is_not_alive(env):
    curl_out(env, [node(), node("connector-b", state="OFFLINE")])
    r = env.run("--dry-run", NAME, **API)
    assert "WARNING: no OTHER Connector is ALIVE" in r.stdout


def test_precheck_excludes_this_connector(env):
    curl_out(env, [node()])
    r = env.run("--dry-run", NAME, **API)
    assert "WARNING: no OTHER" in r.stdout


def test_precheck_only_counts_the_same_remote_network(env):
    curl_out(env, [node(), node("connector-b", rn="rn2")])
    r = env.run("--dry-run", NAME, **API)
    assert "WARNING: no OTHER" in r.stdout


def test_precheck_warns_when_this_connector_is_not_found_by_name(env):
    curl_out(env, [node("someone-else"), node("connector-b")])
    r = env.run("--dry-run", NAME, **API)
    assert "WARNING: this Connector was not found" in r.stdout


def test_precheck_pages_through_the_results(env):
    curl_out(env, [node()], n=1, more=True, cursor="CUR1")
    curl_out(env, [node("connector-b")], n=2)
    r = env.run("--dry-run", NAME, **API)
    assert "1 other Connector(s) ALIVE" in r.stdout and "WARNING" not in r.stdout
    reqs = env.curl_argv().splitlines()
    assert len(reqs) == 2 and '"after":"CUR1"' in reqs[1]


def test_precheck_page_cap(env):
    curl_out(env, [node()], more=True, cursor="CUR")
    r = env.run("--dry-run", NAME, **API)
    assert len(env.curl_argv().splitlines()) == 10
    assert "incomplete" in r.stdout


def test_precheck_warning_aborts_under_yes(env):
    curl_out(env, [node()])
    r = env.run("--yes", NAME, **API)
    assert r.returncode == 3 and "aborted-precheck" in r.stdout
    assert changed(env) == []


def test_precheck_warning_with_force_continues(env):
    curl_out(env, [node()])
    r = env.run("--yes", "--force", NAME, **API)
    assert r.returncode == 0 and "WARNING: no OTHER" in r.stdout
    assert len(env.runs_d()) == 1


def test_precheck_warning_does_not_abort_a_dry_run(env):
    curl_out(env, [node()])
    r = env.run("--dry-run", "--yes", NAME, **API)
    assert r.returncode == 0


BAD_URLS = [
    "https://evil.example/x.twingate.com",
    "https://evil.example:8443/a/b.twingate.com",
    "https://user:pw@evil.example/a.twingate.com",
    "https://a.twingate.com@evil.example",
    "https://example-net.twingate.com/extra",
    "https://example-net.twingate.com:8443",
    "https://evil.example.invalid",
    "http://example-net.twingate.com",
    "evil.example/x.twingate.com",
    "https://.twingate.com",
    "https://a.b.twingate.com",
]


@pytest.mark.parametrize("url", BAD_URLS)
def test_network_url_must_be_exactly_a_twingate_host(env, url):
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY=API_KEY, TWINGATE_NETWORK_URL=url)
    assert "pre-check skipped" in r.stdout
    assert env.curl_argv() == ""
    r = env.run("--yes", NAME, TWINGATE_API_KEY=API_KEY, TWINGATE_NETWORK_URL=url)
    assert r.returncode == 3 and changed(env) == []
    assert env.curl_argv() == ""


@pytest.mark.parametrize("url", ["example-net.twingate.com", "https://example-net.twingate.com"])
def test_network_url_good_forms(env, url):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY=API_KEY, TWINGATE_NETWORK_URL=url)
    assert "WARNING" not in r.stdout
    assert "https://example-net.twingate.com/api/graphql/" in env.curl_stdin()


def test_api_key_with_odd_characters_is_refused(env):
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY='k"; header = "X: y',
                TWINGATE_NETWORK_URL="example-net.twingate.com")
    assert "pre-check skipped" in r.stdout and env.curl_argv() == ""


def test_an_input_with_a_newline_is_refused_before_anything_runs(env):
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY='k"\nheader = "X: y',
                TWINGATE_NETWORK_URL="example-net.twingate.com")
    assert r.returncode == 2 and env.curl_argv() == "" and env.log() == []


# --- finding 9: health in Twingate ---------------------------------------------

def test_updated_only_when_twingate_shows_alive_on_the_new_version(env):
    curl_out(env, [node(version="1.96.0"), node("connector-b")])
    r = env.run("--yes", NAME, **API)
    assert r.returncode == 0 and "result=updated" in r.stdout
    assert "Twingate confirms" in r.stdout


def test_updated_unconfirmed_when_twingate_shows_the_old_version(env):
    curl_out(env, [node(version="1.95.0"), node("connector-b")])
    r = env.run("--yes", NAME, **API)
    assert r.returncode == 4
    assert "result=updated-unconfirmed" in r.stdout and "result=updated\n" not in r.stdout
    assert "NOT confirmed in Twingate" in r.stderr


def test_updated_unconfirmed_when_twingate_shows_it_offline(env):
    curl_out(env, [node(state="OFFLINE"), node("connector-b")])
    r = env.run("--yes", "--force", NAME, **API)
    assert r.returncode == 4


def test_health_not_confirmed_is_stated_when_no_api(env):
    r = env.run("--yes", NAME)
    assert r.returncode == 0 and "result=updated" in r.stdout
    assert "NOT confirmed in Twingate" in r.stdout


# --- round 2 (adversarial review r1) ------------------------------------------

def hold_run(env, **kw):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME, **kw)
    env.wait_for("in_run")
    return p


def finish_run(env, p):
    env.release()
    try:
        p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()


# finding 1: poll interval and wait are canonical bounded integers

@pytest.mark.parametrize("bad", ["08", "09", "007", "+5", "-1", "1e2", "99999", "100", "0", "x"])
def test_malformed_poll_interval_never_bypasses_the_rollback(env, bad):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)", TWINGATE_UPDATE_POLL_SECS=bad)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert "result=rolled-back" in r.stdout
    assert len(env.runs_d()) == 2
    assert env.leftovers() == []


def test_a_huge_poll_never_sleeps_past_the_wait(env):
    t0 = time.time()
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)",
                TWINGATE_UPDATE_WAIT_SECS="3", TWINGATE_UPDATE_POLL_SECS="60")
    assert r.returncode == 1
    assert time.time() - t0 < 20


# finding 3: every kept env entry must be one docker accepts

BAD_ENV = [
    "TWINGATE_BAD KEY=x",
    "TWINGATE_TAB\tKEY=x",
    "TWINGATE_X=a\rb",
    "TWINGATE_X=" + "a" * 9000,
    "TWINGATE_X=a\x00b",
    "TWINGATE_=x",
    "TWINGATE_BAD-KEY=x",
]


@pytest.mark.parametrize("entry", BAD_ENV, ids=["space", "tab", "cr", "long", "nul", "emptyname", "dash"])
def test_invalid_env_entries_are_refused_before_the_stop(env, entry):
    set_inspect(env, cfg={"Env": ["PATH=/usr/bin", f"TWINGATE_ACCESS_TOKEN={SECRET}", entry]})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "malformed environment" in r.stderr
    assert changed(env) == []
    assert SECRET not in r.stdout + r.stderr


def test_duplicate_env_keys_are_refused(env):
    set_inspect(env, cfg={"Env": ["PATH=/usr/bin", f"TWINGATE_ACCESS_TOKEN={SECRET}", "TWINGATE_ACCESS_TOKEN=other"]})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "duplicate" in r.stderr and changed(env) == []


def test_a_long_but_legal_env_entry_is_kept(env):
    set_inspect(env, cfg={"Env": ["PATH=/usr/bin", f"TWINGATE_ACCESS_TOKEN={SECRET}", "TWINGATE_X=" + "a" * 4000]})
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


# finding 4: curl never reads a config file, never follows, never uses a proxy

def curl_lines(env):
    return [l for l in env.curl_argv().splitlines() if l]


def test_every_curl_call_ignores_curlrc_redirects_and_proxies(env):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--yes", NAME, **HOOK, **API)
    assert r.returncode == 0, r.stderr
    lines = curl_lines(env)
    assert len(lines) >= 3  # pre-check, post-check, notice
    for l in lines:
        assert l.split()[0] == "-q", l
        assert "--max-redirs 0" in l and "--noproxy *" in l and "--proto =https" in l, l
        assert " -L" not in l and "--location" not in l


# finding 5: complete effective-config comparison

DROPPED = [
    ("host", {"PidsLimit": 64}),
    ("host", {"OomKillDisable": True}),
    ("host", {"OomScoreAdj": 500}),
    ("host", {"CpuPeriod": 100000}),
    ("host", {"CpusetCpus": "0-1"}),
    ("host", {"MemorySwappiness": 10}),
    ("host", {"CgroupnsMode": "host"}),
    ("host", {"IpcMode": "host"}),
    ("host", {"ShmSize": 1073741824}),
    ("host", {"Runtime": "nvidia"}),
    ("host", {"Init": True}),
    ("host", {"MaskedPaths": ["/proc/custom"]}),
    ("host", {"ReadonlyPaths": ["/etc"]}),
    ("host", {"PortBindings": {"80/tcp": [{"HostPort": "80"}]}}),
    ("host", {"VolumesFrom": ["other"]}),
    ("host", {"CgroupParent": "custom.slice"}),
    ("cfg", {"StopSignal": "SIGUSR1"}),
    ("cfg", {"StopTimeout": 30}),
    ("cfg", {"OpenStdin": True}),
    ("cfg", {"Hostname": "custom-host"}),
    ("cfg", {"Domainname": "example.invalid"}),
    ("cfg", {"ExposedPorts": {"80/tcp": {}}}),
    ("cfg", {"Volumes": {"/data": {}}}),
]


@pytest.mark.parametrize("kind,val", DROPPED, ids=[f"{k}-{json.dumps(v)[:40]}" for k, v in DROPPED])
def test_settings_a_recreate_would_drop_are_refused(env, kind, val):
    set_inspect(env, **{kind: val})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "layout differs" in r.stderr
    assert changed(env) == []


def test_docker_default_values_are_not_refused(env):
    host = {"CgroupnsMode": "private", "IpcMode": "private", "ShmSize": 67108864, "Runtime": "runc",
            "ConsoleSize": [0, 0], "PortBindings": {}, "CpusetCpus": "", "OomKillDisable": False,
            "PidsLimit": None, "MemorySwappiness": None, "OomScoreAdj": 0, "Isolation": "",
            "MaskedPaths": ["/proc/kcore", "/sys/firmware"], "ReadonlyPaths": ["/proc/sys"]}
    cfg = {"Hostname": "abcdef123456", "Domainname": "", "AttachStdout": False, "OpenStdin": False}
    set_inspect(env, host=host, cfg=cfg)
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


# finding 6: one lock for the whole host

def test_the_lock_is_host_wide_not_per_environment(env):
    p = hold_run(env)
    try:
        assert (env.lock_base / "twingate-connector-update.lock.d").is_dir()
        n_before = len(env.log())
        other_tmp = env.root / "other-tmp"
        other_xdg = env.root / "other-xdg"
        other_tmp.mkdir()
        other_xdg.mkdir()
        r2 = env.run("--yes", NAME, TMPDIR=str(other_tmp), XDG_RUNTIME_DIR=str(other_xdg))
        assert r2.returncode == 2 and "in progress" in r2.stderr
        assert len(env.log()) == n_before
    finally:
        finish_run(env, p)
    assert p.returncode == 0
    assert env.leftovers() == []


LOCK_NAME = "twingate-connector-update.lock.d"


def test_non_root_real_run_is_refused_with_a_clear_message(env):
    # make the copy believe root (uid 0) is the trusted user; we are not root
    t = env.script.read_text().replace(f"TRUSTED_UID={os.getuid()}", "TRUSTED_UID=0")
    env.script.write_text(t)
    if os.getuid() == 0:
        pytest.skip("needs a non-root test user")
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "needs root" in r.stderr and changed(env) == []
    r = env.run("--dry-run", NAME)
    assert r.returncode == 0


def test_attacker_owned_lock_path_is_not_used_and_gives_a_fixed_message(env):
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text("ATTACKER-CONTROLLED-TEXT\n")
    (env.d / "foreign").write_text(f"{lock}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "not a root-owned directory" in r.stderr
    assert "ATTACKER-CONTROLLED-TEXT" not in r.stdout + r.stderr
    assert changed(env) == []
    assert (lock / "pid").read_text() == "ATTACKER-CONTROLLED-TEXT\n"  # untouched, not taken over


def test_attacker_owned_lock_with_a_dead_pid_is_not_taken_over(env):
    dead = subprocess.Popen(["sh", "-c", "exit 0"])
    dead.wait()
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    (env.d / "foreign").write_text(f"{lock}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "stale lock" not in r.stdout
    assert changed(env) == [] and lock.is_dir()


def test_attacker_symlink_at_the_lock_path_is_refused(env):
    target = env.root / "elsewhere-lock"
    target.mkdir()
    (env.lock_base / LOCK_NAME).symlink_to(target)
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []
    assert list(target.iterdir()) == []


def test_root_owned_stale_lock_from_a_dead_pid_is_cleared(env):
    dead = subprocess.Popen(["sh", "-c", "exit 0"])
    dead.wait()
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0 and "stale lock" in r.stdout
    assert env.leftovers() == []


def test_missing_lock_base_refuses(env):
    env.lock_base.rmdir()
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "lock" in r.stderr and changed(env) == []


# finding 7: tokens never go through the inherited TMPDIR or XDG_RUNTIME_DIR

def test_inherited_tmpdir_and_xdg_runtime_dir_are_never_used(env):
    p = hold_run(env)
    try:
        assert list(env.tmp.rglob("*")) == []  # hostile TMPDIR and XDG_RUNTIME_DIR
        assert any(f.name == "connector.env" for f in env.run_dir.rglob("*"))
    finally:
        finish_run(env, p)
    assert list(env.tmp.rglob("*")) == []
    assert env.leftovers() == []


def test_runtime_dir_with_loose_mode_is_refused(env):
    d = env.run_dir / "twingate-connector-update"
    d.mkdir()
    d.chmod(0o755)
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "private" in r.stderr and changed(env) == []


def test_runtime_dir_symlink_is_refused(env):
    target = env.root / "elsewhere"
    target.mkdir()
    target.chmod(0o700)
    (env.run_dir / "twingate-connector-update").symlink_to(target)
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and changed(env) == []
    assert list(target.iterdir()) == []


# finding 8: the API key and webhook URL never reach a child's environment

def test_api_key_and_webhook_url_are_not_exported_to_children(env):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--yes", NAME, **HOOK, **API)
    assert r.returncode == 0, r.stderr
    dump = env.envdump()
    assert "PATH=" in dump  # the fakes did record their environments
    assert API_KEY not in dump and "TWINGATE_API_KEY" not in dump
    assert "FAKE-WEBHOOK-PATH" not in dump and "NOTIFY_WEBHOOK_URL" not in dump
    assert API_KEY in env.curl_stdin()  # still delivered, only on curl's stdin


def test_api_key_is_not_exported_in_a_dry_run(env):
    curl_out(env, [node(), node("connector-b")])
    env.run("--dry-run", NAME, **API)
    assert API_KEY not in env.envdump() and "TWINGATE_API_KEY" not in env.envdump()


# finding 9: post-check matches the exact Connector and an exact version

def postcheck(env, nodes_or_raw):
    curl_out(env, [node(), node("connector-b")], n=1)
    if isinstance(nodes_or_raw, str):
        (env.d / "curl.out").write_text(nodes_or_raw)
    else:
        curl_out(env, nodes_or_raw)
    return env.run("--yes", NAME, **API)


def test_postcheck_rejects_a_different_connector_with_the_same_name(env):
    r = postcheck(env, [node(nid="some-other-id"), node("connector-b")])
    assert r.returncode == 4 and "result=updated-unconfirmed" in r.stdout


def test_postcheck_rejects_a_substring_version(env):
    r = postcheck(env, [node(version="11.96.0"), node("connector-b")])
    assert r.returncode == 4 and "result=updated-unconfirmed" in r.stdout


def test_postcheck_rejects_an_answer_with_graphql_errors(env):
    good = json.loads(gql([node(), node("connector-b")]))
    good["errors"] = [{"message": "partial"}]
    r = postcheck(env, json.dumps(good))
    assert r.returncode == 4 and "result=updated-unconfirmed" in r.stdout


def test_postcheck_rejects_a_network_change(env):
    r = postcheck(env, [node(rn="other-net"), node("connector-b")])
    assert r.returncode == 4


def test_postcheck_accepts_the_same_connector_with_a_prefixed_exact_version(env):
    r = postcheck(env, [node(version="Connector 1.96.0"), node("connector-b")])
    assert r.returncode == 0 and "result=updated\n" in r.stdout


# finding 10: API responses are size bounded

def test_oversized_api_response_is_refused(env):
    big = json.loads(gql([node(), node("connector-b")]))
    big["pad"] = "x" * 2_000_000
    (env.d / "curl.out").write_text(json.dumps(big))
    r = env.run("--dry-run", NAME, **API)
    assert "could not read Connector state" in r.stdout


def test_api_response_just_under_the_bound_is_read(env):
    ok = json.loads(gql([node(), node("connector-b")]))
    ok["pad"] = "x" * 900_000
    (env.d / "curl.out").write_text(json.dumps(ok))
    r = env.run("--dry-run", NAME, **API)
    assert "1 other Connector(s) ALIVE" in r.stdout


def test_empty_api_answer_is_not_trusted(env):
    (env.d / "curl.out").write_text("")
    r = env.run("--dry-run", NAME, **API)
    assert "could not read Connector state" in r.stdout


# --- static checks -----------------------------------------------------------

@pytest.mark.parametrize("path", [SCRIPT, LAUNCHER], ids=["updater", "launcher"])
def test_script_is_executable_and_syntax_valid(path):
    assert path.exists()
    assert path.stat().st_mode & stat.S_IXUSR
    assert subprocess.run(["sh", "-n", str(path)]).returncode == 0


def run_shellcheck(path):
    return subprocess.run([shutil.which("shellcheck"), "-s", "sh", str(path)],
                          capture_output=True, text=True)


def test_script_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if sc is None and os.environ.get("CI"):
        pytest.fail("shellcheck must be on PATH in CI; this check never skips there")
    for path in (SCRIPT, LAUNCHER):
        if sc:
            r = run_shellcheck(path)
            assert r.returncode == 0, r.stdout
        else:  # local run without shellcheck: syntax check only
            assert subprocess.run(["sh", "-n", str(path)]).returncode == 0
    text = SCRIPT.read_text()
    assert "umask 077" in text and "mktemp -d" in text and "trap" in text
    assert "docker image prune" not in text and "docker system prune" not in text


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="needs shellcheck to prove the guard bites")
def test_shellcheck_guard_bites(tmp_path):
    bad = tmp_path / "bad.sh"
    bad.write_text("#!/bin/sh\nx=1\necho $x $y\ncd $x\n")
    assert run_shellcheck(bad).returncode != 0


def test_shellcheck_missing_in_ci_fails_not_skips(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception):
        test_script_shellcheck_clean()


def test_shellcheck_missing_locally_falls_back_to_syntax_check(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.delenv("CI", raising=False)
    test_script_shellcheck_clean()


# =============================================================================
# Round 3 (Daybreak round 2 findings R2-1 .. R2-7)
# =============================================================================

HOSTILE_ENV = {
    "DOCKER_HOST": "tcp://127.0.0.1:1", "DOCKER_CONTEXT": "evil", "DOCKER_CONFIG": "/nonexistent-evil",
    "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/nonexistent-evil", "SSL_CERT_FILE": "/nonexistent-evil",
    "SSL_CERT_DIR": "/nonexistent-evil", "CURL_CA_BUNDLE": "/nonexistent-evil",
    "https_proxy": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
    "XDG_CONFIG_HOME": "/nonexistent-evil", "XDG_DATA_HOME": "/nonexistent-evil",
    "LD_PRELOAD": "/nonexistent-evil.so", "CURL_HOME": "/nonexistent-evil",
}


def dump_names(env):
    names = set()
    for line in env.envdump().splitlines():
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m:
            names.add(m.group(1))
    return names


# --- R2-1: the whole environment is cleared -------------------------------------

def test_docker_and_curl_never_see_the_callers_environment(env):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--yes", NAME, **HOOK, **API, **HOSTILE_ENV)
    assert r.returncode == 0, r.stderr
    dump = env.envdump()
    assert "PATH=" in dump  # both fakes recorded their environment
    names = dump_names(env)
    assert not (names & (set(HOSTILE_ENV) - {"DOCKER_HOST", "DOCKER_CONFIG"})), names & set(HOSTILE_ENV)
    assert "tcp://127.0.0.1:1" not in dump and "nonexistent-evil" not in dump
    assert "DOCKER_HOST=unix:///var/run/docker.sock" in dump
    assert f"DOCKER_CONFIG={env.run_dir}/twingate-connector-update/docker-config" in dump
    assert f"HOME={env.run_dir}/twingate-connector-update/home" in dump
    assert "XDG_RUNTIME_DIR" not in names and "TMPDIR" not in names
    assert env.leftovers() == []


def test_an_environment_that_was_not_cleared_is_refused(env):
    # The launcher always clears the environment, so this starts the updater
    # directly: a caller that claims the environment is clean while it holds more
    # is refused.
    r = subprocess.run(["sh", str(env.script), "--yes", NAME], capture_output=True, text=True,
                       env=env.environ(TWINGATE_UPDATE_CLEAN_ENV="1", SSL_CERT_FILE="/nonexistent-evil"),
                       cwd=str(env.root), timeout=60)
    assert r.returncode == 2 and "not cleared" in r.stderr
    assert env.log() == []


def test_the_updater_refuses_a_direct_run_and_names_the_launcher(env):
    r = subprocess.run(["sh", str(env.script), "--dry-run", NAME], capture_output=True, text=True,
                       env=env.environ(), cwd=str(env.root), timeout=60)
    assert r.returncode == 2 and "launcher" in r.stderr
    assert env.log() == []


def test_a_hostile_environment_through_the_launcher_never_reaches_the_updater(env):
    r = env.run("--dry-run", NAME, TWINGATE_UPDATE_CLEAN_ENV="1", SSL_CERT_FILE="/nonexistent-evil")
    assert r.returncode == 0, r.stderr
    assert "nonexistent-evil" not in env.envdump()


def test_docker_config_and_home_dirs_are_private_and_empty_during_the_run(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    try:
        env.wait_for("in_run")
        base = env.run_dir / "twingate-connector-update"
        for d in ("docker-config", "home"):
            assert stat.S_IMODE((base / d).stat().st_mode) == 0o700
            assert list((base / d).iterdir()) == []
        env.release()
        p.communicate(timeout=40)
    finally:
        if p.poll() is None:
            p.kill()
            p.communicate()
    assert env.leftovers() == []


# --- R2-2: a SIGKILL leftover is removed by the next run ---------------------------

def kill_hard_during_recreate(env):
    (env.d / "hold").write_text("")
    p = env.start("--yes", NAME)
    env.wait_for("in_run")
    left = list(env.run_dir.glob("twingate-connector-update/run.*/connector.env"))
    assert len(left) == 1
    os.kill(p.pid, signal.SIGKILL)
    p.communicate()
    env.release()  # let the orphaned fake docker finish
    time.sleep(0.3)
    (env.d / "hold").unlink()
    (env.d / "go").unlink()
    for f in list(env.d.glob("in_*")):
        f.unlink()
    return left[0]


def test_sigkill_leftover_run_dir_is_securely_removed_by_the_next_run(env):
    leftover = kill_hard_during_recreate(env)
    assert leftover.exists() and SECRET in leftover.read_text()
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert "stale lock" in r.stdout and "private dir left by the dead run" in r.stdout
    assert not leftover.exists() and not leftover.parent.exists()
    assert env.leftovers() == []


def test_a_recorded_run_dir_outside_the_runtime_dir_is_never_removed(env):
    dead = subprocess.Popen(["true"])
    dead.wait()
    victim = env.root / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    (lock / "rundir").write_text(f"{victim}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert (victim / "keep.txt").read_text() == "keep"


def test_a_recorded_run_dir_that_is_a_symlink_is_never_removed(env):
    dead = subprocess.Popen(["true"])
    dead.wait()
    victim = env.root / "victim2"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    base = env.run_dir / "twingate-connector-update"
    base.mkdir(mode=0o700)
    (base / "run.1234").symlink_to(victim)
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    (lock / "rundir").write_text(f"{base}/run.1234\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert (victim / "keep.txt").read_text() == "keep"


# --- R2-3: env values must survive docker's env-file grammar ------------------------

def parsed_env(env):
    files = sorted(env.d.glob("env_parsed_*"))
    assert files, "the fake docker never parsed an env file"
    return json.loads(files[0].read_text())


def test_env_file_round_trips_through_the_env_file_parser(env):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig-_abc=="
    envs = ["PATH=/usr/bin", "LANG=C.UTF-8", f"TWINGATE_ACCESS_TOKEN={jwt}",
            "TWINGATE_REFRESH_TOKEN=a.b-c_d", "TWINGATE_NETWORK=example-net", "TWINGATE_LOG_LEVEL=3",
            "TWINGATE_LABEL_HOSTNAME=host.example.invalid", "TWINGATE_EMPTY="]
    set_inspect(env, cfg={"Env": envs})
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert parsed_env(env) == [e for e in envs if e.startswith("TWINGATE_")]


HOSTILE_VALUES = [
    '"quoted"', "'single'", "back\\slash", "dollar$HOME", "has space", "hash#tag", " leading", "trailing ",
    "tab\there", "back`tick`", "semi;colon", "paren(x)", "\\n", "x\\", "a b ", "${X}", "~", "=",
]


@pytest.mark.parametrize("value", [v for v in HOSTILE_VALUES if v not in ("~", "=")],
                         ids=lambda v: repr(v))
def test_values_that_could_change_meaning_in_an_env_file_are_refused(env, value):
    envs = ["PATH=/usr/bin", "LANG=C.UTF-8", f"TWINGATE_ACCESS_TOKEN={SECRET}", f"TWINGATE_NETWORK={value}"]
    set_inspect(env, cfg={"Env": envs})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "not safe for an env file" in r.stderr, r.stderr
    assert changed(env) == []
    assert SECRET not in r.stdout + r.stderr


def test_the_env_file_model_does_change_hostile_values():
    # proves the parser model bites: quoting and edge whitespace are not preserved
    altered = set()
    for v in HOSTILE_VALUES:
        entry = f"TWINGATE_NETWORK={v}"
        out = subprocess.run(["python3", "-I", "-c", ENV_PARSER.replace("sys.argv[1]", "'/dev/stdin'")],
                             input=entry, capture_output=True, text=True).stdout
        if json.loads(out) != [entry]:
            altered.add(v)
    assert {'"quoted"', "'single'", "trailing ", "a b "} <= altered


# --- R2-4: hostname and attach fields --------------------------------------------

def test_a_host_equal_hostname_is_accepted_with_host_networking(env):
    import socket
    set_inspect(env, cfg={"Hostname": socket.gethostname()})
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


def test_a_host_equal_hostname_is_refused_without_host_networking(env):
    import socket
    set_inspect(env, host={"NetworkMode": "bridge"}, cfg={"Hostname": socket.gethostname()})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "hostname override" in r.stderr
    assert changed(env) == []


def test_a_host_equal_hostname_is_refused_with_a_uts_mode(env):
    import socket
    set_inspect(env, host={"UTSMode": "host"}, cfg={"Hostname": socket.gethostname()})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "hostname override" in r.stderr
    assert changed(env) == []


def test_a_custom_hostname_is_still_refused_with_host_networking(env):
    set_inspect(env, cfg={"Hostname": "custom-host"})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "hostname override" in r.stderr
    assert changed(env) == []


def test_the_container_id_default_hostname_is_accepted(env):
    set_inspect(env, cfg={"Hostname": "abcdef123456"})
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("field", ["AttachStdin", "AttachStdout", "AttachStderr"])
def test_attach_fields_must_match_a_detached_run(env, field):
    set_inspect(env, cfg={field: True})
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "attach settings differ" in r.stderr
    assert changed(env) == []


# --- R2-5: curl's own exit status decides -----------------------------------------

def test_precheck_ignores_a_valid_body_when_curl_fails_afterwards(env):
    curl_out(env, [node(), node("connector-b")])
    r = env.run("--dry-run", NAME, FAKE_CURL_FAIL_AFTER="1", **API)
    assert "could not read Connector state" in r.stdout
    assert "other Connector(s) ALIVE" not in r.stdout


def test_postcheck_ignores_a_valid_body_when_curl_fails_afterwards(env):
    curl_out(env, [node(version="1.96.0"), node("connector-b")])
    r = env.run("--yes", "--force", NAME, FAKE_CURL_FAIL_AFTER="1", **API)
    assert r.returncode == 4 and "result=updated-unconfirmed" in r.stdout
    assert "Twingate confirms" not in r.stdout


# --- R2-6: the webhook needs an explicit trusted host list --------------------------

def test_no_allowlist_means_no_notice_but_the_update_succeeds(env):
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL=WEBHOOK)
    assert r.returncode == 0 and "result=updated" in r.stdout
    assert "NOTIFY_WEBHOOK_ALLOWED_HOSTS is not set" in r.stdout
    assert env.curl_argv() == ""


def test_an_allowed_host_matches_case_insensitively_with_a_port(env):
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL="https://Hooks.Example.Invalid:8443/x",
                NOTIFY_WEBHOOK_ALLOWED_HOSTS="other.example.invalid, hooks.example.invalid".replace(" ", ""))
    assert r.returncode == 0 and "notice sent" in r.stdout


BAD_HOSTS = [
    ("https://127.0.0.1/x", "127.0.0.1"),
    ("https://169.254.169.254/x", "169.254.169.254"),
    ("https://10.0.0.5:9443/admin", "10.0.0.5"),
    ("https://2130706433/x", "2130706433"),
    ("https://0x7f.0.0.1/x", "0x7f.0.0.1"),
    ("https://[::1]/x", "::1"),
    ("https://[::1]:9443/x", "[::1]"),
    ("https://localhost/x", "localhost"),
    ("https://a.localhost/x", "a.localhost"),
    ("https://intranet/x", "intranet"),
    ("https://user@hooks.example.invalid/x", "hooks.example.invalid"),
    ("https://hooks.example.invalid:8a/x", "hooks.example.invalid"),
    ("https://hooks.example.invalid/x", "*.example.invalid"),
    ("https://hooks.example.invalid/x", "example.invalid"),
    ("https://hooks.example.invalid/x", "*"),
    ("https://evil.example.invalid/x", "hooks.example.invalid"),
    ("https://hooks.example.invalid.evil.invalid/x", "hooks.example.invalid"),
]


@pytest.mark.parametrize("url,allowed", BAD_HOSTS, ids=[u for u, _ in BAD_HOSTS])
def test_untrusted_webhook_hosts_get_no_request(env, url, allowed):
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL=url, NOTIFY_WEBHOOK_ALLOWED_HOSTS=allowed)
    assert r.returncode == 0 and "result=updated" in r.stdout
    assert "notice skipped" in r.stdout and "notice sent" not in r.stdout
    assert env.curl_argv() == ""


# --- R2-7: lock identity is PID + start time + updater identity --------------------

def proc_start_time(pid):
    st = open(f"/proc/{pid}/stat").read()
    return st.rsplit(") ", 1)[1].split(" ")[19]


def spawn_holder(env, token="tok123"):
    """A live process that looks like an updater: script path in argv, token in env."""
    p = subprocess.Popen(["sh", "-c", "sleep 30; true", str(env.script)],
                         env={"PATH": os.environ["PATH"], "TWINGATE_UPDATE_RUN_TOKEN": token})
    for _ in range(100):  # wait for the exec
        if str(env.script) in open(f"/proc/{p.pid}/cmdline").read():
            break
        time.sleep(0.02)
    return p


def write_lock(env, pid, start, script, token):
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{pid}\n")
    (lock / "start").write_text(f"{start}\n")
    (lock / "ident").write_text(f"script={script}\ntoken={token}\n")
    return lock


def test_a_live_holder_with_matching_identity_blocks(env):
    live = spawn_holder(env)
    try:
        write_lock(env, live.pid, proc_start_time(live.pid), env.script, "tok123")
        r = env.run("--yes", NAME)
        assert r.returncode == 2 and f"in progress (pid {live.pid})" in r.stderr
        assert changed(env) == []
    finally:
        live.kill()
        live.wait()


def test_a_reused_pid_with_a_different_start_time_is_stale(env):
    live = spawn_holder(env)
    try:
        write_lock(env, live.pid, "1", env.script, "tok123")
        r = env.run("--yes", NAME)
        assert r.returncode == 0 and "stale lock" in r.stdout, r.stderr
    finally:
        live.kill()
        live.wait()


@pytest.mark.parametrize("which", ["script", "token", "no-ident"])
def test_a_live_pid_that_is_not_this_updater_is_stale(env, which):
    live = spawn_holder(env)
    try:
        lock = write_lock(env, live.pid, proc_start_time(live.pid),
                          "/not/this/script.sh" if which == "script" else env.script,
                          "wrongtoken" if which == "token" else "tok123")
        if which == "no-ident":
            (lock / "ident").unlink()
        r = env.run("--yes", NAME)
        assert r.returncode == 0 and "stale lock" in r.stdout, r.stderr
    finally:
        live.kill()
        live.wait()


# --- round 8 (Daybreak round 7): the launcher is the one trust root -----------------
# The path checks live in scripts/twingate-connector-update-launcher.sh. They run
# before any updater text does. The updater (SCRIPT) cannot vouch for its own path.

def make_race_copy(env, hook):
    """A mutant of the launcher copy: `hook` runs right before the clean exec."""
    out, n = [], 0
    for line in env.launcher.read_text().splitlines(keepends=True):
        if line.startswith('exec "$ENV" -i '):
            out.append(hook + "\n")
            n += 1
        out.append(line)
    assert n == 1
    race = env.root / "race-under-test.sh"
    race.write_text("".join(out))
    return race


def test_updater_swapped_at_the_exec_boundary_is_not_executed(env):
    marker = env.root / "pwned"
    race = make_race_copy(
        env, f': >"{env.d}/at_exec"; i=0; while [ ! -f "{env.d}/swapped" ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i+1)); done')
    p = subprocess.Popen(["sh", str(race), "--yes", NAME], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env=env.environ(), cwd=str(env.root))
    env.wait_for("at_exec")
    env.script.write_text(f'#!/bin/sh\n: >"{marker}"\nexit 0\n')
    (env.d / "swapped").write_text("")
    out, err = p.communicate(timeout=60)
    assert not marker.exists(), "the replacement file was executed"
    assert p.returncode == 0, err
    assert "result=updated" in out


def test_a_relative_launcher_path_is_refused(env):
    r = subprocess.run(["sh", "launcher-under-test.sh", "--dry-run", NAME], capture_output=True, text=True,
                       env=env.environ(), cwd=str(env.root), timeout=60)
    assert r.returncode == 2 and "absolute" in r.stderr
    assert env.log() == []


def test_the_lock_records_the_fixed_updater_path(env):
    (env.d / "pull_hold").write_text("")
    p = subprocess.Popen(["sh", str(env.launcher), "--yes", NAME], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env=env.environ(FAKE_PULL_HOLD="1"), cwd=str(env.root))
    try:
        env.wait_for("in_pull")
        ident = (env.lock_base / "twingate-connector-update.lock.d" / "ident").read_text()
        assert f"script={os.path.realpath(env.script)}\n" in ident
    finally:
        env.release()
        p.communicate(timeout=60)
    assert p.returncode == 0


def test_the_updater_path_is_fixed_not_taken_from_arguments_or_environment(env):
    marker = env.root / "hostile-ran"
    hostile = env.root / "hostile.sh"
    hostile.write_text(f'#!/bin/sh\n: >"{marker}"\nexit 0\n')
    r = env.run("--dry-run", NAME, str(hostile), UPDATER=str(hostile), TWINGATE_UPDATER=str(hostile))
    assert r.returncode == 2  # two names: refused by the REAL updater
    assert not marker.exists()
    r = env.run("--dry-run", NAME, UPDATER=str(hostile))
    assert r.returncode == 0, r.stderr
    assert not marker.exists()


def test_a_symlinked_directory_in_the_updater_path_is_refused(env):
    link = env.root / "linkdir"
    link.symlink_to(env.root)
    t = env.launcher.read_text().replace(f'UPDATER="{env.script}"', f'UPDATER="{link}/script-under-test.sh"')
    assert str(link) in t
    env.launcher.write_text(t)
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and "symbolic link" in r.stderr
    assert env.log() == []


def test_a_symlinked_updater_file_is_refused(env):
    link = env.root / "link.sh"
    link.symlink_to(env.script)
    t = env.launcher.read_text().replace(f'UPDATER="{env.script}"', f'UPDATER="{link}"')
    assert str(link) in t
    env.launcher.write_text(t)
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "symbolic link" in r.stderr
    assert env.log() == []


def test_a_missing_updater_is_refused(env):
    env.script.unlink()
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and "missing" in r.stderr
    assert env.log() == []


def test_an_empty_or_oversized_updater_is_refused_and_one_just_under_the_cap_runs(env):
    base = env.script.read_text()
    env.script.write_text("")
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and "empty or too large" in r.stderr
    env.script.write_text(base + "#" * 100000 + "\n")
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and "empty or too large" in r.stderr
    assert env.log() == []
    env.script.write_text(base + "#" * (99000 - len(base)) + "\n")  # under the cap
    r = env.run("--dry-run", NAME)
    assert r.returncode == 0, r.stderr


def _ancestors(path):
    out = [str(path)]
    cur = os.path.dirname(str(path))
    while True:
        out.append(cur)
        if cur == "/":
            return out
        cur = os.path.dirname(cur)


@pytest.mark.parametrize("which", ["file", "dir", "parent", "root"])
@pytest.mark.parametrize("listfile,reason", [("foreign", "not owned by root"), ("gw", "writable")])
def test_untrusted_updater_path_or_ancestor_is_refused(env, which, listfile, reason):
    chain = _ancestors(os.path.realpath(env.script))
    target = {"file": chain[0], "dir": chain[1], "parent": chain[2], "root": chain[-1]}[which]
    (env.d / listfile).write_text(target + "\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert reason in r.stderr and "updater" in r.stderr
    assert env.log() == []
    assert env.leftovers() == []


def _launcher_as_non_root(env):
    # TRUSTED_UID=0 in this copy: the test user is not root
    t = env.launcher.read_text().replace(f"TRUSTED_UID={os.getuid()}", "TRUSTED_UID=0")
    assert "TRUSTED_UID=0" in t
    env.launcher.write_text(t)


@pytest.mark.parametrize("args", [("--dry-run",), ("--dry-run", "--yes"), ("--yes",), ("--help",), ()])
def test_the_launcher_refuses_every_non_root_run_dry_run_help_or_not(env, args):
    if os.getuid() == 0:
        pytest.skip("needs a non-root test user")
    _launcher_as_non_root(env)
    r = env.run(*args, NAME)
    assert r.returncode == 2 and "must be run as root" in r.stderr
    assert env.log() == []


def _marker_at_top(path, marker):
    lines = path.read_text().splitlines(keepends=True)
    assert lines[0].startswith("#!")
    lines.insert(1, f": >{shlex.quote(str(marker))}\n")
    path.write_text("".join(lines))


@pytest.mark.parametrize("listfile", ["gw", "foreign", "acl", "getfacl"])
@pytest.mark.parametrize("args", [("--dry-run",), ("--yes",), ("--help",), ()])
def test_the_launcher_executes_no_updater_text_before_validating_it(env, listfile, args):
    # The marker is the very FIRST line of the updater, not a line after some check.
    marker = env.root / "updater-top-marker"
    _marker_at_top(env.script, marker)
    (env.d / listfile).write_text(os.path.dirname(os.path.realpath(env.script)) + "\n")
    r = env.run(*args, NAME)
    assert r.returncode == 2
    assert not marker.exists()
    assert env.log() == []
    # control: with a trusted path the same first line runs, so the probe is live
    (env.d / listfile).write_text("")
    env.run("--dry-run", NAME)
    assert marker.exists()


def test_a_non_root_run_executes_no_updater_text(env):
    if os.getuid() == 0:
        pytest.skip("needs a non-root test user")
    marker = env.root / "updater-top-marker-nonroot"
    _marker_at_top(env.script, marker)
    _launcher_as_non_root(env)
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and not marker.exists()


def test_the_launchers_own_first_line_is_the_trust_root_and_runs_unconditionally(env):
    # The launcher cannot validate itself: its own text is the trust root, and its
    # install location is the control. A marker at its top runs even when it then
    # refuses, which is why the docs say so and why it holds no functions.
    marker = env.root / "launcher-top-marker"
    _marker_at_top(env.launcher, marker)
    (env.d / "gw").write_text(os.path.dirname(os.path.realpath(env.script)) + "\n")
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and marker.exists()


def test_the_launcher_defines_no_functions_and_checks_come_first():
    code = [l for l in LAUNCHER.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert not [l for l in code if re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)", l)]
    assert not [l for l in code if l.lstrip().startswith("function ")]
    head = []
    for l in code:
        if l.startswith(("WHY=", "case \"$0\" in")):
            break
        head.append(l)
    # only fixed assignments and umask/export before the first check
    assert all(re.match(r"(umask 077|TRUSTED_UID=0|PATH=|export PATH|UPDATER=|NL=|[A-Z]+=/usr/bin/[a-z]+$|'$)", l) for l in head), head
    assert len(code) < 100


def _chain(env):
    c = _ancestors(os.path.realpath(env.script))
    return {"file": c[0], "dir": c[1], "parent": c[2], "root": c[-1]}


@pytest.mark.parametrize("which", ["file", "dir", "parent", "root"])
@pytest.mark.parametrize("listfile", ["acl", "getfacl"])
def test_an_extended_acl_on_the_updater_or_any_ancestor_is_refused(env, which, listfile):
    (env.d / listfile).write_text(_chain(env)[which] + "\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "access control list" in r.stderr
    assert env.log() == []
    assert env.leftovers() == []


def test_acl_check_fails_closed_when_getfacl_fails(env):
    (env.d / "getfacl_fail").write_text("")
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "access control list" in r.stderr
    assert env.log() == []


@pytest.mark.parametrize("body", [
    "",                                                  # empty success output
    "garbage\n",                                         # malformed
    "user::rwx\ngroup::r-x\n",                           # incomplete: no other::
    "group::r-x\nother::r-x\n",                          # incomplete: no user::
    "user::rwx\nuser::rwx\ngroup::r-x\nother::r-x\n",    # duplicate
    "user::rwx\ngroup::r-x\nother::r-x\nother::r-x\n",   # duplicate
    "user::rwx\ngroup::r-x\nother::r-x\nbogus\n",        # trailing junk
    "user::rwx\ngroup::r-x\nother::zzz\n",              # malformed permissions
])
def test_acl_check_fails_closed_on_empty_or_malformed_getfacl_output(env, body):
    (env.bin / "getfacl").write_text("#!/bin/sh\ncat <<'EOF_X'\n" + body + "EOF_X\nexit 0\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "access control list" in r.stderr
    assert env.log() == []


def test_acl_check_fails_closed_when_the_listing_cannot_be_read(env):
    (env.bin / "ls").write_text("#!/bin/sh\nexit 1\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "access control list" in r.stderr


def test_no_acl_means_the_path_check_passes(env):
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr


# --- R7-4: help is static text; no program is handed the updater path ----------------

@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_prints_static_text_and_never_reopens_the_updater_path(env, flag):
    r = env.run(flag)
    assert r.returncode == 0, r.stderr
    assert "Usage: twingate-connector-update" in r.stdout
    assert env.log() == []
    seen = ""
    for f in ("cat.args", "sed.args"):
        if (env.d / f).exists():
            seen += (env.d / f).read_text()
    assert seen != ""  # the recorders were live (the updater itself calls sed)
    assert str(env.script) not in seen


def test_a_nested_mount_in_a_reset_directory_is_never_descended_into(env):
    rd = env.run_dir / "twingate-connector-update"
    mnt = rd / "docker-config" / "mnt"
    mnt.mkdir(parents=True)
    (rd / "home").mkdir()
    rd.chmod(0o700)
    (mnt / "precious").write_text("x")
    (env.d / "mnt").write_text(str(mnt) + "\n")
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (mnt / "precious").exists()
    assert "mount point" in r.stderr
    assert changed(env) == []


def _prepopulate_run_dir(env):
    rd = env.run_dir / "twingate-connector-update"
    (rd / "docker-config").mkdir(parents=True)
    (rd / "home").mkdir()
    rd.chmod(0o700)
    (rd / "docker-config" / "keep").write_text("x")
    return rd


def _find_fails_on_scans(env, only_second):
    # Fails every scan of the reset directories (the trust query is answered as usual).
    cond = '*" -xdev "*' if only_second else '*" -mindepth "*'
    f = env.bin / "find"
    body = f.read_text().replace(
        "# The test tree is not root-owned",
        f'case " $* " in {cond}) exit 1 ;; esac\n# The test tree is not root-owned', 1)
    assert body != f.read_text()
    f.write_text(body)


@pytest.mark.parametrize("only_second", [False, True])
def test_a_failing_find_scan_refuses_and_removes_nothing(env, only_second):
    rd = _prepopulate_run_dir(env)
    _find_fails_on_scans(env, only_second)
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (rd / "docker-config" / "keep").exists()
    assert "cannot scan" in r.stderr
    assert changed(env) == []


def test_find_failing_with_equal_empty_output_does_not_pass_the_scan(env):
    rd = _prepopulate_run_dir(env)
    f = env.bin / "find"
    f.write_text(f.read_text().replace(
        "# The test tree is not root-owned",
        'case " $* " in *" -mindepth "*) exit 1 ;; esac\n# The test tree is not root-owned', 1))
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (rd / "docker-config" / "keep").exists()
    assert changed(env) == []


def test_a_failing_removal_is_refused_with_no_unrestricted_fallback(env):
    rd = _prepopulate_run_dir(env)
    log = env.root / "rm.log"
    (env.bin / "rm").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >>{shlex.quote(str(log))}\n"
        'case " $* " in *" --one-file-system "*) exit 1 ;; esac\n'
        'exec /bin/rm "$@"\n')
    (env.bin / "rm").chmod(0o755)
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert "--one-file-system is required" in r.stderr
    calls = [l for l in log.read_text().splitlines() if "-rf" in l]
    assert calls and all("--one-file-system" in l for l in calls), calls
    assert changed(env) == []


def test_real_find_refuses_an_updater_that_root_does_not_own_as_the_trusted_user(env):
    # no fake find: the launcher copy's PATH is reset to the system directories, so
    # the real ownership and mode checks run. The shipped TRUSTED_UID=0 stays; `id`
    # is a shim that says 0, so the launcher runs as "root", and the updater is a
    # file owned by the test user, i.e. NOT by the trusted user.
    if os.getuid() == 0:
        pytest.skip("needs a non-root test user")
    idshim = env.root / "id-says-root"
    idshim.write_text("#!/bin/sh\necho 0\n")
    idshim.chmod(0o755)
    own = env.root / "owned-by-the-test-user.sh"
    own.write_text("exit 0\n")
    own.chmod(0o600)
    t = LAUNCHER.read_text().replace("ID=/usr/bin/id\n", f"ID={idshim}\n")
    t = t.replace("UPDATER=\"/usr/local/libexec/twingate-connector-update/twingate-connector-update.sh\"",
                  f'UPDATER="{own}"')
    assert f'UPDATER="{own}"' in t and f"ID={idshim}" in t and "TRUSTED_UID=0" in t
    copy = env.root / "launcher-real-find.sh"
    copy.write_text(t)
    r = subprocess.run(["sh", str(copy), "--yes", NAME], capture_output=True, text=True,
                       env=env.environ(), cwd=str(env.root), timeout=60)
    assert r.returncode == 2
    assert "not owned by root or is group- or world-writable" in r.stderr
    assert env.log() == []


def test_the_shipped_launcher_refuses_when_no_updater_is_installed(env):
    r = env.run("--dry-run", NAME, original=True)
    assert r.returncode == 2
    assert env.log() == []


def test_prepopulated_docker_config_and_home_are_wiped_before_use(env):
    rd = env.run_dir / "twingate-connector-update"
    (rd / "docker-config").mkdir(parents=True)
    (rd / "home").mkdir()
    rd.chmod(0o700)
    (rd / "docker-config" / "config.json").write_text('{"credsStore": "evil"}')
    (rd / "docker-config" / "nested").mkdir()
    (rd / "docker-config" / "nested" / "x").write_text("x")
    (rd / "home" / ".dockerrc").write_text("x")
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    seen = (env.d / "cfgls").read_text().split() if (env.d / "cfgls").exists() else []
    assert "config.json" not in seen and "nested" not in seen
    assert env.leftovers() == []


def test_docker_config_that_is_a_symlink_is_replaced(env):
    rd = env.run_dir / "twingate-connector-update"
    rd.mkdir()
    rd.chmod(0o700)
    other = env.hostile / "cfg"
    other.mkdir()
    (other / "config.json").write_text("{}")
    (rd / "docker-config").symlink_to(other)
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert (other / "config.json").exists()
    seen = (env.d / "cfgls").read_text().split() if (env.d / "cfgls").exists() else []
    assert "config.json" not in seen


# =============================================================================
# Round 8 (Daybreak round 7): R7-2 cleanup failures, R7-3 starting-point mount
# =============================================================================

def _fail_scan_of_run_dirs(env):
    # Every directory scan of a per-run private dir (run.<pid>) fails; the trust
    # queries are answered as usual. Models `find` failing inside the EXIT handler
    # and inside stale-lock recovery.
    f = env.bin / "find"
    body = f.read_text().replace(
        "# The test tree is not root-owned",
        'case " $* " in *"/run."*" -mindepth "*) exit 1 ;; esac\n# The test tree is not root-owned', 1)
    assert body != f.read_text()
    f.write_text(body)


def _fail_one_file_system_removal(env):
    (env.bin / "rm").write_text(
        "#!/bin/sh\n"
        'case " $* " in *" --one-file-system "*) exit 1 ;; esac\n'
        'exec /bin/rm "$@"\n')
    (env.bin / "rm").chmod(0o755)


FAILERS = [_fail_scan_of_run_dirs, _fail_one_file_system_removal]
FAILER_IDS = ["find-fails", "removal-fails"]


def _dead_lock_with_old_run_dir(env):
    dead = subprocess.Popen(["true"])
    dead.wait()
    base = env.run_dir / "twingate-connector-update"
    base.mkdir(mode=0o700)
    old = base / "run.4242"
    old.mkdir(mode=0o700)
    (old / "connector.env").write_text(f"TWINGATE_ACCESS_TOKEN={SECRET}\n")
    lock = env.lock_base / LOCK_NAME
    lock.mkdir()
    (lock / "pid").write_text(f"{dead.pid}\n")
    (lock / "rundir").write_text(f"{old}\n")
    return old, lock


@pytest.mark.parametrize("failer", FAILERS, ids=FAILER_IDS)
@pytest.mark.parametrize("scenario,want_rc", [("ok", 5), ("pullfail", 1)])
def test_a_failed_cleanup_forces_a_nonzero_exit_and_names_the_retained_directory(env, failer, scenario, want_rc):
    failer(env)
    kw = {"FAKE_PULL_FAIL": "1"} if scenario == "pullfail" else {}
    r = env.run("--yes", NAME, **kw)
    assert r.returncode == want_rc, (r.returncode, r.stderr)
    kept = list(env.run_dir.glob("twingate-connector-update/run.*"))
    assert len(kept) == 1
    assert f"ERROR: the private directory {kept[0]} could not be removed" in r.stderr
    if scenario == "ok":
        assert "result=updated" in r.stdout  # the update itself had finished
    # the lock record of that directory is kept, so the next run can still find it
    assert (env.lock_base / LOCK_NAME / "rundir").read_text().strip() == str(kept[0])
    assert SECRET not in r.stdout + r.stderr


@pytest.mark.parametrize("failer", FAILERS, ids=FAILER_IDS)
def test_a_directory_kept_by_a_failed_cleanup_is_removed_by_the_next_run(env, failer):
    failer(env)
    r = env.run("--yes", NAME)
    assert r.returncode == 5
    kept = list(env.run_dir.glob("twingate-connector-update/run.*"))
    assert len(kept) == 1
    # the fault is gone
    if (env.bin / "rm").exists():
        (env.bin / "rm").unlink()
    f = env.bin / "find"
    f.write_text(f.read_text().replace('case " $* " in *"/run."*" -mindepth "*) exit 1 ;; esac\n', ""))
    r = env.run("--yes", NAME)
    assert r.returncode == 0, r.stderr
    assert "private dir left by the dead run" in r.stdout
    assert not kept[0].exists()


@pytest.mark.parametrize("failer", FAILERS, ids=FAILER_IDS)
def test_stale_lock_recovery_keeps_the_lock_record_when_the_old_directory_cannot_be_removed(env, failer):
    old, lock = _dead_lock_with_old_run_dir(env)
    failer(env)
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert f"cannot remove the private dir {old}" in r.stderr
    assert old.exists()
    assert (lock / "rundir").read_text().strip() == str(old)  # the only record is not erased
    assert changed(env) == []
    assert SECRET not in r.stdout + r.stderr


# --- R7-3: the directory passed to the removal must not itself be a mount point ---------

def test_a_reset_directory_that_is_itself_a_mount_point_is_refused(env):
    rd = _prepopulate_run_dir(env)
    dc = os.path.realpath(rd / "docker-config")
    (env.d / "mountinfo").write_text(
        f"20 1 0:5 / /proc rw - proc proc rw\n36 35 0:30 / {dc} rw,relatime - tmpfs tmpfs rw\n")
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (rd / "docker-config" / "keep").exists()
    assert "is a mount point" in r.stderr
    assert changed(env) == []


def test_an_unreadable_or_empty_mount_table_refuses_the_removal(env):
    rd = _prepopulate_run_dir(env)
    (env.d / "mountinfo").write_text("")
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (rd / "docker-config" / "keep").exists()
    assert "cannot check whether" in r.stderr
    assert changed(env) == []


# --- round 9 (Daybreak round 8): no command is found through PATH; bounded read -----
CMD_CONSTANTS = {"ID": "id", "DIRNAME": "dirname", "FIND": "find", "LS": "ls", "GETFACL": "getfacl",
                 "HEAD": "head", "TEE": "tee", "WC": "wc", "OD": "od", "TR": "tr", "ENV": "env", "SH": "sh"}


def test_the_shipped_launcher_names_every_command_by_a_fixed_absolute_path():
    text = LAUNCHER.read_text()
    for var, name in CMD_CONSTANTS.items():
        assert re.search(rf"^{var}=/usr/bin/{name}$", text, re.M), var
    # the constants are the only way a command is run: no bare name at a command position
    code = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    body = "\n".join(l for l in code if not re.match(r"[A-Z]+=/usr/bin/", l))
    assert not re.search(r"(^|[|;&(`]|\$\(|\{)\s*(" + "|".join(CMD_CONSTANTS.values()) + r"|cat|dd|command|sleep|grep|sed)\s", body, re.M), body


def _probe_copy(env, shims, mutate=None):
    """Launcher copy for the command-resolution tests: every command constant points
    at a shim in `shims` (a dict VAR -> path); `mutate` names one VAR whose uses go
    back to the bare command name."""
    out, seen = [], set()
    for line in LAUNCHER.read_text().splitlines(keepends=True):
        s = line.rstrip("\n")
        m = re.match(r"([A-Z]+)=/usr/bin/[a-z]+$", s)
        if m and m.group(1) in CMD_CONSTANTS:
            var = m.group(1)
            seen.add(var)
            line = f"{var}={shims[var]}\n"
        elif s == PATH_LINE:
            line = f'PATH="{env.trap}:/usr/bin:/bin"\n'
        elif s == "TRUSTED_UID=0":
            line = f"TRUSTED_UID={os.getuid()}\n"
        elif s.startswith("UPDATER="):
            line = f'UPDATER="{env.probe_updater}"\n'
        out.append(line)
    assert seen == set(CMD_CONSTANTS)
    text = "".join(out)
    if mutate:
        old = '$("$GETFACL" -p' if mutate == "GETFACL" else f'"${mutate}"'
        new = "$(getfacl -p" if mutate == "GETFACL" else CMD_CONSTANTS[mutate]
        assert old in text
        text = text.replace(old, new)
    dest = env.root / "launcher-probe.sh"
    dest.write_text(text)
    return dest


@pytest.fixture
def probe(env):
    trap = env.root / "trap"
    trap.mkdir()
    marks = env.root / "marks"
    marks.mkdir()
    env.trap = trap
    # a fake of EVERY command name, first in PATH, each recording a marker
    for n in list(CMD_CONSTANTS.values()) + ["cat", "dd", "grep", "sed", "sleep", "printf"]:
        f = trap / n
        f.write_text(f'#!/bin/sh\n: >"{marks}/path-{n}"\nexit 99\n')
        f.chmod(0o755)
    # shims by ABSOLUTE path: record the use, then run the real program
    shims = {}
    shimdir = env.root / "shims"
    shimdir.mkdir()
    for var, n in CMD_CONSTANTS.items():
        f = shimdir / n
        if n == "find":
            body = f'printf "%s\\n" "$1"'   # the test tree is not root-owned: answer "trusted"
        elif n == "getfacl":
            body = "printf 'user::rwx\\ngroup::r-x\\nother::r-x\\n'"
        else:
            body = f'exec /usr/bin/{n} "$@"'
        f.write_text(f'#!/bin/sh\n: >"{marks}/abs-{n}"\n{body}\n')
        f.chmod(0o755)
        shims[var] = str(f)
    env.probe_updater = env.root / "probe-updater.sh"
    env.probe_updater.write_text(f'#!/bin/sh\n: >"{marks}/updater-ran"\nexit 0\n')
    env.probe_updater.chmod(0o600)
    env.marks = marks
    env.shims = shims
    return env


def _run_probe(env, copy):
    return subprocess.run(["/usr/bin/sh", str(copy), "--dry-run", NAME], capture_output=True, text=True,
                          env={"PATH": f"{env.trap}:/usr/bin:/bin", "HOME": str(env.root)},
                          cwd=str(env.root), timeout=60)


def test_the_launcher_never_resolves_a_command_through_path(probe):
    r = _run_probe(probe, _probe_copy(probe, probe.shims))
    assert r.returncode == 0, r.stderr
    assert (probe.marks / "updater-ran").exists()
    assert sorted(m.name for m in probe.marks.iterdir() if m.name.startswith("path-")) == []


def test_an_executable_at_the_absolute_path_is_the_one_used(probe):
    r = _run_probe(probe, _probe_copy(probe, probe.shims))
    assert r.returncode == 0, r.stderr
    used = {m.name[4:] for m in probe.marks.iterdir() if m.name.startswith("abs-")}
    assert used == set(CMD_CONSTANTS.values()), used


@pytest.mark.parametrize("var", sorted(CMD_CONSTANTS))
def test_a_bare_command_name_is_found_through_path_and_the_probe_catches_it(probe, var):
    # mutant: this one command goes back to a bare name, which PATH resolves to the trap
    name = CMD_CONSTANTS[var]
    r = _run_probe(probe, _probe_copy(probe, probe.shims, mutate=var))
    assert (probe.marks / f"path-{name}").exists(), (var, r.returncode, r.stderr)


def test_the_updater_is_handed_the_launchers_fixed_path(probe):
    probe.probe_updater.write_text(f'#!/bin/sh\nprintf "%s" "$PATH" >"{probe.marks}/updater-path"\nexit 0\n')
    r = _run_probe(probe, _probe_copy(probe, probe.shims))
    assert r.returncode == 0, r.stderr
    assert (probe.marks / "updater-path").read_text() == f"{probe.trap}:/usr/bin:/bin"
    assert f'PATH="{PATH_VALUE}"' in LAUNCHER.read_text()


PATH_VALUE = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _bounded_read_copy(env, text=None):
    """Launcher copy whose HEAD is a recorder: it logs the arguments, keeps the bytes
    the real head produced and passes them on. The updater is a 5 MB regular file."""
    rec = env.root / "head-recorder"
    rec.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >>"{env.d}/head.args"\n'
                   f'/usr/bin/head "$@" >"{env.d}/head.out"; st=$?\n/usr/bin/cat "{env.d}/head.out"\nexit $st\n')
    rec.chmod(0o755)
    t = env.launcher.read_text()
    assert t.count("HEAD=/usr/bin/head\n") == 1
    t = t.replace("HEAD=/usr/bin/head\n", f"HEAD={rec}\n")
    if text:
        t = text(t)
    copy = env.root / "launcher-bounded.sh"
    copy.write_text(t)
    env.script.write_text("#!/bin/sh\n" + "#" * (5 * 1024 * 1024) + "\n")
    return copy


def _run_copy(env, copy):
    return subprocess.run(["sh", str(copy), "--dry-run", NAME], capture_output=True, text=True,
                          env=env.environ(), cwd=str(env.root), timeout=60)


def test_a_huge_updater_is_read_with_a_bounded_read_of_the_cap_plus_one(env):
    r = _run_copy(env, _bounded_read_copy(env))
    assert r.returncode == 2 and "empty or too large" in r.stderr, r.stderr
    assert (env.d / "head.args").read_text().split() == ["-c", "100001"]
    assert (env.d / "head.out").stat().st_size == 100001  # never more than the cap plus one byte
    assert env.log() == []


def test_without_the_bound_the_recorder_sees_the_whole_file(env):
    # the mutant: the byte limit is removed from the reader, the same test goes red
    r = _run_copy(env, _bounded_read_copy(env, lambda t: t.replace('"$HEAD" -c 100001', '"$HEAD" -c 100000000')))
    assert r.returncode == 2
    assert (env.d / "head.args").read_text().split() == ["-c", "100000000"]
    assert (env.d / "head.out").stat().st_size > 100001


def test_a_file_that_ends_in_many_newlines_after_the_cap_is_still_refused(env):
    # trailing newlines are dropped by command substitution; the sentinel keeps them counted
    env.script.write_text("#!/bin/sh\nexit 0\n" + "\n" * 100010)
    r = _run_copy(env, env.launcher)
    assert r.returncode == 2 and "empty or too large" in r.stderr


# --- round 10 (Daybreak round 9): bytes counted as read; open first, check the descriptor ---
# The launcher copy still differs from the shipped file in exactly six lines (PATH,
# TRUSTED_UID, UPDATER, FIND, LS, GETFACL): TEE is not rewritten, so the real tee runs.

def _mutant(env, old, new, name="launcher-mutant.sh"):
    t = env.launcher.read_text()
    assert t.count(old) == 1, old
    copy = env.root / name
    copy.write_text(t.replace(old, new))
    return copy


def _run_launcher(env, copy, timeout=60):
    return subprocess.run(["sh", str(copy), "--dry-run", NAME], capture_output=True, text=True,
                          env=env.environ(), cwd=str(env.root), timeout=timeout)


def _run_updater_bytes(env, data, copy=None, timeout=60):
    env.script.write_bytes(data)
    return _run_launcher(env, copy or env.launcher, timeout)


# the shipped size test; the mutants below stand for the old behaviour
CAP_TEST = '[ "$COUNT" -ge 100000 ] || [ "$TLEN" != "$COUNT" ]'


@pytest.mark.parametrize("size", [100, 99999, 100000, 100001, 200000])
def test_an_updater_with_nul_bytes_is_refused_at_every_size_around_the_cap(env, size):
    # command substitution drops NUL bytes, so the text can be far shorter than what was read
    r = _run_updater_bytes(env, b"exit 0\n" + b"\0" * (size - 7))
    assert r.returncode == 2 and "empty or too large" in r.stderr, (size, r.stderr)
    assert env.log() == []


def test_without_the_nul_check_a_small_nul_updater_would_run(env):
    # mutant: the text length is no longer compared with the bytes read
    mutant = _mutant(env, CAP_TEST, '[ "$COUNT" -ge 100000 ]')
    r = _run_updater_bytes(env, b"exit 0\n\0\0\0\0", copy=mutant)
    assert r.returncode == 0  # the NULs were silently dropped and the text ran


def test_counting_the_text_instead_of_the_bytes_read_lets_a_huge_nul_updater_pass_the_size_test(env):
    # mutant: the old rule, the cap applies to the length of the transformed text
    mutant = _mutant(env, CAP_TEST, '[ "$TLEN" -ge 100000 ]')
    r = _run_updater_bytes(env, b"exit 0\n" + b"\0" * 100000, copy=mutant)
    assert "empty or too large" not in r.stderr  # the cap no longer fires; the shipped file refuses it above


@pytest.mark.parametrize("size,ok", [(99999, True), (100000, False), (100001, False), (150000, False)])
def test_an_updater_ending_in_newlines_is_counted_in_bytes_at_the_cap(env, size, ok):
    r = _run_updater_bytes(env, b"exit 0\n" + b"\n" * (size - 7))
    if ok:
        assert r.returncode == 0, r.stderr
    else:
        assert r.returncode == 2 and "empty or too large" in r.stderr, (size, r.stderr)


def test_a_cap_one_byte_too_high_accepts_the_newline_updater_of_exactly_the_cap(env):
    mutant = _mutant(env, '[ "$COUNT" -ge 100000 ]', '[ "$COUNT" -ge 100001 ]')
    r = _run_updater_bytes(env, b"exit 0\n" + b"\n" * (100000 - 7), copy=mutant)
    assert r.returncode == 0  # the shipped cap refuses exactly this file (test above)


# --- the type of the updater is checked on the OPEN descriptor ----------------------------

def _fifo_updater(env):
    env.script.unlink()
    os.mkfifo(env.script)


def test_a_fifo_as_the_updater_is_refused_without_blocking(env):
    _fifo_updater(env)
    r = _run_launcher(env, env.launcher, timeout=20)
    assert r.returncode == 2 and "not a regular file" in r.stderr, r.stderr
    assert env.log() == []


def test_a_read_only_open_would_block_on_a_fifo(env):
    # mutant: the descriptor is opened read-only; the open waits for a writer forever
    _fifo_updater(env)
    mutant = _mutant(env, 'exec 4<>"$UPDATER"', 'exec 4<"$UPDATER"')
    with pytest.raises(subprocess.TimeoutExpired):
        _run_launcher(env, mutant, timeout=4)


SWAP_TO_FIFO = '/usr/bin/rm -f "$UPDATER" && /usr/bin/mkfifo "$UPDATER"; exec 4<>"$UPDATER"'


def test_a_regular_file_swapped_for_a_fifo_between_the_checks_and_the_open_is_refused(env):
    # the writer of the directory replaces the file right before the open
    swap = _mutant(env, 'exec 4<>"$UPDATER"', SWAP_TO_FIFO)
    r = _run_launcher(env, swap, timeout=20)
    assert r.returncode == 2 and "not a regular file" in r.stderr, r.stderr


def test_the_same_swap_blocks_a_launcher_that_opens_read_only(env):
    swap = _mutant(env, 'exec 4<>"$UPDATER"', SWAP_TO_FIFO.replace("4<>", "4<"))
    with pytest.raises(subprocess.TimeoutExpired):
        _run_launcher(env, swap, timeout=4)


def _device_copy(env, text):
    copy = env.root / "launcher-device.sh"
    assert f'UPDATER="{env.script}"' in text
    copy.write_text(text.replace(f'UPDATER="{env.script}"', 'UPDATER="/dev/null"'))
    return copy


def test_a_device_as_the_updater_is_refused_by_the_descriptor_check(env):
    r = _run_launcher(env, _device_copy(env, env.launcher.read_text()), timeout=20)
    assert r.returncode == 2 and "not a regular file" in r.stderr, r.stderr


def test_without_the_descriptor_type_test_a_device_is_not_called_a_non_regular_file(env):
    mutant = _mutant(env, '[ ! -f /dev/fd/4 ] || ', '')
    r = _run_launcher(env, _device_copy(env, mutant.read_text()), timeout=20)
    assert "not a regular file" not in r.stderr


def test_a_directory_as_the_updater_is_refused_cleanly(env):
    env.script.unlink()
    env.script.mkdir()
    r = _run_launcher(env, env.launcher, timeout=20)
    assert r.returncode == 2 and "refused:" in r.stderr and "not a regular file" in r.stderr, r.stderr


def test_a_missing_updater_is_not_created_by_the_open(env):
    env.script.unlink()
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and "missing" in r.stderr
    assert not env.script.exists()


@pytest.mark.parametrize("listfile,reason", [("foreign", "not owned by root"), ("gw", "writable"),
                                             ("acl", "access control list"), ("getfacl", "access control list")])
def test_the_opened_descriptor_itself_is_checked_for_owner_mode_and_acl(env, listfile, reason):
    (env.d / listfile).write_text("/dev/fd/4\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 2 and reason in r.stderr, r.stderr
    assert env.log() == []
    # mutant: only the path is inspected, as before
    mutant = _mutant(env, "p=/dev/fd/4\n", 'p="$UPDATER"\n')
    r = _run_launcher(env, mutant)
    assert reason not in r.stderr


def test_a_read_that_stopped_short_is_refused_by_the_size_comparison(env):
    # the reader delivers 12 bytes of a longer file
    short = env.root / "head-short"
    short.write_text('#!/bin/sh\n/usr/bin/head -c 100001 | /usr/bin/head -c 12\n')
    short.chmod(0o755)
    env.script.write_text("echo hello-from-the-updater; exit 0\n# padding to be longer than twelve bytes\n")
    mutant = _mutant(env, "HEAD=/usr/bin/head\n", f"HEAD={short}\n")
    r = _run_launcher(env, mutant)
    assert r.returncode == 2 and "not read completely" in r.stderr, r.stderr
    # mutant: the size comparison is gone, the truncated text runs
    t = mutant.read_text()
    assert t.count('-size "${COUNT}c"') == 1
    gone = env.root / "launcher-nosize.sh"
    gone.write_text(t.replace('-size "${COUNT}c"', "-size +0c"))
    r = _run_launcher(env, gone)
    assert "not read completely" not in r.stderr


# --- inherited descriptors ---------------------------------------------------------------

def _fd_report_updater(env):
    mark = env.root / "fds-seen"
    env.script.write_text(f'/usr/bin/ls -1 /proc/self/fd >"{mark}"\nexit 0\n')
    return mark


def _run_with_fds(env, launcher, opens, shell="sh"):
    redirs = " ".join(f"{n}</dev/null" for n in opens)
    return subprocess.run([shell, "-c", f'exec {redirs}; exec sh "$0" --dry-run {NAME}', str(launcher)],
                          capture_output=True, text=True, env=env.environ(), cwd=str(env.root), timeout=60)


def test_inherited_descriptors_5_to_9_are_closed_before_the_updater_runs(env):
    mark = _fd_report_updater(env)
    r = _run_with_fds(env, env.launcher, [5, 7, 9])
    assert r.returncode == 0, r.stderr
    seen = set(mark.read_text().split())
    assert seen and not seen & {"5", "6", "7", "8", "9"}, seen  # 3 and 4: heredoc and the ls own directory


def test_without_the_close_an_inherited_descriptor_reaches_the_updater(env):
    mark = _fd_report_updater(env)
    mutant = _mutant(env, "exec 4<&- 5<&- 6<&- 7<&- 8<&- 9<&-", "exec 4<&-")
    r = _run_with_fds(env, mutant, [5, 7])
    assert r.returncode == 0, r.stderr
    assert {"5", "7"} <= set(mark.read_text().split())


def test_an_inherited_descriptor_above_nine_is_refused(env):
    mark = _fd_report_updater(env)
    r = _run_with_fds(env, env.launcher, [12], shell="bash")
    assert r.returncode == 2 and "inherited file descriptor above 9" in r.stderr, r.stderr
    assert not mark.exists()


def test_without_the_listing_check_a_high_descriptor_reaches_the_updater(env):
    mark = _fd_report_updater(env)
    mutant = _mutant(env, "|*[0-9][0-9]*)", ")")
    r = _run_with_fds(env, mutant, [12], shell="bash")
    assert r.returncode == 0 and "12" in mark.read_text().split()


def test_descriptors_that_cannot_be_listed_are_refused(env):
    (env.bin / "ls").write_text('#!/bin/sh\nfor a in "$@"; do if [ "$a" = /proc/self/fd ]; then exit 1; fi; done\nexec /bin/ls "$@"\n')
    r = env.run("--dry-run", NAME)
    assert r.returncode == 2 and "descriptors cannot be listed" in r.stderr


# --- R8-3: the mount table writes some characters as octal escapes --------------------------

ESCAPED = [("040", "run dir"), ("011", "run\tdir"), ("134", "run\\dir"), ("012", "run\ndir")]


def _mount_setup(env, arm, name, mutate_arm=False):
    base = env.root / name
    base.mkdir()
    env.run_dir = base
    t = env.script.read_text()
    old = f'RUN_BASE="{env.root / "run"}"'
    assert t.count(old) == 1
    t = t.replace(old, f'RUN_BASE="{base}"')
    if mutate_arm:  # mutant: this one escape is no longer decoded
        needle = "'" + chr(92) + arm + "'*) _dec="
        assert t.count(needle) == 1
        t = t.replace(needle, needle + "Q")
    env.script.write_text(t)
    rd = _prepopulate_run_dir(env)
    dc = os.path.realpath(rd / "docker-config")
    assert name in dc
    (env.d / "mountinfo").write_text(
        f"20 1 0:5 / /proc rw - proc proc rw\n36 35 0:30 / {dc.replace(name, 'run' + chr(92) + arm + 'dir')} rw - tmpfs tmpfs rw\n")
    return rd


@pytest.mark.parametrize("arm,name", ESCAPED, ids=[a for a, _ in ESCAPED])
def test_a_mount_point_whose_name_has_an_escaped_character_is_found(env, arm, name):
    rd = _mount_setup(env, arm, name)
    r = env.run("--yes", NAME)
    assert r.returncode != 0
    assert (rd / "docker-config" / "keep").exists()
    assert "is a mount point" in r.stderr, r.stderr


@pytest.mark.parametrize("arm,name", ESCAPED, ids=[a for a, _ in ESCAPED])
def test_each_mountinfo_escape_arm_is_needed(env, arm, name):
    _mount_setup(env, arm, name, mutate_arm=True)
    r = env.run("--yes", NAME)
    assert "is a mount point" not in r.stderr
