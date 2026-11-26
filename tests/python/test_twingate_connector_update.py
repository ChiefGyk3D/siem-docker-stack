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
for a in "$@"; do
  case "$a" in
    /*) if [ -f "$FD/foreign" ] && grep -qxF "$a" "$FD/foreign"; then exit 0; fi ;;
  esac
done
exec /usr/bin/find "$@"
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
        (self.bin / "envparse.py").write_text(ENV_PARSER)
        for n, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL), ("find", FAKE_FIND)):
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
        script = SCRIPT if original else self.script
        return subprocess.run(["sh", str(script), *args], input=stdin, capture_output=True,
                              text=True, env=self.environ(**env), timeout=60,
                              cwd=str(self.root))

    def start(self, *args, **env):
        return subprocess.Popen(["sh", str(self.script), *args], stdin=subprocess.DEVNULL,
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
    assert "TWINGATE_UPDATE_BIN_DIR" not in SCRIPT.read_text()


def test_test_copy_differs_from_the_shipped_script_in_four_lines_only(env):
    a = SCRIPT.read_text().splitlines()
    b = env.script.read_text().splitlines()
    assert len(a) == len(b)
    assert len([1 for x, y in zip(a, b) if x != y]) == 4


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
    cmd = f'sh "{env.script}" --yes {NAME} | head -n 1'
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

def test_script_is_executable_and_syntax_valid():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0


def run_shellcheck(path):
    return subprocess.run([shutil.which("shellcheck"), "-s", "sh", str(path)],
                          capture_output=True, text=True)


def test_script_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if sc is None and os.environ.get("CI"):
        pytest.fail("shellcheck must be on PATH in CI; this check never skips there")
    if sc:
        r = run_shellcheck(SCRIPT)
        assert r.returncode == 0, r.stdout
    else:  # local run without shellcheck: syntax check only
        assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0
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
    # a caller that claims the environment is clean while it holds more is refused
    r = env.run("--yes", NAME, TWINGATE_UPDATE_CLEAN_ENV="1", SSL_CERT_FILE="/nonexistent-evil")
    assert r.returncode == 2 and "not cleared" in r.stderr
    assert env.log() == []


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

def test_a_hostname_equal_to_the_host_name_is_refused(env):
    import socket
    set_inspect(env, cfg={"Hostname": socket.gethostname()})
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
