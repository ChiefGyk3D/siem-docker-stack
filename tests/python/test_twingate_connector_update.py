"""Tests for scripts/twingate-connector-update.sh (issue #220).

The script runs against a FAKE `docker` (and a fake `curl`) that the script
finds through its TWINGATE_UPDATE_BIN_DIR test seam. Both record their
arguments and never touch a real engine, network or Twingate account.
Tokens below are placeholders.
"""
import json
import os
import re
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
API_KEY = "FAKE-API-KEY-not-real-4455"

FAKE_DOCKER = r'''#!/bin/sh
D="$FAKE_DIR"
echo "$*" >>"$D/log"
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
D="$FAKE_DIR"
echo "$*" >>"$D/curl.argv"
cat >>"$D/curl.stdin"
printf '\n---\n' >>"$D/curl.stdin"
n=$(wc -l <"$D/curl.argv")
[ -z "$FAKE_CURL_FAIL" ] || exit 7
if [ -f "$D/curl.out.$n" ]; then cat "$D/curl.out.$n"
elif [ -f "$D/curl.out" ]; then cat "$D/curl.out"
else printf '{}'; fi
'''

IMAGE_ENV = ["PATH=/usr/bin", "LANG=C.UTF-8"]


def inspect_json(host=None, cfg=None, mounts=None):
    c = {
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
        for p in (self.d, self.bin, self.tmp, self.run_dir):
            p.mkdir()
        self.run_dir.chmod(0o700)
        for n, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
            f = self.bin / n
            f.write_text(body)
            f.chmod(0o755)
        (self.d / "inspect.json").write_text(inspect_json())
        (self.d / "image.json").write_text(image_json())
        (self.d / "new_id").write_text(NEW_ID + "\n")
        (self.d / "version").write_text("Connector 1.95.0\n")
        (self.d / "state").write_text("Up 3 days\n")

    def environ(self, hook=True, **env):
        e = {"PATH": os.environ["PATH"], "FAKE_DIR": str(self.d),
             "FAKE_SECRET": SECRET, "TMPDIR": str(self.tmp), "HOME": str(self.root),
             "XDG_RUNTIME_DIR": str(self.run_dir),
             "HOST_LABEL": "host-test", "TWINGATE_UPDATE_WAIT_SECS": "2",
             "TWINGATE_UPDATE_POLL_SECS": "1"}
        if hook:
            e["TWINGATE_UPDATE_BIN_DIR"] = str(self.bin)
        e.update(env)
        return e

    def run(self, *args, stdin="", hook=True, **env):
        return subprocess.run(["sh", str(SCRIPT), *args], input=stdin, capture_output=True,
                              text=True, env=self.environ(hook, **env), timeout=60,
                              cwd=str(self.root))

    def start(self, *args, **env):
        return subprocess.Popen(["sh", str(SCRIPT), *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=self.environ(True, **env), cwd=str(self.root))

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
        for base in (self.tmp, self.run_dir):
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


# --- finding 8: absolute PATH -------------------------------------------------

def test_inherited_path_and_cwd_are_not_used(env):
    # a fake docker sits first on the INHERITED PATH and in the cwd; the script
    # must not use either (only the TWINGATE_UPDATE_BIN_DIR seam is honored)
    shutil.copy(env.bin / "docker", env.root / "docker")
    r = env.run("--dry-run", NAME, hook=False, PATH=f"{env.bin}::{os.environ['PATH']}")
    assert r.returncode == 2
    assert env.log() == []


@pytest.mark.parametrize("bad", ["relative/bin", "/a:/b", "/a b"])
def test_bin_dir_seam_must_be_one_absolute_path(env, bad):
    r = env.run("--dry-run", NAME, TWINGATE_UPDATE_BIN_DIR=bad)
    assert r.returncode == 2 and env.log() == []


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
            if f.name == "pid":  # the lock
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
    cmd = f'sh "{SCRIPT}" --yes {NAME} | head -n 1'
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=60,
                       env=env.environ(True), cwd=str(env.root))
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
    lock = env.run_dir / "twingate-connector-update" / "lock.d"
    lock.mkdir(parents=True)
    (lock / "pid").write_text(f"{dead.pid}\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0 and "stale lock" in r.stdout
    assert env.leftovers() == []


def test_unreadable_lock_is_not_stolen(env):
    lock = env.run_dir / "twingate-connector-update" / "lock.d"
    lock.mkdir(parents=True)
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
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL=WEBHOOK)
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
    r = env.run("--yes", NAME, NOTIFY_WEBHOOK_URL=WEBHOOK, FAKE_CURL_FAIL="1")
    assert r.returncode == 0 and "notice failed" in r.stdout


def test_no_webhook_in_dry_run(env):
    env.run("--dry-run", NAME, NOTIFY_WEBHOOK_URL=WEBHOOK)
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
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY='k"\nheader = "X: y',
                TWINGATE_NETWORK_URL="example-net.twingate.com")
    assert "pre-check skipped" in r.stdout and env.curl_argv() == ""


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
