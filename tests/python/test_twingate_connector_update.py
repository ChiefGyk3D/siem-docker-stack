"""Tests for scripts/twingate-connector-update.sh (issue #220).

The script runs against a FAKE `docker` (and a fake `curl`) placed first on
PATH. Both record their arguments and never touch a real engine, network or
Twingate account. Tokens below are placeholders.
"""
import json
import os
import shutil
import stat
import subprocess

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
case "$1" in
  inspect)
    [ -f "$D/inspect.json" ] || exit 1
    cat "$D/inspect.json" ;;
  image)
    cat "$D/new_id" ;;
  pull)
    [ -z "$FAKE_PULL_FAIL" ] || { echo "pull failed $FAKE_SECRET" >&2; exit 1; }
    exit 0 ;;
  exec)
    [ -f "$D/version" ] || exit 1
    cat "$D/version" ;;
  stop|rm) exit 0 ;;
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
    if [ "$last" = "twingate/connector:1" ]; then
      echo "${FAKE_NEW_STATUS:-Up 2 seconds}" >"$D/state"
      echo "Connector 1.96.0" >"$D/version"
    else
      echo "${FAKE_OLD_STATUS:-Up 2 seconds}" >"$D/state"
      echo "Connector 1.95.0" >"$D/version"
    fi
    exit 0 ;;
esac
exit 0
'''

FAKE_CURL = r'''#!/bin/sh
D="$FAKE_DIR"
echo "$*" >>"$D/curl.argv"
cat >>"$D/curl.stdin"
printf '\n---\n' >>"$D/curl.stdin"
[ -z "$FAKE_CURL_FAIL" ] || exit 7
if [ -f "$D/curl.out" ]; then cat "$D/curl.out"; else printf '{}'; fi
'''


def inspect_json(**over):
    c = {
        "Image": OLD_ID,
        "Config": {"Image": "twingate/connector:1",
                   "Env": ["PATH=/usr/bin", f"TWINGATE_ACCESS_TOKEN={SECRET}", "TWINGATE_NETWORK=example-net"]},
        "HostConfig": {"NetworkMode": "host", "Binds": None,
                       "RestartPolicy": {"Name": "unless-stopped"}, "Privileged": False},
        "Mounts": [],
    }
    for k, v in over.items():
        if k == "Mounts":
            c["Mounts"] = v
        else:
            c["HostConfig"][k] = v
    return json.dumps([c])


class Env:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.d = tmp_path / "fake"
        self.bin = tmp_path / "bin"
        self.tmp = tmp_path / "tmp"
        for p in (self.d, self.bin, self.tmp):
            p.mkdir()
        for n, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
            f = self.bin / n
            f.write_text(body)
            f.chmod(0o755)
        (self.d / "inspect.json").write_text(inspect_json())
        (self.d / "new_id").write_text(NEW_ID + "\n")
        (self.d / "version").write_text("Connector 1.95.0\n")
        (self.d / "state").write_text("Up 3 days\n")
        self.extra = {}

    def run(self, *args, stdin="", **env):
        e = {"PATH": f"{self.bin}:{os.environ['PATH']}", "FAKE_DIR": str(self.d),
             "FAKE_SECRET": SECRET, "TMPDIR": str(self.tmp), "HOME": str(self.root),
             "HOST_LABEL": "host-test", "TWINGATE_UPDATE_WAIT_SECS": "2",
             "TWINGATE_UPDATE_POLL_SECS": "1"}
        e.update(self.extra)
        e.update(env)
        return subprocess.run(["sh", str(SCRIPT), *args], input=stdin, capture_output=True,
                              text=True, env=e, timeout=60)

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


CHANGING = ("pull", "stop", "rm")


def changed(env):
    return [l for l in env.log() if l.split()[0] in CHANGING or l.startswith("run -d")]


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
    assert not any(l.startswith("PATH=") for l in envfile)
    # new version is read with no network and a fixed entrypoint
    assert any(l.startswith("run --rm --network none --entrypoint ./connectord ") for l in log)


# --- layout refusal ----------------------------------------------------------

@pytest.mark.parametrize("over", [
    {"NetworkMode": "bridge"},
    {"Binds": ["/etc/x:/etc/x"]},
    {"Mounts": [{"Type": "bind", "Source": "/a", "Destination": "/b"}]},
    {"RestartPolicy": {"Name": "always"}},
    {"RestartPolicy": {"Name": "no"}},
    {"Privileged": True},
    {"CapAdd": ["NET_ADMIN"]},
    {"Sysctls": {"net.ipv4.ping_group_range": "0 2147483647"}},
])
def test_layout_refusal_changes_nothing(env, over):
    (env.d / "inspect.json").write_text(inspect_json(**over))
    r = env.run("--yes", NAME)
    assert r.returncode == 2
    assert "layout differs" in r.stderr
    assert changed(env) == []
    assert "image" not in env.verbs()


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


# --- equal image no-op -------------------------------------------------------

def test_equal_image_is_noop(env):
    (env.d / "new_id").write_text(OLD_ID + "\n")
    r = env.run("--yes", NAME)
    assert r.returncode == 0
    assert "already up to date" in r.stdout
    assert [l for l in env.log() if l.startswith(("stop", "rm", "run"))] == []


# --- rollback ----------------------------------------------------------------

def test_rollback_on_unhealthy(env):
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)")
    assert r.returncode == 1
    assert "result=rolled-back" in r.stdout
    assert "Rolling back" in r.stderr
    runs = env.runs_d()
    assert len(runs) == 2
    assert runs[0].endswith(" twingate/connector:1")
    assert runs[1].endswith(" " + OLD_ID)
    assert "--network host" in runs[1] and f"--name {NAME}" in runs[1]
    seen = sorted(env.d.glob("env_seen_*"))
    assert len(seen) == 2 and seen[0].read_text() == seen[1].read_text()
    assert "prune" not in " ".join(env.log())


def test_rollback_failure_is_loud(env):
    # the old image does not come back healthy either
    r = env.run("--yes", NAME, FAKE_NEW_STATUS="Up 1 second (unhealthy)", FAKE_OLD_STATUS="Up 1 second (unhealthy)")
    assert r.returncode == 2
    assert "ROLLBACK FAILED" in r.stderr and "result=rollback-failed" in r.stdout
    assert len(env.runs_d()) == 2


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
    assert list(env.tmp.iterdir()) == []


@pytest.mark.parametrize("extra,rc", [
    ({"FAKE_PULL_FAIL": "1"}, 1),
    ({"FAKE_NEW_STATUS": "Up 1 second (unhealthy)"}, 1),
])
def test_tmp_removed_on_error(env, extra, rc):
    r = env.run("--yes", NAME, **extra)
    assert r.returncode == rc
    assert list(env.tmp.iterdir()) == []


def test_tmp_removed_on_layout_refusal(env):
    (env.d / "inspect.json").write_text(inspect_json(NetworkMode="bridge"))
    env.run("--yes", NAME)
    assert list(env.tmp.iterdir()) == []


# --- dry run, args, confirmation --------------------------------------------

def test_dry_run_runs_only_read_only_commands(env):
    r = env.run("--dry-run", NAME)
    assert r.returncode == 0
    assert "DRY-RUN would" in r.stdout
    assert set(env.verbs()) <= {"inspect", "image", "exec"}
    assert env.curl_argv() == ""


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


# --- Twingate API pre-check --------------------------------------------------

API = {"TWINGATE_API_KEY": API_KEY, "TWINGATE_NETWORK_URL": "https://example-net.twingate.com"}


def test_precheck_reminder_without_api(env):
    r = env.run("--dry-run", NAME)
    assert "REMINDER" in r.stdout and env.curl_argv() == ""


def test_precheck_warns_when_only_one_alive(env):
    out = json.dumps({"data": {"connectors": {"edges": [
        {"node": {"state": "ALIVE"}}, {"node": {"state": "OFFLINE"}}]}}})
    (env.d / "curl.out").write_text(out)
    r = env.run("--dry-run", NAME, **API)
    assert "WARNING: only 1" in r.stdout
    assert API_KEY not in env.curl_argv() + r.stdout + r.stderr
    assert API_KEY in env.curl_stdin()


def test_precheck_ok_when_two_alive(env):
    out = json.dumps({"data": {"connectors": {"edges": [
        {"node": {"state": "ALIVE"}}, {"node": {"state": "ALIVE"}}]}}})
    (env.d / "curl.out").write_text(out)
    r = env.run("--dry-run", NAME, **API)
    assert "2 Connectors ALIVE" in r.stdout and "WARNING" not in r.stdout


def test_precheck_rejects_non_twingate_url(env):
    r = env.run("--dry-run", NAME, TWINGATE_API_KEY=API_KEY,
                TWINGATE_NETWORK_URL="https://evil.example.invalid")
    assert "pre-check skipped" in r.stdout and env.curl_argv() == ""


# --- static checks -----------------------------------------------------------

def test_script_is_executable_and_syntax_valid():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0


def test_script_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if sc:
        assert subprocess.run([sc, "-s", "sh", str(SCRIPT)]).returncode == 0
    text = SCRIPT.read_text()
    assert "umask 077" in text and "mktemp -d" in text and "trap" in text
    assert "docker image prune" not in text and "docker system prune" not in text
