"""Tests for the Twingate collector wiring (issue #222): the InfluxDB writer, the wrapper,
the systemd units, the docs and the rule data-gap settings. Everything runs against a fake
InfluxDB on loopback; the user, password and network values below are placeholders."""
import base64
import http.server
import os
import re
import shutil
import stat
import subprocess
import sys
import threading

import pytest
import yaml

from conftest import REPO_ROOT

WRITER = REPO_ROOT / "scripts" / "live-deploy" / "twingate-influx-write.py"
WRAPPER = REPO_ROOT / "scripts" / "live-deploy" / "twingate-collect"
SYSTEMD = REPO_ROOT / "docs" / "systemd"
RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-alert-rules-twingate.yml"
USER = "twingate_wo"
PASSWORD = "FAKE-pw-not-real-0123456789"
GOOD = ("twingate_connector_behind,connector=c1,managed_by=docker value=0i\n"
        "twingate_connector_up,connector=c1,managed_by=docker value=1i\n"
        "twingate_update_check_success value=1i\n")
FAIL_LINE = "twingate_update_check_success value=0i\n"


class Fake:
    """A loopback HTTP server that records requests and answers with a fixed status."""

    def __init__(self, status=204, location=None):
        self.status, self.location, self.requests = status, location, []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                       "body": self.rfile.read(n).decode()})
                self.send_response(outer.status)
                if outer.location:
                    self.send_header("Location", outer.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.t.join(5)


@pytest.fixture
def fake():
    made = []

    def make(**kw):
        f = Fake(**kw)
        made.append(f)
        return f
    yield make
    for f in made:
        f.close()


def run_writer(body, env_extra=None, drop=()):
    env = {"PATH": os.environ["PATH"], "TWINGATE_INFLUX_USER": USER, "TWINGATE_INFLUX_PASSWORD": PASSWORD}
    env.update(env_extra or {})
    for k in drop:
        env.pop(k, None)
    return subprocess.run([sys.executable, "-I", str(WRITER)], input=body, capture_output=True,
                          text=True, env=env, timeout=30)


def leaks(p):
    return USER in p.stdout + p.stderr or PASSWORD in p.stdout + p.stderr or \
        base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode() in p.stdout + p.stderr


# ---- writer ----------------------------------------------------------------------------

def test_writer_posts_line_protocol_with_basic_auth_and_prints_only_counts(fake):
    f = fake(status=204)
    p = run_writer(GOOD, {"INFLUX_URL": f.url})
    assert p.returncode == 0, p.stderr
    r = f.requests[0]
    assert r["path"] == "/write?db=telegraf&precision=s"
    assert r["auth"] == "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    assert r["body"] == GOOD
    assert "lines=3" in p.stdout and "status=204" in p.stdout
    assert not leaks(p) and "twingate_connector" not in p.stdout


def test_writer_fails_on_401_and_never_replays(fake):
    f = fake(status=401)
    p = run_writer(GOOD, {"INFLUX_URL": f.url})
    assert p.returncode != 0 and "401" in p.stdout + p.stderr and not leaks(p)
    assert len(f.requests) == 1                      # no retry of a write


@pytest.mark.parametrize("status", [400, 404, 500, 199])
def test_writer_fails_on_non_2xx(fake, status):
    f = fake(status=status)
    assert run_writer(GOOD, {"INFLUX_URL": f.url}).returncode != 0


@pytest.mark.parametrize("body", ["", "\n", "  \n\n"])
def test_writer_fails_on_empty_body_without_sending(fake, body):
    f = fake()
    p = run_writer(body, {"INFLUX_URL": f.url})
    assert p.returncode != 0 and f.requests == []


def test_writer_does_not_follow_redirects_or_carry_credentials(fake):
    target = fake(status=204)
    f = fake(status=307, location=target.url + "/write?db=telegraf&precision=s")
    p = run_writer(GOOD, {"INFLUX_URL": f.url})
    assert p.returncode != 0
    assert target.requests == [] and len(f.requests) == 1


def test_writer_rejects_missing_credentials_and_bad_config(fake):
    f = fake()
    env = {"INFLUX_URL": f.url}
    assert run_writer(GOOD, env, drop=("TWINGATE_INFLUX_PASSWORD",)).returncode != 0
    assert run_writer(GOOD, env, drop=("TWINGATE_INFLUX_USER",)).returncode != 0
    assert run_writer(GOOD, {"INFLUX_URL": "ftp://127.0.0.1:1"}).returncode != 0
    assert run_writer(GOOD, {"INFLUX_URL": "http://user:pw@127.0.0.1:1"}).returncode != 0
    p = run_writer(GOOD, {"INFLUX_URL": "http://192.0.2.5:8086"})            # cleartext off-box
    assert p.returncode != 0 and "cleartext" in p.stderr
    assert run_writer(GOOD, {"INFLUX_URL": f.url, "TWINGATE_INFLUX_DB": "a&b=c"}).returncode != 0
    assert f.requests == []


def test_writer_rejects_foreign_or_malformed_lines_and_oversize_input(fake):
    f = fake()
    for body in ("cpu,host=a value=1i\n", "twingate_x value=abc\n", GOOD + "garbage\n",
                 "twingate_x value=1i\n" * 5000):
        assert run_writer(body, {"INFLUX_URL": f.url}).returncode != 0
    assert f.requests == []


def test_writer_connection_failure_exits_nonzero_without_echoing_values():
    p = run_writer(GOOD, {"INFLUX_URL": "http://127.0.0.1:1"})
    assert p.returncode != 0 and not leaks(p)


def test_writer_default_url_is_loopback_8086_and_timeout_is_five_seconds():
    src = WRITER.read_text(encoding="utf-8")
    assert "http://127.0.0.1:8086" in src and "TIMEOUT = 5" in src and "timeout=TIMEOUT" in src
    assert "urlopen" not in src          # urllib follows redirects; http.client does not


def test_writer_takes_no_arguments_so_no_value_reaches_argv():
    src = WRITER.read_text(encoding="utf-8")
    assert "sys.argv" not in src and "argparse" not in src


# ---- wrapper ---------------------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    """A copy of the wrapper next to stub siem-run, collector and writer."""
    live = tmp_path / "scripts" / "live-deploy"
    live.mkdir(parents=True)
    shutil.copy(WRAPPER, live / "twingate-collect")
    for name, body in {
        "siem-run": 'exec "$@"\n',
    }.items():
        (live / name).write_text("#!/usr/bin/env bash\n" + body)
    (live / "twingate-influx-write.py").write_text(
        "import os, sys\n"
        "data = sys.stdin.read()\n"
        "open(os.environ['OUT'], 'a').write(data)\n"
        "sys.exit(int(os.environ.get('WRITER_RC', '0')))\n")
    for p in live.iterdir():
        p.chmod(0o755)
    return tmp_path


def set_collector(tree, text, rc):
    (tree / "scripts" / "twingate-update-metric.py").write_text(
        "import sys\nsys.stdout.write(%r)\nsys.exit(%d)\n" % (text, rc))


def run_wrapper(tree, **env_extra):
    env = {"PATH": os.environ["PATH"], "OUT": str(tree / "out.txt")}
    env.update(env_extra)
    p = subprocess.run([str(tree / "scripts" / "live-deploy" / "twingate-collect")], capture_output=True,
                       text=True, env=env, timeout=30)
    out = tree / "out.txt"
    return p, (out.read_text() if out.exists() else "")


def test_wrapper_success_passes_collector_lines_to_writer(tree):
    set_collector(tree, GOOD, 0)
    p, sent = run_wrapper(tree)
    assert p.returncode == 0 and sent == GOOD


def test_wrapper_collector_failure_is_nonzero_but_failure_line_still_lands(tree):
    set_collector(tree, FAIL_LINE, 1)           # what twingate-update-metric.py does on a failed check
    p, sent = run_wrapper(tree)
    assert p.returncode != 0                     # pipefail: the writer succeeded, the collector did not
    assert sent == FAIL_LINE                     # so the health rule goes red quickly


def test_wrapper_writer_failure_is_nonzero(tree):
    set_collector(tree, GOOD, 0)
    p, _ = run_wrapper(tree, WRITER_RC="1")
    assert p.returncode != 0


def test_wrapper_zero_lines_from_collector_is_nonzero(tree, fake):
    f = fake()
    set_collector(tree, "", 0)
    shutil.copy(WRITER, tree / "scripts" / "live-deploy" / "twingate-influx-write.py")   # the real writer
    p, _ = run_wrapper(tree, INFLUX_URL=f.url, TWINGATE_INFLUX_USER=USER, TWINGATE_INFLUX_PASSWORD=PASSWORD)
    assert p.returncode != 0 and f.requests == []


def test_wrapper_uses_pipefail_and_passes_no_values_in_argv():
    src = WRAPPER.read_text(encoding="utf-8")
    assert re.search(r"(?m)^set -[a-z]*o pipefail|^set -o pipefail", src)
    assert "TWINGATE_INFLUX_PASSWORD" not in src and "TWINGATE_API_KEY" not in src
    assert "siem-run" in src and "python3 -I" in src
    assert stat.S_IMODE(WRAPPER.stat().st_mode) & 0o111


# ---- systemd units ---------------------------------------------------------------------

def unit(name):
    return (SYSTEMD / name).read_text(encoding="utf-8")


def test_service_unit_is_a_hardened_oneshot_with_a_failure_hook():
    s = unit("twingate-collect.service")
    assert "Type=oneshot" in s and "OnFailure=twingate-collect-failure.service" in s
    for needle in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes"):
        assert needle in s, needle
    assert "ExecStart=" in s and "twingate-collect" in s
    assert "PASSWORD" not in s and "API_KEY" not in s     # no secret value in a unit file


def test_timer_is_hourly_persistent_and_jittered():
    t = unit("twingate-collect.timer")
    assert "OnCalendar=hourly" in t and "Persistent=true" in t and "RandomizedDelaySec=120" in t
    assert "WantedBy=timers.target" in t


def test_failure_unit_exists_and_logs_only_fixed_text():
    s = unit("twingate-collect-failure.service")
    assert "Type=oneshot" in s and "journalctl -u twingate-collect.service" in s


# ---- rules: a dead collector must not look green ---------------------------------------

def test_every_twingate_rule_alerts_on_missing_data_and_errors_and_stays_paused():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    rules = [r for g in data["groups"] for r in g["rules"]]
    assert len(rules) == 5
    for r in rules:
        assert r["noDataState"] == "Alerting" and r["execErrState"] == "Alerting", r["uid"]
        assert r["isPaused"] is True, r["uid"]          # not unpaused by #222
    stale = next(r for r in rules if r["uid"] == "update-twingate-check-failing")
    assert next(d for d in stale["data"] if d["refId"] == "A")["relativeTimeRange"]["from"] == 21600


def test_writer_database_matches_the_datasource():
    ds = yaml.safe_load((REPO_ROOT / "docker/grafana/provisioning/datasources/datasources.yml")
                        .read_text(encoding="utf-8"))["datasources"]
    twingate = next(d for d in ds if d["uid"] == "influxdb-twingate")
    assert twingate["database"] == "telegraf"
    assert '"telegraf"' in WRITER.read_text(encoding="utf-8")


# ---- docs ------------------------------------------------------------------------------

def test_docs_give_owner_steps_rollback_and_stopped_connector_behavior():
    for name in ("live-deploy-runbook.md", "update-alerting.md"):
        text = (REPO_ROOT / "docs" / name).read_text(encoding="utf-8")
        flat = " ".join(text.split())
        assert "—" not in text
        for needle in ("twingate_wo", "GRANT WRITE ON \"telegraf\"", "TWINGATE_INFLUX_PASSWORD",
                       "TWINGATE_INFLUX_USER", "prd_network", "twingate-collect.timer",
                       "twingate_connector_up", "Rollback"):
            assert needle in flat, (name, needle)
    rb = (REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8")
    assert not re.search(r"doppler secrets set[^\n]*PASSWORD=\S", rb)        # value never on a command line
    assert "> /dev/null" in rb
