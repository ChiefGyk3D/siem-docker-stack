"""Tests for the Twingate collector wiring (issue #222): the InfluxDB writer, the wrapper,
the systemd units, the docs and the rule data-gap settings. Everything runs against a fake
InfluxDB on loopback; the user, password and network values below are placeholders."""
import base64
import json
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
SECRETS_INJECTED = {"TWINGATE_API_KEY": "k", "TWINGATE_NETWORK_URL": "https://x.twingate.com",
                    "TWINGATE_EXPECTED_CONNECTORS": '["c1"]', "TWINGATE_INFLUX_USER": USER,
                    "TWINGATE_INFLUX_PASSWORD": PASSWORD,
                    # names a stage must never receive, even if the secret config holds them
                    "PATH": "/evil", "BASH_ENV": "/evil", "UNRELATED_SECRET": "FAKE", "LD_PRELOAD": "/evil.so"}


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
    # A stand-in for siem-run: records what it was given, then injects only the secrets named in
    # SIEM_ONLY_SECRETS (as the secret manager's only-secrets flag does) plus the service-token variables.
    (live / "siem-run").write_text(
        "#!/usr/bin/python3\n"
        "import json, os, sys\n"
        "inject = json.load(open(%r))\n"
        "only = [x for x in os.environ.get('SIEM_ONLY_SECRETS', '').split(',') if x]\n"
        "open(%r, 'a').write(json.dumps({'only': only, 'env': dict(os.environ)}) + '\\n')\n"
        "env = dict(os.environ)\n"
        "env.update({k: v for k, v in inject.items() if k in only})\n"
        "env.update({'DOPPLER_TOKEN': 'FAKE-token', 'DOPPLER_CONFIG': 'c', 'DOPPLER_PROJECT': 'p', 'DOPPLER_ENVIRONMENT': 'e'})\n"
        "os.execve(sys.argv[1], sys.argv[1:], env)\n"
        % (str(tmp_path / "inject.json"), str(tmp_path / "siemrun.jsonl")))
    (tmp_path / "inject.json").write_text(json.dumps(SECRETS_INJECTED))
    (live / "twingate-influx-write.py").write_text(
        "import json, os, resource, sys\n"
        "data = sys.stdin.read()\n"
        "open(%r, 'a').write(data)\n"
        "json.dump({'env': sorted(os.environ), 'core': resource.getrlimit(resource.RLIMIT_CORE)}, open(%r, 'w'))\n"
        "rc = %r\n"
        "sys.exit(int(open(rc).read()) if os.path.exists(rc) else 0)\n"
        % (str(tmp_path / "out.txt"), str(tmp_path / "writer-seen.json"), str(tmp_path / "writer-rc")))
    for p in live.iterdir():
        p.chmod(0o755)
    return tmp_path


def set_collector(tree, text, rc):
    (tree / "scripts" / "twingate-update-metric.py").write_text(
        "import json, os, resource, sys\n"
        "json.dump({'env': sorted(os.environ), 'core': resource.getrlimit(resource.RLIMIT_CORE)}, open(%r, 'w'))\n"
        "sys.stdout.write(%r)\nsys.exit(%d)\n" % (str(tree / "collector-seen.json"), text, rc))


def run_wrapper(tree, **env_extra):
    env = {"PATH": os.environ["PATH"]}
    env.update(env_extra)
    p = subprocess.run(["/usr/bin/bash", str(tree / "scripts" / "live-deploy" / "twingate-collect")],
                       capture_output=True, text=True, env=env, timeout=30)
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
    (tree / "writer-rc").write_text("1")
    p, _ = run_wrapper(tree)
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
    # the secret names appear only as allowlist words: never expanded or assigned (so never in argv)
    assert not re.search(r"\$\{?TWINGATE_(INFLUX_PASSWORD|API_KEY)|TWINGATE_(INFLUX_PASSWORD|API_KEY)=", src)
    assert "siem-run" in src and " -I " in src and "/usr/bin/python3" in src
    assert stat.S_IMODE(WRAPPER.stat().st_mode) & 0o111


SECRETS = {"TWINGATE_API_KEY": "k", "TWINGATE_NETWORK_URL": "https://x.twingate.com",
           "TWINGATE_INFLUX_USER": USER, "TWINGATE_INFLUX_PASSWORD": PASSWORD,
           "DOPPLER_TOKEN": "FAKE-token", "UNRELATED_SECRET": "FAKE"}


def seen(tree, name):
    return json.loads((tree / name).read_text())


def siemrun_calls(tree):
    """What siem-run itself saw, per stage ('collector' or 'writer'): the only place a token may be."""
    calls = [json.loads(x) for x in (tree / "siemrun.jsonl").read_text().splitlines()]
    return {("collector" if "TWINGATE_API_KEY" in c["only"] else "writer"): c for c in calls}


def test_each_stage_receives_only_its_own_secrets(tree):
    set_collector(tree, GOOD, 0)
    p, _ = run_wrapper(tree, **SECRETS)
    assert p.returncode == 0
    col, wr = seen(tree, "collector-seen.json")["env"], seen(tree, "writer-seen.json")["env"]
    assert "TWINGATE_API_KEY" in col and "TWINGATE_NETWORK_URL" in col and "TWINGATE_EXPECTED_CONNECTORS" in col
    assert not {"TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD", "DOPPLER_TOKEN", "UNRELATED_SECRET"} & set(col)
    assert "TWINGATE_INFLUX_USER" in wr and "TWINGATE_INFLUX_PASSWORD" in wr
    assert not {"TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "DOPPLER_TOKEN", "UNRELATED_SECRET"} & set(wr)


def test_the_service_token_reaches_only_siem_run_and_each_stage_gets_only_its_own_secret_names(tree):
    set_collector(tree, GOOD, 0)
    p, _ = run_wrapper(tree, **SECRETS)
    assert p.returncode == 0, p.stderr
    calls = siemrun_calls(tree)
    # siem-run is asked for exactly that stage's secrets and nothing else
    assert set(calls["collector"]["only"]) == {"TWINGATE_API_KEY", "TWINGATE_NETWORK_URL",
                                               "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                                               "TWINGATE_CONNECTOR_MANAGED_BY", "TWINGATE_EXPECTED_CONNECTORS"}
    assert set(calls["writer"]["only"]) == {"TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD"}
    for stage_name, c in calls.items():
        # the caller's own secrets never entered siem-run's environment
        assert not {"TWINGATE_API_KEY", "TWINGATE_INFLUX_PASSWORD", "UNRELATED_SECRET", "DOPPLER_TOKEN"} & set(c["env"]), stage_name
        assert c["env"]["PATH"].startswith("/usr/local/bin:/usr/bin") and c["env"]["LC_ALL"] == "C"
    col, wr = seen(tree, "collector-seen.json")["env"], seen(tree, "writer-seen.json")["env"]
    for env in (col, wr):
        assert not [n for n in env if n.startswith("DOPPLER_")] and "SIEM_ONLY_SECRETS" not in env
        assert not {"BASH_ENV", "LD_PRELOAD", "UNRELATED_SECRET", "HOME", "SIEM_CONFIG_DIR"} & set(env)


def test_the_collector_receives_the_expected_inventory_and_the_writer_does_not(tree):
    set_collector(tree, GOOD, 0)
    p, _ = run_wrapper(tree)
    assert p.returncode == 0
    assert "TWINGATE_EXPECTED_CONNECTORS" in seen(tree, "collector-seen.json")["env"]
    assert "TWINGATE_EXPECTED_CONNECTORS" not in seen(tree, "writer-seen.json")["env"]


def hostile_env(tree):
    """Startup controls and look-alike commands a caller (or a secret config) might set."""
    evil = tree / "evil"
    evil.mkdir()
    marker = tree / "PWNED"
    for name in ("bash", "python3", "env", "doppler", "cat", "dirname", "siem-run"):
        f = evil / name
        f.write_text("#!/bin/sh\necho %s >> %s\n" % (name, marker))
        f.chmod(0o755)
    (evil / "sitecustomize.py").write_text("open(%r, 'a').write('pythonpath\\n')\n" % str(marker))
    hook = tree / "hook.sh"
    hook.write_text("echo hook >> %s\n/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort > %s\n" % (marker, tree / "hook-env.txt"))
    return {"PATH": str(evil) + ":" + os.environ["PATH"], "BASH_ENV": str(hook), "ENV": str(hook),
            "PYTHONPATH": str(evil), "PYTHONHOME": str(evil), "PYTHONSTARTUP": str(hook), "PYTHONUSERBASE": str(evil),
            "PYTHONINSPECT": "1", "SHELLOPTS": "allexport", "BASHOPTS": "xpg_echo", "LD_PRELOAD": "/nonexistent/evil.so",
            "BASH_FUNC_dirname%%": "() { echo func >> %s; command dirname \"$@\"; }" % marker,
            "BASH_FUNC_cd%%": "() { echo func-cd >> %s; builtin cd \"$@\"; }" % marker,
            "TWINGATE_COLLECT_CLEAN": "0"}, marker


def test_hostile_startup_controls_path_and_python_variables_do_not_reach_any_stage(tree):
    set_collector(tree, GOOD, 0)
    hostile, marker = hostile_env(tree)
    p, sent = run_wrapper(tree, **hostile, **SECRETS)
    assert p.returncode == 0 and sent == GOOD, p.stderr
    # no look-alike command or Python startup file ran; only the first bash, which runs before siem-run
    # injects anything, may have sourced BASH_ENV (the unit avoids even that by starting through env -i)
    hits = marker.read_text().split() if marker.exists() else []
    assert not [h for h in hits if h not in ("hook", "func", "func-cd")], hits
    bad = {"BASH_ENV", "ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT", "SHELLOPTS",
           "BASHOPTS", "LD_PRELOAD", "BASH_FUNC_dirname%%", "BASH_FUNC_cd%%", "TWINGATE_COLLECT_CLEAN"}
    for stage_name, c in siemrun_calls(tree).items():
        assert not bad & set(c["env"]), (stage_name, sorted(bad & set(c["env"])))
        assert c["env"]["PATH"] == "/usr/local/bin:/usr/bin:/bin", c["env"]["PATH"]
    for name in ("collector-seen.json", "writer-seen.json"):
        env = seen(tree, name)["env"]
        assert not bad & set(env), (name, sorted(bad & set(env)))
        assert not [n for n in env if n.startswith(("PYTHON", "LD_", "BASH"))], env
        assert "PATH" in env and "evil" not in "".join(env)


def test_started_through_env_i_like_the_unit_no_hook_runs_at_all(tree):
    set_collector(tree, GOOD, 0)
    hostile, marker = hostile_env(tree)
    p = subprocess.run(["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
                        str(tree / "scripts" / "live-deploy" / "twingate-collect")],
                       capture_output=True, text=True, timeout=30, env=hostile)    # env -i drops all of it
    assert p.returncode == 0, p.stderr
    assert not marker.exists()


def test_wrapper_start_unsets_startup_controls_and_uses_absolute_commands():
    src = WRAPPER.read_text(encoding="utf-8")
    first = src.index('exec "$ENV_BIN" -i')
    assert src.index("set -euo pipefail") < first < src.index("HERE=")        # the re-exec is the first action
    assert re.search(r"(?m)^unset BASH_ENV ENV$", src) and "set +o allexport" in src
    assert "ENV_BIN=/usr/bin/env" in src and "PYTHON=/usr/bin/python3" in src
    assert "/usr/bin/bash --noprofile --norc" in src
    assert "-u DOPPLER_TOKEN" in src


def test_core_dumps_are_disabled_for_both_stages(tree):
    set_collector(tree, GOOD, 0)
    p, _ = run_wrapper(tree)
    assert p.returncode == 0
    assert seen(tree, "collector-seen.json")["core"] == [0, 0]
    assert seen(tree, "writer-seen.json")["core"] == [0, 0]


# ---- systemd units ---------------------------------------------------------------------

def unit(name):
    return (SYSTEMD / name).read_text(encoding="utf-8")


def test_service_unit_is_a_hardened_oneshot_with_a_failure_hook():
    s = unit("twingate-collect.service")
    assert "Type=oneshot" in s and "OnFailure=twingate-collect-failure.service" in s
    for needle in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes"):
        assert needle in s, needle
    assert "ExecStart=" in s and "twingate-collect" in s
    exec_line = re.search(r"(?m)^ExecStart=(.*)$", s).group(1)
    assert exec_line.startswith("/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME="), exec_line   # first bash starts clean
    assert "DOPPLER" not in s
    assert "PASSWORD" not in s and "API_KEY" not in s     # no secret value in a unit file
    assert "LimitCORE=0" in s


def test_timer_is_hourly_persistent_and_jittered():
    t = unit("twingate-collect.timer")
    assert "OnCalendar=hourly" in t and "Persistent=true" in t and "RandomizedDelaySec=120" in t
    assert "WantedBy=timers.target" in t


def test_failure_unit_exists_and_logs_only_fixed_text():
    s = unit("twingate-collect-failure.service")
    assert "Type=oneshot" in s and "journalctl -u twingate-collect.service" in s
    assert re.search(r"(?m)^(DynamicUser=yes|User=(?!root\b)\S+)", s) and not re.search(r"(?m)^User=root", s)
    for needle in ("NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX\n",
                   "SystemCallFilter=@system-service", "LimitCORE=0"):
        assert needle in s, needle


def test_runbook_and_alerting_docs_never_put_a_password_in_a_command_argument():
    docs = [REPO_ROOT / "docs" / "live-deploy-runbook.md", REPO_ROOT / "docs" / "update-alerting.md"]
    text = "\n".join(d.read_text(encoding="utf-8") for d in docs)
    assert "INFLUX_PASSWORD=" in text                      # something was collected: the env form is used
    for m in re.finditer(r"(?m)^[^#\n]*\s-(?:password|p)\s+\S*(?:PASSWORD|KEY|TOKEN)\S*", text):
        raise AssertionError("password in argv: " + m.group(0)[:60])


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


def test_docs_say_the_expected_inventory_is_required_and_name_the_extras_metric():
    for name in ("live-deploy-runbook.md", "update-alerting.md"):
        text = (REPO_ROOT / "docs" / name).read_text(encoding="utf-8")
        flat = " ".join(text.split())
        for needle in ("TWINGATE_EXPECTED_CONNECTORS", "twingate_unexpected_connector", "empty environment" if name == "update-alerting.md" else "env -i"):
            assert needle in flat, (name, needle)
        assert "optional" not in flat.lower().split("twingate_expected_connectors")[1][:200], name
        assert "—" not in text
    rb = (REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8")
    assert "## 10. Twingate collector" in rb and "REQUIRES the expected Connector inventory" in " ".join(rb.split())
