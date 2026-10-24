"""Guards for the threat-model High findings (issue #32): fail closed on
secrets, loopback-by-default published ports, opt-in Portainer, and
least-privilege accounts for Grafana and the UniFi poller."""
import re

import yaml

from conftest import REPO_ROOT

COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
CI_ENV = REPO_ROOT / "tests" / "compose.ci.env"
README = REPO_ROOT / "README.md"
PIPELINES = sorted((REPO_ROOT / "docker" / "logstash" / "pipeline").glob("*.conf"))
DATASOURCES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources" / "datasources.yml"
DASHBOARDS_YML = REPO_ROOT / "docker" / "wazuh" / "opensearch_dashboards.yml"

SECRET_NAME = re.compile(r"(PASSWORD|PASS|SECRET|TOKEN)(_|$)")
REF = re.compile(r"\$\{([A-Z0-9_]+)(:?[-?])?([^}]*)\}")
SAFE_BIND = re.compile(r"^(127\.0\.0\.1|\$\{(BIND_ADDR|INGEST_BIND_ADDR|PORTAINER_BIND_ADDR):-127\.0\.0\.1\}):")


def secret_fallbacks(text):
    """Variables whose name looks like a secret but carry a `:-` default."""
    return [m.group(1) for m in REF.finditer(text)
            if SECRET_NAME.search(m.group(1)) and m.group(2) in (":-", "-")]


def unsafe_ports(services):
    bad = []
    for name, svc in services.items():
        for port in svc.get("ports", []):
            if not SAFE_BIND.match(str(port)):
                bad.append((name, port))
    return bad


def _compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def test_guard_bites_on_fallback_secret():
    assert secret_fallbacks("X=${GRAFANA_ADMIN_PASS:-changeme}") == ["GRAFANA_ADMIN_PASS"]
    assert secret_fallbacks("X=${GRAFANA_ADMIN_PASS:?set it}") == []
    assert secret_fallbacks("X=${GRAFANA_ADMIN_USER:-admin}") == []


def test_guard_bites_on_open_port():
    assert unsafe_ports({"s": {"ports": ["9443:9443"]}}) == [("s", "9443:9443")]
    assert unsafe_ports({"s": {"ports": ["0.0.0.0:9443:9443"]}}) != []
    assert unsafe_ports({"s": {"ports": ["${BIND_ADDR:-127.0.0.1}:1:1"]}}) == []


def test_compose_has_no_secret_fallbacks():
    assert COMPOSE.read_text(encoding="utf-8").count("services:") == 1
    assert secret_fallbacks(COMPOSE.read_text(encoding="utf-8")) == []


def test_every_published_port_defaults_to_loopback():
    services = _compose()
    assert sum(len(s.get("ports", [])) for s in services.values()) > 10
    assert unsafe_ports(services) == []


def test_portainer_is_opt_in():
    svc = _compose()["portainer"]
    assert svc.get("profiles") == ["portainer"]
    assert all(str(p).startswith("${PORTAINER_BIND_ADDR:-127.0.0.1}:") for p in svc["ports"])


def test_required_variables_are_in_ci_env_and_readme():
    text = COMPOSE.read_text(encoding="utf-8")
    required = sorted({m.group(1) for m in REF.finditer(text) if m.group(2) == ":?"})
    assert "WAZUH_DASHBOARD_PASSWORD" in required and "GRAFANA_INFLUX_PASSWORD" in required
    ci_env = CI_ENV.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    for var in required:
        assert re.search(rf"^{var}=\S+", ci_env, re.M), f"{var} missing from tests/compose.ci.env"
        assert var in readme, f"{var} not documented in README upgrade notes"


def test_logstash_pipelines_read_password_without_default():
    assert PIPELINES
    for path in PIPELINES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"\s*password\s*=>", line):
                assert re.search(r'"\$\{OPENSEARCH_LOGSTASH_PASSWORD\}"', line), f"{path.name}: {line}"


def test_wazuh_dashboard_password_comes_from_environment():
    cfg = yaml.safe_load(DASHBOARDS_YML.read_text(encoding="utf-8"))
    assert cfg["opensearch.password"] == "${DASHBOARD_PASSWORD}"
    env = _compose()["wazuh-dashboard"]["environment"]
    assert any(e.startswith("DASHBOARD_PASSWORD=${WAZUH_DASHBOARD_PASSWORD:?") for e in env)


def test_grafana_and_poller_do_not_hold_influx_admin():
    services = _compose()
    for name in ("grafana", "unifi-poller"):
        env = "\n".join(services[name]["environment"])
        assert "INFLUXDB_ADMIN" not in env, name
    ds = DATASOURCES.read_text(encoding="utf-8")
    assert "INFLUXDB_ADMIN" not in re.sub(r"(?m)^#.*$", "", ds)
    assert "GRAFANA_INFLUX_PASSWORD" in ds


def _run_check_env(tmp_path, body):
    import subprocess
    env = tmp_path / ".env"
    env.write_text(body, encoding="utf-8")
    return subprocess.run(["bash", str(REPO_ROOT / "scripts" / "check-env.sh"), str(env)],
                          capture_output=True, text=True, check=False)


def test_check_env_rejects_missing_and_known_defaults(tmp_path):
    names = [ln.split("=")[0] for ln in CI_ENV.read_text(encoding="utf-8").splitlines()
             if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    good = "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(names))
    assert _run_check_env(tmp_path, good).returncode == 0
    bad = _run_check_env(tmp_path, good.replace("Zx9-unique-0", "changeme"))
    assert bad.returncode == 1 and "changeme" not in bad.stderr
    assert _run_check_env(tmp_path, good.replace("Zx9-unique-3", "")).returncode == 1
    assert _run_check_env(tmp_path, "").returncode == 1


def test_check_env_warns_loudly_when_ingest_stays_on_loopback(tmp_path):
    """Loopback ingest is the safe default, but an upgraded stack stops hearing
    from firewalls and agents without any error, so say so (non-fatal)."""
    names = [ln.split("=")[0] for ln in CI_ENV.read_text(encoding="utf-8").splitlines()
             if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    good = "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(dict.fromkeys(names)))
    for body in (good, good + "INGEST_BIND_ADDR=127.0.0.1\n"):
        res = _run_check_env(tmp_path, body)
        assert res.returncode == 0
        assert "INGEST_BIND_ADDR" in res.stderr and "other hosts" in res.stderr
    res = _run_check_env(tmp_path, good + "INGEST_BIND_ADDR=192.0.2.10\n")
    assert res.returncode == 0 and "INGEST_BIND_ADDR" not in res.stderr
