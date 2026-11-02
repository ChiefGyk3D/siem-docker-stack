"""Guards for the Prometheus OTLP receiver change (issue #331 in the
maintainer's tracker): the receiver flag, the out-of-order window, a bind
address that stays loopback by default, and docs that carry the
unauthenticated-receiver warning, the firewall step, the verification step and
the rollback note with placeholder addresses only."""
import re

import yaml

from conftest import REPO_ROOT

COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
PROM_YML = REPO_ROOT / "docker" / "prometheus" / "prometheus.yml"
DOC = REPO_ROOT / "docs" / "prometheus-otlp.md"
README = REPO_ROOT / "README.md"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
RULES = sorted((REPO_ROOT / "docker" / "prometheus" / "rules").glob("*.yml"))
DATASOURCES = (REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources"
               / "datasources.yml")
WEB_EXAMPLE = REPO_ROOT / "docker" / "prometheus" / "web.yml.example"
RENDER = REPO_ROOT / "scripts" / "render-prometheus-web-config.sh"
GITIGNORE = REPO_ROOT / ".gitignore"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
# Documentation range (RFC 5737) plus loopback and wildcard are the only
# addresses a public doc may name.
ALLOWED_IP = re.compile(r"^(192\.0\.2\.\d{1,3}(/\d{1,2})?|127\.0\.0\.1|0\.0\.0\.0)$")


def non_placeholder_ips(text):
    return [m for m in IPV4.findall(text) if not ALLOWED_IP.match(m)]


def _prometheus_service():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["prometheus"]


def test_ip_guard_bites():
    assert non_placeholder_ips("allow 10.1.2.3 and 192.0.2.10") == ["10.1.2.3"]
    assert non_placeholder_ips("allow 198.51.100.7/24") == ["198.51.100.7/24"]
    assert non_placeholder_ips("allow 192.0.2.10 and 192.0.2.0/24") == []


def test_compose_enables_otlp_receiver():
    assert "--web.enable-otlp-receiver" in _prometheus_service()["command"]


def test_compose_prometheus_bind_defaults_to_loopback():
    ports = _prometheus_service()["ports"]
    assert len(ports) == 1
    assert ports[0].startswith(
        "${PROMETHEUS_BIND_ADDR:-${BIND_ADDR:-127.0.0.1}}:"), ports[0]
    assert "0.0.0.0" not in ports[0]


def test_prometheus_yml_out_of_order_window():
    data = yaml.safe_load(PROM_YML.read_text(encoding="utf-8"))
    assert data["storage"]["tsdb"]["out_of_order_time_window"] == "30m"


def test_prometheus_yml_does_not_promote_every_resource_attribute():
    data = yaml.safe_load(PROM_YML.read_text(encoding="utf-8"))
    otlp = data.get("otlp")
    assert isinstance(otlp, dict), "an explicit otlp block is required"
    assert not otlp.get("promote_all_resource_attributes")


def test_env_example_documents_prometheus_bind_addr():
    assert "PROMETHEUS_BIND_ADDR" in ENV_EXAMPLE.read_text(encoding="utf-8")


def test_doc_has_required_sections_and_warning():
    text = DOC.read_text(encoding="utf-8")
    assert "authenticated and firewalled" in text
    assert "basic_auth" in text and "web.config.file" in text
    for heading in ("## Firewall", "## Apply order", "## Verify", "## Rollback"):
        assert heading in text, f"missing {heading}"
    assert "DOCKER-USER" in text
    assert "/api/v1/otlp/v1/metrics" in text
    assert "30m" in text


def test_doc_uses_placeholder_addresses_only():
    assert non_placeholder_ips(DOC.read_text(encoding="utf-8")) == []


def test_readme_links_doc_and_warns():
    text = README.read_text(encoding="utf-8")
    assert "docs/prometheus-otlp.md" in text
    assert "PROMETHEUS_BIND_ADDR" in text


# --- authentication in front of the receiver ---------------------------------

def test_compose_prometheus_requires_basic_auth():
    svc = _prometheus_service()
    assert "--web.config.file=/etc/prometheus/web.yml" in svc["command"]
    mounts = " ".join(svc["volumes"])
    assert "./prometheus/web.yml:/etc/prometheus/web.yml:ro" in mounts
    assert "/etc/prometheus/secrets" in mounts


def test_grafana_gets_prometheus_password_as_required_secret():
    env = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["grafana"]["environment"]
    line = [e for e in env if e.startswith("PROMETHEUS_BASIC_AUTH_PASSWORD=")]
    assert line and ":?" in line[0], "must be a required (${VAR:?}) secret"


def test_grafana_prometheus_datasource_authenticates():
    sources = yaml.safe_load(DATASOURCES.read_text(encoding="utf-8"))["datasources"]
    ds = [d for d in sources if d["uid"] == "prometheus"][0]
    assert ds["basicAuth"] is True and ds["basicAuthUser"] == "prometheus"
    assert ds["secureJsonData"]["basicAuthPassword"] == "$PROMETHEUS_BASIC_AUTH_PASSWORD"


def test_self_scrape_authenticates_with_a_password_file():
    data = yaml.safe_load(PROM_YML.read_text(encoding="utf-8"))
    job = [j for j in data["scrape_configs"] if j["job_name"] == "prometheus"][0]
    assert job["basic_auth"]["username"] == "prometheus"
    assert job["basic_auth"]["password_file"].startswith("/etc/prometheus/secrets/")


def test_web_config_example_and_ignore_rules():
    data = yaml.safe_load(WEB_EXAMPLE.read_text(encoding="utf-8"))
    assert list(data["basic_auth_users"]) == ["prometheus"]
    ignore = GITIGNORE.read_text(encoding="utf-8")
    assert "docker/prometheus/web.yml" in ignore
    assert "docker/prometheus/secrets/" in ignore


def test_render_script_keeps_the_password_off_the_command_line():
    text = RENDER.read_text(encoding="utf-8")
    assert "htpasswd -niBC" in text, "password must go to htpasswd on stdin"
    assert "htpasswd -nb" not in text and "htpasswd -nBb" not in text


# --- alert rules are scoped to their scrape jobs ---------------------------------

JOB_MATCHER = re.compile(r"\bjob\s*(=~|=)\s*\"")


def unscoped_alerts(rule_files):
    bad = []
    for path in rule_files:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for rule in group["rules"]:
                if "alert" in rule and not JOB_MATCHER.search(rule["expr"]):
                    bad.append(rule["alert"])
    return bad


def test_scope_guard_bites(tmp_path):
    f = tmp_path / "r.yml"
    f.write_text("groups:\n- name: g\n  rules:\n  - alert: A\n    expr: foo > 1\n"
                 "  - alert: B\n    expr: foo{job=\"x\"} > 1\n", encoding="utf-8")
    assert unscoped_alerts([f]) == ["A"]


def test_every_alert_rule_selects_a_scrape_job():
    assert RULES, "no rule files collected"
    assert unscoped_alerts(RULES) == []
