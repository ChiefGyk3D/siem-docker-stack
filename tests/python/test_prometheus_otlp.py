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
    assert "no authentication" in text.lower()
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
