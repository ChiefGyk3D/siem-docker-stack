"""YAML validity and schema sanity for Phase F configs: Prometheus alert
rules, Alertmanager config, Grafana datasource provisioning, and the
OpenSearch node/security configuration."""
import yaml

import pytest

from conftest import REPO_ROOT

DOCKER = REPO_ROOT / "docker"
RULE_FILES = sorted((DOCKER / "prometheus" / "rules").glob("*.yml"))
SECURITY_FILES = sorted((DOCKER / "opensearch" / "security").glob("*.yml*"))


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_rules_dir_not_empty():
    assert RULE_FILES, "docker/prometheus/rules/ must contain at least one rule file"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_prometheus_rule_file_schema(path):
    data = _load(path)
    assert isinstance(data.get("groups"), list) and data["groups"]
    for group in data["groups"]:
        assert isinstance(group.get("name"), str) and group["name"]
        assert isinstance(group.get("rules"), list) and group["rules"]
        for rule in group["rules"]:
            assert rule.get("alert") or rule.get("record")
            assert isinstance(rule.get("expr"), (str, int, float))
            if rule.get("alert"):
                labels = rule.get("labels", {})
                assert labels.get("severity") in {"critical", "warning", "info"}, \
                    f"{rule['alert']}: alerts must carry a severity label"


def test_siem_health_covers_required_alerts():
    names = set()
    for path in RULE_FILES:
        for group in _load(path)["groups"]:
            names.update(r["alert"] for r in group["rules"] if "alert" in r)
    required = {"ClusterStatusRed", "ClusterStatusYellow", "IngestRateZero",
                "TargetDown", "ContainerRestarting",
                "PrometheusRuleEvaluationFailures"}
    assert required <= names, f"missing alerts: {required - names}"


def test_alertmanager_config_schema():
    data = _load(DOCKER / "alertmanager" / "alertmanager.yml")
    assert "route" in data and "receivers" in data
    receiver_names = {r["name"] for r in data["receivers"]}
    assert data["route"]["receiver"] in receiver_names
    for route in data["route"].get("routes", []):
        assert route["receiver"] in receiver_names
    webhooks = [w for r in data["receivers"]
                for w in r.get("webhook_configs", [])]
    assert webhooks, "expected at least one webhook receiver (n8n)"
    for w in webhooks:
        # Rendered config must not contain unexpanded ${...} placeholders.
        assert "${" not in w["url"]


def test_alertmanager_template_parses_and_has_placeholder():
    data = _load(DOCKER / "alertmanager" / "alertmanager.yml.template")
    urls = [w["url"] for r in data["receivers"]
            for w in r.get("webhook_configs", [])]
    assert any("${N8N_ALERTMANAGER_WEBHOOK_URL}" in u for u in urls)


def test_grafana_datasources_schema():
    data = _load(DOCKER / "grafana" / "provisioning" / "datasources" /
                 "datasources.yml")
    sources = data["datasources"]
    assert isinstance(sources, list) and sources
    by_uid = {}
    for ds in sources:
        for key in ("name", "uid", "type", "access", "url"):
            assert isinstance(ds.get(key), str) and ds[key], \
                f"datasource {ds.get('name')} missing {key}"
        assert ds["uid"] not in by_uid, f"duplicate uid {ds['uid']}"
        by_uid[ds["uid"]] = ds
    # Phase F1: the main-cluster OpenSearch datasources must be https + authed
    for uid in ("opensearch-suricata", "opensearch-syslog",
                "opensearch-pfblockerng", "opensearch-crowdsec"):
        ds = by_uid[uid]
        assert ds["url"].startswith("https://opensearch-hot:9200")
        assert ds.get("basicAuth") is True
        assert ds.get("basicAuthUser") == "readonly"
        assert ds["jsonData"].get("tlsSkipVerify") is True


@pytest.mark.parametrize(
    "path",
    [DOCKER / "opensearch" / "opensearch-hot.yml",
     DOCKER / "opensearch" / "opensearch-warm.yml"],
    ids=lambda p: p.name)
def test_opensearch_node_config(path):
    data = _load(path)
    assert data.get("plugins.security.disabled") is None, \
        "security plugin must not be disabled (Phase F1)"
    assert data.get("plugins.security.ssl.http.enabled") is True
    assert data.get("plugins.security.ssl.transport.pemcert_filepath")
    assert "/mnt/snapshots" in data.get("path.repo", []), \
        "snapshot repo path required (Phase F4)"


@pytest.mark.parametrize("path", SECURITY_FILES, ids=lambda p: p.name)
def test_opensearch_security_yaml_parses(path):
    data = _load(path)
    assert isinstance(data, dict)
    assert data.get("_meta", {}).get("config_version") == 2
