"""Tests for scripts/deploy-grafana-alerts.py.

The script is import-safe: rule definitions are built at module level from
env-var configuration, and all network calls live under main() /
resolve_alert_folder_uid(), which these tests never invoke.
"""
import json

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPT = REPO_ROOT / "scripts" / "deploy-grafana-alerts.py"


@pytest.fixture()
def alerts(monkeypatch):
    """Import the script fresh with known datasource env vars set."""
    monkeypatch.setenv("DS_WAZUH", "test-wazuh-uid")
    monkeypatch.setenv("DS_SURICATA", "test-suricata-uid")
    monkeypatch.setenv("DS_PROMETHEUS", "test-prometheus-uid")
    monkeypatch.setenv("ALERT_FOLDER_UID", "test-folder-uid")
    return import_module_from_path("deploy_grafana_alerts_test", SCRIPT)


def test_rules_are_json_serializable_dicts(alerts):
    assert isinstance(alerts.RULES, list) and alerts.RULES
    for rule in alerts.RULES:
        assert isinstance(rule, dict), f"rule is not a dict: {rule!r}"
        # Round-trips through JSON without error (what the API POST does).
        json.loads(json.dumps(rule))


def test_rules_have_required_provisioning_fields(alerts):
    for rule in alerts.RULES:
        for field in ("title", "ruleGroup", "condition", "data", "labels",
                      "annotations", "for", "noDataState", "execErrState"):
            assert field in rule, f"'{rule.get('title')}' missing '{field}'"
        assert isinstance(rule["data"], list) and rule["data"], rule["title"]


def test_rule_titles_are_unique(alerts):
    titles = [r["title"] for r in alerts.RULES]
    assert len(titles) == len(set(titles))


def test_agent_disconnect_rule_queries_rule_id_504(alerts):
    rule = next(r for r in alerts.RULES if r["title"] == "Wazuh Agent Disconnected")
    query = rule["data"][0]["model"]["query"]
    assert 'rule.id:"504"' in query


def test_datasource_uids_come_from_env(alerts):
    assert alerts.DS_WAZUH == "test-wazuh-uid"
    assert alerts.DS_SURICATA == "test-suricata-uid"
    assert alerts.DS_PROMETHEUS == "test-prometheus-uid"

    # Every non-expression query node must use an env-provided UID.
    env_uids = {"test-wazuh-uid", "test-suricata-uid", "test-prometheus-uid"}
    for rule in alerts.RULES:
        for node in rule["data"]:
            uid = node["datasourceUid"]
            if uid != alerts.DS_EXPR:
                assert uid in env_uids, (
                    f"'{rule['title']}' refId {node['refId']} uses "
                    f"hard-coded datasource uid {uid!r}"
                )
