"""Guards for the Grafana notification failure alert (issue #81).

The rule watches Grafana's own failed-notification counter. It must reach a human
through a contact point that does not depend on the one that may be failing.
"""
import re

import yaml

from conftest import REPO_ROOT

ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
RULE_FILE = ALERTING / "notification-failure-alert-rule.yml"
POLICY_FILE = ALERTING / "notification-failure-notification-policy.yml.example"
CONTACT_FILE = ALERTING / "notification-failure-contact-point.yml.example"
DOC = REPO_ROOT / "docs" / "notification-failure-alerts.md"
PROM = REPO_ROOT / "docker" / "prometheus" / "prometheus.yml"

FORBIDDEN = {"update_alert", "heartbeat", "phone"}
ROUTE_LABEL = ("delivery_failure", "true")


def _rule():
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    rules = [r for g in data["groups"] for r in g["rules"]]
    assert len(rules) == 1, "expected exactly one rule"
    return data, rules[0]


def test_rule_file_exists_and_is_provisioned_shape():
    data, rule = _rule()
    assert data["apiVersion"] == 1
    assert rule["uid"] and rule["title"]
    assert rule["for"] == "5m"


def test_condition_refid_exists_and_expression_chain_resolves():
    _, rule = _rule()
    ids = {d["refId"] for d in rule["data"]}
    assert rule["condition"] in ids
    for d in rule["data"]:
        src = d["model"].get("expression")
        if d["datasourceUid"] == "__expr__" and src:
            assert src in ids, "expression %s reads a missing refId" % d["refId"]


def test_query_names_the_counter_and_window_is_in_one_place():
    _, rule = _rule()
    queries = [d for d in rule["data"] if d["datasourceUid"] != "__expr__"]
    assert len(queries) == 1
    expr = queries[0]["model"]["expr"]
    assert "grafana_alerting_notifications_failed_total" in expr
    assert "increase(" in expr
    assert re.findall(r"\[(\d+[smh])\]", expr) == ["10m"], "window must appear once, in the query"
    assert queries[0]["datasourceUid"] == "prometheus"


def test_labels_route_away_and_carry_no_forbidden_label():
    _, rule = _rule()
    labels = rule["labels"]
    assert labels["severity"] == "warning"
    assert labels[ROUTE_LABEL[0]] == ROUTE_LABEL[1]
    assert not FORBIDDEN & set(labels)


def test_states_are_the_documented_choice():
    _, rule = _rule()
    assert rule["noDataState"] == "OK"
    assert rule["execErrState"] == "Alerting"
    assert "UNVERIFIED" in RULE_FILE.read_text(encoding="utf-8")


def test_policy_example_routes_to_a_receiver_other_than_the_webhook():
    data = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    root = data["policies"][0]
    routes = [r for r in root["routes"] if ["delivery_failure", "=", "true"] in r["object_matchers"]]
    assert len(routes) == 1
    assert routes[0]["receiver"] != "n8n-grafana-router"
    contacts = yaml.safe_load(CONTACT_FILE.read_text(encoding="utf-8"))
    names = {c["name"] for c in contacts["contactPoints"]}
    assert routes[0]["receiver"] in names
    for c in contacts["contactPoints"]:
        for r in c["receivers"]:
            assert r["type"] == "discord"
            assert str(r["settings"]["url"]).startswith("$")


def test_grafana_is_scraped_by_prometheus():
    cfg = yaml.safe_load(PROM.read_text(encoding="utf-8"))
    jobs = {j["job_name"]: j for j in cfg["scrape_configs"]}
    assert "grafana" in jobs
    assert "grafana:3000" in jobs["grafana"]["static_configs"][0]["targets"]


def test_doc_states_unverified_name_and_confirmation():
    text = DOC.read_text(encoding="utf-8")
    assert "unverified" in text.lower()
    assert "grafana_alerting_notifications_failed_total" in text
    assert "#78" in text and "#80" in text
    assert "—" not in text


def test_guard_bites_on_forbidden_label():
    bad = {"severity": "warning", "delivery_failure": "true", "phone": "true"}
    assert FORBIDDEN & set(bad)
    assert not FORBIDDEN & {"severity", "delivery_failure"}
