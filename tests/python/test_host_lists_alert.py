"""Guards for the stale apt lists alert (issue #233): the paused Grafana rules for the host update
collector, the router allow-list, the taxonomy source and the doc paragraph.

The collector itself already measures the lists age and fails closed (tests/python/
test_host_update_metric.py); this file covers the alert side only. Collection is loose (a fixed
file that must exist); assertions are strict, and negative cases prove the checks bite.
"""
import json
import re

import yaml

from conftest import REPO_ROOT

RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-alert-rules-host.yml"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
DOC = REPO_ROOT / "docs" / "host-update-collector.md"
ALERT_DOC = REPO_ROOT / "docs" / "update-alerting.md"
TAXONOMY_DOC = REPO_ROOT / "docs" / "alert-taxonomy.md"

STALE = "update-host-lists-stale"
FAILING = "update-host-check-failing"


def _rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    (group,) = data["groups"]
    assert group["folder"] == "Update Alerts"
    return {r["uid"]: r for r in group["rules"]}


def _data(rule, ref):
    return next(d for d in rule["data"] if d["refId"] == ref)


def test_exactly_the_two_host_rules_and_all_paused():
    rules = _rules()
    assert set(rules) == {STALE, FAILING}
    for uid, r in rules.items():
        assert r["isPaused"] is True, uid
        assert r["execErrState"] == "Alerting", uid
        # missing data must never read as a healthy host
        assert r["noDataState"] == "Alerting", uid
        assert r["labels"]["source"] == "host" and r["labels"]["update_alert"] == "true", uid
        assert r["labels"]["alert_group"] == "updates", uid
        assert (r["labels"]["severity"], r["labels"]["tier"], r["labels"]["phone"]) == ("warning", "P2", "false"), uid


def test_stale_rule_fires_above_two_days_the_warning_before_the_three_day_hard_failure():
    r = _rules()[STALE]
    q = _data(r, "A")
    assert "host_update_lists_age_seconds" in q["model"]["query"]
    c = _data(r, "C")["model"]
    assert c["type"] == "threshold"
    (cond,) = c["conditions"]
    assert cond["evaluator"] == {"type": "gt", "params": [172800]}


def test_failing_rule_fires_on_zero_or_missing_success():
    r = _rules()[FAILING]
    q = _data(r, "A")
    assert "host_update_check_success" in q["model"]["query"]
    (cond,) = _data(r, "C")["model"]["conditions"]
    assert cond["evaluator"] == {"type": "lt", "params": [1]}
    # the lists failure prints only check_success 0 (no age), so this rule must see it
    assert "lists" in r["annotations"]["description"].lower()


def test_both_rules_use_the_telegraf_database_and_a_data_window_that_outlives_one_missed_run():
    for uid, r in _rules().items():
        a = _data(r, "A")
        assert a["datasourceUid"] == "influxdb-twingate", uid
        assert a["relativeTimeRange"]["from"] >= 6 * 3600, uid
        assert "GROUP BY \"host\"" in a["model"]["query"], uid


def test_alert_names_are_in_the_router_allow_list():
    text = ROUTER.read_text(encoding="utf-8")
    js = next(n["parameters"]["jsCode"] for n in json.loads(text)["nodes"]
              if "ALLOWED_ALERTNAMES = [" in n.get("parameters", {}).get("jsCode", ""))
    m = re.search(r"const ALLOWED_ALERTNAMES = \[(.*?)\];", js, re.S)
    listed = set(re.findall(r"'([^']*)'", m.group(1)))
    for r in _rules().values():
        assert r["title"] in listed


def test_taxonomy_knows_the_host_source():
    assert "`host`" in TAXONOMY_DOC.read_text(encoding="utf-8")


def test_docs_describe_the_alert_and_that_it_ships_paused():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "update-alert-rules-host.yml" in flat
    assert "paused" in flat.lower()
    assert "host_update_lists_age_seconds" in flat
    assert "update-alert-rules-host.yml" in ALERT_DOC.read_text(encoding="utf-8")


def test_the_threshold_check_bites_on_a_wrong_value():
    # negative case: a rule at 259200 (3 days, equal to the hard failure) would never warn first
    bad = {"evaluator": {"type": "gt", "params": [259200]}}
    assert bad["evaluator"] != _data(_rules()[STALE], "C")["model"]["conditions"][0]["evaluator"]
