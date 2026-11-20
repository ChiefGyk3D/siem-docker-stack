"""Guards for the draft Patch Gremlin alert set (issue #65, epic #62).

Everything ships inactive: the rule file ends in .example (not .yml, and not
.yml.example, which the alert taxonomy test also scans), the scrape snippet is
a .example file, and the target file is an .example.json. Nothing deploys until
the owner copies them. The label rules are the ones in the alert taxonomy
(PR #142); they are repeated here so this test does not depend on that PR.
"""
import json
import re

import pytest
import yaml

from conftest import REPO_ROOT

ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
PROM = REPO_ROOT / "docker" / "prometheus"
RULES = ALERTING / "patch-gremlin-alert-rules.example"
SCRAPE = PROM / "patch-gremlin-scrape.example"
TARGETS = PROM / "targets" / "patch-gremlin.example.json"
DOC = REPO_ROOT / "docs" / "patch-gremlin-alerts.md"

# Metric names the exporter emits (monitoring/prometheus-exporter.sh in
# ChiefGyk3D/Patch-Gremlin). Anything else a rule queries must be on the
# documented-as-inferred list, and that rule must ship paused.
VERIFIED = {
    "patch_gremlin_health", "patch_gremlin_last_run_timestamp_seconds",
    "patch_gremlin_last_notification_success", "patch_gremlin_packages_upgraded",
    "patch_gremlin_pending_updates", "patch_gremlin_pending_security_updates",
    "patch_gremlin_status_info",
}
INFERRED = {"node_reboot_required"}

SEVERITIES = {"critical", "warning", "info"}
ALLOWED_LABELS = {"severity", "tier", "phone", "alert_group", "source",
                  "update_alert", "update_security"}


def _rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    return [r for g in data["groups"] for r in g["rules"]]


def _exprs(rule):
    return [d["model"]["expr"] for d in rule["data"] if "expr" in d.get("model", {})]


def _metrics(text):
    return set(re.findall(r"\b((?:patch_gremlin|node_reboot)_[a-z_]+)", text))


def test_files_exist_and_parse():
    assert len(_rules()) == 3
    assert yaml.safe_load(SCRAPE.read_text(encoding="utf-8"))["scrape_configs"]
    assert json.loads(TARGETS.read_text(encoding="utf-8"))


def test_rule_file_is_not_auto_loaded():
    # Grafana loads *.yml and *.yaml from the provisioning directory only.
    assert RULES.suffix == ".example"
    assert not list(ALERTING.glob("patch-gremlin*.yml"))
    assert not list(ALERTING.glob("patch-gremlin*.yaml"))
    # The taxonomy test scans *.yml and *.yml.example; this file must not match
    # until the owner promotes it (and adds the source to that test).
    assert not list(ALERTING.glob("patch-gremlin*.yml.example"))


def test_scrape_snippet_is_not_the_live_config():
    live = (PROM / "prometheus.yml").read_text(encoding="utf-8")
    assert "patch-gremlin" not in live
    assert SCRAPE.suffix == ".example"
    assert not (PROM / "targets" / "patch-gremlin.json").exists()


@pytest.mark.parametrize("rule", _rules(), ids=lambda r: r["uid"])
def test_rule_labels(rule):
    labels = rule["labels"]
    assert set(labels) <= ALLOWED_LABELS
    assert all(isinstance(v, str) for v in labels.values())
    for k in ("severity", "tier", "phone", "alert_group", "source", "update_alert"):
        assert k in labels, k
    assert labels["severity"] in SEVERITIES
    assert labels["alert_group"] == "updates"
    assert labels["source"] == "patch-gremlin"
    assert labels["update_alert"] == "true"
    pair = (labels["tier"], labels["severity"], labels["phone"])
    assert pair in {("P1", "critical", "true"), ("P2", "warning", "false")}


@pytest.mark.parametrize("rule", _rules(), ids=lambda r: r["uid"])
def test_rule_states_and_shape(rule):
    assert rule["execErrState"] == "Alerting"
    assert rule["noDataState"] in {"OK", "Alerting", "NoData"}
    assert rule["condition"] in {d["refId"] for d in rule["data"]}
    assert rule["uid"].startswith("update-patch-gremlin-")
    assert rule["annotations"]["summary"] and rule["annotations"]["description"]


def test_reboot_rule_ships_paused():
    # Its metric is not emitted by Patch Gremlin; it stays paused until the
    # owner supplies it.
    reboot = [r for r in _rules() if "reboot" in r["uid"]]
    assert len(reboot) == 1 and reboot[0]["isPaused"] is True


def test_rule_uids_and_titles_unique():
    r = _rules()
    assert len({x["uid"] for x in r}) == len(r)
    assert len({x["title"] for x in r}) == len(r)


def test_queries_use_only_known_metrics():
    used = set()
    for rule in _rules():
        for e in _exprs(rule):
            used |= _metrics(e)
    assert used
    assert used <= VERIFIED | INFERRED, used - VERIFIED - INFERRED
    for rule in _rules():
        if not rule["isPaused"]:
            for e in _exprs(rule):
                assert _metrics(e) <= VERIFIED, (rule["uid"], e)


def test_non_security_query_subtracts_security():
    rule = next(r for r in _rules() if "pending" in r["uid"])
    expr = " ".join(_exprs(rule))
    assert "patch_gremlin_pending_updates" in expr
    assert "patch_gremlin_pending_security_updates" in expr
    assert "-" in expr


def test_stale_rule_covers_failed_status():
    rule = next(r for r in _rules() if "stale" in r["uid"])
    expr = " ".join(_exprs(rule))
    assert "patch_gremlin_last_run_timestamp_seconds" in expr
    assert 'patch_gremlin_status_info{status="error"}' in expr
    assert rule["noDataState"] == "Alerting"


def test_datasource_is_provisioned_prometheus():
    ds = (ALERTING.parent / "datasources" / "datasources.yml").read_text(encoding="utf-8")
    assert "uid: prometheus\n" in ds
    for rule in _rules():
        for d in rule["data"]:
            if "expr" in d.get("model", {}):
                assert d["datasourceUid"] == "prometheus"


def test_scrape_snippet_keeps_only_patch_gremlin_series():
    job = yaml.safe_load(SCRAPE.read_text(encoding="utf-8"))["scrape_configs"][0]
    assert job["job_name"] == "patch-gremlin"
    relabel = job["metric_relabel_configs"][0]
    assert relabel["action"] == "keep"
    assert "patch_gremlin_" in relabel["regex"]


ALL_TEXT = {p.name: p.read_text(encoding="utf-8")
            for p in (RULES, SCRAPE, TARGETS, DOC)}


@pytest.mark.parametrize("name", sorted(ALL_TEXT))
def test_no_real_hosts_secrets_or_em_dashes(name):
    text = ALL_TEXT[name]
    assert "—" not in text, "em dash"
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith("192.0.2."), ip
    assert not re.search(r"(token|password|secret)\s*[:=]\s*[^\s<]{8,}", text, re.I)
    for host in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|lan|home|local|internal)\b", text):
        assert host == "github.com" or re.search(r"(^|\.)example\.(com|net|org)$", host), host


def test_doc_states_verified_and_inferred_and_commit():
    text = DOC.read_text(encoding="utf-8")
    for m in VERIFIED:
        assert m in text
    assert "VERIFIED" in text and "INFERRED" in text
    assert "monitoring/prometheus-exporter.sh" in text
    assert re.search(r"\b[0-9a-f]{40}\b", text), "pinned commit"
    assert "Rollback" in text
