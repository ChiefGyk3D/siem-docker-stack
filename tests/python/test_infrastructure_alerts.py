"""Guard for docker/grafana/provisioning/alerting/infra-alerts.yml (issue #224).

The rules must page the phone only for the critical infrastructure jobs, select
exactly the jobs docs/infrastructure-alerts.md lists, and treat a vanished job as
an alert. check_infra() is the checker; the negative cases prove each clause bites.
"""
import copy
import json
import re

import yaml

from conftest import REPO_ROOT

RULE_FILE = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "infra-alerts.yml"
DOC = REPO_ROOT / "docs" / "infrastructure-alerts.md"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"

CRITICAL_JOBS = {"twingate-ztna", "unifi-controller"}
# The SIEM host (job "node") hosts the alert engine: disk rules only, never host-down
# (a Grafana rule cannot report its own host down while Grafana is dead).
DISK_CRITICAL_JOBS = CRITICAL_JOBS | {"node"}
OTHER_UP_JOBS = {"Security", "AI", "Cryptocurrency", "grafana", "prometheus"}
OTHER_DISK_JOBS = {"Security", "AI", "Cryptocurrency"}
LIVE_TITLES = {"Host Down", "Disk Usage Critical"}
EXPECTED = {
    "infra-host-down-critical": ("up", CRITICAL_JOBS, True),
    "infra-host-down-other": ("up", OTHER_UP_JOBS, False),
    "infra-disk-critical": ("disk", DISK_CRITICAL_JOBS, True),
    "infra-disk-other": ("disk", OTHER_DISK_JOBS, False),
}


def load_rules(path=RULE_FILE):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [r for g in data["groups"] for r in g["rules"]]


def expr_of(rule):
    (a,) = [d for d in rule["data"] if d["refId"] == "A"]
    return a["model"]["expr"]


def jobs_of(expr):
    sets = {frozenset(m.split("|")) for m in re.findall(r'job=~"([^"]*)"', expr)}
    return sets


def check_infra(rules):
    problems = []
    by_uid = {r["uid"]: r for r in rules}
    if set(by_uid) != set(EXPECTED) or len(by_uid) != len(rules):
        problems.append("rule uids differ from the expected four")
    for uid, (kind, jobs, pages) in EXPECTED.items():
        r = by_uid.get(uid)
        if r is None:
            continue
        labels, expr = r.get("labels", {}), expr_of(r)
        if r["title"] in LIVE_TITLES:
            problems.append(f"{uid}: title reuses a live rule title")
        if jobs_of(expr) != {frozenset(jobs)}:
            problems.append(f"{uid}: job selector is not exactly {sorted(jobs)}")
        if "job=" in expr.replace("job=~", ""):
            problems.append(f"{uid}: exact job matcher found, use the regex form")
        if "Computers" in expr:
            problems.append(f"{uid}: Computers must never be selected")
        if labels.get("alert_group") != "infrastructure":
            problems.append(f"{uid}: alert_group is not infrastructure")
        if "update_alert" in labels:
            problems.append(f"{uid}: update_alert must not be set")
        if pages:
            if (labels.get("phone"), labels.get("tier"), labels.get("severity")) != ("true", "P1", "critical"):
                problems.append(f"{uid}: critical rule must be phone true, P1, critical")
            if r.get("noDataState") != "Alerting":
                problems.append(f"{uid}: critical rule needs noDataState Alerting")
        else:
            if labels.get("phone") != "false" or labels.get("severity") == "critical" and labels.get("tier") == "P1":
                problems.append(f"{uid}: non-critical rule must not page")
        if kind == "up" and "up{" not in expr:
            problems.append(f"{uid}: not an up query")
        if kind == "disk":
            if "tmpfs|overlay|squashfs" not in expr or "node_filesystem_size_bytes" not in expr:
                problems.append(f"{uid}: disk query must exclude tmpfs, overlay and squashfs")
            (c,) = [d for d in r["data"] if d["refId"] == "C"]
            ev = c["model"]["conditions"][0]["evaluator"]
            if (ev["type"], ev["params"]) != ("gt", [85]):
                problems.append(f"{uid}: disk threshold is not above 85")
        if r.get("for") != "5m":
            problems.append(f"{uid}: for is not 5m")
    phone_uids = {u for u, r in by_uid.items() if r.get("labels", {}).get("phone") == "true"}
    if phone_uids != {u for u, e in EXPECTED.items() if e[2]}:
        problems.append("phone true is not limited to the two critical rules")
    return problems


def test_rule_file_passes_the_checker():
    assert check_infra(load_rules()) == []


def test_titles_are_new_and_not_allowlisted():
    rules = load_rules()
    assert rules and not {r["title"] for r in rules} & LIVE_TITLES
    router = ROUTER.read_text(encoding="utf-8")
    json.loads(router)
    for r in rules:
        assert r["title"] not in router.split("ALLOWED_ALERTNAMES", 1)[1].split("]", 1)[0], r["title"]


def test_critical_disk_rule_ships_paused_and_host_rules_do_not():
    by = {r["uid"]: r for r in load_rules()}
    assert by["infra-disk-critical"]["isPaused"] is True
    assert by["infra-host-down-critical"]["isPaused"] is False


def test_doc_lists_every_job_and_the_migration():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("twingate-ztna", "unifi-controller", "Computers", "Alertmanager", "node_exporter",
                   "Host Down", "Disk Usage Critical", "Rollback", "ALLOWED_ALERTNAMES", "PBFA97"):
        assert needle in text, needle
    assert "—" not in text


def test_node_job_is_in_critical_disk_rule_only():
    by = {r["uid"]: r for r in load_rules()}
    assert "node" in next(iter(jobs_of(expr_of(by["infra-disk-critical"]))))
    for uid in ("infra-host-down-critical", "infra-host-down-other", "infra-disk-other"):
        assert "node" not in next(iter(jobs_of(expr_of(by[uid])))), uid
    labels = by["infra-disk-critical"]["labels"]
    assert (labels["phone"], labels["tier"], labels["severity"]) == ("true", "P1", "critical")


def test_doc_explains_why_host_down_excludes_node():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "`node`" in text and "docs/heartbeat.md" in text
    assert "cannot report its own host down" in text


# Negative cases: each mutant must be caught by the checker.
def _mutate(fn):
    rules = copy.deepcopy(load_rules())
    by = {r["uid"]: r for r in rules}
    fn(by)
    return check_infra(rules)


def _set_expr(r, old, new):
    (a,) = [d for d in r["data"] if d["refId"] == "A"]
    assert old in a["model"]["expr"]
    a["model"]["expr"] = a["model"]["expr"].replace(old, new)


def test_checker_catches_phone_on_a_warning_rule():
    assert _mutate(lambda b: b["infra-host-down-other"]["labels"].update(phone="true"))


def test_checker_catches_critical_rule_losing_phone():
    assert _mutate(lambda b: b["infra-host-down-critical"]["labels"].update(phone="false"))


def test_checker_catches_critical_no_data_ok():
    assert _mutate(lambda b: b["infra-disk-critical"].update(noDataState="OK"))
    assert _mutate(lambda b: b["infra-host-down-critical"].update(noDataState="NoData"))


def test_checker_catches_selector_drift():
    assert _mutate(lambda b: _set_expr(b["infra-host-down-critical"], "twingate-ztna|unifi-controller", "twingate-ztna"))
    assert _mutate(lambda b: _set_expr(b["infra-host-down-other"], "AI|", "AI|Computers|"))
    assert _mutate(lambda b: _set_expr(b["infra-disk-critical"], "unifi-controller", "unifi-controller|Security"))


def test_checker_catches_filesystem_filter_and_threshold_loss():
    assert _mutate(lambda b: _set_expr(b["infra-disk-other"], "tmpfs|overlay|squashfs", "tmpfs"))

    def thr(b):
        (c,) = [d for d in b["infra-disk-critical"]["data"] if d["refId"] == "C"]
        c["model"]["conditions"][0]["evaluator"]["params"] = [95]
    assert _mutate(thr)


def test_checker_catches_title_reuse_and_update_label():
    assert _mutate(lambda b: b["infra-host-down-critical"].update(title="Host Down"))
    assert _mutate(lambda b: b["infra-host-down-critical"]["labels"].update(update_alert="true"))


def test_checker_catches_node_dropped_or_added_to_host_down():
    assert _mutate(lambda b: _set_expr(b["infra-disk-critical"], "unifi-controller|node", "unifi-controller"))
    assert _mutate(lambda b: _set_expr(b["infra-host-down-critical"], "unifi-controller", "unifi-controller|node"))
    assert _mutate(lambda b: _set_expr(b["infra-host-down-other"], "prometheus", "prometheus|node"))
