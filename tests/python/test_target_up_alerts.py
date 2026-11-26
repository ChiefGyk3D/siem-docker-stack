"""Target-up alert rules (issue #203): severity and phone label taxonomy.

Critical infrastructure jobs page the phone (severity critical, phone=true).
Every other file_sd group is warning with no phone label, so a laptop that
sleeps never pages. A missing target file leaves no `up` series, so the
critical jobs also get an absent() rule.
"""
import copy
import re

import yaml

from conftest import REPO_ROOT

RULES = REPO_ROOT / "docker" / "prometheus" / "rules" / "target-up.yml"
PROM = REPO_ROOT / "docker" / "prometheus" / "prometheus.yml"

CRITICAL_JOBS = {"twingate-ztna", "unifi-controller", "node"}
WARNING_JOBS = {"Computers", "Cryptocurrency", "AI", "Security"}


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _rules(data):
    return [r for g in data["groups"] for r in g["rules"] if "alert" in r]


def _jobs(expr):
    """Job names an expression selects, from job="x" and job=~"a|b"."""
    jobs = set()
    for m in re.finditer(r'job\s*(=~|=)\s*"([^"]+)"', expr):
        jobs.update(m.group(2).split("|") if m.group(1) == "=~" else [m.group(2)])
    return jobs


def _violations(data):
    """Return taxonomy violations; an empty list means the rules conform."""
    bad = []
    rules = _rules(data)
    if not rules:
        return ["no alert rules collected"]
    for r in rules:
        labels = r.get("labels", {})
        jobs = _jobs(r["expr"])
        if not jobs:
            bad.append(f"{r['alert']}: no job matcher")
            continue
        critical = jobs <= CRITICAL_JOBS
        warning = jobs <= WARNING_JOBS
        if not (critical or warning):
            bad.append(f"{r['alert']}: mixes or names unknown jobs {jobs}")
        elif critical:
            if labels.get("severity") != "critical" or labels.get("phone") != "true":
                bad.append(f"{r['alert']}: critical job needs severity=critical, phone=true")
        else:
            if labels.get("severity") != "warning" or "phone" in labels:
                bad.append(f"{r['alert']}: warning job needs severity=warning and no phone label")
    return bad


def test_rule_file_parses_and_has_alerts():
    data = _load(RULES)
    assert _rules(data), "target-up.yml must define alerts"
    for r in _rules(data):
        assert r["expr"] and r["labels"]["severity"] in {"critical", "warning"}
        assert r["annotations"]["summary"]


def test_labels_follow_taxonomy():
    assert _violations(_load(RULES)) == []


def test_phone_true_only_on_critical_jobs():
    rules = _rules(_load(RULES))
    phone = [r for r in rules if r["labels"].get("phone") == "true"]
    assert phone, "critical jobs must page"
    for r in phone:
        assert _jobs(r["expr"]) <= CRITICAL_JOBS, r["alert"]
        assert r["labels"]["severity"] == "critical"
    for r in rules:
        if _jobs(r["expr"]) & WARNING_JOBS:
            assert "phone" not in r["labels"], r["alert"]


def test_every_group_covered_by_up_rule():
    up = set()
    for r in _rules(_load(RULES)):
        if "== 0" in r["expr"] and r["expr"].startswith("up{"):
            up |= _jobs(r["expr"])
    assert up == CRITICAL_JOBS | WARNING_JOBS


def test_covered_jobs_are_file_sd_jobs_in_prometheus_yml():
    sd = {j["job_name"] for j in _load(PROM)["scrape_configs"]
          if "file_sd_configs" in j}
    assert CRITICAL_JOBS | WARNING_JOBS <= sd


def test_up_rules_wait_five_minutes():
    for r in _rules(_load(RULES)):
        if r["expr"].startswith("up{"):
            assert r["for"] == "5m", r["alert"]


def test_each_critical_job_has_absent_rule():
    absent = set()
    for r in _rules(_load(RULES)):
        m = re.fullmatch(r'absent\(up\{job="([^"]+)"\}\)', r["expr"].strip())
        if m:
            absent.add(m.group(1))
            assert r["labels"]["phone"] == "true"
    assert absent == CRITICAL_JOBS


def test_guard_bites_on_bad_phone_labels():
    good = _load(RULES)
    # a laptop group that pages
    bad = copy.deepcopy(good)
    for r in _rules(bad):
        if _jobs(r["expr"]) & WARNING_JOBS:
            r["labels"]["phone"] = "true"
    assert _violations(bad)
    # a critical job that does not page
    bad2 = copy.deepcopy(good)
    for r in _rules(bad2):
        if _jobs(r["expr"]) <= CRITICAL_JOBS:
            r["labels"].pop("phone", None)
    assert _violations(bad2)
    assert _violations({"groups": []}) 
