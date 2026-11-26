"""Alert taxonomy guard (issue #71, epic #62). The label set and tier meaning
live in docs/alert-taxonomy.md; this test keeps every provisioned Grafana rule
(and the example policy matchers) inside it.

Rules are read from docker/grafana/provisioning/alerting/*.yml and *.yml.example
(files without a `groups` key, such as policies and contact points, hold no rules).

KNOWN_VIOLATIONS lists rules that break the taxonomy today and whose fix would
change routing, so the owner decides (see the PR body for #71). They are strict
xfails: the test fails the day one is fixed, which forces the entry to be removed.
"""
import yaml

import pytest

from conftest import REPO_ROOT

ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
FILES = sorted(list(ALERTING.glob("*.yml")) + list(ALERTING.glob("*.yml.example")))

SEVERITIES = {"critical", "warning", "info"}
TIERS = {"P1", "P2", "P3", "none"}
BOOL = {"true", "false"}
ALERT_GROUPS = {"updates", "heartbeat", "alert-path", "infrastructure"}
SOURCES = {"unifi", "pfsense", "twingate"}
# Every label a rule may carry. A label outside this set is a defect: nothing
# reads it, so it is either a typo or an unrecorded routing key.
ALLOWED_LABELS = {
    "severity", "tier", "phone", "digest", "alert_group", "source",
    "update_alert", "update_security", "heartbeat", "delivery_failure",
}
REQUIRED = ("severity", "tier", "phone", "alert_group")
# Labels a notification policy matcher may use, with their value sets.
POLICY_VALUES = {
    "severity": SEVERITIES, "tier": TIERS, "phone": BOOL, "digest": {"true"},
    "update_alert": {"true"}, "update_security": {"true"},
    "heartbeat": {"true"}, "delivery_failure": {"true"},
}

# uid -> reason. Empty: the two 24h update rules were fixed to P2, phone=false
# (owner decision 2026-11-20, issue #152). A future entry here is a strict xfail.
KNOWN_VIOLATIONS = {}


def check_labels(labels):
    """Return the list of taxonomy problems for one rule's labels."""
    problems = []
    if not isinstance(labels, dict):
        return ["labels is not a mapping"]
    for k, v in labels.items():
        if k not in ALLOWED_LABELS:
            problems.append(f"unknown label {k}")
        if not isinstance(v, str):
            problems.append(f"label {k} is not a quoted string")
    for k in REQUIRED:
        if k not in labels:
            problems.append(f"missing required label {k}")
    sev, tier, phone = labels.get("severity"), labels.get("tier"), labels.get("phone")
    if "severity" in labels and sev not in SEVERITIES:
        problems.append(f"severity {sev!r} not allowed")
    if "tier" in labels and tier not in TIERS:
        problems.append(f"tier {tier!r} not allowed")
    if "phone" in labels and phone not in BOOL:
        problems.append(f"phone {phone!r} not allowed")
    if "alert_group" in labels and labels["alert_group"] not in ALERT_GROUPS:
        problems.append(f"alert_group {labels['alert_group']!r} not allowed")
    if labels.get("alert_group") == "updates" and labels.get("source") not in SOURCES:
        problems.append("updates rule needs source in " + "/".join(sorted(SOURCES)))
    if "source" in labels and labels["source"] not in SOURCES:
        problems.append(f"source {labels['source']!r} not allowed")
    for k in ("update_alert", "update_security", "heartbeat", "delivery_failure", "digest"):
        if k in labels and labels[k] != "true":
            problems.append(f"{k} must be \"true\" or absent")
    if labels.get("alert_group") == "infrastructure" and ("update_alert" in labels or "update_security" in labels):
        problems.append("infrastructure rule must not carry update labels")
    if labels.get("alert_group") == "infrastructure" and phone == "true" and (tier, sev) != ("P1", "critical"):
        problems.append("infrastructure may page only as P1 critical")
    if "update_security" in labels and labels.get("update_alert") != "true":
        problems.append("update_security needs update_alert=true")
    if labels.get("alert_group") == "updates" and labels.get("update_alert") != "true":
        problems.append("updates rule needs update_alert=true")
    # Tier meaning.
    if labels.get("heartbeat") == "true":
        if (tier, sev, phone) != ("none", "info", "false") or "digest" in labels:
            problems.append("heartbeat must be tier none, severity info, phone false, no digest")
    elif tier == "none":
        problems.append("tier none is only for the heartbeat")
    elif tier == "P1" and (sev, phone) != ("critical", "true"):
        problems.append("P1 needs severity critical and phone true")
    elif tier == "P2" and sev != "warning":
        problems.append("P2 needs severity warning")
    elif tier == "P2" and phone != "false" and not (
            phone == "true" and labels.get("alert_group") == "updates" and labels.get("update_alert") == "true"):
        # Owner decision (#199, #200): a warning-level pending-update rule for critical infrastructure
        # pages the phone (84h repeats). No other P2 rule may.
        problems.append("P2 needs phone false (only an update-alerting warning may page)")
    elif tier == "P3" and (sev, phone) != ("info", "false"):
        problems.append("P3 needs severity info and phone false")
    if "digest" in labels and tier != "P3":
        problems.append("digest is only for P3")
    if tier == "P3" and labels.get("digest") != "true":
        problems.append("P3 needs digest=true")
    return problems


def _rules():
    out = []
    for path in FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "groups" not in data:
            continue
        for group in data["groups"]:
            for rule in group.get("rules", []):
                out.append((path.name, rule))
    return out


def _policy_matchers():
    out = []

    def walk(route, name):
        for m in route.get("object_matchers", []) or []:
            out.append((name, tuple(m)))
        for sub in route.get("routes", []) or []:
            walk(sub, name)

    for path in FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        for pol in data.get("policies", []) or []:
            walk(pol, path.name)
    return out


RULES = _rules()


def test_rule_files_found():
    names = {n for n, _ in RULES}
    assert len(RULES) >= 7, RULES
    assert {"update-alert-rules-pfsense.yml", "update-alert-rules-unifi.yml",
            "heartbeat-alert-rule.yml", "notification-failure-alert-rule.yml"} <= names


def _param(item):
    fname, rule = item
    marks = []
    if rule["uid"] in KNOWN_VIOLATIONS:
        marks.append(pytest.mark.xfail(strict=True, reason=KNOWN_VIOLATIONS[rule["uid"]]))
    return pytest.param(item, marks=marks, id=f"{fname}:{rule['uid']}")


@pytest.mark.parametrize("item", [_param(i) for i in RULES])
def test_rule_follows_taxonomy(item):
    fname, rule = item
    assert check_labels(rule.get("labels")) == [], f"{fname} {rule['uid']}"


@pytest.mark.parametrize("uid", ["update-unifi-pending-24h", "update-pfsense-pending-24h"])
def test_pending_24h_rules_are_p2_without_the_phone(uid):
    # Owner decision 2026-11-20 (issue #152): P2, no phone page.
    (labels,) = [r["labels"] for _, r in RULES if r["uid"] == uid]
    assert (labels["severity"], labels["tier"], labels["phone"]) == ("warning", "P2", "false")
    assert check_labels(labels) == []
    assert uid not in KNOWN_VIOLATIONS


def test_known_violations_are_real_rules():
    uids = {r["uid"] for _, r in RULES}
    assert set(KNOWN_VIOLATIONS) <= uids


def test_rule_uids_unique():
    uids = [r["uid"] for _, r in RULES]
    assert len(uids) == len(set(uids))


@pytest.mark.parametrize("name,matcher", _policy_matchers())
def test_policy_matcher_uses_taxonomy(name, matcher):
    label, op, value = matcher
    assert label in POLICY_VALUES, f"{name}: policy matches unknown label {label}"
    assert op == "="
    assert value in POLICY_VALUES[label], f"{name}: {label}={value} not allowed"


# Guards for the checker itself: synthetic labels, since no P3 rule exists yet.
GOOD = {
    "P1": {"severity": "critical", "tier": "P1", "phone": "true", "alert_group": "alert-path"},
    "P2": {"severity": "warning", "tier": "P2", "phone": "false", "alert_group": "alert-path"},
    "P3": {"severity": "info", "tier": "P3", "phone": "false", "digest": "true", "alert_group": "alert-path"},
    "HB": {"severity": "info", "tier": "none", "phone": "false", "alert_group": "heartbeat", "heartbeat": "true"},
}


@pytest.mark.parametrize("key", sorted(GOOD))
def test_checker_accepts_good(key):
    assert check_labels(GOOD[key]) == []


@pytest.mark.parametrize("key,change", [
    ("P1", {"severity": "warning"}),
    ("P1", {"phone": "false"}),
    ("P1", {"severity": "urgent"}),
    ("P1", {"tier": "P0"}),
    ("P1", {"owner": "me"}),
    ("P1", {"phone": True}),
    ("P1", {"digest": "true"}),
    ("P2", {"phone": "true"}),
    ("P2", {"phone": "true", "update_alert": "true"}),
    ("P2", {"phone": "true", "alert_group": "updates"}),
    ("P2", {"phone": "true", "alert_group": "updates", "update_alert": "true", "source": "other"}),
    ("P2", {"tier": "none"}),
    ("P3", {"digest": None}),
    ("P3", {"phone": "true"}),
    ("HB", {"phone": "true"}),
    ("HB", {"tier": "P2"}),
    ("P1", {"alert_group": "updates"}),
    ("P1", {"update_security": "true"}),
    ("P1", {"alert_group": "infrastructure", "update_alert": "true"}),
    ("P2", {"alert_group": "infrastructure", "phone": "true"}),
    ("P2", {"alert_group": "infrastructure", "phone": "true", "update_alert": "true", "source": "twingate"}),
    ("P1", {"alert_group": "infra"}),
])
def test_checker_rejects_bad(key, change):
    labels = dict(GOOD[key])
    for k, v in change.items():
        if v is None:
            labels.pop(k)
        else:
            labels[k] = v
    assert check_labels(labels) != []


def test_checker_allows_a_paging_update_warning():
    labels = dict(GOOD["P2"], phone="true", alert_group="updates", update_alert="true", source="twingate")
    assert check_labels(labels) == []


@pytest.mark.parametrize("missing", REQUIRED)
def test_checker_requires_label(missing):
    labels = dict(GOOD["P1"])
    del labels[missing]
    assert any("missing" in p for p in check_labels(labels))


def test_checker_accepts_infrastructure_p1_and_p2():
    assert check_labels(dict(GOOD["P1"], alert_group="infrastructure")) == []
    assert check_labels(dict(GOOD["P2"], alert_group="infrastructure")) == []
