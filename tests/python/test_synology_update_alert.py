"""Guards for the Synology DSM update alert (issue #257): the Telegraf SNMPv3 example, the
provisioned Grafana rules (shipped paused), the router allow-list and the owner doc.

Collection is loose (fixed file list that must exist); the assertions are strict, and negative
cases prove the secret guard and the exclusive-range check bite.
"""
import json
import re
import tomllib

import pytest
import yaml

from conftest import REPO_ROOT

CONF = REPO_ROOT / "docs" / "examples" / "synology-snmp-telegraf.conf.example"
RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-alert-rules-synology.yml"
DOC = REPO_ROOT / "docs" / "synology-update-alert.md"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
POLICY = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-notification-policy.yml.example"

OID_VERSION = ".1.3.6.1.4.1.6574.1.5.3.0"
OID_UPGRADE = ".1.3.6.1.4.1.6574.1.5.4.0"
SECRET_NAMES = ["SYNOLOGY_SNMP_AGENT", "SYNOLOGY_SNMP_USER", "SYNOLOGY_SNMP_AUTH_PASSWORD",
                "SYNOLOGY_SNMP_PRIV_PASSWORD", "SYNOLOGY_INFLUX_URL", "SYNOLOGY_INFLUX_USER",
                "SYNOLOGY_INFLUX_PASSWORD"]
SENSITIVE_KEY = re.compile(r"(password|passphrase|sec_name|username|secret|token|community)", re.I)
ENV_REF = re.compile(r"^\$\{[A-Z][A-Z0-9_]*\}$")


def _conf():
    return tomllib.loads(CONF.read_text(encoding="utf-8"))


def literal_secrets(node, path=""):
    """Return the paths of sensitive keys whose value is not a pure ${ENV_VAR} reference."""
    bad = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                bad += literal_secrets(v, f"{path}.{k}")
            elif SENSITIVE_KEY.search(k) and not (isinstance(v, str) and ENV_REF.match(v)):
                bad.append(f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            bad += literal_secrets(v, f"{path}[{i}]")
    return bad


def _rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    (group,) = data["groups"]
    return group, {r["uid"]: r for r in group["rules"]}


def _data(rule, ref):
    return next(d for d in rule["data"] if d["refId"] == ref)


# --- Telegraf example ------------------------------------------------------

def test_conf_parses_and_polls_snmpv3_authpriv_hourly():
    (snmp,) = _conf()["inputs"]["snmp"]
    assert snmp["version"] == 3 and snmp["sec_level"] == "authPriv"
    assert snmp["interval"] == "1h"
    assert snmp["agents"] == ["udp://${SYNOLOGY_SNMP_AGENT}:161"]
    assert snmp["auth_protocol"] and snmp["priv_protocol"]
    fields = {f["name"]: f["oid"] for f in snmp["field"]}
    assert fields == {"dsm_version": OID_VERSION, "upgrade_available": OID_UPGRADE}
    assert snmp["name"] == "synology_dsm"
    assert snmp["tags"]["nas"] == "nas-example"


def test_conf_has_no_literal_secret_only_environment_references():
    conf = _conf()
    assert literal_secrets(conf) == []
    text = CONF.read_text(encoding="utf-8")
    for name in SECRET_NAMES:
        assert "${" + name + "}" in text, name
    (out,) = conf["outputs"]["influxdb"]
    assert out["database"] == "telegraf" and out["namepass"] == ["synology_dsm"]
    assert out["urls"] == ["${SYNOLOGY_INFLUX_URL}"]


@pytest.mark.parametrize("bad", [
    {"inputs": {"snmp": [{"auth_password": "hunter2hunter2"}]}},
    {"inputs": {"snmp": [{"sec_name": "monitor"}]}},
    {"outputs": {"influxdb": [{"password": "x${A}"}]}},
    {"inputs": {"snmp": [{"community": "public"}]}},
])
def test_secret_guard_bites(bad):
    assert literal_secrets(bad) != []


def test_secret_guard_accepts_env_reference():
    assert literal_secrets({"a": [{"password": "${SYNOLOGY_INFLUX_PASSWORD}"}]}) == []


# --- Grafana rules ---------------------------------------------------------

def test_rules_are_the_four_expected_and_all_paused():
    group, rules = _rules()
    assert set(rules) == {"update-synology-pending-24h", "update-synology-pending-7d",
                          "update-synology-data-stale", "update-synology-check-failing"}
    assert group["folder"] == "Update Alerts"
    for uid, r in rules.items():
        assert r["isPaused"] is True, uid
        assert r["execErrState"] == "Alerting" and r["noDataState"] == "Alerting", uid
        assert r["labels"]["source"] == "synology" and r["labels"]["update_alert"] == "true", uid
        assert r["labels"]["alert_group"] == "updates", uid
        assert any(d["datasourceUid"] == "influxdb-twingate" for d in r["data"]), uid
        assert "synology_dsm" in json.dumps(r["data"]), uid


def test_severity_tier_and_phone_labels_follow_the_existing_update_pattern():
    _, rules = _rules()
    lab = {u: (r["labels"]["severity"], r["labels"]["tier"], r["labels"]["phone"]) for u, r in rules.items()}
    assert lab["update-synology-pending-24h"] == ("warning", "P2", "false")
    assert lab["update-synology-pending-7d"] == ("critical", "P1", "true")
    assert lab["update-synology-data-stale"] == ("warning", "P2", "false")
    assert lab["update-synology-check-failing"] == ("warning", "P2", "false")


def test_pending_rules_have_no_for_clock_and_share_one_bucket_query():
    _, rules = _rules()
    warn, crit = rules["update-synology-pending-24h"], rules["update-synology-pending-7d"]
    assert warn["for"] == crit["for"] == "0s"
    pw, pc = _data(warn, "P"), _data(crit, "P")
    assert pw["model"]["query"] == pc["model"]["query"]
    assert pw["relativeTimeRange"] == pc["relativeTimeRange"] == {"from": 604800, "to": 0}
    assert "GROUP BY time(1h)" in pw["model"]["query"] and '"upgrade_available" = 1' in pw["model"]["query"]


def bands(expr_w, expr_c):
    mw = re.fullmatch(r"\$B == 1 && \$Pc >= (\d+) && \$Pc < (\d+)", expr_w)
    mc = re.fullmatch(r"\$B == 1 && \$Pc >= (\d+)", expr_c)
    assert mw and mc, (expr_w, expr_c)
    return int(mw.group(1)), int(mw.group(2)), int(mc.group(1))


def check_exclusive(w_lo, w_hi, c_lo):
    assert (w_lo, w_hi, c_lo) == (24, 160, 160)
    for n in range(0, 208):
        w, c = w_lo <= n < w_hi, n >= c_lo
        assert not (w and c), f"overlap at {n}"
        expected = "none" if n < 24 else ("warning" if n < 160 else "critical")
        assert ("warning" if w else "critical" if c else "none") == expected, n


def test_warning_and_critical_are_exclusive_with_no_gap():
    _, rules = _rules()
    ew = _data(rules["update-synology-pending-24h"], "C")["model"]["expression"]
    ec = _data(rules["update-synology-pending-7d"], "C")["model"]["expression"]
    check_exclusive(*bands(ew, ec))


def test_exclusive_range_check_bites():
    with pytest.raises(AssertionError):
        check_exclusive(24, 170, 160)  # overlap
    with pytest.raises(AssertionError):
        check_exclusive(24, 150, 160)  # gap
    with pytest.raises(AssertionError):
        bands("$B > 0 && $Pc >= 24 && $Pc < 160", "$B == 1 && $Pc >= 160")


def test_check_failing_rule_fires_on_enum_3_or_4_only_and_persists():
    _, rules = _rules()
    r = rules["update-synology-check-failing"]
    expr = _data(r, "C")["model"]["expression"]
    assert expr == "$B == 3 || $B == 4"
    assert r["for"] == "6h"


def test_data_stale_rule_watches_the_three_hour_window_for_the_hourly_poll():
    _, rules = _rules()
    r = rules["update-synology-data-stale"]
    assert _data(r, "A")["relativeTimeRange"] == {"from": 10800, "to": 0}
    assert "now() - 3h" in _data(r, "A")["model"]["query"]
    assert _data(r, "C")["model"]["conditions"][0]["evaluator"] == {"type": "lt", "params": [1]}


def test_titles_are_on_the_router_allow_list_and_policy_repeats_match():
    _, rules = _rules()
    wf = json.loads(ROUTER.read_text(encoding="utf-8"))
    js = next(n["parameters"]["jsCode"] for n in wf["nodes"] if "ALLOWED_ALERTNAMES" in n["parameters"].get("jsCode", ""))
    listed = set(re.findall(r"'([^']*)'", re.search(r"const ALLOWED_ALERTNAMES = \[(.*?)\];", js, re.S).group(1)))
    assert {r["title"] for r in rules.values()} <= listed
    routes = yaml.safe_load(POLICY.read_text(encoding="utf-8"))["policies"][0]["routes"][0]["routes"]
    rep = {next(m for m in r["object_matchers"] if m[0] == "severity")[2]: r["repeat_interval"] for r in routes}
    assert rep == {"warning": "84h", "critical": "24h"}


# --- Doc -------------------------------------------------------------------

def test_doc_covers_scope_limits_secrets_and_the_live_check():
    text = DOC.read_text(encoding="utf-8")
    for name in SECRET_NAMES:
        assert name in text, name
    for needle in ["snmpget -v3", OID_UPGRADE, OID_VERSION, "update-alert-rules-synology.yml",
                   "nas-example", "paused", "screenshot", "Packages", "authPriv", "isPaused",
                   "Not verified", "udp://", "telegraf"]:
        assert needle in text, needle


def test_doc_never_puts_a_passphrase_on_a_command_line():
    text = DOC.read_text(encoding="utf-8")
    assert not re.search(r"\s-[AXaxu]\s+\S", text.replace("-v3", "")), "no -A/-X/-u option with a value"
    assert "SNMPCONFPATH" in text
