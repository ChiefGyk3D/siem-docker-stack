"""Guards for update alerting (issue #53): the n8n router (webhook auth, Pushover
nodes, payload builder), the Grafana alert provisioning files, and the pfSense
update metric script.

Node is REQUIRED: the Code node logic is executed for real, never string-matched.
"""
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from conftest import REPO_ROOT

ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
RULE_FILES = sorted(ALERTING.glob("*rules*.yml"))
SCRIPT = REPO_ROOT / "scripts" / "pfsense-update-metric.sh"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DOC = REPO_ROOT / "docs" / "update-alerting.md"
POLICY = ALERTING / "update-notification-policy.yml.example"
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"

DISCORD_FIRING = "Discord — Firing"
DISCORD_RESOLVED = "Discord — Resolved"
ORIGIN = "https://grafana.example.com"
GOOD_NAME = "UniFi update pending over 24h"
GOOD_FP = "abcdef0123456789"


PENDING_UNIFI = ("update-unifi-pending-24h", "update-unifi-pending-7d")


def _workflow():
    return json.loads(ROUTER.read_text(encoding="utf-8"))


def _nodes():
    return {n["name"]: n for n in _workflow()["nodes"]}


def _build_node():
    nodes = [n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.code"
             and "ALLOWED_ALERTNAMES" in n["parameters"]["jsCode"]]
    assert len(nodes) == 1, "expected exactly one Pushover payload builder Code node"
    return nodes[0]


def _http_nodes():
    """The Pushover HTTP nodes (the heartbeat ping node is covered by test_heartbeat.py)."""
    return [n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"
            and "api.pushover.net" in str(n["parameters"].get("url", ""))]


def _node_bin():
    node = shutil.which("node")
    assert node, "node is required for these tests (it must not be skipped or faked)"
    return node


def _run_build(body, origin=None, enabled=None):
    """Run the real Code node source under node; return its first output item."""
    js = _build_node()["parameters"]["jsCode"]
    if origin is not None:
        js, n = re.subn(r"(?m)^const ALLOWED_DASHBOARD_ORIGIN = '[^']*';",
                        "const ALLOWED_DASHBOARD_ORIGIN = " + json.dumps(origin) + ";", js)
        assert n == 1
    if enabled is not None:
        js, n = re.subn(r"(?m)^const PUSHOVER_ENABLED = (true|false);",
                        f"const PUSHOVER_ENABLED = {'true' if enabled else 'false'};", js)
        assert n == 1
    harness = (
        "const f=new Function('$input','$'," + json.dumps(js) + ");\n"
        "const b=" + json.dumps(body) + ";\n"
        "const r=f({first:()=>({json:{body:b}})},(n)=>({first:()=>({json:{body:b}}),isExecuted:true}));\n"
        "console.log(JSON.stringify(r[0].json));"
    )
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _alert(status, labels=None, name=GOOD_NAME, fp=GOOD_FP, **extra):
    a = {"labels": dict({"alertname": name}, **(labels or {})),
         "annotations": {"summary": "s"}, "fingerprint": fp}
    a.update(extra)
    return {"status": status, "alerts": [a]}


# --- n8n router: structure -------------------------------------------------

def test_router_discord_nodes_still_present_and_connected():
    nodes = _nodes()
    for name in (DISCORD_FIRING, DISCORD_RESOLVED):
        assert nodes[name]["type"] == "n8n-nodes-base.discord"
    outs = _workflow()["connections"]["Alert Status"]["main"]
    assert any(c["node"] == DISCORD_FIRING for c in outs[0])
    assert any(c["node"] == DISCORD_RESOLVED for c in outs[1])


def _edges(wf):
    edges = {}
    for src, conn in wf["connections"].items():
        for branch in conn["main"]:
            for c in branch:
                edges.setdefault(src, set()).add(c["node"])
    return edges


def _reachable(start, edges, blocked=()):
    seen, todo = set(), [start]
    while todo:
        n = todo.pop()
        if n in seen or n in blocked:
            continue
        seen.add(n)
        todo.extend(edges.get(n, ()))
    return seen


def test_every_node_is_reachable_only_through_the_authenticated_webhook():
    wf = _workflow()
    names = {n["name"] for n in wf["nodes"]}
    hooks = [n["name"] for n in wf["nodes"] if n["type"] == "n8n-nodes-base.webhook"]
    assert hooks == ["Grafana Webhook", "Expiry Watch Webhook"], "two entry points: Grafana's and the expiry watch's"
    edges = _edges(wf)
    has_incoming = {t for ts in edges.values() for t in ts}
    assert names - has_incoming == set(hooks), "a node other than the webhooks is an entry point"
    assert set().union(*(_reachable(h, edges) for h in hooks)) == names, "unreachable node in the graph"
    # nothing at all is reachable if the webhooks are cut
    assert _reachable(hooks[0], edges, blocked=set(hooks)) == set()
    # the Pushover HTTP nodes need the enable gate and the payload builder, from either entry
    http = {n["name"] for n in _http_nodes()}
    assert http
    for hook in hooks:
        assert not (http & _reachable(hook, edges, blocked={"Pushover Enabled?"}))
        assert not (http & _reachable(hook, edges, blocked={_build_node()["name"]}))


def test_webhook_requires_header_auth_with_credential_reference():
    hook = next(n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.webhook")
    assert hook["parameters"]["authentication"] == "headerAuth"
    cred = hook["credentials"]["httpHeaderAuth"]
    assert set(cred) == {"id", "name"} and cred["name"] == "grafana-webhook-auth"
    assert not re.search(r"[A-Za-z0-9+/_-]{32,}", json.dumps(hook["credentials"]))


def test_pushover_secrets_come_from_a_credential_not_env_or_node_output():
    text = ROUTER.read_text(encoding="utf-8")
    # the only env access is the heartbeat sink setting, read in its own Code node (test_heartbeat.py)
    assert set(re.findall(r"\$env\.(\w+)", text)) <= {"HEARTBEAT_PING_URL", "HEARTBEAT_KIND", "EXPIRY_WATCH_ROUTER_SECRET"}
    assert "$env" not in _build_node()["parameters"]["jsCode"], "the Pushover builder reads no env"
    assert "PUSHOVER_APP_TOKEN" not in text and "PUSHOVER_USER_KEY" not in text
    code = _build_node()["parameters"]["jsCode"]
    assert not re.search(r"\btoken\b|\buser\b", code), "Code node must not handle the Pushover secrets"
    http = _http_nodes()
    assert len(http) == 2
    for n in http:
        assert "api.pushover.net" in n["parameters"]["url"]
        assert n["parameters"]["authentication"] == "genericCredentialType"
        assert n["parameters"]["genericAuthType"] == "httpCustomAuth"
        cred = n["credentials"]["httpCustomAuth"]
        assert set(cred) == {"id", "name"} and cred["name"] == "pushover-api"
        assert not re.search(r"[A-Za-z0-9+/_-]{32,}", json.dumps(n["credentials"]))


def test_workflow_does_not_persist_successful_executions():
    s = _workflow()["settings"]
    assert s["saveDataSuccessExecution"] == "none"
    assert s["saveManualExecutions"] is False
    assert s["saveExecutionProgress"] is False


def test_workflow_does_not_persist_failed_executions():
    # a failed execution keeps the first node's output, which includes the request
    # headers (the Authorization header carries the webhook credential)
    assert _workflow()["settings"]["saveDataErrorExecution"] == "none"
    text = " ".join(DOC.read_text(encoding="utf-8").lower().split())
    assert "failed executions are deliberately not stored" in text
    assert "rotate" in text and "n8n log" in text


def test_cancel_only_for_namespaced_tags():
    nodes = _nodes()
    cond = json.dumps(nodes["Pushover Cancel?"]["parameters"])
    assert "upd-" in cond
    assert "cancel_by_tag" in nodes["Pushover Cancel Repeats"]["parameters"]["url"]
    wf = _workflow()
    assert _edges(wf)["Pushover Cancel?"] == {"Pushover Cancel Repeats", "Pushover Notify"}


# --- n8n router: Code node behavior (real execution) ------------------------

def test_default_is_disabled():
    out = _run_build(_alert("firing", {"severity": "warning"}))
    assert out["enabled"] is False
    # enabled alone is not enough: the alert must also carry phone=true
    assert _run_build(_alert("firing", {"severity": "warning", "phone": "true"}), enabled=True)["enabled"] is True


def test_priority_mapping():
    crit = _run_build(_alert("firing", {"severity": "critical"}))["pushover"]
    sec = _run_build(_alert("firing", {"severity": "warning", "update_security": "true"}))["pushover"]
    warn = _run_build(_alert("firing", {"severity": "warning"}))["pushover"]
    res = _run_build(_alert("resolved", {"severity": "critical"}))["pushover"]
    assert crit["priority"] == 2 and crit["retry"] == 300 and crit["expire"] == 10800
    assert sec["priority"] == 2
    assert warn["priority"] == 1 and "retry" not in warn and "expire" not in warn
    assert res["priority"] == 0 and "retry" not in res
    assert len(crit["title"]) <= 250 and len(crit["message"]) <= 1024
    for k in ("token", "user"):
        assert k not in crit


def test_unknown_alertname_cannot_get_emergency_priority_or_cancel():
    fake = _run_build(_alert("firing", {"severity": "critical", "update_security": "true"},
                             name="fake", fp="victim1"))
    assert fake["pushover"]["priority"] == 1
    assert "tags" not in fake["pushover"] and "retry" not in fake["pushover"]
    res = _run_build(_alert("resolved", {}, name="fake", fp="abcd"))
    assert res["cancelTag"] == ""


def test_tags_are_namespaced_hashes_and_cancel_matches():
    expected = "upd-" + hashlib.sha256(f"{GOOD_NAME}|{GOOD_FP}".encode()).hexdigest()[:32]
    fire = _run_build(_alert("firing", {"severity": "critical"}))
    assert fire["pushover"]["tags"] == expected
    res = _run_build(_alert("resolved", {"severity": "critical"}))
    assert res["cancelTag"] == expected
    assert fire["cancelTag"] == ""
    # an invalid fingerprint yields no tag and no cancel
    bad = _run_build(_alert("firing", {"severity": "critical"}, fp="../../x"))
    assert "tags" not in bad["pushover"]
    assert _run_build(_alert("resolved", {}, fp="../../x"))["cancelTag"] == ""


def test_pure_js_sha256_matches_node_crypto():
    js = _build_node()["parameters"]["jsCode"]
    m = re.search(r"function sha256hex\(.*?\n\}\n", js, re.S)
    assert m, "sha256hex helper missing"
    helper = m.group(0)
    harness = (helper + "\nconst crypto=require('crypto');const bad=[];"
               "for (const s of ['', 'abc', 'a|b', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'x'.repeat(200)])"
               "{ if (sha256hex(s) !== crypto.createHash('sha256').update(s).digest('hex')) bad.push(s.length); }"
               "console.log(JSON.stringify(bad));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == []


def test_code_node_does_not_need_node_builtins():
    code = _build_node()["parameters"]["jsCode"]
    assert "require(" not in code


@pytest.mark.parametrize("body", [
    {"status": "firing", "alerts": "nope"},
    {"status": "firing", "alerts": {"0": {}}},
    {"status": "firing", "alerts": [None]},
    {"status": "firing", "alerts": []},
    {"status": "firing", "alerts": [{"labels": "x"}]},
    {"status": "firing", "alerts": [{"labels": [], "annotations": 5}]},
    {"status": "firing", "alerts": [{"labels": {"alertname": {"toString": "x"}}}]},
    {"status": "weird", "alerts": [{}]},
    {"status": ["firing"], "alerts": [{}]},
    "just a string",
    None,
    {"status": "firing", "alerts": [{"labels": {"alertname": 5, "severity": {"a": 1}},
                                      "annotations": {"summary": {"x": 1}, "description": 7},
                                      "fingerprint": {"a": 1}, "dashboardURL": 12}]},
])
def test_malformed_bodies_never_throw_and_never_page_at_emergency(body):
    out = _run_build(body, enabled=True)
    first = body["alerts"][0] if isinstance(body, dict) and isinstance(body.get("alerts"), list) \
        and body["alerts"] else None
    structurally_ok = (isinstance(body, dict) and body.get("status") in ("firing", "resolved")
                       and isinstance(first, dict) and isinstance(first.get("labels", {}), dict)
                       and isinstance(first.get("annotations", {}), dict))
    # a structurally broken body is a pipeline fault and always pushes; a parseable one
    # follows the phone label gate (these carry none)
    assert out["enabled"] is (not structurally_ok)
    assert out["pushover"]["priority"] in (0, 1)
    assert out["cancelTag"] == ""
    assert isinstance(out["pushover"]["title"], str) and isinstance(out["pushover"]["message"], str)


def test_malformed_structure_yields_generic_priority_one_alert():
    out = _run_build({"status": "firing", "alerts": "nope"})
    assert out["pushover"]["priority"] == 1
    assert "malformed" in out["pushover"]["message"].lower()


def test_dashboard_origin_constant_defaults_empty():
    js = _build_node()["parameters"]["jsCode"]
    assert re.search(r"(?m)^const ALLOWED_DASHBOARD_ORIGIN = '';", js)
    assert re.search(r"(?m)^const PUSHOVER_ENABLED = false;", js)
    assert "ALLOWED_DASHBOARD_ORIGIN" in DOC.read_text(encoding="utf-8")


@pytest.mark.parametrize("url,origin,kept", [
    (ORIGIN + "/d/abc?orgId=1", ORIGIN, True),
    (ORIGIN + "/d/abc", ORIGIN + "/", True),              # configured origin is canonicalized
    (ORIGIN + "/d/abc", "", False),                       # default: always dropped
    ("http://grafana.example.com/d/abc", ORIGIN, False),
    ("javascript:alert(1)", ORIGIN, False),
    ("https://evil.example.net/d/abc", ORIGIN, False),
    ("https://grafana.example.com.evil.example.net/", ORIGIN, False),
    ("https://grafana.example.com@evil.example.net/", ORIGIN, False),
    ("https://user:pw@grafana.example.com/d/abc", ORIGIN, False),
    ("https://grafana.example.com\\@evil.example.net/d/a", ORIGIN, False),
    ("https://grafana.example.com/d/a\nb", ORIGIN, False),
    ("https://grafana.example.com/d/a\x00b", ORIGIN, False),
    (ORIGIN + "/d/" + "a" * 600, ORIGIN, False),          # over-long
    ("not a url", ORIGIN, False),
])
def test_dashboard_url_allowlist(url, origin, kept):
    out = _run_build(_alert("firing", {"severity": "warning"}, dashboardURL=url), origin=origin)
    sent = out["pushover"].get("url")
    if kept:
        assert sent == ORIGIN + (url[len(ORIGIN):])
    else:
        assert sent is None


def test_dashboard_url_returns_normalized_href():
    out = _run_build(_alert("firing", {"severity": "warning"},
                            dashboardURL="HTTPS://GRAFANA.example.com:443/d/a b"), origin=ORIGIN)
    assert out["pushover"]["url"] == "https://grafana.example.com/d/a%20b"


def test_public_alert_names_equal_provisioned_rule_titles():
    js = _build_node()["parameters"]["jsCode"]
    m = re.search(r"const ALLOWED_ALERTNAMES = \[(.*?)\];", js, re.S)
    assert m
    listed = re.findall(r"'([^']*)'", m.group(1))
    provisioned = {r["title"] for _, _, r in _rules() if r["labels"].get("update_alert") == "true"}
    assert len(listed) == len(set(listed))
    assert set(listed) == provisioned and len(provisioned) >= 6


# --- webhook secret handling -------------------------------------------------

def test_contact_point_sends_secret_from_environment_only():
    path = ALERTING / "contact-points.yml"
    settings = yaml.safe_load(path.read_text(encoding="utf-8"))["contactPoints"][0]["receivers"][0]["settings"]
    assert settings["authorization_scheme"] == "Bearer"
    assert settings["authorization_credentials"] == "$GRAFANA_WEBHOOK_SECRET"
    assert not re.search(r"[A-Za-z0-9+/_-]{32,}", path.read_text(encoding="utf-8"))
    assert settings["url"].endswith("/webhook/grafana-alerts")


def test_webhook_secret_is_required_non_empty_in_compose():
    assert re.search(r"^# GRAFANA_WEBHOOK_SECRET=\s*$", ENV_EXAMPLE.read_text(encoding="utf-8"), re.M)
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    env = compose["services"]["grafana"]["environment"]
    entry = [e for e in env if e.startswith("GRAFANA_WEBHOOK_SECRET")]
    assert len(entry) == 1
    assert entry[0].startswith("GRAFANA_WEBHOOK_SECRET=${GRAFANA_WEBHOOK_SECRET:?"), \
        "must fail closed on an unset or empty value"
    assert ":-" not in entry[0]
    ci_env = (REPO_ROOT / "tests" / "compose.ci.env").read_text(encoding="utf-8")
    assert re.search(r"^GRAFANA_WEBHOOK_SECRET=\S+", ci_env, re.M)


def test_env_example_has_no_pushover_secret_names():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "PUSHOVER_APP_TOKEN" not in text and "PUSHOVER_USER_KEY" not in text


# --- Grafana provisioning --------------------------------------------------

def _rules():
    assert RULE_FILES, "no alert rule provisioning files"
    out = []
    for path in RULE_FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["apiVersion"] == 1
        for group in data["groups"]:
            for rule in group["rules"]:
                out.append((path.name, group, rule))
    return out


def test_rule_schema():
    rules = _rules()
    assert len(rules) >= 6
    uids = [r["uid"] for _, _, r in rules]
    assert len(uids) == len(set(uids))
    for fname, _group, rule in rules:
        assert rule["uid"] and rule["title"], fname
        refs = {d["refId"] for d in rule["data"]}
        assert rule["condition"] in refs, rule["title"]
        assert rule["labels"]["severity"] in {"warning", "critical"}, rule["title"]
        assert rule["labels"]["update_alert"] == "true", rule["title"]
        assert rule["for"], rule["title"]
        if rule["uid"] in PENDING_UNIFI:
            # no data legitimately means no pending update; a failing query must alert
            assert rule["noDataState"] == "OK", rule["title"]
            assert rule["execErrState"] == "Alerting", rule["title"]
        else:
            # pfSense detector: missing data or a failed query must not look healthy
            assert rule["noDataState"] == "Alerting", rule["title"]
            assert rule["execErrState"] == "Alerting", rule["title"]


def test_unifi_rules_escalate_24h_then_7d():
    by = {r["uid"]: r for _, _, r in _rules()}
    warn, crit = by["update-unifi-pending-24h"], by["update-unifi-pending-7d"]
    # both clocks live in the condition (bucket counts), so a data gap cannot restart a `for` clock
    assert warn["for"] == "0s" and warn["labels"]["severity"] == "warning"
    assert crit["for"] == "0s" and crit["labels"]["severity"] == "critical"
    assert not warn.get("isPaused") and not crit.get("isPaused")
    assert "upgradeable" in json.dumps(warn["data"])
    assert any(d["datasourceUid"] == "influxdb-unifi" for d in warn["data"])


def _unifi_pair():
    by = {r["uid"]: r for _, _, r in _rules()}
    return by["update-unifi-pending-24h"], by["update-unifi-pending-7d"]


def _data(rule, ref):
    return next(d for d in rule["data"] if d["refId"] == ref)


def test_unifi_warning_is_bounded_by_the_critical_rule_with_no_overlap_or_gap():
    warn, crit = _unifi_pair()
    # both rules measure the same thing: hourly buckets that held a pending point in the last 7 days
    pw, pc = _data(warn, "P"), _data(crit, "P")
    assert pw["model"]["query"] == pc["model"]["query"]
    assert pw["relativeTimeRange"] == pc["relativeTimeRange"] == {"from": 604800, "to": 0}
    assert "GROUP BY time(1h)" in pw["model"]["query"] and '"upgradeable" = true' in pw["model"]["query"]
    full = 604800 // 3600  # buckets in a week that is pending the whole time
    expr_w = _data(warn, "C")["model"]["expression"]
    expr_c = _data(crit, "C")["model"]["expression"]
    mw = re.fullmatch(r"\$B > 0 && \$Pc >= (\d+) && \$Pc < (\d+)", expr_w)
    mc = re.fullmatch(r"\$B > 0 && \$Pc >= (\d+)", expr_c)
    assert mw and mc, (expr_w, expr_c)
    w_lo, w_hi, c_lo = int(mw.group(1)), int(mw.group(2)), int(mc.group(1))
    assert (w_lo, w_hi, c_lo) == (24, 160, 160), "24h to the tolerance bound, then critical"
    assert w_hi == c_lo, "upper bound of warning must equal lower bound of critical"
    assert full - c_lo == 8, "tolerance is about 8 hours of missing data per week"
    # every bucket count from 0 to 207: nothing below 24, warning 24..159, critical 160+, never both
    for n in range(0, 208):
        w = w_lo <= n < w_hi
        c = n >= c_lo
        assert not (w and c), f"overlap at {n} buckets"
        expected = "none" if n < 24 else ("warning" if n < 160 else "critical")
        got = "warning" if w else ("critical" if c else "none")
        assert got == expected, f"{n} buckets: {got}, expected {expected}"
    for rule in (warn, crit):
        assert _data(rule, "Pc")["model"]["reducer"] == "count"
        assert rule["condition"] == "C"
        assert rule["noDataState"] == "OK" and rule["execErrState"] == "Alerting"


def test_pfsense_rules_ship_active_and_use_metric():
    pf = [r for _, _, r in _rules() if r["uid"].startswith("update-pfsense")]
    assert len(pf) >= 4
    for r in pf:
        assert r["isPaused"] is False, r["uid"]
        assert "pfsense_update" in json.dumps(r["data"])
    assert any(r["labels"].get("update_security") == "true"
               and r["labels"]["severity"] == "critical" for r in pf)
    text = "\n".join(p.read_text(encoding="utf-8") for p in RULE_FILES)
    assert "Telegraf" in text, "comment explaining when pfSense rules are enabled"


def test_pfsense_collector_health_rule():
    by = {r["uid"]: r for _, _, r in _rules()}
    r = by["update-pfsense-check-failing"]
    assert r["title"] == "pfSense update check failing or stale"
    assert "pfsense_update_check_success" in json.dumps(r["data"])
    assert "36h" in json.dumps(r["data"]) or 129600 in [d["relativeTimeRange"]["from"] for d in r["data"]
                                                         if "relativeTimeRange" in d]
    assert r["isPaused"] is False and r["noDataState"] == "Alerting"
    cond = json.dumps([d["model"] for d in r["data"] if d["refId"] == "C"])
    assert '"lt"' in cond


def test_rules_have_no_manual_dismiss_logic():
    text = "\n".join(p.read_text(encoding="utf-8") for p in RULE_FILES).lower()
    for word in ("silence", "dismiss", "acknowledge"):
        assert word not in text, word


def test_notification_policy_repeats():
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    root = data["policies"][0]
    routes = root["routes"][0]["routes"]
    rep = {next(m for m in r["object_matchers"] if m[0] == "severity")[2]: r["repeat_interval"]
           for r in routes}
    # owner decisions: warning twice a week (#199), critical a fresh page daily (#53)
    assert rep == {"warning": "84h", "critical": "24h"}
    # no update route may repeat less often than 84h
    for sev, val in rep.items():
        assert val.endswith("h") and int(val[:-1]) <= 84, sev


def test_pending_update_rules_all_push_to_the_phone():
    # #199: every pending rule pages, except the two 24h warnings. UniFi: owner decision
    # 2026-11-26 ("wait 7 days first"), auto-patching devices usually finish first.
    # pfSense 24h: P2 by owner decision 2026-11-20 (#152, already on master). The 7d
    # critical and the pfSense security rule page.
    pending = [r for _, _, r in _rules() if r["labels"]["alert_group"] == "updates"
               and "poller" not in r["uid"]]
    assert len(pending) >= 6
    for r in pending:
        # the operator-managed Twingate rule auto-updates and never pages (#200)
        want = "false" if r["uid"] in {"update-unifi-pending-24h", "update-pfsense-pending-24h",
                                       "update-twingate-operator-behind",
                                       "update-twingate-unexpected-connector",
                                       # #257: the two Synology health rules are quiet (Discord and Matrix only)
                                       "update-synology-data-stale", "update-synology-check-failing"} else "true"
        assert r["labels"]["phone"] == want, r["uid"]
    uids = {r["uid"] for r in pending}
    assert {"update-unifi-pending-24h", "update-unifi-pending-7d"} <= uids
    assert any(u.startswith("update-pfsense") for u in uids)


def test_contact_point_is_webhook_to_router():
    data = yaml.safe_load((ALERTING / "contact-points.yml").read_text(encoding="utf-8"))
    cp = data["contactPoints"][0]["receivers"][0]
    assert cp["type"] == "webhook"


# --- pfSense metric script -------------------------------------------------

FAKE_UP = """#!/bin/sh
echo "pfSense-upgrade $*" >> "$REC"
if [ "$*" != "-c" ]; then echo "unexpected args: $*" >&2; exit 99; fi
cat <<'EOT'
{out}
EOT
exit {rc}
"""
FAKE_PKG = """#!/bin/sh
echo "pkg-static $*" >> "$REC"
if [ "$*" != "version -qRl <" ]; then echo "unexpected args: $*" >&2; exit 99; fi
cat <<'EOT'
{out}
EOT
exit {rc}
"""


def _fake_bin(tmp_path, upgrade_out, pkg_out, upgrade_rc=0, pkg_rc=0):
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    (d / "pfSense-upgrade").write_text(FAKE_UP.format(out=upgrade_out, rc=upgrade_rc), encoding="utf-8")
    (d / "pkg-static").write_text(FAKE_PKG.format(out=pkg_out, rc=pkg_rc), encoding="utf-8")
    for f in d.iterdir():
        f.chmod(0o755)
    return d


def _run(tmp_path, upgrade_out, pkg_out, **kw):
    d = _fake_bin(tmp_path, upgrade_out, pkg_out, **kw)
    rec = tmp_path / "calls.txt"
    env = {"PATH": f"{d}:/usr/bin:/bin", "REC": str(rec)}
    r = subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True,
                       env=env, timeout=30, check=False, cwd=str(tmp_path))
    calls = rec.read_text(encoding="utf-8").splitlines() if rec.exists() else []
    return r, calls


def _metrics(out):
    res = {}
    for line in out.strip().splitlines():
        if line == "pfsense_update_check_success value=1i":
            res["ok"] = 1
            continue
        m = re.match(r"pfsense_update_pending,kind=(\w+),security=(\w+) value=(\d)i$", line)
        assert m, line
        res[(m.group(1), m.group(2))] = int(m.group(3))
    return res


def test_script_syntax_and_shellcheck():
    assert subprocess.run(["sh", "-n", str(SCRIPT)], timeout=30).returncode == 0
    sc = shutil.which("shellcheck")
    if sc:
        assert subprocess.run([sc, "-s", "sh", str(SCRIPT)], timeout=60).returncode == 0


def test_script_is_read_only_by_denylist():
    # A denylist is a weak guard; the exact-argv tests below are the real check.
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for bad in ("pkg-static upgrade", "pkg-static install", "pfSense-upgrade -y",
                "pfSense-upgrade -d", "curl", "wget", "rm ", "reboot"):
        assert bad not in code, bad
    assert text.startswith("#!/bin/sh")


def test_up_to_date_and_exact_argv(tmp_path):
    r, calls = _run(tmp_path, "Your system is up to date", "")
    assert r.returncode == 0
    m = _metrics(r.stdout)
    assert m.pop("ok") == 1
    assert len(m) == 6 and sum(m.values()) == 0
    assert calls == ["pfSense-upgrade -c", "pkg-static version -qRl <"]


def test_core_update_pending(tmp_path):
    r, _ = _run(tmp_path, "Version 99.9 is available\n", "pfSense-99.9   <\n")
    m = _metrics(r.stdout)
    assert m[("core", "false")] == 1 and m[("core", "true")] == 0
    assert m[("kernel", "false")] == 0 and m[("package", "false")] == 0


def test_kernel_and_package_pending(tmp_path):
    r, _ = _run(tmp_path, "Your system is up to date",
                "pfSense-kernel-pfSense-99.9   <\npfSense-pkg-Telegraf-1.2   <\n")
    m = _metrics(r.stdout)
    assert m[("kernel", "false")] == 1 and m[("package", "false")] == 1
    assert m[("core", "false")] == 0


def test_security_flag(tmp_path):
    r, _ = _run(tmp_path, "Version 99.9 is available (security update)\n", "pfSense-99.9 <\n")
    m = _metrics(r.stdout)
    assert m[("core", "true")] == 1 and m[("core", "false")] == 0


def _assert_failure(r):
    assert r.returncode != 0
    assert r.stdout.strip() == "pfsense_update_check_success value=0i"
    assert "pfsense_update_pending" not in r.stdout


def test_upgrade_check_failure_is_a_failure_not_healthy(tmp_path):
    r, _ = _run(tmp_path, "unable to reach update server", "", upgrade_rc=1)
    _assert_failure(r)


REAL_PENDING = (">>> Updating repositories metadata...done.\n"
                "26.07.2 version of pfSense is available")


def test_real_exit_2_pending_output_is_core_pending(tmp_path):
    # Captured from a live firewall on 2026-11-26 (issue #206).
    r, _ = _run(tmp_path, REAL_PENDING, "", upgrade_rc=2)
    assert r.returncode == 0
    m = _metrics(r.stdout)
    assert m.pop("ok") == 1
    assert m[("core", "false")] == 1 and m[("core", "true")] == 0
    assert m[("kernel", "false")] == 0 and m[("package", "false")] == 0


def test_exit_2_security_line_sets_security_true(tmp_path):
    r, _ = _run(tmp_path, REAL_PENDING + " (security update)", "", upgrade_rc=2)
    m = _metrics(r.stdout)
    assert m[("core", "true")] == 1 and m[("core", "false")] == 0


@pytest.mark.parametrize("out,rc", [
    (REAL_PENDING, 1),
    (REAL_PENDING, 3),
    (REAL_PENDING, 127),
    ("Your system is up to date", 2),
    (">>> Updating repositories metadata...done.", 2),
    ("", 2),
    (">>> Updating repositories metadata...done.\nsomething odd happened\n26.07.2 version of pfSense is available", 2),
    (">>> Updating repositories metadata...failed.\n26.07.2 version of pfSense is available", 2),
    (">>> Fetching metadata\n26.07.2 version of pfSense is available", 2),
    (">>> Updating repositories metadata...done.\nWarning: mirror slow\n26.07.2 version of pfSense is available", 2),
    ("Your system is up to date\n26.07.2 version of pfSense is available", 2),
    ("Your system is up to date\n26.07.2 version of pfSense is available", 0),
    ("Error: repository unreachable\n26.07.2 version of pfSense is available", 2),
    ("", 0),
    (">>> Updating repositories metadata...done.", 0),
])
def test_exit_2_and_progress_changes_stay_fail_closed(tmp_path, out, rc):
    r, _ = _run(tmp_path, out, "", upgrade_rc=rc)
    _assert_failure(r)


def test_pkg_static_failure_is_a_failure_not_healthy(tmp_path):
    r, _ = _run(tmp_path, "Your system is up to date", "", pkg_rc=1)
    _assert_failure(r)


def test_missing_tools_is_a_failure(tmp_path):
    (tmp_path / "empty").mkdir()
    r = subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True, timeout=30,
                       env={"PATH": str(tmp_path / "empty")}, check=False)
    _assert_failure(r)


REAL_PKG = """nginx-1.30.6_16,3                  <
pfSense-26.07.1                    <
pfSense-base-26.07.1               <
pfSense-boot-26.07.1               <
pfSense-default-config-26.07.1     <
pfSense-kernel-pfSense-26.07.1     <
pfSense-pkg-Nexus-26.07.1_3        <
pfSense-pkg-System_Patches-2.3.6   <
pfSense-repoc-20261117.174617      <
pfSense-system-26.07.1             <
php85-8.5.12                       <
php85-bcmath-8.5.12                <
php85-pdo_sqlite-8.5.12            <
php85-pfSense-module-26.07.1       <
"""


def test_real_pkg_version_output_is_classified(tmp_path):
    # Captured from a live firewall on 2026-11-26 (issue #215): name-version,
    # padding, then "<".
    r, _ = _run(tmp_path, "Your system is up to date", REAL_PKG)
    assert r.returncode == 0
    m = _metrics(r.stdout)
    assert m.pop("ok") == 1
    assert m[("core", "false")] == 1 and m[("kernel", "false")] == 1
    assert m[("package", "false")] == 1 and m[("core", "true")] == 0


@pytest.mark.parametrize("line,kind", [
    ("nginx-1.30.6_16,3   <", "package"),
    ("php85-8.5.12   <", "package"),
    ("pfSense-pkg-Nexus-26.07.1_3   <", "package"),
    ("pfSense-26.07.1   <", "core"),
    ("pfSense-base-26.07.1   <", "core"),
    ("pfSense-boot-26.07.1   <", "core"),
    ("pfSense-default-config-26.07.1   <", "core"),
    ("pfSense-system-26.07.1   <", "core"),
    ("pfSense-repoc-20261117.174617   <", "core"),
    ("pfSense-rc-26.07.1   <", "core"),
    ("php85-pfSense-module-26.07.1   <", "core"),
    ("pfSense-kernel-pfSense-26.07.1   <", "kernel"),
    ("pfSense-kernel-pfSense-26.07.1\t<", "kernel"),
])
def test_pkg_classification(tmp_path, line, kind):
    r, _ = _run(tmp_path, "Your system is up to date", line + "\n")
    assert r.returncode == 0
    m = _metrics(r.stdout)
    got = {k for k in ("core", "kernel", "package") if m[(k, "false")] == 1}
    assert got == {kind}


@pytest.mark.parametrize("pkg_out", [
    "pfSense-99.9\n",                       # old bare shape: no "<"
    "pfSense-99.9   >\n",                   # wrong operator
    "pfSense-99.9   <   extra\n",           # extra field
    "pfSense-99.9   =\n",
    "pfSense-99.9   <<\n",
    "pfSense-99.9   <\r\n",                  # carriage return
    "pfSense-99.9   <\nnginx\n",            # second line has one field
    "pfSense-99.9   <\nx;touch y   <\n",    # newline injection of a metacharacter
    "pfSense-99.9   <\n$(touch y)   <\n",
    "pfSense;touch-1.0   <\n",
    "pfSense-1.0`id`   <\n",
    "pfSense-1.0|x   <\n",
    "pfSense-1.0$HOME   <\n",              # no spaces: only the $ guard can catch it
    "pfSense-$(id)-1.0   <\n",
    "pfSense-1.0;id   <\n",
    "pfSense-1.0`   <\n",                  # lone backtick, no spaces in name
    "-pfSense-1.0   <\n",                  # leading hyphen (option-like)
    "--version-1.0   <\n",
    "-n-1.0   <\n",
    "a-1" + "0" * 126 + "   <\n",           # 129 chars: over the cap
    "*   <\n",
    "pfSense-*   <\n",
    "nginx   <\n",                          # no hyphen-digit version
    "nginx-abc   <\n",
    "pfSense-99.9 <   <\n",
    "   <\n",
])
def test_pkg_malformed_lines_fail_closed(tmp_path, pkg_out):
    (tmp_path / "pfSense-99.9").write_text("x", encoding="utf-8")
    r, _ = _run(tmp_path, "Your system is up to date", pkg_out)
    _assert_failure(r)
    assert not (tmp_path / "y").exists()


def test_pkg_name_at_length_cap_passes(tmp_path):
    name = "pfSense-1" + "0" * (128 - len("pfSense-1"))
    assert len(name) == 128
    r, _ = _run(tmp_path, "Your system is up to date", name + "   <\n")
    assert r.returncode == 0
    assert _metrics(r.stdout)[("core", "false")] == 1


def test_docs_exist_and_cover_required_topics():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("grafana-webhook-auth", "pushover-api", "GRAFANA_WEBHOOK_SECRET",
                   "ALLOWED_DASHBOARD_ORIGIN", "ALLOWED_ALERTNAMES", "authenticated Grafana caller",
                   "openssl rand -base64 32", "Known limitations", "pre-deploy checklist",
                   "PUSHOVER_ENABLED", "Doppler"):
        assert needle in text, needle
    assert "—" not in text, "em dash in docs"
    # Doppler secret names (not environment variables): the app token is PUSHOVER_API_KEY
    assert "PUSHOVER_APP_TOKEN" not in text
    assert "PUSHOVER_API_KEY" in text and "PUSHOVER_USER_KEY" in text
    assert "project `homelab`, config `prd_network`" in text
    assert "siem-docker-stack`, config `dev`" not in text and "siem-docker-stack" not in text
    assert "N8N_BLOCK_ENV_ACCESS_IN_NODE" not in text
    assert "n8n rejects the call" not in text
    # every doppler command names the project and config, and sets values from stdin
    cmds = re.findall(r"`([^`]*\bdoppler [^`]*)`", text)
    assert cmds
    for cmd in cmds:
        assert "--project homelab" in cmd and "--config prd_network" in cmd, cmd
    sets = [c for c in cmds if "doppler secrets set" in c]
    assert sets
    for cmd in sets:
        # the value arrives on stdin; the name is the last positional before the flags
        assert re.match(r"^openssl rand -base64 32 \| doppler secrets set [A-Z_]+ --project", cmd), cmd
        assert cmd.endswith("> /dev/null"), cmd


def test_env_example_names_the_homelab_doppler_location():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "project homelab, config prd_network" in text
    assert "siem-docker-stack, config dev" not in text


# --- round 4: end-to-end routing, secret validation, unknown pfSense output ----

def _ctx_js(ctx):
    """JS preamble binding $ (node references), $prevNode and $env from a context dict.

    ctx["env"]: a dict of environment variables, or the string "blocked" to model n8n
    refusing env access (reading any key then throws)."""
    ctx = ctx or {}
    env = ctx.get("env", {})
    env_js = ("new Proxy({}, {get() { throw new Error('access to env vars denied'); }})"
              if env == "blocked" else json.dumps(env))
    return ("const $env=" + env_js + ";" +"const __o=" + json.dumps(ctx.get("outputs", {})) + ";"
            "const $=(n)=>({first:()=>({json:(__o[n]||[{}])[0]}),all:()=>(__o[n]||[]).map(j=>({json:j})),"
            "isExecuted:Object.prototype.hasOwnProperty.call(__o,n)});"
            "const $prevNode={name:" + json.dumps(ctx.get("prev", "")) + "};")


def _js_eval(code, item, ctx=None):
    """Run JS with `$json` bound to item; return its JSON value."""
    harness = (_ctx_js(ctx) + "const $json=" + json.dumps(item) + ";"
               "const f=new Function('$json','$','$prevNode'," + json.dumps("return (" + code + ");") + ");"
               "const v=f($json,$,$prevNode);console.log(JSON.stringify({v:v===undefined?null:v}));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, "expression errored (the node would fail in n8n): " + r.stderr[-300:]
    return json.loads(r.stdout)["v"]


def _expr(value):
    assert value.startswith("={{") and value.rstrip().endswith("}}"), value
    return value[3:].rstrip()[:-2]


def _run_code_node(node, item, ctx=None):
    harness = (_ctx_js(ctx) + "const $getWorkflowStaticData=(t)=>({});"  # fresh, empty workflow static data per run
               "const f=new Function('$input','$','$prevNode','$env','$getWorkflowStaticData',"
               + json.dumps(node["parameters"]["jsCode"]) + ");"
               "const r=f({first:()=>({json:" + json.dumps(item) + "})},$,$prevNode,$env,$getWorkflowStaticData);"
               "console.log(JSON.stringify(r.map(x=>x.json)));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, "Code node threw: " + r.stderr[-300:]
    return json.loads(r.stdout)


def _templates(text):
    """Yield the JS inside each {{ ... }} of an n8n expression string (balanced braces)."""
    i = 0
    while True:
        i = text.find("{{", i)
        if i < 0:
            return
        j, depth = i + 2, 0
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                if depth == 0 and text.startswith("}}", j):
                    break
                depth -= 1
            j += 1
        assert j < len(text), "unbalanced expression"
        yield text[i + 2:j].strip()
        i = j + 2


def _expressions(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _expressions(v)
    elif isinstance(value, list):
        for v in value:
            yield from _expressions(v)
    elif isinstance(value, str) and value.startswith("="):
        yield from _templates(value[1:])


def _eval_many(codes, item, ctx=None):
    """Evaluate many expressions in one node process; each result is {v} or {error}."""
    harness = (_ctx_js(ctx) + "const $json=" + json.dumps(item) + ";const out=[];"
               "for (const c of " + json.dumps(codes) + ") { try {"
               " const f=new Function('$json','$','$prevNode','return ('+c+');'); const v=f($json,$,$prevNode);"
               " out.push({v:v===undefined?null:v}); } catch(e) { out.push({error:String(e)}); } }"
               "console.log(JSON.stringify(out));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-300:]
    return json.loads(r.stdout)


def _run_graph(webhook_item, pushover_enabled=False, fail=(), wf=None, env=None, start=None):
    """Walk the real graph from the webhook, the way n8n runs it (first match for a
    switch, continue-on-error outputs, a failed node without one stops the run).

    fail: names of Discord or HTTP nodes that should fail when they run.
    Returns a dict: reached, notified (every Discord or HTTP node that ran), failed,
    response (the HTTP status the webhook answered, as a string), body (what it sent),
    run ("success" or "error": how the run ended, which is what the error workflow
    sees) and error (the Stop and Error message, or the failing node's name).
    start: the webhook node the call enters through (default: the first, the Grafana one).
    env: the environment variables the Code nodes see ($env), or "blocked".
    requests: one {node, url} per HTTP node that ran, with its URL expression evaluated.

    Verified live: the FIRST Respond to Webhook node reached decides the answer. A run
    that stops with an error before any Respond node ran answers 200 with an EMPTY
    body, so Grafana would treat it as delivered."""
    wf = wf or _workflow()
    nodes = {n["name"]: n for n in wf["nodes"]}
    hook = start or next(n["name"] for n in wf["nodes"] if n["type"] == "n8n-nodes-base.webhook")
    res = {"reached": [], "notified": set(), "failed": set(), "response": None, "body": None,
           "run": "success", "error": "", "requests": []}

    def stop(message):
        res["run"], res["error"] = "error", message
        if res["response"] is None:
            res["response"], res["body"] = "200", ""   # verified live: 200 with an empty body
        return res

    outputs = {}
    todo = [(hook, [webhook_item], "")]
    steps = 0
    while todo:
        steps += 1
        assert steps < 200, "routing loop"
        name, items, prev = todo.pop(0)
        node = nodes[name]
        res["reached"].append(name)
        t = node["type"]
        ctx = {"outputs": outputs, "prev": prev, "env": {} if env is None else env}
        conn = wf["connections"].get(name, {"main": []})["main"]
        outs = [[] for _ in range(max(len(conn), 1))]
        if t in ("n8n-nodes-base.discord", "n8n-nodes-base.httpRequest"):
            # evaluate every expression of the node: a throw here is a lost notification
            codes = list(_expressions(node["parameters"]))
            for code, r in zip(codes, _eval_many(codes, items[0], ctx)):
                assert "error" not in r, f"{name}: expression failed: {r['error']} in {code[:80]}"
            res["notified"].add(name)
            if t == "n8n-nodes-base.httpRequest":
                url = str(node["parameters"].get("url", ""))
                if url.startswith("={{") and len(codes) == 1:
                    url = _eval_many(codes, items[0], ctx)[0]["v"]
                res["requests"].append({"node": name, "url": url})
            if name in fail and t == "n8n-nodes-base.discord":
                # Verified live: the Discord node reports a failure as ONE item with an
                # `error` key (a string) on its NORMAL output. Its error output stays empty.
                res["failed"].add(name)
                outs[0] = [{"error": "boom"}]
            elif name in fail:
                res["failed"].add(name)
                mode = node.get("onError")
                err = [{"error": {"message": "boom"}}]
                if mode == "continueErrorOutput":
                    outs = [[], err]
                elif mode == "continueRegularOutput":
                    outs[0] = err
                else:
                    return stop(name)
            else:
                outs[0] = [{"ok": True}]
        elif t == "n8n-nodes-base.webhook":
            outs[0] = items
        elif t == "n8n-nodes-base.code":
            if pushover_enabled and "ALLOWED_ALERTNAMES" in node["parameters"]["jsCode"]:
                node = json.loads(json.dumps(node))
                node["parameters"]["jsCode"] = node["parameters"]["jsCode"].replace(
                    "const PUSHOVER_ENABLED = false;", "const PUSHOVER_ENABLED = true;")
            outs[0] = _run_code_node(node, items[0], ctx)
        elif t == "n8n-nodes-base.switch":
            rules = node["parameters"]["rules"]["values"]
            hit = len(rules)  # fallback output
            for i, rule in enumerate(rules):
                cond = rule["conditions"]["conditions"][0]
                if _js_eval(_expr(cond["leftValue"]), items[0], ctx) == cond["rightValue"]:
                    hit = i
                    break
            outs = [[] for _ in range(max(len(conn), hit + 1))]
            outs[hit] = items
        elif t == "n8n-nodes-base.if":
            cond = node["parameters"]["conditions"]["conditions"][0]
            ok = _js_eval(_expr(cond["leftValue"]), items[0], ctx) is True
            outs = [[], []]
            outs[0 if ok else 1] = items
        elif t == "n8n-nodes-base.stopAndError":
            msg = node["parameters"].get("errorMessage", "")
            codes = list(_expressions({"m": msg}))
            if codes:
                msg = str(_eval_many(codes, items[0], ctx)[0].get("v"))
            return stop(msg)
        elif t == "n8n-nodes-base.respondToWebhook":
            codes = list(_expressions(node["parameters"]))
            for code, r in zip(codes, _eval_many(codes, items[0], ctx)):
                assert "error" not in r, f"{name}: expression failed: {r['error']}"
            if res["response"] is None:  # the first Respond node reached answers
                res["response"] = str(node["parameters"].get("options", {}).get("responseCode", 200))
                res["body"] = node["parameters"].get("responseBody", "")
            outs[0] = items
        else:
            raise AssertionError("node type not modeled: " + t)
        if any(outs):
            outputs[name] = outs[0] if outs[0] else next(o for o in outs if o)
        for idx, produced in enumerate(outs):
            if produced and idx < len(conn):
                for c in conn[idx]:
                    todo.append((c["node"], produced, name))
    return res


def _simulate(webhook_item, pushover_enabled=False):
    res = _run_graph(webhook_item, pushover_enabled)
    assert res["run"] == "success" and res["response"] == "200", \
        f"a healthy run must answer 200, got {res['response']} ({res['error']})"
    return res["reached"], res["notified"]


def test_alert_status_switch_has_every_output_connected():
    wf = _workflow()
    switch = next(n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.switch")
    n_out = len(switch["parameters"]["rules"]["values"]) + 1  # plus the fallback output
    main = wf["connections"][switch["name"]]["main"]
    assert len(main) == n_out
    assert all(main[i] for i in range(n_out)), "a switch output is not connected"


VALID_ALERT = {"labels": {"alertname": GOOD_NAME, "severity": "warning"},
               "annotations": {"summary": "s"}, "fingerprint": GOOD_FP}
ROUTING_CASES = {
    "firing": ({"status": "firing", "alerts": [VALID_ALERT]}, DISCORD_FIRING),
    "resolved": ({"status": "resolved", "alerts": [VALID_ALERT]}, DISCORD_RESOLVED),
    "status absent": ({"alerts": [VALID_ALERT]}, "Discord — Malformed"),
    "status weird": ({"status": "weird", "alerts": [{}]}, "Discord — Malformed"),
    "status number": ({"status": 5, "alerts": [{}]}, "Discord — Malformed"),
    "status array": ({"status": ["firing"], "alerts": [{}]}, "Discord — Malformed"),
    "alerts not array": ({"status": "firing", "alerts": "x"}, "Discord — Malformed"),
    "alerts empty": ({"status": "firing", "alerts": []}, "Discord — Malformed"),
    "first alert null": ({"status": "firing", "alerts": [None]}, "Discord — Malformed"),
    "body is a string": ("just text", "Discord — Malformed"),
    "body is null": (None, "Discord — Malformed"),
}


@pytest.mark.parametrize("case", sorted(ROUTING_CASES))
def test_every_authenticated_body_ends_in_a_notification(case):
    body, expected = ROUTING_CASES[case]
    reached, notified = _simulate({"headers": {}, "body": body})
    assert notified, "silent drop"
    assert expected in notified
    assert _build_node()["name"] in reached, "Pushover builder not reached"
    if case not in ("firing", "resolved"):
        assert DISCORD_FIRING not in notified and DISCORD_RESOLVED not in notified


def test_missing_body_entirely_still_notifies():
    reached, notified = _simulate({"headers": {}})
    assert "Discord — Malformed" in notified


def test_malformed_discord_message_is_static():
    node = _nodes()["Discord — Malformed"]
    assert node["type"] == "n8n-nodes-base.discord"
    assert "{{" not in json.dumps(node["parameters"]), "no caller data in the malformed message"
    assert node["credentials"]["discordWebhookApi"]["name"] == "Discord Webhook Alerts"


# check-env.sh: the webhook secret

CHECK_ENV = REPO_ROOT / "scripts" / "check-env.sh"
VALID_SECRET = "Zx9-" + "k3Lm" * 10  # 44 characters, not a placeholder


def _env_body(secret_line):
    ci = (REPO_ROOT / "tests" / "compose.ci.env").read_text(encoding="utf-8").splitlines()
    names = [ln.split("=")[0] for ln in ci if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    lines = [f"{n}=Zx9-unique-{i}" for i, n in enumerate(dict.fromkeys(names))
             if n != "GRAFANA_WEBHOOK_SECRET"]
    if secret_line is not None:
        lines.append(secret_line)
    return "\n".join(lines) + "\n"


def _check_env(tmp_path, secret_line):
    env = tmp_path / ".env"
    env.write_text(_env_body(secret_line), encoding="utf-8")
    return subprocess.run(["bash", str(CHECK_ENV), str(env)], capture_output=True,
                          text=True, timeout=60, check=False)


@pytest.mark.parametrize("line", [
    None,                                              # unset
    "GRAFANA_WEBHOOK_SECRET=",                         # empty
    "GRAFANA_WEBHOOK_SECRET=   ",                      # whitespace only
    'GRAFANA_WEBHOOK_SECRET="   "',
    "GRAFANA_WEBHOOK_SECRET=changeme",                 # placeholder
    "GRAFANA_WEBHOOK_SECRET=changeme-" + "x" * 40,     # placeholder prefix, long
    "GRAFANA_WEBHOOK_SECRET=x",                        # one character
    "GRAFANA_WEBHOOK_SECRET=" + "a" * 31,              # one short of the minimum
    "GRAFANA_WEBHOOK_SECRET=" + " " * 20 + "ab" * 8,   # padding does not count
])
def test_check_env_rejects_bad_webhook_secrets(tmp_path, line):
    r = _check_env(tmp_path, line)
    assert r.returncode == 1, r.stderr
    assert "GRAFANA_WEBHOOK_SECRET" in r.stderr
    assert "changeme" not in r.stderr and "aaaa" not in r.stderr, "value must not be printed"


def test_check_env_accepts_a_valid_webhook_secret(tmp_path):
    for line in ("GRAFANA_WEBHOOK_SECRET=" + VALID_SECRET,
                 'GRAFANA_WEBHOOK_SECRET="' + VALID_SECRET + '"',
                 "GRAFANA_WEBHOOK_SECRET=" + "a" * 32):
        r = _check_env(tmp_path, line)
        assert r.returncode == 0, r.stderr


def test_docs_claim_only_what_is_enforced():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    row = next(ln for ln in readme.splitlines() if "`GRAFANA_WEBHOOK_SECRET`" in ln)
    assert "32 characters" in row and "check-env.sh" in row
    assert "32 random bytes" not in DOC.read_text(encoding="utf-8")
    text = DOC.read_text(encoding="utf-8")
    for needle in ("accepted residual risk", "does not prove which Grafana", "allow", "unique to this contact point"):
        assert needle in text, needle


# pfSense: unknown output must not look healthy

@pytest.mark.parametrize("text", [
    "unable to contact update server; status unavailable",
    "Impossible de contacter le serveur de mises a jour",           # localized
    "something unexpected happened",
    "WARNING: repository metadata is stale",                        # warning, exit 0
    "Your system is up to date\nERROR: could not verify signature",  # mixed
    "Version 99.9 is available\nWarning: low disk space",            # update plus warning
    "",                                                             # empty output
    "   \n",
])
def test_unknown_upgrade_output_fails_closed(tmp_path, text):
    r, _ = _run(tmp_path, text, "")
    _assert_failure(r)


def test_known_healthy_and_update_outputs_still_work(tmp_path):
    r, _ = _run(tmp_path, "Your system is up to date", "")
    assert r.returncode == 0 and "pfsense_update_check_success value=1i" in r.stdout
    r, _ = _run(tmp_path, "Version 99.9 is available", "")
    assert _metrics(r.stdout)[("core", "false")] == 1


@pytest.mark.parametrize("pkg", [
    "Updating repository catalogue",           # chatter, spaces
    "nopackageversion",                       # no name-version shape
    "pfSense-pkg-Foo-1.0\nrepository error",  # mixed
])
def test_unexpected_pkg_output_fails_closed(tmp_path, pkg):
    r, _ = _run(tmp_path, "Your system is up to date", pkg)
    _assert_failure(r)


# --- round 5: type-safe normalization, .env parsing, negated pfSense text ------

HOSTILE = [7, {"a": {"b": 1}}, [1, 2], None, True, "x" * 100000, {"toString": "x"}]
LABEL_KEYS = ["alertname", "severity", "instance", "agent", "job", "srcip", "update_security"]
ANNOTATION_KEYS = ["summary", "description", "trigger_logic", "trigger_query", "threshold", "window"]
ALERT_SCALARS = ["valueString", "startsAt", "endsAt", "dashboardURL", "panelURL", "generatorURL", "fingerprint"]


def _hostile_body(status, value):
    alert = {"labels": {k: value for k in LABEL_KEYS},
             "annotations": {k: value for k in ANNOTATION_KEYS}}
    alert.update({k: value for k in ALERT_SCALARS})
    return {"status": status, "alerts": [alert]}


def _normalize_node():
    return _nodes()["Normalize Alert"]


def _discord_texts():
    # the phone-failure notices read the error output, not the alert, so they are not part of this scan
    return [c for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.discord"
            and "Phone Failed" not in n["name"]
            for c in _expressions(n["parameters"])]


@pytest.mark.parametrize("status", ["firing", "resolved"])
@pytest.mark.parametrize("value", HOSTILE, ids=["number", "object", "array", "null", "bool", "long", "tostring"])
def test_hostile_field_types_reach_notifications_without_throwing(status, value):
    reached, notified = _simulate({"headers": {}, "body": _hostile_body(status, value)})
    expected = DISCORD_FIRING if status == "firing" else DISCORD_RESOLVED
    assert expected in notified, "alert was not routed to its Discord node"
    assert _build_node()["name"] in reached


def test_normalize_builds_a_fresh_typed_body():
    out = _run_code_node(_normalize_node(), {"headers": {"x": 1}, "body": _hostile_body("firing", 7),
                                             "extra": {"a": 1}})[0]
    assert set(out) == {"body"}, "only the rebuilt body may pass"
    a = out["body"]["alerts"][0]
    assert all(isinstance(a[k], str) for k in ALERT_SCALARS)
    assert all(isinstance(v, str) for v in a["labels"].values())
    assert all(isinstance(v, str) for v in a["annotations"].values())
    big = _run_code_node(_normalize_node(), {"body": _hostile_body("firing", "x" * 100000)})[0]
    assert len(json.dumps(big)) < 20000, "lengths must be capped"
    bad_ts = _run_code_node(_normalize_node(), {"body": {"status": "firing", "alerts": [
        {"labels": {}, "startsAt": "not-a-timestamp", "endsAt": "2026-01-01T00:00:00Z"}]}})[0]
    assert bad_ts["body"]["alerts"][0]["startsAt"] == ""
    assert bad_ts["body"]["alerts"][0]["endsAt"] == "2026-01-01T00:00:00Z"


def test_normalize_covers_every_field_the_expressions_reference():
    blob = "\n".join(_discord_texts())
    pairs = set(re.findall(r"\)\[0\]\.(\w+)(?:\?\.(\w+))?", blob))
    assert pairs, "no field references found"
    assert not (set(re.findall(r"\$json\.(\w+)", blob)) - {"body"}), "expressions read outside $json.body"
    item = {"body": {"status": "firing", "alerts": [{
        "labels": {k: "v-" + k for k in LABEL_KEYS + ["extra_label"]},
        "annotations": {k: "v-" + k for k in ANNOTATION_KEYS},
        **{k: "v-" + k for k in ALERT_SCALARS}}]}}
    item["body"]["alerts"][0]["startsAt"] = item["body"]["alerts"][0]["endsAt"] = "2026-01-01T00:00:00Z"
    a = _run_code_node(_normalize_node(), item)[0]["body"]["alerts"][0]
    for top, sub in sorted(pairs):
        if sub:
            assert a[top][sub] == "v-" + sub, f"{top}.{sub} is read by an expression but not normalized"
        elif top == "labels":
            assert a["labels"].get("extra_label") == "v-extra_label"
        else:
            assert top in a, f"{top} is read by an expression but not normalized"


# check-env.sh: parse the value the way Compose does

def _check_env_lines(tmp_path, *lines):
    env = tmp_path / ".env"
    env.write_text(_env_body(None) + "".join(line + "\n" for line in lines), encoding="utf-8")
    return subprocess.run(["bash", str(CHECK_ENV), str(env)], capture_output=True,
                          text=True, timeout=60, check=False)


COMMENT_REPRO = "GRAFANA_WEBHOOK_SECRET=x # this-comment-makes-the-raw-line-long-enough"


@pytest.mark.parametrize("lines", [
    [COMMENT_REPRO],
    ["GRAFANA_WEBHOOK_SECRET=x\t# this-comment-makes-the-raw-line-long-enough"],
    ['GRAFANA_WEBHOOK_SECRET="x" # this-comment-makes-the-raw-line-long-enough'],
    ["GRAFANA_WEBHOOK_SECRET='x' # this-comment-makes-the-raw-line-long-enough"],
    ["GRAFANA_WEBHOOK_SECRET= # " + "c" * 40],
    ['GRAFANA_WEBHOOK_SECRET="' + "a" * 20 + '\\n' + "b" * 20 + '"'],   # newline escape
    ['GRAFANA_WEBHOOK_SECRET="' + "a" * 40],                                 # unmatched quote
    ["GRAFANA_WEBHOOK_SECRET='" + "a" * 40],
    ["GRAFANA_WEBHOOK_SECRET=" + "a" * 20 + "$HOME" + "b" * 20],             # Compose would interpolate
    ["GRAFANA_WEBHOOK_SECRET=" + "a" * 40, "GRAFANA_WEBHOOK_SECRET=x"],      # duplicate, last is short
    ["GRAFANA_WEBHOOK_SECRET=x", "GRAFANA_WEBHOOK_SECRET=" + "a" * 40],      # duplicate, last is good
])
def test_check_env_parses_like_compose_and_rejects(tmp_path, lines):
    r = _check_env_lines(tmp_path, *lines)
    assert r.returncode == 1, r.stderr
    assert "GRAFANA_WEBHOOK_SECRET" in r.stderr
    assert "this-comment" not in r.stderr and "aaaa" not in r.stderr, "value must not be printed"


@pytest.mark.parametrize("line", [
    "GRAFANA_WEBHOOK_SECRET=" + "a" * 40,
    "GRAFANA_WEBHOOK_SECRET=" + "a" * 40 + "   # a comment",
    'GRAFANA_WEBHOOK_SECRET="' + "a" * 40 + '"',
    'GRAFANA_WEBHOOK_SECRET="' + "a" * 40 + '"  # a comment',
    "GRAFANA_WEBHOOK_SECRET='" + "a" * 40 + "'",
    "GRAFANA_WEBHOOK_SECRET='" + "a" * 40 + "' # a comment",
    "GRAFANA_WEBHOOK_SECRET=" + VALID_SECRET,
    "GRAFANA_WEBHOOK_SECRET=" + "ab+/" * 11 + "==",
])
def test_check_env_accepts_valid_compose_forms(tmp_path, line):
    r = _check_env_lines(tmp_path, line)
    assert r.returncode == 0, r.stderr


def _real_compose():
    try:
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and "Docker Compose" in r.stdout


def test_compose_resolves_the_comment_fixture_to_the_short_value(tmp_path):
    if not _real_compose():
        pytest.skip("docker compose is not available here (the docker command is a podman emulation or missing)")
    (tmp_path / "c.yml").write_text("services:\n  a:\n    image: x\n    environment:\n"
                                    "      V: ${GRAFANA_WEBHOOK_SECRET}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(COMMENT_REPRO + "\n", encoding="utf-8")
    r = subprocess.run(["docker", "compose", "-f", str(tmp_path / "c.yml"), "--env-file",
                        str(tmp_path / ".env"), "config", "--format", "json"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["services"]["a"]["environment"]["V"] == "x"


# pfSense: negated or stale "up to date" text is not healthy

@pytest.mark.parametrize("text", [
    "Your system is no longer up to date",
    "Your system is not up to date",
    "Your system is not currently up to date",
    "Your system isn't up to date",
    "Your system is out of date",
    "Your system is outdated",
    "Your system is up to date (cache is stale)",
    "Your system is up to date\nVersion 99.9 is available",
    "System status: up to date",            # not a known complete line
    "your system is up to date, probably",
])
def test_negated_or_unknown_healthy_text_fails_closed(tmp_path, text):
    r, _ = _run(tmp_path, text, "")
    _assert_failure(r)


@pytest.mark.parametrize("text", [
    "Your system is up to date",
    "your system is up to date.",
    "  Your system is up to date  \n\n",
])
def test_exact_healthy_lines_are_accepted(tmp_path, text):
    r, _ = _run(tmp_path, text, "")
    assert r.returncode == 0 and "pfsense_update_check_success value=1i" in r.stdout


# --- the poller field name, verified against a live unpoller database ----------

WRONG_FIELD = "upgrad" + "able"   # the misspelling; kept split so this file never contains it
RIGHT_FIELD = "upgrade" + "able"


def test_unifi_rules_query_the_real_poller_field_name():
    unifi = ALERTING / "update-alert-rules-unifi.yml"
    for path in (unifi, DOC, Path(__file__)):
        assert WRONG_FIELD not in path.read_text(encoding="utf-8"), path.name
    rules = [r for _, _, r in _rules() if r["uid"] in PENDING_UNIFI]
    assert len(rules) == 2
    stale = next(r for _, _, r in _rules() if r["uid"] == "update-unifi-poller-stale")
    assert f'"{RIGHT_FIELD}"' in _data(stale, "A")["model"]["query"]
    for rule in rules:
        for ref in ("A", "P"):
            query = _data(rule, ref)["model"]["query"]
            assert f'"{RIGHT_FIELD}"' in query, (rule["uid"], ref)
            assert WRONG_FIELD not in query
            m = re.search(r"FROM /\^\(([^)]*)\)\$/", query)
            assert m, query
            assert {"uap", "usw"} <= set(m.group(1).split("|")), "uap and usw must stay in the measurement regex"
    assert "verified on 2026-11-18" in " ".join(unifi.read_text(encoding="utf-8").split()).lower()


# --- round 6: the phone label gate, rule labels, execErrState, stale-poller rule ---

def _phone_body(status, labels, name=GOOD_NAME):
    return _alert(status, labels, name=name)


@pytest.mark.parametrize("status", ["firing", "resolved"])
@pytest.mark.parametrize("name", [GOOD_NAME, "pfSense SECURITY update pending", "some SIEM alert"])
@pytest.mark.parametrize("labels", [
    {"severity": "critical"}, {"severity": "warning"}, {"severity": "info"},
    {"severity": "critical", "update_security": "true"}, {"severity": "warning", "update_security": "true"},
])
def test_alert_without_phone_label_never_pushes(status, name, labels):
    out = _run_build(_phone_body(status, labels, name), enabled=True)
    assert out["enabled"] is False
    for phone in ("false", "True", "yes", "1", "", "TRUE"):
        assert _run_build(_phone_body(status, dict(labels, phone=phone), name), enabled=True)["enabled"] is False, phone
    assert _run_build(_phone_body(status, dict(labels, phone="true"), name), enabled=True)["enabled"] is True


def test_phone_gate_keeps_priority_and_cancel_rules():
    crit = _run_build(_phone_body("firing", {"severity": "critical", "phone": "true"}), enabled=True)
    assert crit["pushover"]["priority"] == 2
    other = _run_build(_phone_body("firing", {"severity": "critical", "phone": "true"}, "some SIEM alert"), enabled=True)
    assert other["enabled"] is True and other["pushover"]["priority"] == 1 and other["cancelTag"] == ""
    res = _run_build(_phone_body("resolved", {"severity": "critical", "phone": "true"}), enabled=True)
    assert res["enabled"] is True and res["cancelTag"].startswith("upd-")
    # a resolved alert without the label must not even cancel
    assert _run_build(_phone_body("resolved", {"severity": "critical"}), enabled=True)["enabled"] is False


def test_malformed_notice_still_reaches_the_phone_without_the_label():
    out = _run_build({"status": "weird", "alerts": [{}]}, enabled=True)
    assert out["enabled"] is True and out["pushover"]["priority"] == 1
    assert _run_build({"status": "weird", "alerts": [{}]})["enabled"] is False  # Pushover itself still off


def test_normalize_carries_the_phone_label_through():
    item = {"body": {"status": "firing", "alerts": [{"labels": {"alertname": GOOD_NAME, "phone": "true"}}]}}
    out = _run_code_node(_normalize_node(), item)[0]
    assert out["body"]["alerts"][0]["labels"]["phone"] == "true"
    out = _run_code_node(_normalize_node(), {"body": {"status": "firing", "alerts": [
        {"labels": {"phone": True}}]}})[0]
    assert out["body"]["alerts"][0]["labels"]["phone"] == "true"   # booleans are coerced, then compared as strings


@pytest.mark.parametrize("status", ["firing", "resolved"])
def test_graph_pushes_only_when_the_label_is_set(status):
    base = {"severity": "critical"}
    _, without = _simulate({"headers": {}, "body": _phone_body(status, base)}, pushover_enabled=True)
    assert "Pushover Notify" not in without and "Pushover Cancel Repeats" not in without
    assert (DISCORD_FIRING if status == "firing" else DISCORD_RESOLVED) in without, "Discord is unchanged"
    _, with_label = _simulate({"headers": {}, "body": _phone_body(status, dict(base, phone="true"))},
                              pushover_enabled=True)
    assert "Pushover Notify" in with_label
    if status == "resolved":
        assert "Pushover Cancel Repeats" in with_label


def test_graph_malformed_notice_pushes_when_enabled():
    _, notified = _simulate({"headers": {}, "body": {"status": "weird"}}, pushover_enabled=True)
    assert "Pushover Notify" in notified


def test_every_update_rule_sets_the_phone_label_explicitly():
    seen = 0
    for _, _, rule in _rules():
        # the poller-stale rule and the two 24h rules (P2, owner decision 2026-11-20, issue #152) stay off the phone;
        # the UniFi 24h rule is also quiet by owner decision 2026-11-26 (7-day wait, issue #199)
        p2 = {"update-unifi-poller-stale", "update-unifi-pending-24h", "update-pfsense-pending-24h",
              "update-twingate-operator-behind", "update-twingate-unexpected-connector",
              "update-synology-data-stale", "update-synology-check-failing"}  # synology health: quiet (#257); operator: digest only (#200); unexpected: warning, no phone (#222)
        want = "false" if rule["uid"] in p2 else "true"
        assert rule["labels"].get("phone") == want, rule["uid"]
        seen += 1
    assert seen >= 7


def test_stale_poller_rule():
    by = {r["uid"]: r for _, _, r in _rules()}
    r = by["update-unifi-poller-stale"]
    assert r["title"] == "UniFi poller data stale"
    assert r["labels"]["severity"] == "warning" and r["labels"]["phone"] == "false"
    assert r["noDataState"] == "Alerting" and r["execErrState"] == "Alerting"
    assert r["for"] == "5m" and not r.get("isPaused")
    a = _data(r, "A")
    assert a["datasourceUid"] == "influxdb-unifi"
    assert a["relativeTimeRange"] == {"from": 900, "to": 0}
    assert '"usw"' in a["model"]["query"] and "now() - 15m" in a["model"]["query"]


def test_docs_have_the_label_taxonomy_and_health_notes():
    text = DOC.read_text(encoding="utf-8")
    assert "Label taxonomy" in text
    for label in ("`update_alert`", "`severity`", "`phone`", "`alert_group`", "`update_security`"):
        assert label in text, label
    flat = " ".join(text.split())
    assert "stay off the phone until they carry `phone=true`" in flat
    assert "84h" in flat and "twice a week" in flat
    assert "24h critical" in flat and "1h critical" not in flat  # issue #53
    assert "heartbeat" in flat.lower() and "not part of this change" in flat.lower()


# --- issue #61: a failing query must alert, never read as OK ---

def test_no_update_rule_treats_a_query_error_as_ok():
    rules = _rules()
    files = {fname for fname, _, _ in rules}
    assert any("unifi" in f for f in files) and any("pfsense" in f for f in files)
    assert len(rules) >= 7
    for fname, _group, rule in rules:
        # the key must be present: Grafana's default is Alerting, but the rule
        # files state it so a later edit cannot lean on a default
        assert "execErrState" in rule, rule["uid"]
        assert rule["execErrState"] == "Alerting", (fname, rule["uid"], rule["execErrState"])
        assert rule["execErrState"] not in {"OK", "Error"}, rule["uid"]


@pytest.mark.parametrize("uid", sorted({r["uid"] for _, _, r in _rules()}))
def test_each_update_rule_alerts_on_query_error(uid):
    rule = {r["uid"]: r for _, _, r in _rules()}[uid]
    assert rule["execErrState"] == "Alerting"
    # NoData is a separate decision: only the two UniFi pending rules treat it as OK
    expect = "OK" if uid in PENDING_UNIFI else "Alerting"
    assert rule["noDataState"] == expect


def test_docs_describe_the_query_error_failure_mode():
    flat = " ".join((REPO_ROOT / "docs" / "update-alerting.md").read_text().split())
    assert "### Query errors" in flat
    assert "`execErrState: Alerting`" in flat
    assert "DatasourceError" in flat
    assert "instead of the default" in flat
