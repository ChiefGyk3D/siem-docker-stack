"""Guards for the alert-path heartbeat (issue #80).

A Grafana rule that always fires reaches the n8n router with the label heartbeat=true.
The router sends no Discord or phone message for it. It pings an observer outside this
host's failure domain (hosted Healthchecks, a self-hosted Healthchecks or Uptime Kuma on
another host, or Uptime Kuma behind a private-access layer). When the pings stop, the
observer alerts through its own channels.

The Code node and the expressions run under Node for real; the graph is walked with the
evaluator in test_update_alerting.py. It is a model of n8n, not n8n.
"""
import json
import re

import pytest
import yaml

from conftest import REPO_ROOT
from test_update_alerting import (ALERTING, DISCORD_FIRING, DISCORD_RESOLVED, ENV_EXAMPLE, ROUTER, ROUTING_CASES,
                                  _alert, _edges, _expressions, _nodes, _reachable, _run_code_node, _run_graph,
                                  _workflow)

RULE_FILE = ALERTING / "heartbeat-alert-rule.yml"
POLICY_FILE = ALERTING / "heartbeat-notification-policy.yml.example"
DOC = REPO_ROOT / "docs" / "heartbeat.md"

PING_NODE = "Heartbeat Ping"
BUILD_NODE = "Build Heartbeat Ping"
IF_NODE = "Heartbeat?"
SEND_NODE = "Heartbeat Send?"
MALFORMED = "Discord — Malformed"
# documentation-only addresses (example.com); never a real ping URL
HC_URL = "https://hc-ping.example.com/00000000-0000-4000-8000-000000000000"
HC_KEY_URL = "https://hc-ping.example.com/KEY0000000000000/router-heartbeat"
KUMA_URL = "https://kuma.example.com/api/push/TOKEN0000?status=up&msg=OK&ping="
HB_LABELS = {"heartbeat": "true", "phone": "false", "severity": "info"}


def _hb(status="firing", **labels):
    merged = dict(HB_LABELS, **labels)
    body = _alert(status, merged, name="Alert path heartbeat")
    body["alerts"][0]["annotations"] = {"summary": "MARKER-SUMMARY-XYZ"}
    return {"headers": {"authorization": "Bearer HEADER-MARKER-XYZ"}, "body": body}


def _run(item, url=HC_URL, kind=None, **kw):
    env = {}
    if url is not None:
        env["HEARTBEAT_PING_URL"] = url
    if kind is not None:
        env["HEARTBEAT_KIND"] = kind
    return _run_graph(item, env=kw.pop("env", env), **kw)


CHANNELS = {DISCORD_FIRING, DISCORD_RESOLVED, MALFORMED, "Pushover Notify", "Pushover Cancel Repeats",
            "Discord — Phone Failed (send)", "Discord — Phone Failed (cancel)"}


# --- the heartbeat branch: no message, one ping ------------------------------------------

def test_a_heartbeat_sends_no_discord_or_phone_message_and_one_ping():
    res = _run(_hb(), pushover_enabled=True)
    assert res["response"] == "200" and res["run"] == "success"
    assert res["requests"] == [{"node": PING_NODE, "url": HC_URL}]
    assert res["notified"] == {PING_NODE}, "nothing but the ping may be sent"


def test_a_heartbeat_ping_is_sent_only_after_the_router_reached_the_end_of_the_branch():
    wf = _workflow()
    edges = _edges(wf)
    assert wf["connections"]["Normalize Alert"]["main"][0][0]["node"] == IF_NODE
    # the response comes after the ping, so a ping means the webhook was authenticated,
    # normalized and routed
    assert "Respond OK" in _reachable(PING_NODE, edges)
    assert PING_NODE not in _reachable("Respond OK", edges)
    res = _run(_hb())
    assert res["reached"].index("Normalize Alert") < res["reached"].index(PING_NODE) < res["reached"].index("Respond OK")


def test_no_channel_node_is_reachable_from_the_heartbeat_branch():
    edges = _edges(_workflow())
    branch = _reachable(BUILD_NODE, edges)
    assert branch & set(_nodes()) >= {BUILD_NODE, SEND_NODE, PING_NODE, "Respond OK"}
    assert not (branch & (CHANNELS | {"Alert Status", "Build Pushover Payload", "Pushover Enabled?", "Respond Error",
                                      "Fail Run", "Discord Failed?"}))


def test_the_ping_node_is_the_only_new_http_node_and_never_fails_the_run():
    http = [n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"
            and "pushover" not in str(n["parameters"].get("url", ""))]
    assert [n["name"] for n in http] == [PING_NODE]
    p = http[0]
    assert p["onError"] == "continueRegularOutput"
    assert p["parameters"]["method"] == "GET"
    assert p["parameters"]["url"] == "={{ $json.url }}"
    assert p["parameters"]["options"]["timeout"] <= 15000
    assert "credentials" not in p and "authentication" not in p["parameters"]


@pytest.mark.parametrize("pushover", [False, True])
def test_a_failed_ping_never_fails_the_run(pushover):
    res = _run(_hb(), pushover_enabled=pushover, fail={PING_NODE})
    assert res["response"] == "200" and res["run"] == "success" and res["error"] == ""
    assert PING_NODE in res["failed"] and "Respond Error" not in res["reached"]


# --- off when unset ------------------------------------------------------------------------

@pytest.mark.parametrize("env", [
    {}, {"HEARTBEAT_PING_URL": ""}, {"HEARTBEAT_PING_URL": "   "}, {"HEARTBEAT_PING_URL": None}, "blocked",
    {"HEARTBEAT_PING_URL": "ftp://hc-ping.example.com/x"}, {"HEARTBEAT_PING_URL": "javascript:alert(1)"},
    {"HEARTBEAT_PING_URL": "hc-ping.example.com/x"}, {"HEARTBEAT_PING_URL": "https://a.example.com/x y"},
    {"HEARTBEAT_PING_URL": "https://a.example.com/" + "x" * 600}, {"HEARTBEAT_PING_URL": "https://"},
    {"HEARTBEAT_PING_URL": 5}, {"HEARTBEAT_PING_URL": HC_URL, "HEARTBEAT_KIND": "nagios"},
], ids=["unset", "empty", "blank", "null", "env-blocked", "ftp", "js", "no-scheme", "space", "long", "no-host",
        "number", "unknown-kind"])
def test_the_feature_is_off_without_a_valid_setting_and_still_answers_200(env):
    res = _run(_hb(), pushover_enabled=True, env=env)
    assert res["requests"] == [] and PING_NODE not in res["notified"]
    assert res["notified"] == set(), "no ping, no Discord, no phone"
    assert res["response"] == "200" and res["run"] == "success" and res["error"] == ""
    # and a resolved heartbeat is silent too
    off = _run(_hb("resolved"), pushover_enabled=True, env=env)
    assert off["notified"] == set() and off["response"] == "200"


def test_the_ping_url_is_only_read_in_the_heartbeat_code_node_and_never_logged():
    text = ROUTER.read_text(encoding="utf-8")
    # the only other env read is the expiry watch's own router secret, in its own check node
    # (test_router_expiry_secret.py)
    assert set(re.findall(r"\$env\.(\w+)", text)) == {"HEARTBEAT_PING_URL", "HEARTBEAT_KIND", "EXPIRY_WATCH_ROUTER_SECRET"}
    code = _nodes()[BUILD_NODE]["parameters"]["jsCode"]
    for bad in ("console.", "throw ", "JSON.stringify"):
        assert bad not in code, bad
    assert "ALLOWED_ALERTNAMES" not in code
    for name, node in _nodes().items():
        if name not in (BUILD_NODE, "Check Expiry Secret"):
            assert "$env" not in json.dumps(node), name


# --- the outcome: ok, /fail, resolved ------------------------------------------------------

def test_a_heartbeat_that_breaks_its_contract_sends_fail_and_still_no_message():
    for labels in ({"phone": "true"}, {"phone": ""}, {"phone": "TRUE"}):
        res = _run(_hb(**labels), pushover_enabled=True)
        assert res["requests"] == [{"node": PING_NODE, "url": HC_URL + "/fail"}], labels
        assert res["notified"] == {PING_NODE}, "a contract failure must never page"
        assert res["response"] == "200"
    missing = _hb()
    del missing["body"]["alerts"][0]["labels"]["phone"]
    assert _run(missing)["requests"] == [{"node": PING_NODE, "url": HC_URL + "/fail"}]


def test_a_resolved_heartbeat_sends_nothing():
    res = _run(_hb("resolved"), pushover_enabled=True)
    assert res["notified"] == set() and res["requests"] == []
    assert res["response"] == "200" and res["run"] == "success"


@pytest.mark.parametrize("url,ok,fail", [
    (HC_URL, HC_URL, HC_URL + "/fail"),
    (HC_URL + "/", HC_URL, HC_URL + "/fail"),
    (HC_KEY_URL, HC_KEY_URL, HC_KEY_URL + "/fail"),
    ("http://hc.example.com:8000/ping/abc", "http://hc.example.com:8000/ping/abc",
     "http://hc.example.com:8000/ping/abc/fail"),
])
def test_healthchecks_style_urls_ping_the_base_and_fail_appends_fail(url, ok, fail):
    assert _run(_hb(), url=url)["requests"][0]["url"] == ok
    assert _run(_hb(), url=url, kind="healthchecks")["requests"][0]["url"] == ok
    assert _run(_hb(phone="true"), url=url)["requests"][0]["url"] == fail


def test_uptime_kuma_push_urls_get_the_status_query():
    up = _run(_hb(), url=KUMA_URL, kind="uptimekuma")["requests"][0]["url"]
    assert up == "https://kuma.example.com/api/push/TOKEN0000?status=up&msg=OK"
    down = _run(_hb(phone="true"), url=KUMA_URL, kind="uptimekuma")["requests"][0]["url"]
    assert down.startswith("https://kuma.example.com/api/push/TOKEN0000?status=down&msg=")
    assert " " not in down and "MARKER" not in down and "/fail" not in down
    bare = _run(_hb(), url="https://kuma.example.com/api/push/TOKEN0000", kind="uptimekuma")["requests"][0]["url"]
    assert bare == up


def test_the_request_never_carries_alert_content():
    res = _run(_hb(phone="true"), pushover_enabled=True)
    blob = json.dumps(res["requests"])
    assert "MARKER" not in blob and "Bearer" not in blob and "Alert path heartbeat" not in blob
    assert "MARKER" not in res["error"]


def test_the_code_node_output_has_only_the_send_decision_and_the_url():
    node = _nodes()[BUILD_NODE]
    item = {"body": _hb()["body"]}
    ctx = {"env": {"HEARTBEAT_PING_URL": HC_URL}}
    assert _run_code_node(node, item, ctx) == [{"send": True, "url": HC_URL}]
    assert _run_code_node(node, item, {"env": {}}) == [{"send": False}]
    assert _run_code_node(node, item, {"env": "blocked"}) == [{"send": False}]
    # odd input never throws
    for odd in ({}, {"body": None}, {"body": {"alerts": []}}, {"body": {"status": 5, "alerts": [None]}}):
        assert _run_code_node(node, odd, ctx)[0]["send"] in (True, False)


# --- normal alerts are untouched --------------------------------------------------------------

@pytest.mark.parametrize("case", sorted(ROUTING_CASES))
def test_every_earlier_routing_case_is_unchanged_with_the_heartbeat_on(case):
    body, expected = ROUTING_CASES[case]
    res = _run({"headers": {}, "body": body})
    assert res["response"] == "200" and res["requests"] == []
    assert expected in res["notified"] and PING_NODE not in res["notified"]


@pytest.mark.parametrize("value", ["false", "TRUE", "True", "yes", "1", "", "true "])
def test_only_the_exact_label_value_true_is_a_heartbeat(value):
    item = {"headers": {}, "body": _alert("firing", {"heartbeat": value, "severity": "warning"})}
    res = _run(item)
    assert res["requests"] == [] and DISCORD_FIRING in res["notified"]


def test_a_discord_failure_still_answers_502_and_sends_no_ping():
    item = {"headers": {}, "body": _alert("firing", {"severity": "warning", "phone": "true"})}
    res = _run(item, pushover_enabled=True, fail={DISCORD_FIRING})
    assert res["response"] == "502" and res["run"] == "error"
    assert PING_NODE not in res["notified"]
    assert "Pushover Notify" in res["notified"]


def test_the_heartbeat_label_never_reaches_the_phone_even_with_phone_true():
    res = _run(_hb(phone="true", severity="critical"), pushover_enabled=True)
    assert not (res["notified"] & CHANNELS)


def test_a_malformed_body_is_not_a_heartbeat():
    res = _run({"headers": {}, "body": {"status": "weird", "alerts": [{"labels": HB_LABELS}]}})
    assert MALFORMED in res["notified"] and res["requests"] == []


def test_the_router_keeps_its_response_and_error_wiring():
    nodes = _nodes()
    assert nodes["Respond OK"]["parameters"]["options"]["responseCode"] == 200
    assert [c["node"] for c in _workflow()["connections"]["Discord Failed?"]["main"][0]] == ["Respond Error"]
    assert [c["node"] for c in _workflow()["connections"]["Alert Status"]["main"][0]] == [DISCORD_FIRING]
    assert [c["node"] for c in _workflow()["connections"][IF_NODE]["main"][1]] == ["Alert Status"]


# --- no secret in any file ------------------------------------------------------------------

HC_REAL = re.compile(r"hc-ping\.com/[0-9a-zA-Z-]{8,}")
KUMA_REAL = re.compile(r"https?://[^\s\"']*/api/push/(?!<)[A-Za-z0-9]{16,}")


def test_no_ping_url_or_key_is_stored_anywhere_in_the_repo():
    checked = 0
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or path.name == "test_heartbeat.py":
            continue
        if path.suffix not in {".md", ".yml", ".json", ".example", ".py", ".sh"} and path.name != ".env.example":
            continue
        checked += 1
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not HC_REAL.search(text), path
        assert not KUMA_REAL.search(text), path
    assert checked > 20, "the scan must have collected the repo files"
    # the guard bites: a real-looking ping URL is caught by the same patterns
    assert HC_REAL.search("https://hc-ping.com/0a1b2c3d-0000")
    assert KUMA_REAL.search("https://k.example.com/api/push/Abcdefghij0123456789")
    assert not KUMA_REAL.search("https://kuma.example.com/api/push/<push-token>")


def test_env_example_documents_the_two_settings_commented_and_without_a_value():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert re.search(r"(?m)^# HEARTBEAT_PING_URL=$", text)
    assert re.search(r"(?m)^# HEARTBEAT_KIND=healthchecks$", text)
    assert not re.search(r"(?m)^HEARTBEAT_", text), "the feature stays off by default"
    assert "docs/heartbeat.md" in text


# --- Grafana provisioning ---------------------------------------------------------------------

def _rule():
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    assert len(data["groups"]) == 1 and len(data["groups"][0]["rules"]) == 1
    return data["groups"][0], data["groups"][0]["rules"][0]


def test_the_heartbeat_rule_always_fires_from_a_constant_and_is_not_an_update_rule():
    group, rule = _rule()
    assert rule["title"] == "Alert path heartbeat" and rule["uid"] == "alert-path-heartbeat"
    assert group["orgId"] == 1 and group["folder"] and group["interval"] == "1m"
    refs = {d["refId"]: d for d in rule["data"]}
    assert rule["condition"] in refs
    for d in rule["data"]:
        assert d["datasourceUid"] == "__expr__", "no data source: the rule cannot depend on one"
    consts = [d for d in rule["data"] if d["model"].get("type") == "math"]
    assert consts and re.fullmatch(r"\s*[1-9][0-9]*\s*", consts[0]["model"]["expression"])
    cond = refs[rule["condition"]]["model"]
    assert cond["type"] == "threshold" and cond["conditions"][0]["evaluator"] == {"type": "gt", "params": [0]}
    assert rule["for"] == "0s" and rule["isPaused"] is False
    assert rule["noDataState"] == "OK" and rule["execErrState"] == "OK", "a broken rule must not ping"
    assert rule["annotations"]["summary"] and rule["annotations"]["description"]


def test_the_heartbeat_rule_labels_keep_it_off_the_phone_and_out_of_the_update_rules():
    _, rule = _rule()
    assert rule["labels"] == {"severity": "info", "heartbeat": "true", "phone": "false", "alert_group": "heartbeat"}
    assert "update_alert" not in rule["labels"]
    # the update-rule files are untouched by this rule, and no other rule carries the label
    for path in ALERTING.glob("*rules*.yml"):
        assert "heartbeat" not in path.read_text(encoding="utf-8").lower(), path.name


def test_the_heartbeat_policy_example_repeats_every_five_minutes_and_matches_the_rule_labels():
    data = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    root = data["policies"][0]
    routes = [r for r in root["routes"] if ["heartbeat", "=", "true"] in r["object_matchers"]]
    assert len(routes) == 1
    route = routes[0]
    assert route["receiver"] == "n8n-grafana-router"
    assert route["repeat_interval"] == "5m" and route["group_interval"] == "1m" and route["group_wait"] == "0s"
    assert route["group_by"] == ["alertname"]
    _, rule = _rule()
    for label, op, value in route["object_matchers"]:
        assert op == "=" and rule["labels"][label] == value
    text = POLICY_FILE.read_text(encoding="utf-8")
    assert "replaces" in text and "example" in POLICY_FILE.name


def test_the_new_files_are_not_picked_up_by_the_update_rule_schema_tests():
    # update tests glob *rules*.yml; the heartbeat rule has its own schema above
    assert RULE_FILE not in set(ALERTING.glob("*rules*.yml"))
    assert RULE_FILE.exists() and POLICY_FILE.exists()


# --- docs ----------------------------------------------------------------------------------------

def test_docs_cover_setup_observers_and_what_is_unverified():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("HEARTBEAT_PING_URL", "HEARTBEAT_KIND", "healthchecks", "uptimekuma", "Healthchecks.io",
                   "period of 5 minutes", "grace time of 10 minutes", "N8N_BLOCK_ENV_ACCESS_IN_NODE",
                   "example.com", "192.0.2.", "private-access", "/fail", "status=down",
                   "Verified", "Unverified", "failure domain", "repeat_interval", "off when unset",
                   "never fails the delivery of a real alert", "Alert path heartbeat"):
        assert needle in flat, needle
    # only documentation addresses
    for host in re.findall(r"https?://([\w.-]+)", flat):
        assert host.endswith("example.com") or host.startswith("192.0.2.") or host in {
            "hc-ping.com", "healthchecks.io", "localhost"}, host
    assert "hc-ping.com/" not in re.sub(r"https://hc-ping\.com/<[^>]+>", "", flat), "no real ping URL"
    assert "heartbeat.md" in (REPO_ROOT / "docs" / "update-alerting.md").read_text(encoding="utf-8")


def test_the_guard_bites_a_router_that_lets_a_heartbeat_through_to_discord():
    """Negative case: with the heartbeat branch cut, the alert goes to Discord, so the tests above would fail."""
    wf = _workflow()
    wf["connections"]["Normalize Alert"]["main"][0] = [{"node": "Alert Status", "type": "main", "index": 0}]
    res = _run_graph(_hb(), wf=wf, env={"HEARTBEAT_PING_URL": HC_URL})
    assert DISCORD_FIRING in res["notified"] and res["requests"] == []
