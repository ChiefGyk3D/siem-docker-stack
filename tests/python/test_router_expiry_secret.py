"""Guards for the expiry watch's own router credential (issue #127, owner decision Q11).

Grafana keeps its entry point exactly as it was: the `Grafana Webhook` node with n8n Header
Auth and the credential grafana-webhook-auth. The expiry watch gets a SECOND entry point,
`Expiry Watch Webhook`, whose Authorization header is checked by a Code node against the
environment variable EXPIRY_WATCH_ROUTER_SECRET. A call that does not pass is answered 403
and goes no further. Both entries feed the same Normalize Alert node, so every downstream
guard (normalizing, routing, delivery) is shared.

The Code node and the expressions run under Node for real; the graph is walked with the
evaluator in test_update_alerting.py. It is a model of n8n, not n8n.
"""
import copy
import importlib.util
import json
import re
import subprocess

import pytest

from conftest import REPO_ROOT, import_module_from_path
from test_update_alerting import (DISCORD_FIRING, ENV_EXAMPLE, ROUTER, _alert, _edges, _reachable, _run_code_node,
                                  _run_graph, _workflow)

GRAFANA_HOOK = "Grafana Webhook"
EXPIRY_HOOK = "Expiry Watch Webhook"
CHECK = "Check Expiry Secret"
GATE = "Expiry Authorized?"
DENY = "Respond Unauthorized"
VAR = "EXPIRY_WATCH_ROUTER_SECRET"
# fixtures only: made-up values, never a real secret
SECRET = "Zx9-expiry-fixture-value-0123456789"
OTHER = "Zx9-grafana-fixture-value-0123456789"
DOC = REPO_ROOT / "docs" / "expiry-watch.md"
RUNBOOK = REPO_ROOT / "docs" / "owner-runbook.md"
UPDATE_DOC = REPO_ROOT / "docs" / "update-alerting.md"
SETUP = REPO_ROOT / "scripts" / "live-deploy" / "n8n-setup-alert-router.py"


def _by_name():
    return {n["name"]: n for n in _workflow()["nodes"]}


def _expiry_body(severity="warning", phone=True, stage="14", name="deploy-key"):
    """What scripts/expiry_watch.py build_payload sends (see the contract test below)."""
    labels = {"alertname": "Expiry watch: " + name, "severity": severity, "expiry_watch": "true", "item": name,
              "kind": "ssh-key", "stage": stage}
    if phone:
        labels["phone"] = "true"
    return {"receiver": "expiry-watch", "status": "firing", "alerts": [{
        "status": "firing", "labels": labels,
        "annotations": {"summary": "MARKER-SUMMARY", "description": "MARKER-DESCRIPTION"},
        "startsAt": "2026-01-01T12:00:00Z", "fingerprint": "0123456789abcdef0123456789abcdef"}]}


def _built(body):
    """The body the check node must hand on: a fresh copy with the fixed source label."""
    a = body["alerts"][0]
    return {"status": "firing", "alerts": [{
        "labels": dict(a["labels"], source="expiry-watch"),
        "annotations": a["annotations"], "startsAt": a["startsAt"], "fingerprint": a["fingerprint"]}]}


def _item(auth="Bearer " + SECRET, body=None):
    headers = {} if auth is None else {"authorization": auth}
    return {"headers": headers, "body": body if body is not None else _expiry_body()}


def _call(auth="Bearer " + SECRET, env=None, **kw):
    env = {VAR: SECRET} if env is None else env
    return _run_graph(_item(auth), env=env, start=EXPIRY_HOOK, **kw)


def _assert_denied(res):
    assert res["response"] == "403", res
    assert json.loads(res["body"]) == {"status": "unauthorized"}
    assert res["notified"] == set(), "a denied call must send nothing"
    assert "Normalize Alert" not in res["reached"]
    assert res["run"] == "success"


# --- Grafana's entry point is untouched ----------------------------------------------------

GRAFANA_HOOK_PINNED = {
    "parameters": {"httpMethod": "POST", "path": "grafana-alerts", "options": {}, "authentication": "headerAuth",
                   "responseMode": "responseNode"},
    "type": "n8n-nodes-base.webhook", "typeVersion": 2.1, "position": [0, 300], "id": "grafana-webhook",
    "name": "Grafana Webhook", "webhookId": "grafana-alerts",
    "credentials": {"httpHeaderAuth": {"id": "YOUR_CREDENTIAL_ID", "name": "grafana-webhook-auth"}},
}


def test_the_grafana_webhook_node_is_unchanged_and_still_first():
    """Guard: Grafana's authentication is byte for byte what it was."""
    assert _workflow()["nodes"][0] == GRAFANA_HOOK_PINNED


def test_a_grafana_call_still_routes_and_never_touches_the_new_variable():
    """Guard: the Grafana path is not gated by the expiry secret (set, unset, empty or blocked)."""
    for env in ({}, {VAR: ""}, {VAR: SECRET}, "blocked"):
        res = _run_graph(_item("Bearer " + OTHER), env=env)
        assert res["response"] == "200" and res["run"] == "success"
        assert DISCORD_FIRING in res["notified"]
        assert CHECK not in res["reached"] and GATE not in res["reached"]


def test_the_header_auth_credential_is_attached_to_no_other_node():
    """Guard: the Grafana credential never leaks onto the new entry point."""
    holders = {n["name"] for n in _workflow()["nodes"] if "httpHeaderAuth" in (n.get("credentials") or {})}
    assert holders == {GRAFANA_HOOK}


# --- the new entry point -------------------------------------------------------------------

def test_the_expiry_webhook_is_a_post_webhook_answering_through_a_response_node():
    hook = _by_name()[EXPIRY_HOOK]
    p = hook["parameters"]
    assert hook["type"] == "n8n-nodes-base.webhook"
    assert p["httpMethod"] == "POST" and p["responseMode"] == "responseNode"
    # the committed path is a placeholder; the import helper replaces it with a private one
    assert p["path"] == "expiry-watch-alerts" and hook["webhookId"] == "expiry-watch-alerts"
    # no n8n credential: the check is the Code node's, from the environment
    assert p.get("authentication", "none") == "none" and "credentials" not in hook
    other_ids = [n["webhookId"] for n in _workflow()["nodes"] if n.get("webhookId") and n["name"] != EXPIRY_HOOK]
    assert hook["webhookId"] not in other_ids and p["path"] != "grafana-alerts"


def test_the_expiry_webhook_reaches_nothing_but_the_check_node():
    wf = _workflow()
    assert _edges(wf)[EXPIRY_HOOK] == {CHECK}
    assert _edges(wf)[CHECK] == {GATE}
    main = wf["connections"][GATE]["main"]
    assert [c["node"] for c in main[0]] == ["Normalize Alert"], "only an authorized call is routed"
    assert [c["node"] for c in main[1]] == [DENY], "everything else is denied"
    assert DENY not in wf["connections"], "the denial ends the run"


def test_no_node_past_the_gate_is_reachable_without_the_gate():
    """Guard: cutting the normalizer or the gate leaves the expiry entry with nothing else."""
    edges = _edges(_workflow())
    assert _reachable(EXPIRY_HOOK, edges, blocked={"Normalize Alert"}) == {EXPIRY_HOOK, CHECK, GATE, DENY}
    assert _reachable(EXPIRY_HOOK, edges, blocked={GATE}) == {EXPIRY_HOOK, CHECK}


def test_the_gate_tests_only_the_check_nodes_boolean():
    """Guard: the gate is a strict boolean on `authorized === true`, so a truthy string never passes."""
    cond = _by_name()[GATE]["parameters"]["conditions"]["conditions"][0]
    assert cond["leftValue"] == "={{ $json.authorized === true }}"
    assert cond["operator"] == {"type": "boolean", "operation": "true", "singleValue": True}


def test_the_denial_answers_403_with_a_static_body():
    p = _by_name()[DENY]["parameters"]
    assert p["options"]["responseCode"] == 403 and p["respondWith"] == "json"
    assert json.loads(p["responseBody"]) == {"status": "unauthorized"}
    assert "{{" not in p["responseBody"]


# --- the check: accept ---------------------------------------------------------------------

def test_the_right_secret_is_routed_to_discord_and_answered_200():
    res = _call()
    assert res["response"] == "200" and res["run"] == "success"
    assert DISCORD_FIRING in res["notified"]
    assert res["reached"].index(CHECK) < res["reached"].index(GATE) < res["reached"].index("Normalize Alert")


def test_a_resolved_notice_is_denied_because_the_watch_only_fires():
    body = _expiry_body()
    body["status"] = "resolved"
    _assert_denied(_run_graph(_item(body=body), env={VAR: SECRET}, start=EXPIRY_HOOK))


def test_the_check_output_carries_the_body_and_no_header_or_secret():
    """Guard: neither the header nor either secret travels past the check node."""
    node = _by_name()[CHECK]
    out = _run_code_node(node, _item(), {"env": {VAR: SECRET}})
    assert len(out) == 1 and out[0]["authorized"] is True
    assert out[0]["body"] == _built(_item()["body"])
    assert set(out[0]) == {"authorized", "body"}
    assert SECRET not in json.dumps(out)
    assert _run_code_node(node, _item("Bearer wrong"), {"env": {VAR: SECRET}}) == [{"authorized": False}]


# --- the check: reject ---------------------------------------------------------------------

@pytest.mark.parametrize("auth", [
    "Bearer " + SECRET[:-1] + "X", "Bearer " + SECRET[:-1], "Bearer " + SECRET + "x", "Bearer " + OTHER,
    "Bearer ", "Bearer", "", "bearer " + SECRET, "BEARER " + SECRET, "Bearer  " + SECRET, " Bearer " + SECRET,
    "Bearer " + SECRET + " ", "Basic " + SECRET, SECRET, "Bearer\t" + SECRET, "Bearer " + SECRET + "\n",
    "Bearer " + SECRET.upper(), "Bearer " + SECRET + "\u0000", 5, ["Bearer " + SECRET], {"v": "Bearer " + SECRET}, True, None,
], ids=["last-char", "short", "long", "grafana-secret", "empty-token", "scheme-only", "empty", "lower-scheme",
        "upper-scheme", "double-space", "leading-space", "trailing-space", "wrong-scheme", "no-scheme", "tab",
        "newline", "case-changed", "trailing-nul", "number", "array", "object", "boolean", "null"])
def test_a_wrong_malformed_or_oddly_typed_header_is_denied(auth):
    _assert_denied(_call(auth))


def test_a_missing_header_is_denied():
    _assert_denied(_call(None))
    _assert_denied(_run_graph({"body": _item()["body"]}, env={VAR: SECRET}, start=EXPIRY_HOOK))
    _assert_denied(_run_graph("just text", env={VAR: SECRET}, start=EXPIRY_HOOK))


def test_a_header_under_another_name_or_shape_is_denied():
    """n8n lower-cases header names; the check reads exactly `authorization`."""
    value = "Bearer " + SECRET
    for headers in ({"Authorization": value}, {"x-authorization": value}, {"authorization ": value}, value, None, [],
                    {"authorization": {"0": value}}):
        _assert_denied(_run_graph({"headers": headers, "body": _item()["body"]}, env={VAR: SECRET}, start=EXPIRY_HOOK))


@pytest.mark.parametrize("env", [
    {}, {VAR: ""}, {VAR: " "}, {VAR: "   "}, {VAR: "\t\n"}, {VAR: None}, {VAR: 5}, {VAR: True}, {VAR: ["x"]},
    {VAR: {"a": 1}}, "blocked",
], ids=["unset", "empty", "one-space", "blank", "whitespace", "null", "number", "boolean", "array", "object",
        "env-blocked"])
def test_an_unset_empty_or_unreadable_variable_denies_every_call(env):
    """Guard: fail closed; an empty configured value never matches an empty or missing header."""
    for auth in ("Bearer " + SECRET, "Bearer ", "Bearer", "", " ", None, "Bearer " + str(env), OTHER):
        _assert_denied(_call(auth, env=env))


def test_an_empty_variable_does_not_match_an_empty_token_after_the_scheme():
    """Guard: the classic hole is `Bearer ` + '' == `Bearer `; it must be denied."""
    for blank in ("", " ", "  "):
        _assert_denied(_call("Bearer " + blank, env={VAR: blank}))
        _assert_denied(_call(None, env={VAR: blank}))


def test_the_grafana_secret_environment_variable_is_not_consulted():
    """Guard: the watch is accepted only by its own variable, never by Grafana's."""
    _assert_denied(_call("Bearer " + OTHER, env={VAR: SECRET, "GRAFANA_WEBHOOK_SECRET": OTHER}))
    _assert_denied(_call("Bearer " + OTHER, env={"GRAFANA_WEBHOOK_SECRET": OTHER}))
    assert "GRAFANA_WEBHOOK_SECRET" not in _by_name()[CHECK]["parameters"]["jsCode"]


def test_a_denied_call_runs_nothing_when_pushover_is_on():
    _assert_denied(_call("Bearer wrong", pushover_enabled=True))


def test_the_check_node_never_throws_on_hostile_input():
    node = _by_name()[CHECK]
    for item in ({}, {"headers": {"authorization": {"toString": 1}}}, {"headers": {"authorization": "x" * 100000}},
                 {"headers": {"authorization": "\u0000"}}, {"headers": {"authorization": "Bearer é"}}):
        assert _run_code_node(node, item, {"env": {VAR: SECRET}}) == [{"authorized": False}]


def test_the_secret_may_contain_pattern_and_unicode_characters():
    """Guard: the comparison is a plain character compare, not a pattern."""
    tricky = "a.b*c(d)[e]\\f$^|?+{1}-é中"
    node = _by_name()[CHECK]
    assert _run_code_node(node, _item("Bearer " + tricky), {"env": {VAR: tricky}})[0]["authorized"] is True
    near = "axb*c(d)[e]\\f$^|?+{1}-é中"
    assert _run_code_node(node, _item("Bearer " + near), {"env": {VAR: tricky}}) == [{"authorized": False}]


# --- what the expiry entry may express (Daybreak round 1, finding 1) ----------------------------

EW = import_module_from_path("expiry_watch", REPO_ROOT / "scripts" / "expiry_watch.py")
PREFIX = "Expiry watch: "


def _check(body=None, env=None):
    out = _run_code_node(_by_name()[CHECK], _item(body=body), {"env": {VAR: SECRET} if env is None else env})
    assert len(out) == 1
    return out[0]


def _mut(fn, **kw):
    body = _expiry_body(**kw)
    fn(body, body["alerts"][0], body["alerts"][0]["labels"], body["alerts"][0]["annotations"])
    return body


def _downstream(body):
    """Run the real Normalize Alert and Pushover payload nodes on what the check handed on."""
    nodes = _by_name()
    checked = _check(body)
    assert checked["authorized"] is True, checked
    norm = _run_code_node(nodes["Normalize Alert"], checked, {})[0]
    build = json.loads(json.dumps(nodes["Build Pushover Payload"]))
    build["parameters"]["jsCode"] = build["parameters"]["jsCode"].replace(
        "const PUSHOVER_ENABLED = false;", "const PUSHOVER_ENABLED = true;")
    push = _run_code_node(build, norm, {"outputs": {"Normalize Alert": [norm]}})[0]
    assert "malformed" not in push["pushover"]["title"], "the builder must read a real alert, not its error path"
    return norm, push


@pytest.mark.parametrize("stage,days", [("30", 30), ("14", 14), ("7", 7), ("daily", 3), ("expired", -2),
                                         ("disappeared", 0)])
@pytest.mark.parametrize("phone", [True, False])
def test_every_payload_the_watch_really_builds_is_accepted_and_handed_on_unchanged(stage, days, phone):
    """Contract: the check admits exactly what build_payload produces, so tightening it cannot silence the watch."""
    import datetime as dt
    item = EW.Item.build(name="deploy-key", kind="ssh-key", expires=dt.date(2026, 3, 1), owner="ops@example.com",
                         runbook="https://wiki.example.com/runbooks/rotate-key")
    chans = ("discord", "pushover") if phone else ("discord",)
    notice = EW.Notice(item, stage, days, chans)
    body = EW.build_payload(notice, dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc))
    out = _check(body)
    assert out["authorized"] is True
    handed = out["body"]["alerts"][0]
    sent = body["alerts"][0]
    assert handed["labels"] == dict(sent["labels"], source="expiry-watch")
    assert handed["annotations"] == sent["annotations"] and handed["fingerprint"] == sent["fingerprint"]
    assert out["body"]["status"] == "firing" and len(out["body"]["alerts"]) == 1


def test_the_source_label_is_always_expiry_watch_and_cannot_be_chosen_by_the_caller():
    assert _check()["body"]["alerts"][0]["labels"]["source"] == "expiry-watch"
    body = _mut(lambda b, a, l, an: l.update(source="grafana"))
    _assert_denied(_run_graph(_item(body=body), env={VAR: SECRET}, start=EXPIRY_HOOK))


def test_the_check_builds_a_fresh_body_so_nothing_unlisted_is_handed_on():
    out = _check()
    assert set(out["body"]) == {"status", "alerts"}
    assert set(out["body"]["alerts"][0]) == {"labels", "annotations", "startsAt", "fingerprint"}
    assert set(out["body"]["alerts"][0]["labels"]) == {"alertname", "severity", "expiry_watch", "item", "kind",
                                                       "stage", "phone", "source"}


IMPERSONATIONS = {
    "grafana-allowlisted-name": lambda b, a, l, an: l.update(alertname="pfSense SECURITY update pending"),
    "allowlisted-name-with-prefix-trick": lambda b, a, l, an: l.update(alertname="pfSense update pending over 24h"),
    "update-security-label": lambda b, a, l, an: l.update(update_security="true"),
    "heartbeat-label": lambda b, a, l, an: l.update(heartbeat="true", phone="false"),
    "heartbeat-label-alone": lambda b, a, l, an: l.update(heartbeat="true"),
    "extra-label": lambda b, a, l, an: l.update(team="x"),
    "source-label": lambda b, a, l, an: l.update(source="grafana"),
    "name-not-in-namespace": lambda b, a, l, an: l.update(alertname="Disk full"),
    "name-differs-from-item": lambda b, a, l, an: l.update(alertname=PREFIX + "other"),
    "namespace-only-case": lambda b, a, l, an: l.update(alertname="expiry watch: deploy-key"),
    "expiry-flag-missing": lambda b, a, l, an: l.pop("expiry_watch"),
    "expiry-flag-false": lambda b, a, l, an: l.update(expiry_watch="false"),
    "expiry-flag-boolean": lambda b, a, l, an: l.update(expiry_watch=True),
    "severity-unknown": lambda b, a, l, an: l.update(severity="page-me"),
    "severity-missing": lambda b, a, l, an: l.pop("severity"),
    "severity-case": lambda b, a, l, an: l.update(severity="CRITICAL"),
    "phone-false": lambda b, a, l, an: l.update(phone="false"),
    "phone-boolean": lambda b, a, l, an: l.update(phone=True),
    "phone-yes": lambda b, a, l, an: l.update(phone="yes"),
    "stage-unknown": lambda b, a, l, an: l.update(stage="page"),
    "stage-missing": lambda b, a, l, an: l.pop("stage"),
    "kind-missing": lambda b, a, l, an: l.pop("kind"),
    "item-empty": lambda b, a, l, an: l.update(item="", alertname=PREFIX),
    "item-too-long": lambda b, a, l, an: l.update(item="x" * 101, alertname=PREFIX + "x" * 101),
    "kind-too-long": lambda b, a, l, an: l.update(kind="k" * 41),
    "label-number": lambda b, a, l, an: l.update(kind=5),
    "labels-array": lambda b, a, l, an: a.update(labels=[]),
    "labels-missing": lambda b, a, l, an: a.pop("labels"),
    "annotation-extra": lambda b, a, l, an: an.update(trigger_logic="x"),
    "annotation-number": lambda b, a, l, an: an.update(summary=5),
    "summary-too-long": lambda b, a, l, an: an.update(summary="s" * 301),
    "description-too-long": lambda b, a, l, an: an.update(description="d" * 1001),
    "annotations-array": lambda b, a, l, an: a.update(annotations=[]),
    "dashboard-url": lambda b, a, l, an: a.update(dashboardURL="https://grafana.example.com/d/x"),
    "panel-url": lambda b, a, l, an: a.update(panelURL="https://grafana.example.com/p"),
    "generator-url": lambda b, a, l, an: a.update(generatorURL="https://grafana.example.com/g"),
    "alert-extra-key": lambda b, a, l, an: a.update(valueString="x"),
    "alert-status-resolved": lambda b, a, l, an: a.update(status="resolved"),
    "top-status-resolved": lambda b, a, l, an: b.update(status="resolved"),
    "top-status-missing": lambda b, a, l, an: b.pop("status"),
    "top-extra-key": lambda b, a, l, an: b.update(externalURL="https://x.example.com"),
    "receiver-other": lambda b, a, l, an: b.update(receiver="grafana-default"),
    "two-alerts": lambda b, a, l, an: b["alerts"].append(copy.deepcopy(a)),
    "no-alerts": lambda b, a, l, an: b.update(alerts=[]),
    "alerts-object": lambda b, a, l, an: b.update(alerts={"0": a}),
    "fingerprint-allowlist-style": lambda b, a, l, an: a.update(fingerprint="DEADBEEF"),
    "fingerprint-short": lambda b, a, l, an: a.update(fingerprint="abcdef"),
    "fingerprint-missing": lambda b, a, l, an: a.pop("fingerprint"),
    "starts-at-junk": lambda b, a, l, an: a.update(startsAt="tomorrow"),
}


@pytest.mark.parametrize("name", sorted(IMPERSONATIONS))
def test_a_caller_holding_only_the_expiry_secret_cannot_send_anything_but_an_expiry_notice(name):
    """Each forged shape is denied by the check, and nothing is sent or routed."""
    body = _mut(IMPERSONATIONS[name])
    assert _check(body) == {"authorized": False}
    _assert_denied(_run_graph(_item(body=body), env={VAR: SECRET}, start=EXPIRY_HOOK, pushover_enabled=True))


def test_a_non_object_body_is_denied():
    for body in ("text", 5, None, [], [_expiry_body()], True):
        item = {"headers": {"authorization": "Bearer " + SECRET}, "body": body}
        assert _run_code_node(_by_name()[CHECK], item, {"env": {VAR: SECRET}}) == [{"authorized": False}]


@pytest.mark.parametrize("severity,phone", [("critical", True), ("critical", False), ("warning", True),
                                              ("warning", False), ("info", True), ("info", False)])
def test_an_expiry_notice_can_never_reach_a_higher_tier_than_priority_1_or_cancel_or_tag(severity, phone):
    """The tier cap: whatever the watch may legitimately send ends at Discord, or Pushover priority 1 at most."""
    norm, push = _downstream(_expiry_body(severity=severity, phone=phone))
    assert push["pushover"]["priority"] <= 1, push
    assert "retry" not in push["pushover"] and "tags" not in push["pushover"]
    assert push["cancelTag"] == ""
    assert push["enabled"] is phone
    assert norm["body"]["alerts"][0]["labels"]["source"] == "expiry-watch"
    # the legitimate case keeps working: an expired item with the phone channel pages at priority 1
    if severity == "critical" and phone:
        assert push["pushover"]["priority"] == 1


def test_no_public_allowlisted_alert_name_is_inside_the_expiry_namespace():
    """Guard: the one constant the tier cap rests on. If a name starting with the expiry prefix were ever
    allowlisted, an expiry caller could reach priority 2."""
    from test_update_alerting import _build_node
    code = _build_node()["parameters"]["jsCode"]
    names = re.findall(r"'([^']+)',?\n", code[code.index("ALLOWED_ALERTNAMES = ["):code.index("];")])
    assert names, "allowlist not found"
    assert not [n for n in names if n.startswith(PREFIX)]


def test_a_forged_grafana_payload_changes_nothing_downstream_even_if_it_were_admitted_by_name():
    """Defense in depth: the heartbeat branch is unreachable from the expiry entry for any admitted body."""
    res = _call()
    assert "Heartbeat?" in res["reached"] and "Build Heartbeat Ping" not in res["reached"]
    assert res["requests"] == []


# --- bounded work before authentication (Daybreak round 1, finding 2) --------------------------

def test_an_oversized_authorization_header_is_denied_before_any_length_dependent_work():
    code = "\n".join(ln for ln in _by_name()[CHECK]["parameters"]["jsCode"].splitlines() if not ln.lstrip().startswith("//"))
    assert "MAX_HEADER = 512" in code
    assert code.index("MAX_HEADER") < code.index("for (let i")
    long_secret = "s" * 600
    assert _check(env={VAR: long_secret}) == {"authorized": False}
    assert _run_code_node(_by_name()[CHECK], _item("Bearer " + long_secret), {"env": {VAR: long_secret}}) == [{"authorized": False}]
    # a secret that fits is still accepted at the documented maximum
    fit = "s" * 400
    assert _run_code_node(_by_name()[CHECK], _item("Bearer " + fit), {"env": {VAR: fit}})[0]["authorized"] is True


def test_the_total_body_is_bounded_by_the_field_limits():
    """Every field has a cap, so an admitted body is small; the largest one the check accepts stays under 8 KB."""
    body = _expiry_body(name="n" * 100)
    a = body["alerts"][0]
    a["labels"]["kind"] = "k" * 40
    a["annotations"] = {"summary": "s" * 300, "description": "d" * 1000}
    out = _check(body)
    assert out["authorized"] is True and len(json.dumps(out["body"])) < 8000


# --- constant-time shape -------------------------------------------------------------------

def test_the_comparison_has_no_early_exit_on_the_secret():
    """Guard (static): the loop visits every position and ORs the differences; no built-in string
    equality or search is applied to the secret or the header."""
    whole = _by_name()[CHECK]["parameters"]["jsCode"]
    code = whole[whole.index("const expected"):whole.index("if (diff === 0)")]
    assert not re.search(r"\.(startsWith|endsWith|includes|indexOf|localeCompare|match|test|split)\(", code)
    assert not re.search(r"\b(cfg|hdr)\b\s*[!=]==?", code) and not re.search(r"[!=]==?\s*\b(cfg|hdr)\b", code)
    assert "|=" in code and "^" in code, "a difference accumulator is expected"
    assert not re.search(r"\bbreak\b|\breturn\b[^;]*\bcfg\b", code)


def test_the_check_reads_exactly_one_variable_and_logs_nothing():
    code = _by_name()[CHECK]["parameters"]["jsCode"]
    assert set(re.findall(r"\$env\.(\w+)", code)) == {VAR}
    live = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("//"))
    assert "console." not in live and not re.search(r"\bthrow\b", live)
    text = ROUTER.read_text(encoding="utf-8")
    assert set(re.findall(r"\$env\.(\w+)", text)) == {VAR, "HEARTBEAT_PING_URL", "HEARTBEAT_KIND"}
    for name, n in _by_name().items():
        if name != CHECK:
            assert VAR not in json.dumps(n), name + " must not read the expiry secret"


def test_no_secret_value_is_in_the_workflow_file():
    text = ROUTER.read_text(encoding="utf-8")
    assert SECRET not in text and OTHER not in text
    assert not re.search(r"Bearer [A-Za-z0-9+/=_-]{20,}", text)


# --- the shared downstream is not weakened -------------------------------------------------

def _master_workflow():
    out = subprocess.run(["git", "show", "origin/master:n8n/grafana-alert-router.json"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_every_existing_node_and_connection_is_kept_and_only_four_nodes_are_added():
    """Guard: nothing that existed was edited; the change is purely additive."""
    wf, old = _workflow(), _master_workflow()
    for src, conn in old["connections"].items():
        assert wf["connections"][src] == conn, "an existing connection changed: " + src
    old_nodes = {n["name"]: n for n in old["nodes"]}
    for name, n in _by_name().items():
        if name in old_nodes:
            assert n == old_nodes[name], "an existing node changed: " + name
    assert set(_by_name()) - set(old_nodes) == {CHECK, GATE, DENY, EXPIRY_HOOK}
    assert set(old_nodes) <= set(_by_name())
    assert wf["settings"] == old["settings"]


def test_both_entries_feed_the_same_normalizer():
    wf = _workflow()
    assert wf["connections"][GRAFANA_HOOK]["main"][0][0]["node"] == "Normalize Alert"
    assert wf["connections"][GATE]["main"][0][0]["node"] == "Normalize Alert"


# --- live-deploy script, env example and docs -----------------------------------------------

def _setup():
    spec = importlib.util.spec_from_file_location("n8n_setup", SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_import_helper_gives_each_webhook_its_own_private_path():
    out = _setup().patch_workflow(copy.deepcopy(_workflow()), webhook_path="grafana-alerts-opaque",
                                  expiry_path="expiry-watch-alerts-opaque2")
    by = {n["name"]: n for n in out["nodes"]}
    assert by[GRAFANA_HOOK]["parameters"]["path"] == "grafana-alerts-opaque"
    assert by[EXPIRY_HOOK]["parameters"]["path"] == "expiry-watch-alerts-opaque2"
    assert by[GRAFANA_HOOK]["webhookId"] != by[EXPIRY_HOOK]["webhookId"]
    assert by[EXPIRY_HOOK]["webhookId"] != "expiry-watch-alerts", "the committed webhook id is replaced as well"


def test_the_import_helper_never_leaves_the_expiry_path_predictable():
    """With no path given the helper makes a random one, never the committed placeholder."""
    mod = _setup()
    paths = set()
    for _ in range(3):
        out = mod.patch_workflow(copy.deepcopy(_workflow()), webhook_path="grafana-alerts-x")
        p = next(n for n in out["nodes"] if n["name"] == EXPIRY_HOOK)["parameters"]["path"]
        assert re.fullmatch(r"expiry-watch-alerts-[A-Za-z0-9_-]{20,}", p), p
        paths.add(p)
    assert len(paths) == 3


def test_the_expiry_path_is_kept_in_its_own_private_file_and_reused():
    mod = _setup()
    assert mod.EXPIRY_PATH_FILE != mod.PATH_FILE and mod.EXPIRY_PATH_FILE.endswith("expiry-path")
    saved = "expiry-watch-alerts-" + "A" * 24
    assert mod.choose_webhook_path(saved + "\n", prefix=mod.EXPIRY_PATH_PREFIX) == saved
    # a Grafana path is never accepted as the expiry path, and the reverse
    assert mod.choose_webhook_path("grafana-alerts-" + "A" * 24, token_fn=lambda: "N",
                                   prefix=mod.EXPIRY_PATH_PREFIX) == "expiry-watch-alerts-N"
    assert mod.choose_webhook_path(saved, token_fn=lambda: "N") == "grafana-alerts-N"
    text = SETUP.read_text(encoding="utf-8")
    assert "umask(0o077)" in text and text.count("EXPIRY_PATH_FILE") >= 3


def test_env_example_lists_the_name_only_commented_and_empty():
    lines = [ln for ln in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines() if VAR in ln]
    assert "# " + VAR + "=" in lines, lines
    assert not any(ln.startswith(VAR) for ln in lines), "must stay commented out"


def test_docs_name_the_variable_the_reason_and_the_owner_steps():
    text = DOC.read_text(encoding="utf-8")
    for needle in (VAR, "Expiry Watch Webhook", "expiry-watch-alerts", "N8N_BLOCK_ENV_ACCESS_IN_NODE", "403",
                   "Owner steps", "EXPIRY_WATCH_ROUTER_TOKEN", "own endpoint", "expiry-path", "N8N_PAYLOAD_SIZE_MAX",
                   "16 MiB", "source=expiry-watch", "rate limit", "512", "priority 1"):
        assert needle in text, needle
    assert VAR in RUNBOOK.read_text(encoding="utf-8")
    upd = UPDATE_DOC.read_text(encoding="utf-8")
    assert VAR in upd and "Expiry Watch Webhook" in upd
    for t in (text, upd, RUNBOOK.read_text(encoding="utf-8")):
        assert SECRET not in t and OTHER not in t
