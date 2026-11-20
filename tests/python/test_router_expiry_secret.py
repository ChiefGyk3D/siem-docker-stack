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

from conftest import REPO_ROOT
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


def _item(auth="Bearer " + SECRET, status="firing"):
    headers = {} if auth is None else {"authorization": auth}
    body = _alert(status, {"severity": "warning"}, name="Expiry watch notice")
    return {"headers": headers, "body": body}


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


def test_a_resolved_notice_is_accepted_the_same_way():
    res = _run_graph(_item(status="resolved"), env={VAR: SECRET}, start=EXPIRY_HOOK)
    assert res["response"] == "200" and "Discord — Resolved" in res["notified"]


def test_the_check_output_carries_the_body_and_no_header_or_secret():
    """Guard: neither the header nor either secret travels past the check node."""
    node = _by_name()[CHECK]
    out = _run_code_node(node, _item(), {"env": {VAR: SECRET}})
    assert len(out) == 1 and out[0]["authorized"] is True
    assert out[0]["body"] == _item()["body"]
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


# --- constant-time shape -------------------------------------------------------------------

def test_the_comparison_has_no_early_exit_on_the_secret():
    """Guard (static): the loop visits every position and ORs the differences; no built-in string
    equality or search is applied to the secret or the header."""
    code = _by_name()[CHECK]["parameters"]["jsCode"]
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

def test_the_import_helper_changes_only_the_grafana_webhook_path():
    spec = importlib.util.spec_from_file_location("n8n_setup", SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = mod.patch_workflow(copy.deepcopy(_workflow()), webhook_path="grafana-alerts-opaque")
    by = {n["name"]: n for n in out["nodes"]}
    assert by[GRAFANA_HOOK]["parameters"]["path"] == "grafana-alerts-opaque"
    assert by[EXPIRY_HOOK]["parameters"]["path"] == "expiry-watch-alerts"
    assert by[EXPIRY_HOOK]["webhookId"] == "expiry-watch-alerts"
    assert by[GRAFANA_HOOK]["webhookId"] != by[EXPIRY_HOOK]["webhookId"]


def test_env_example_lists_the_name_only_commented_and_empty():
    lines = [ln for ln in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines() if VAR in ln]
    assert "# " + VAR + "=" in lines, lines
    assert not any(ln.startswith(VAR) for ln in lines), "must stay commented out"


def test_docs_name_the_variable_the_reason_and_the_owner_steps():
    text = DOC.read_text(encoding="utf-8")
    for needle in (VAR, "Expiry Watch Webhook", "expiry-watch-alerts", "N8N_BLOCK_ENV_ACCESS_IN_NODE", "403",
                   "Owner steps", "EXPIRY_WATCH_ROUTER_TOKEN", "own endpoint"):
        assert needle in text, needle
    assert VAR in RUNBOOK.read_text(encoding="utf-8")
    upd = UPDATE_DOC.read_text(encoding="utf-8")
    assert VAR in upd and "Expiry Watch Webhook" in upd
    for t in (text, upd, RUNBOOK.read_text(encoding="utf-8")):
        assert SECRET not in t and OTHER not in t
