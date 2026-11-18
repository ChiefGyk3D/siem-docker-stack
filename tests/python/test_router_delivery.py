"""Delivery guarantees of the alert router (issues #78 and #79).

The webhook answers only after the channel steps finish, a failed Discord step fails
the run (an error response, and the error workflow fires), a failed Pushover step
never blocks Discord and shows up as a short Discord notice, and the error handler
reports a failed run without ever carrying the alert payload or headers.

The graph is walked with the evaluator in test_update_alerting.py (it models the
node types the router uses). It is a model, not n8n: the response-node behavior is
unverified against a live n8n and the docs say so.
"""
import json
import re

import pytest

from conftest import REPO_ROOT
from test_update_alerting import (DISCORD_FIRING, DISCORD_RESOLVED, GOOD_NAME, ROUTING_CASES, _alert,
                                  _edges, _expressions, _eval_many, _nodes, _reachable, _run_code_node,
                                  _run_graph, _workflow)

HANDLER = REPO_ROOT / "n8n" / "alert-router-error-handler.json"
MALFORMED = "Discord — Malformed"
NOTICE_SEND = "Discord — Phone Failed (send)"
NOTICE_CANCEL = "Discord — Phone Failed (cancel)"
MARKER = "SUMMARY-MARKER-XYZ"
DISCORD_NODES = (DISCORD_FIRING, DISCORD_RESOLVED, MALFORMED)


def _item(status, phone=True, severity="warning"):
    labels = {"severity": severity}
    if phone:
        labels["phone"] = "true"
    body = _alert(status, labels)
    body["alerts"][0]["annotations"] = {"summary": MARKER}
    return {"headers": {"authorization": "Bearer HEADER-MARKER-XYZ"}, "body": body}


# --- the response comes after the channel steps -----------------------------------

def test_webhook_answers_through_a_response_node_not_at_once():
    hook = next(n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.webhook")
    assert hook["parameters"]["responseMode"] == "responseNode"
    assert hook["parameters"]["authentication"] == "headerAuth"
    responds = [n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.respondToWebhook"]
    assert len(responds) == 1
    params = responds[0]["parameters"]
    assert params["respondWith"] == "json"
    assert not list(_expressions(params)), "the response body is static: it never echoes the alert"
    assert json.loads(params["responseBody"])["status"] == "delivered"


def test_every_channel_step_runs_before_the_response():
    wf = _workflow()
    edges = _edges(wf)
    respond = next(n["name"] for n in wf["nodes"] if n["type"] == "n8n-nodes-base.respondToWebhook")
    channel = [n["name"] for n in wf["nodes"] if n["type"] in ("n8n-nodes-base.discord", "n8n-nodes-base.httpRequest")]
    assert len(channel) >= 7
    for name in channel:
        # the response is reachable from every channel node, and the node is not downstream of it
        assert respond in _reachable(name, edges), name
        assert name not in _reachable(respond, edges), name


def test_error_capable_nodes_have_their_error_outputs_wired():
    wf = _workflow()
    nodes = {n["name"]: n for n in wf["nodes"]}
    for name in DISCORD_NODES + ("Pushover Notify", "Pushover Cancel Repeats"):
        assert nodes[name]["onError"] == "continueErrorOutput", name
        main = wf["connections"][name]["main"]
        assert len(main) == 2 and main[0] and main[1], f"{name}: both outputs must be wired"
    for name in (NOTICE_SEND, NOTICE_CANCEL):
        assert nodes[name]["onError"] == "continueRegularOutput", name


# --- success, Discord failure, Pushover failure ---------------------------------------

@pytest.mark.parametrize("case", sorted(ROUTING_CASES))
def test_every_earlier_case_still_ends_in_a_200_response(case):
    body, expected = ROUTING_CASES[case]
    res = _run_graph({"headers": {}, "body": body})
    assert res["response"] == "200" and not res["failed"]
    assert expected in res["notified"]


@pytest.mark.parametrize("status,node", [("firing", DISCORD_FIRING), ("resolved", DISCORD_RESOLVED)])
def test_a_failed_discord_step_fails_the_run_and_the_phone_still_gets_it(status, node):
    res = _run_graph(_item(status), pushover_enabled=True, fail={node})
    assert res["response"] == "error", "the webhook must answer with an error so Grafana retries"
    assert node in res["error"] and "Discord delivery failed" in res["error"]
    assert "Pushover Notify" in res["notified"], "a Discord failure must not silence the phone"


def test_a_failed_malformed_notice_also_fails_the_run():
    res = _run_graph({"headers": {}, "body": {"status": "weird"}}, fail={MALFORMED})
    assert res["response"] == "error" and MALFORMED in res["error"]


def test_the_failure_message_carries_no_alert_content():
    res = _run_graph(_item("firing"), pushover_enabled=True, fail={DISCORD_FIRING})
    assert MARKER not in res["error"] and "HEADER-MARKER" not in res["error"] and "Bearer" not in res["error"]
    assert len(res["error"]) < 300


@pytest.mark.parametrize("status,fail_node,notice", [
    ("firing", "Pushover Notify", NOTICE_SEND),
    ("resolved", "Pushover Notify", NOTICE_SEND),
    ("resolved", "Pushover Cancel Repeats", NOTICE_CANCEL),
])
def test_a_failed_pushover_step_never_blocks_discord_and_leaves_a_notice(status, fail_node, notice):
    res = _run_graph(_item(status), pushover_enabled=True, fail={fail_node})
    assert res["response"] == "200", "a phone failure must not fail the run"
    assert (DISCORD_FIRING if status == "firing" else DISCORD_RESOLVED) in res["notified"]
    assert notice in res["notified"], "the failure must be visible in Discord"


def test_the_phone_failure_notice_is_short_and_has_no_payload_or_headers():
    wf = _workflow()
    for name, step in ((NOTICE_SEND, "Pushover Notify"), (NOTICE_CANCEL, "Pushover Cancel Repeats")):
        node = next(n for n in wf["nodes"] if n["name"] == name)
        ctx = {"outputs": {"Build Pushover Payload": [{"pushover": {"title": MARKER, "message": MARKER}}],
                           "Normalize Alert": [{"body": {"alerts": [{"annotations": {"summary": MARKER}}]}}]},
               "prev": step}
        item = {"error": {"message": "x" * 500 + " Bearer HEADER-MARKER-XYZ"}}
        codes = list(_expressions(node["parameters"]))
        assert codes
        texts = [str(r.get("v")) for r in _eval_many(codes, item, ctx)]
        blob = " ".join(texts) + json.dumps(node["parameters"])
        assert "phone delivery failed" in blob
        assert MARKER not in blob and "HEADER-MARKER" not in " ".join(texts)
        assert step in blob
        assert max(len(t) for t in texts) <= 400


def test_a_failed_notice_does_not_fail_the_run():
    res = _run_graph(_item("firing"), pushover_enabled=True, fail={"Pushover Notify", NOTICE_SEND})
    assert res["response"] == "200"


def test_without_the_phone_label_nothing_pushes_and_discord_failure_still_fails():
    ok = _run_graph(_item("firing", phone=False), pushover_enabled=True)
    assert ok["response"] == "200" and "Pushover Notify" not in ok["notified"]
    bad = _run_graph(_item("firing", phone=False), pushover_enabled=True, fail={DISCORD_FIRING})
    assert bad["response"] == "error"


def test_the_fail_run_node_is_the_only_way_to_an_error_and_names_no_payload():
    node = _nodes()["Fail Run"]
    assert node["type"] == "n8n-nodes-base.stopAndError"
    codes = list(_expressions(node["parameters"]))
    assert codes and not re.search(r"body|headers|labels|annotations|\$json", " ".join(codes))


# --- the error workflow setting ----------------------------------------------------------

def test_router_points_at_the_error_workflow_placeholder():
    settings = _workflow()["settings"]
    assert settings["errorWorkflow"] == "ERROR_WORKFLOW_ID"
    assert settings["saveDataErrorExecution"] == "none"


# --- the error handler workflow ---------------------------------------------------------------

def _handler():
    return json.loads(HANDLER.read_text(encoding="utf-8"))


def _hnodes():
    return {n["name"]: n for n in _handler()["nodes"]}


def _hbuilder():
    return next(n for n in _handler()["nodes"] if n["type"] == "n8n-nodes-base.code")


def test_handler_starts_at_an_error_trigger_and_stores_nothing():
    wf = _handler()
    triggers = [n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.errorTrigger"]
    assert len(triggers) == 1
    s = wf["settings"]
    assert s["saveDataSuccessExecution"] == "none" and s["saveDataErrorExecution"] == "none"
    assert s["saveManualExecutions"] is False and s["saveExecutionProgress"] is False
    assert wf.get("active") is False
    assert "errorWorkflow" not in s
    edges = _edges(wf)
    names = {n["name"] for n in wf["nodes"]}
    assert _reachable(triggers[0]["name"], edges) == names


def test_handler_channels_are_independent_of_discord_by_default():
    code = _hbuilder()["parameters"]["jsCode"]
    assert re.search(r"(?m)^const NOTIFY_PUSHOVER = true;", code)
    assert re.search(r"(?m)^const NOTIFY_DISCORD = false;", code)
    nodes = _hnodes()
    pushover = [n for n in nodes.values() if n["type"] == "n8n-nodes-base.httpRequest"]
    assert len(pushover) == 1 and "api.pushover.net/1/messages.json" in pushover[0]["parameters"]["url"]
    assert pushover[0]["credentials"]["httpCustomAuth"]["name"] == "pushover-api"
    assert pushover[0]["parameters"]["jsonBody"] == "={{ JSON.stringify($json.pushover) }}"
    assert "priority: 1" in code
    assert "$env" not in HANDLER.read_text(encoding="utf-8")


ERROR_ITEM = {
    "execution": {"id": "4242", "url": "http://n8n.example.com/execution/4242", "mode": "webhook",
                  "error": {"message": "Discord delivery failed: boom", "stack": "STACK-MARKER-XYZ"},
                  "lastNodeExecuted": "Fail Run",
                  "data": {"body": {"alerts": [{"labels": {"alertname": "LABEL-MARKER-XYZ"}}]}}},
    "workflow": {"id": "abcdef0123456789", "name": "Grafana SOAR - Alert Router"},
    "headers": {"authorization": "Bearer HEADER-MARKER-XYZ"},
    "body": {"alerts": [{"labels": {"alertname": "LABEL-MARKER-XYZ"},
                         "annotations": {"summary": "ANNOTATION-MARKER-XYZ"}}]},
    "labels": {"a": "LABEL-MARKER-XYZ"}, "annotations": {"summary": "ANNOTATION-MARKER-XYZ"},
}
FORBIDDEN = ("MARKER", "Bearer", "authorization", "ANNOTATION", "LABEL")


def test_handler_message_has_the_four_facts_and_never_the_payload():
    out = _run_code_node(_hbuilder(), ERROR_ITEM)[0]
    text = json.dumps(out)
    for needle in ("Grafana SOAR - Alert Router", "Fail Run", "Discord delivery failed: boom", "4242"):
        assert needle in text, needle
    for bad in FORBIDDEN:
        assert bad not in text, bad
    assert out["pushover"]["priority"] == 1
    assert len(out["pushover"]["title"]) <= 250 and len(out["pushover"]["message"]) <= 1024
    assert out["pushoverOn"] is True and out["discordOn"] is False


def test_handler_trims_the_error_message_to_300_characters():
    item = json.loads(json.dumps(ERROR_ITEM))
    item["execution"]["error"]["message"] = "e" * 5000
    out = _run_code_node(_hbuilder(), item)[0]
    assert "e" * 300 in out["pushover"]["message"] and "e" * 301 not in out["pushover"]["message"]


@pytest.mark.parametrize("item", [
    {}, {"execution": None, "workflow": None}, {"execution": "x", "workflow": []},
    {"execution": {"error": {"message": {"a": 1}}, "id": {"b": 2}, "lastNodeExecuted": 7}, "workflow": {"name": 5}},
    {"execution": {"error": None}, "workflow": {"name": ["x"]}},
])
def test_handler_never_throws_on_odd_error_data(item):
    out = _run_code_node(_hbuilder(), item)[0]
    assert out["pushover"]["priority"] == 1 and out["pushover"]["message"]


def test_handler_code_reads_only_execution_and_workflow():
    code = _hbuilder()["parameters"]["jsCode"]
    assert not re.search(r"\b(body|headers|labels|annotations)\b", code)
    assert "JSON.stringify" not in code, "never dump a whole object into the message"
    assert re.search(r"\bexecution\b", code) and re.search(r"\bworkflow\b", code)


def test_handler_second_channel_is_a_static_template_over_the_built_text():
    nodes = _hnodes()
    discord = [n for n in nodes.values() if n["type"] == "n8n-nodes-base.discord"]
    assert len(discord) == 1
    for code in _expressions(discord[0]["parameters"]):
        assert not re.search(r"body|headers|labels|annotations", code)
    assert nodes["Pushover Send"].get("onError") == "continueRegularOutput"


# --- docs --------------------------------------------------------------------------------

def test_docs_describe_delivery_failure_reporting_and_what_is_unverified():
    doc = " ".join((REPO_ROOT / "docs" / "update-alerting.md").read_text(encoding="utf-8").split())
    for needle in ("responseMode: responseNode", "Respond to Webhook", "continueErrorOutput", "Stop and Error",
                   "phone delivery failed", "ERROR_WORKFLOW_ID", "NOTIFY_DISCORD", "NOTIFY_PUSHOVER",
                   "Failed runs stay unsaved by design", "Unverified against a live n8n"):
        assert needle in doc, needle
    runbook = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("--error-workflow", "--error-workflow-id", "error handler", "docker restart n8n",
                   "break the `Discord - Firing` node", "failure notice"):
        assert needle in runbook, needle
    assert runbook.index("--error-workflow n8n/") < runbook.index("--workflow n8n/grafana-alert-router.json"), \
        "handler is imported before the router"
