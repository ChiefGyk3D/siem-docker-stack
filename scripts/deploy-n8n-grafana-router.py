#!/usr/bin/env python3
"""Deploy Grafana Alert Router workflow in N8N.

Strategy: Create a simple webhook-only workflow via the public API, activate
it via the public API, then PATCH the full workflow (with switch + Discord
nodes) via the internal REST API.  The public API has a validation bug with
switch nodes that prevents direct creation/activation of workflows containing
them.  The internal REST API (same as the N8N UI) does not have this issue.

Usage:
    ssh user@siem-server 'python3 -' < scripts/deploy-n8n-grafana-router.py

Required environment variables (or edit the Configuration section below):
    N8N_BASE            N8N base URL (e.g. http://172.20.0.16:80)
    N8N_API_KEY         N8N public API key
    N8N_EMAIL           N8N login email
    N8N_PASSWORD        N8N login password
    DISCORD_WEBHOOK_URL Discord incoming-webhook URL
    DISCORD_MENTION     Discord user/role mention (e.g. <@USER_ID>)
"""
import json
import os
import urllib.request
import urllib.error
import http.cookiejar
import uuid

# ── Configuration ──────────────────────────────────────────────────────
# Set these via environment variables or edit the defaults below.
N8N_BASE = os.environ.get("N8N_BASE", "http://172.20.0.16:80")
N8N_API = f"{N8N_BASE}/api/v1"
N8N_KEY = os.environ.get("N8N_API_KEY", "YOUR_N8N_API_KEY")
N8N_EMAIL = os.environ.get("N8N_EMAIL", "admin@example.com")
N8N_PASSWORD = os.environ.get("N8N_PASSWORD", "changeme")
DISCORD_URL = os.environ.get("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN")
DISCORD_MENTION = os.environ.get("DISCORD_MENTION", "<@YOUR_DISCORD_USER_ID>")
WORKFLOW_NAME = "Grafana SOAR — Alert Router"

API_HEADERS = {"X-N8N-API-KEY": N8N_KEY, "Content-Type": "application/json"}

# ── Minimal workflow (webhook only — passes public API validation) ─────
SIMPLE_WORKFLOW = {
    "name": WORKFLOW_NAME,
    "nodes": [
        {
            "parameters": {"httpMethod": "POST", "path": "grafana-alerts", "options": {}},
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2.1,
            "position": [0, 300],
            "id": str(uuid.uuid4()),
            "name": "Grafana Webhook",
            "webhookId": "grafana-alerts",
        },
    ],
    "connections": {},
    "settings": {"executionOrder": "v1"},
}


def build_full_workflow(wf_id, version_id):
    """Return the complete workflow payload for the internal REST API."""
    # N8N editor requires UUID-format node IDs to render the canvas
    wh_id = str(uuid.uuid4())
    sw_id = str(uuid.uuid4())
    df_id = str(uuid.uuid4())
    dr_id = str(uuid.uuid4())
    return {
        "id": wf_id,
        "name": WORKFLOW_NAME,
        "active": True,
        "versionId": version_id,
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "grafana-alerts", "options": {}},
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2.1,
                "position": [0, 300],
                "id": wh_id,
                "name": "Grafana Webhook",
                "webhookId": "grafana-alerts",
            },
            {
                "parameters": {
                    "rules": {
                        "values": [
                            {
                                "conditions": {
                                    "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
                                    "conditions": [{"id": "firing", "leftValue": "={{ $json.body.status }}", "rightValue": "firing",
                                        "operator": {"type": "string", "operation": "equals"}}],
                                    "combinator": "and",
                                },
                                "outputIndex": 0, "renameOutput": True, "outputKey": "Firing",
                            },
                            {
                                "conditions": {
                                    "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
                                    "conditions": [{"id": "resolved", "leftValue": "={{ $json.body.status }}", "rightValue": "resolved",
                                        "operator": {"type": "string", "operation": "equals"}}],
                                    "combinator": "and",
                                },
                                "outputIndex": 1, "renameOutput": True, "outputKey": "Resolved",
                            },
                        ],
                    },
                    "options": {"fallbackOutput": {"type": "extra", "outputIndex": 2}},
                },
                "type": "n8n-nodes-base.switch",
                "typeVersion": 3.2,
                "position": [300, 300],
                "id": sw_id,
                "name": "Alert Status",
            },
            {
                "parameters": {
                    "method": "POST", "url": DISCORD_URL,
                    "sendHeaders": True,
                    "headerParameters": {"parameters": [{"name": "Content-Type", "value": "application/json"}]},
                    "sendBody": True, "specifyBody": "json",
                    "jsonBody": '={\n  "content": "' + DISCORD_MENTION + '",\n  "embeds": [{\n    "title": "\ud83d\udd25 FIRING \u2014 {{ ($json.body.alerts || [{}])[0].labels?.alertname || \'Grafana Alert\' }}",\n    "description": "{{ ($json.body.alerts || [{}])[0].annotations?.summary || \'Alert triggered\' }}",\n    "color": 15158332,\n    "fields": [\n      { "name": "Severity", "value": "{{ ($json.body.alerts || [{}])[0].labels?.severity || \'unknown\' }}", "inline": true },\n      { "name": "Instance", "value": "{{ ($json.body.alerts || [{}])[0].labels?.instance_name || ($json.body.alerts || [{}])[0].labels?.instance || \'N/A\' }}", "inline": true },\n      { "name": "Details", "value": "{{ ($json.body.alerts || [{}])[0].annotations?.description || \'\' }}", "inline": false }\n    ],\n    "timestamp": "{{ ($json.body.alerts || [{}])[0].startsAt || new Date().toISOString() }}"\n  }]\n}',
                    "options": {},
                },
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [600, 200],
                "id": df_id,
                "name": "Discord \u2014 Firing",
            },
            {
                "parameters": {
                    "method": "POST", "url": DISCORD_URL,
                    "sendHeaders": True,
                    "headerParameters": {"parameters": [{"name": "Content-Type", "value": "application/json"}]},
                    "sendBody": True, "specifyBody": "json",
                    "jsonBody": '={\n  "embeds": [{\n    "title": "\u2705 RESOLVED \u2014 {{ ($json.body.alerts || [{}])[0].labels?.alertname || \'Grafana Alert\' }}",\n    "description": "{{ ($json.body.alerts || [{}])[0].annotations?.summary || \'Alert resolved\' }}",\n    "color": 3066993,\n    "fields": [\n      { "name": "Instance", "value": "{{ ($json.body.alerts || [{}])[0].labels?.instance_name || \'N/A\' }}", "inline": true }\n    ],\n    "timestamp": "{{ ($json.body.alerts || [{}])[0].endsAt || new Date().toISOString() }}"\n  }]\n}',
                    "options": {},
                },
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [600, 400],
                "id": dr_id,
                "name": "Discord \u2014 Resolved",
            },
        ],
        "connections": {
            "Grafana Webhook": {"main": [[{"node": "Alert Status", "type": "main", "index": 0}]]},
            "Alert Status": {
                "main": [
                    [{"node": "Discord \u2014 Firing", "type": "main", "index": 0}],
                    [{"node": "Discord \u2014 Resolved", "type": "main", "index": 0}],
                    [],
                ]
            },
        },
        "settings": {"executionOrder": "v1", "callerPolicy": "workflowsFromSameOwner"},
    }


def main():
    # Step 1: Check if workflow already exists (by name)
    list_req = urllib.request.Request(f"{N8N_API}/workflows?limit=50", headers=API_HEADERS)
    existing = json.loads(urllib.request.urlopen(list_req).read())
    wf_id = None
    for wf in existing.get("data", []):
        if wf["name"] == WORKFLOW_NAME:
            wf_id = wf["id"]
            is_active = wf["active"]
            print(f"Found existing workflow: {wf_id} (active={is_active})")
            break

    if wf_id is None:
        # Step 2a: Create simple webhook-only workflow via public API
        body = json.dumps(SIMPLE_WORKFLOW).encode()
        req = urllib.request.Request(f"{N8N_API}/workflows", data=body, headers=API_HEADERS, method="POST")
        try:
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read())
            wf_id = data["id"]
            print(f"Created simple workflow: {wf_id}")
        except urllib.error.HTTPError as e:
            print(f"Create failed: {e.code} {e.read().decode()}")
            return

        # Step 2b: Activate via public API (works for simple workflows)
        act_req = urllib.request.Request(f"{N8N_API}/workflows/{wf_id}/activate", data=b"", headers=API_HEADERS, method="POST")
        try:
            act_resp = urllib.request.urlopen(act_req)
            act_data = json.loads(act_resp.read())
            print(f"Activated: {act_data.get('active')}")
        except urllib.error.HTTPError as e:
            print(f"Activate failed: {e.code} {e.read().decode()}")

    # Step 3: Login to internal REST API
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    login_body = json.dumps({"emailOrLdapLoginId": N8N_EMAIL, "password": N8N_PASSWORD}).encode()
    login_req = urllib.request.Request(f"{N8N_BASE}/rest/login", data=login_body,
                                       headers={"Content-Type": "application/json"}, method="POST")
    try:
        opener.open(login_req)
    except urllib.error.HTTPError:
        print("Login failed — cannot update workflow")
        return

    # Step 4: Get current versionId
    get_req = urllib.request.Request(f"{N8N_BASE}/rest/workflows/{wf_id}")
    wf_data = json.loads(opener.open(get_req).read())
    rd = wf_data.get("data", wf_data)
    version_id = rd.get("versionId", "")

    # Step 5: PATCH full workflow via internal REST API (bypasses switch node bug)
    full = build_full_workflow(wf_id, version_id)
    patch_body = json.dumps(full).encode()
    patch_req = urllib.request.Request(f"{N8N_BASE}/rest/workflows/{wf_id}", data=patch_body,
                                       headers={"Content-Type": "application/json"}, method="PATCH")
    try:
        patch_resp = opener.open(patch_req)
        result = json.loads(patch_resp.read())
        rd = result.get("data", result)
        print(f"✓ Deployed: name={rd.get('name')}, active={rd.get('active')}, nodes={len(rd.get('nodes', []))}")
    except urllib.error.HTTPError as e:
        print(f"PATCH failed: {e.code} {e.read().decode()[:500]}")


if __name__ == "__main__":
    main()
