#!/usr/bin/env python3
"""Create the two n8n credentials and import the authenticated alert router.

Runs on the SIEM host under siem-run, so the three values arrive in the
environment: GRAFANA_WEBHOOK_SECRET, PUSHOVER_API_KEY (app token) and
PUSHOVER_USER_KEY. It never prints a value. Credentials go to n8n over stdin to
`n8n import:credentials` inside the container (n8n encrypts them), so no file
with a value is left on the host.

Usage:
  siem-run python3 -I n8n-setup-alert-router.py --check
  siem-run python3 -I n8n-setup-alert-router.py --credentials
  siem-run python3 -I n8n-setup-alert-router.py --error-workflow handler.json [HANDLER_ID]
  siem-run python3 -I n8n-setup-alert-router.py --workflow router.json [WORKFLOW_ID] [--pushover-on] [--error-workflow-id HANDLER_ID]

Import order: the error handler first (--error-workflow prints its id), then the
router with that id (--workflow ... --error-workflow-id ID), so the router's
errorWorkflow setting points at a real workflow. Both import inactive. A re-run
with the same id overwrites. Without --error-workflow-id the router keeps no
errorWorkflow setting (a placeholder id would be rejected by n8n).

Environment (all optional, the current values are the defaults):
  SIEM_CONFIG_DIR         private config directory (default: $HOME/.config/doppler-siem);
                          holds the file "router-path" with the private webhook path
  N8N_CONTAINER           n8n container name (default: n8n)
  GRAFANA_CONTAINER       Grafana container name, read for the dashboard origin
                          (default: grafana)
  N8N_CRED_HEADER_ID      id for the grafana-webhook-auth credential (default: gfwebhookauth01)
  N8N_CRED_PUSHOVER_ID    id for the pushover-api credential (default: pushoverapi0001)
  N8N_CRED_DISCORD_ID     id of the existing Discord webhook credential in n8n
                          (default: dscwhk1479574998; an n8n internal id, not a secret)
  N8N_DISCORD_CRED_NAME   name of that credential (default: Discord Webhook Alerts)
  N8N_ROUTER_NAME         name given to the imported router workflow
  N8N_HANDLER_NAME        name given to the imported error handler workflow
"""
import json
import os
import re
import secrets
import subprocess
import sys
import uuid

CONTAINER = os.environ.get("N8N_CONTAINER", "n8n")
GRAFANA_CONTAINER = os.environ.get("GRAFANA_CONTAINER", "grafana")
CONFIG_DIR = os.environ.get("SIEM_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "doppler-siem")
PATH_FILE = os.path.join(CONFIG_DIR, "router-path")
CRED_HEADER_ID = os.environ.get("N8N_CRED_HEADER_ID", "gfwebhookauth01")
CRED_PUSHOVER_ID = os.environ.get("N8N_CRED_PUSHOVER_ID", "pushoverapi0001")
CRED_DISCORD_ID = os.environ.get("N8N_CRED_DISCORD_ID", "dscwhk1479574998")
DISCORD_NAME = os.environ.get("N8N_DISCORD_CRED_NAME", "Discord Webhook Alerts")
NEW_NAME = os.environ.get("N8N_ROUTER_NAME", "Grafana SOAR — Alert Router (authenticated)")
NEEDED = ("GRAFANA_WEBHOOK_SECRET", "PUSHOVER_API_KEY", "PUSHOVER_USER_KEY")
HANDLER_NAME = os.environ.get("N8N_HANDLER_NAME", "Alert Router Error Handler")
ERROR_PLACEHOLDER = "ERROR_WORKFLOW_ID"
PATH_PREFIX = "grafana-alerts-"
STRIP_KEYS = ("activeVersionId", "shared", "versionMetadata", "versionCounter",
              "createdAt", "updatedAt", "triggerCount", "pinData", "isArchived")


def need(name):
    value = os.environ.get(name, "")
    if not value:
        sys.exit("missing environment value: " + name)
    return value


def docker_in(script, payload):
    """Feed payload to a shell script inside the n8n container over stdin."""
    proc = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "sh", "-c", script],
        input=payload.encode(),
        capture_output=True,
        check=False,
    )
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    # Never echo anything that could contain a value; keep only plain status lines.
    lines = [ln for ln in out.splitlines() if ln.strip() and "Error tracking" not in ln]
    return proc.returncode, lines


def docker_out(*args):
    proc = subprocess.run(["docker", *args], capture_output=True, check=False)
    return proc.returncode, proc.stdout.decode(errors="replace").strip()


# ---- pure logic (importable, no docker, no files) -------------------------------

def build_credentials(secret, token, user):
    """The two n8n credential records, as `n8n import:credentials` takes them."""
    return [
        {
            "id": CRED_HEADER_ID,
            "name": "grafana-webhook-auth",
            "type": "httpHeaderAuth",
            "data": {"name": "Authorization", "value": "Bearer " + secret},
        },
        {
            "id": CRED_PUSHOVER_ID,
            "name": "pushover-api",
            "type": "httpCustomAuth",
            "data": {"json": json.dumps({"body": {"token": token, "user": user}})},
        },
    ]


def credential_id_map():
    """Credential name -> the n8n credential id this tooling creates or expects."""
    return {
        "grafana-webhook-auth": CRED_HEADER_ID,
        "pushover-api": CRED_PUSHOVER_ID,
        DISCORD_NAME: CRED_DISCORD_ID,
    }


def choose_webhook_path(existing, token_fn=None):
    """Reuse the saved private path when it looks right, else make a new one."""
    existing = (existing or "").strip()
    if existing.startswith(PATH_PREFIX) and len(existing) >= 20:
        return existing
    return PATH_PREFIX + (token_fn or (lambda: secrets.token_urlsafe(18)))()


def valid_origin(text):
    """A plain http(s) origin (host and optional port, no path), else empty."""
    if re.match(r"^https?://[A-Za-z0-9.\-]+(:[0-9]+)?/?$", text or ""):
        return text.rstrip("/")
    return ""


def check_id(value, what="workflow id"):
    if value and not re.match(r"^[0-9a-f]{16}$", value):
        raise ValueError(what + " must be 16 hex characters")


def patch_error_workflow(wf, reuse_id="", new_id=None):
    """Return the error handler workflow patched for import (inactive, ids mapped)."""
    check_id(reuse_id)
    for key in STRIP_KEYS:
        wf.pop(key, None)
    wf["id"] = reuse_id or new_id or secrets.token_hex(8)
    wf["name"] = HANDLER_NAME
    wf["active"] = False
    ids = credential_id_map()
    for node in wf["nodes"]:
        for cred in (node.get("credentials") or {}).values():
            if cred.get("name") in ids:
                cred["id"] = ids[cred["name"]]
    return wf


def parse_workflow_args(rest):
    """Parse the arguments after the workflow file: (reuse_id, pushover_on, error_workflow_id)."""
    reuse_id, error_id, pushover_on, i = "", "", False, 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--pushover-on":
            pushover_on = True
        elif arg == "--error-workflow-id":
            if i + 1 >= len(rest):
                raise ValueError("--error-workflow-id needs an id")
            error_id = rest[i + 1]
            i += 1
        elif not reuse_id:
            reuse_id = arg
        else:
            raise ValueError("unexpected argument: " + arg)
        i += 1
    return reuse_id, pushover_on, error_id


def patch_workflow(wf, reuse_id="", pushover_on=False, origin="", webhook_path="",
                   webhook_id=None, new_id=None, error_workflow_id=""):
    """Return the workflow patched for import. Mutates and returns wf."""
    check_id(reuse_id)
    check_id(error_workflow_id, "error workflow id")
    for key in STRIP_KEYS:
        wf.pop(key, None)
    # n8n requires an id. Reuse the id of an earlier import of THIS workflow so a re-run
    # overwrites it; otherwise make a fresh one, which can never overwrite another workflow.
    wf["id"] = reuse_id or new_id or secrets.token_hex(8)
    wf["name"] = NEW_NAME
    wf["active"] = False
    settings = wf.setdefault("settings", {})
    if error_workflow_id:
        settings["errorWorkflow"] = error_workflow_id
    else:
        settings.pop("errorWorkflow", None)
    ids = credential_id_map()
    for node in wf["nodes"]:
        for cred in (node.get("credentials") or {}).values():
            if cred.get("name") in ids:
                cred["id"] = ids[cred["name"]]
        if node["type"].endswith(".webhook") and node["name"] == "Grafana Webhook":
            # only Grafana's entry gets the private path; the expiry watch's entry keeps its fixed one
            node["parameters"]["path"] = webhook_path
            # With a webhookId the production URL is /webhook/<path>; without one n8n
            # serves it under /webhook/<workflowId>/<node name>/<path>.
            node["webhookId"] = webhook_id or str(uuid.uuid4())
        code = node.get("parameters", {}).get("jsCode")
        if code and "PUSHOVER_ENABLED" in code and pushover_on:
            code = re.sub(r"const PUSHOVER_ENABLED = (false|true);",
                          "const PUSHOVER_ENABLED = true;", code, count=1)
            node["parameters"]["jsCode"] = code
        if code and "ALLOWED_DASHBOARD_ORIGIN" in code and origin:
            code = re.sub(r"const ALLOWED_DASHBOARD_ORIGIN = '[^']*';",
                          "const ALLOWED_DASHBOARD_ORIGIN = '%s';" % origin, code, count=1)
            node["parameters"]["jsCode"] = code
    return wf


# ---- command line ----------------------------------------------------------------

def check():
    for name in NEEDED:
        print("%s: %s" % (name, "present" if os.environ.get(name) else "MISSING"))
    return 0 if all(os.environ.get(n) for n in NEEDED) else 1


def credentials():
    creds = build_credentials(need("GRAFANA_WEBHOOK_SECRET"), need("PUSHOVER_API_KEY"),
                              need("PUSHOVER_USER_KEY"))
    script = "cat > /tmp/cred.json && n8n import:credentials --input=/tmp/cred.json; rc=$?; rm -f /tmp/cred.json; exit $rc"
    rc, lines = docker_in(script, json.dumps(creds))
    for ln in lines[:6]:
        print(ln[:160])
    print("credentials import exit code:", rc)
    return rc


def grafana_origin():
    rc, out = docker_out("exec", GRAFANA_CONTAINER, "printenv", "GF_SERVER_ROOT_URL")
    return valid_origin(out) if rc == 0 else ""


def error_workflow(path, reuse_id=""):
    try:
        check_id(reuse_id)
    except ValueError as err:
        sys.exit(str(err))
    with open(path, encoding="utf-8") as handle:
        wf = json.load(handle)
    wf = patch_error_workflow(wf, reuse_id)
    script = "cat > /tmp/eh.json && n8n import:workflow --input=/tmp/eh.json; rc=$?; rm -f /tmp/eh.json; exit $rc"
    rc, lines = docker_in(script, json.dumps([wf]))
    for ln in lines[:6]:
        print(ln[:160])
    print("error workflow import exit code:", rc)
    print("error workflow id:", wf["id"])
    return rc


def workflow(path, reuse_id="", pushover_on=False, error_workflow_id=""):
    try:
        check_id(reuse_id)
        check_id(error_workflow_id, "error workflow id")
    except ValueError as err:
        sys.exit(str(err))
    with open(path, encoding="utf-8") as handle:
        wf = json.load(handle)
    # Reuse the private path from an earlier run (Grafana's contact point already
    # points at it); only make a new one the first time.
    existing = ""
    if os.path.isfile(PATH_FILE):
        with open(PATH_FILE, encoding="utf-8") as handle:
            existing = handle.read()
    new_path = choose_webhook_path(existing)
    origin = grafana_origin()
    wf = patch_workflow(wf, reuse_id, pushover_on, origin, new_path, error_workflow_id=error_workflow_id)
    old = os.umask(0o077)
    try:
        with open(PATH_FILE, "w", encoding="utf-8") as handle:
            handle.write(new_path)
    finally:
        os.umask(old)
    script = "cat > /tmp/wf.json && n8n import:workflow --input=/tmp/wf.json; rc=$?; rm -f /tmp/wf.json; exit $rc"
    rc, lines = docker_in(script, json.dumps([wf]))
    for ln in lines[:6]:
        print(ln[:160])
    print("workflow import exit code:", rc)
    print("new webhook path saved (mode 600):", PATH_FILE)
    print("dashboard origin constant set:", bool(origin))
    print("error workflow set:", bool(error_workflow_id))
    return rc


def main(argv):
    if argv[:1] == ["--check"]:
        return check()
    if argv[:1] == ["--credentials"]:
        return credentials()
    if argv[:1] == ["--error-workflow"] and len(argv) >= 2:
        return error_workflow(argv[1], argv[2] if len(argv) > 2 else "")
    if argv[:1] == ["--workflow"] and len(argv) >= 2:
        try:
            reuse_id, pushover_on, error_id = parse_workflow_args(argv[2:])
        except ValueError as err:
            sys.exit(str(err))
        return workflow(argv[1], reuse_id, pushover_on, error_id)
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
