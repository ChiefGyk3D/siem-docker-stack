#!/usr/bin/env python3
"""Deploy CrowdSec Grafana dashboard.

Usage:
  python3 scripts/deploy-crowdsec-dashboard.py

Environment variables:
  GRAFANA_URL       default: http://localhost:3000
  GRAFANA_USER      default: admin
  GRAFANA_PASS      REQUIRED, no default (the script refuses a missing or placeholder value)
  DS_WAZUH          required datasource UID for OpenSearch/Wazuh datasource
"""

import base64
import json
import os
import pathlib
import re
import urllib.error
import urllib.request

# ── Secrets: no defaults ───────────────────────────────────────────────
# One placeholder rule, kept identical in every deploy-*.py (these scripts are
# also piped over ssh, so they cannot import a sibling module) and in
# scripts/lib-secrets.sh; tests/python/test_required_secrets.py keeps them in step.
_PLACEHOLDER = re.compile(r"(|change[_-]?me.*|your[_-].*|<.*|xxx.*|example.*|placeholder.*|secretpassword|mys3cr3tp4ssw0rd|kibanaserver|admin|password|.*your-password.*|.*strong-password.*)", re.I | re.S)  # placeholder-rule


def is_placeholder(value):
    return _PLACEHOLDER.fullmatch((value or "").strip()) is not None


def require_secret(name, value):
    """Return value, or exit naming the variable (never the value) if it is unusable."""
    if is_placeholder(value):
        raise SystemExit(f"ERROR: {name} is missing, empty, or a placeholder. "
                         "Set a real value (see README, Required secrets).")
    return value


GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS")  # required, checked in main()
DS_WAZUH = os.environ.get("DS_WAZUH", "YOUR_WAZUH_DS_UID")

HEADERS = {"Content-Type": "application/json"}


def replace_ds_uid(node):
    if isinstance(node, dict):
        if "datasource" in node and isinstance(node["datasource"], dict):
            uid = node["datasource"].get("uid")
            if uid == "YOUR_WAZUH_DS_UID":
                node["datasource"]["uid"] = DS_WAZUH
        for v in node.values():
            replace_ds_uid(v)
    elif isinstance(node, list):
        for v in node:
            replace_ds_uid(v)


def _init_auth():
    """Refuse a missing or placeholder password, then build the Basic auth header."""
    password = require_secret("GRAFANA_PASS", GRAFANA_PASS)
    token = base64.b64encode(f"{GRAFANA_USER}:{password}".encode()).decode()
    HEADERS["Authorization"] = f"Basic {token}"


def main():
    _init_auth()
    dashboard_path = pathlib.Path(__file__).resolve().parents[1] / "dashboards" / "crowdsec_overview.json"
    dashboard = json.loads(dashboard_path.read_text())

    replace_ds_uid(dashboard)

    payload = {
        "dashboard": dashboard,
        "folderId": 0,
        "overwrite": True,
    }

    req = urllib.request.Request(
        f"{GRAFANA_URL}/api/dashboards/db",
        data=json.dumps(payload).encode(),
        headers=HEADERS,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
            print(f"ok uid={body.get('uid')} status={resp.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"error status={exc.code} body={body}")
        raise


if __name__ == "__main__":
    main()
