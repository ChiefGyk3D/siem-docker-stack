#!/usr/bin/env python3
"""Deploy CrowdSec Grafana dashboard.

Usage:
  python3 scripts/deploy-crowdsec-dashboard.py

Environment variables:
  GRAFANA_URL       default: http://localhost:3000
  GRAFANA_USER      default: admin
  GRAFANA_PASS      default: changeme
  DS_WAZUH          required datasource UID for OpenSearch/Wazuh datasource
"""

import base64
import json
import os
import pathlib
import urllib.error
import urllib.request

GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "changeme")
DS_WAZUH = os.environ.get("DS_WAZUH", "YOUR_WAZUH_DS_UID")

AUTH = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {AUTH}",
}


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


def main():
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
