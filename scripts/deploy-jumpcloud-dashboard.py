#!/usr/bin/env python3
"""Deploy JumpCloud Security Grafana dashboard.

Usage:
  python3 scripts/deploy-jumpcloud-dashboard.py

Environment variables:
  GRAFANA_URL       default: http://localhost:3000
  GRAFANA_USER      default: admin
  GRAFANA_PASS      default: changeme
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

AUTH = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {AUTH}",
}


def main():
    dashboard_path = pathlib.Path(__file__).resolve().parents[1] / "dashboards" / "jumpcloud_security.json"
    raw = json.loads(dashboard_path.read_text())

    # The JSON file wraps the dashboard in {"dashboard": {...}, "overwrite": true}
    dashboard = raw.get("dashboard", raw)

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
            print(f"ok uid={body.get('uid')} url={body.get('url')} status={resp.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"error status={exc.code} body={body}")
        raise


if __name__ == "__main__":
    main()
