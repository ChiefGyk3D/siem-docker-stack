#!/usr/bin/env python3
"""Deploy all SIEM dashboards to Grafana and organize folders.

Usage (run on SIEM server or any host that can reach Grafana):
    python3 scripts/deploy-dashboards.py

Or via SSH:
    ssh user@siem-server 'cd /path/to/siem-docker-stack && python3 scripts/deploy-dashboards.py'

Environment variables:
    GRAFANA_URL     default: http://localhost:3000
    GRAFANA_USER    default: admin
    GRAFANA_PASS    default: changeme

Actions:
    1. Creates folders: SIEM, System Stats
    2. Imports every dashboard in dashboards/ to the correct folder
    3. Moves "Docker Container Monitoring" to "System Stats"
    4. Also imports jumpcloud-wazuh-bridge dashboard if present
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

# Map dashboard filename -> target folder title.
# Anything not listed goes to "SIEM".
SYSTEM_STATS_DASHBOARDS = {
    "docker_container_monitoring.json",
    "nvidia_gpu_monitoring.json",
    "prometheus_stats.json",
}

SKIP_FILES = {"datasources_reference.json"}

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DASHBOARDS_DIR = REPO_ROOT / "dashboards"
BRIDGE_DASHBOARD = REPO_ROOT.parent / "jumpcloud-wazuh-bridge" / "dashboards" / "jumpcloud_security.json"


def api(method, endpoint, data=None):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        f"{GRAFANA_URL}{endpoint}",
        data=body,
        headers=HEADERS,
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def ensure_folder(title):
    """Create a Grafana folder if it doesn't exist. Return its id."""
    folders, _ = api("GET", "/api/folders")
    for f in folders:
        if f.get("title") == title:
            return f["id"]
    result, status = api("POST", "/api/folders", {"title": title})
    if status < 300:
        print(f"  ✓ Created folder '{title}' (id={result['id']})")
        return result["id"]
    # Folder might already exist with a different case
    if result.get("message", "").startswith("a]"):
        folders, _ = api("GET", "/api/folders")
        for f in folders:
            if f.get("title").lower() == title.lower():
                return f["id"]
    raise RuntimeError(f"Failed to create folder '{title}': {result}")


def import_dashboard(path, folder_id):
    """Import a dashboard JSON file into a Grafana folder."""
    raw = json.loads(path.read_text())
    # Handle API-envelope wrapped files
    dashboard = raw.get("dashboard", raw)
    dashboard["id"] = None  # let Grafana assign

    payload = {
        "dashboard": dashboard,
        "folderId": folder_id,
        "overwrite": True,
    }
    result, status = api("POST", "/api/dashboards/db", payload)
    title = dashboard.get("title", path.stem)
    if status < 300:
        print(f"  ✓ {title} → imported (status={result.get('status', 'ok')})")
    else:
        print(f"  ✗ {title} → failed ({status}: {result.get('message', '')})")


def main():
    print("=== Creating Grafana folders ===")
    siem_folder_id = ensure_folder("SIEM")
    system_folder_id = ensure_folder("System Stats")

    print("\n=== Importing SIEM dashboards ===")
    for path in sorted(DASHBOARDS_DIR.glob("*.json")):
        if path.name in SKIP_FILES:
            continue
        if path.name in SYSTEM_STATS_DASHBOARDS:
            import_dashboard(path, system_folder_id)
        else:
            import_dashboard(path, siem_folder_id)

    # Import JumpCloud dashboard from bridge repo if available
    if BRIDGE_DASHBOARD.exists():
        print("\n=== Importing JumpCloud dashboard from bridge repo ===")
        import_dashboard(BRIDGE_DASHBOARD, siem_folder_id)
    else:
        print(f"\n  ⓘ JumpCloud dashboard not found at {BRIDGE_DASHBOARD}")

    print("\nDone.")


if __name__ == "__main__":
    main()
