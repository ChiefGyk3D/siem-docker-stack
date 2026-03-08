#!/usr/bin/env python3
"""Deploy Grafana SIEM alert rules via the provisioning API.

Usage:
    ssh user@siem-server 'python3 -' < scripts/deploy-grafana-alerts.py

Or copy to server and run locally:
    scp scripts/deploy-grafana-alerts.py user@siem-server:/tmp/
    ssh user@siem-server 'python3 /tmp/deploy-grafana-alerts.py'

Required environment variables (or edit the Configuration section below):
    GRAFANA_URL         Grafana base URL (default: http://localhost:3000)
    GRAFANA_USER        Grafana admin username (default: admin)
    GRAFANA_PASS        Grafana admin password (default: changeme)
    ALERT_FOLDER_UID    Grafana folder UID for alert rules
    DS_WAZUH            Datasource UID for Wazuh alerts
    DS_SURICATA         Datasource UID for Suricata alerts
    DS_PROMETHEUS       Datasource UID for Prometheus metrics
"""
import base64
import json
import os
import urllib.request
import urllib.error

# ── Configuration ──────────────────────────────────────────────────────
# Set these via environment variables or edit the defaults below.
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")
_GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
_GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "changeme")
GRAFANA_AUTH = base64.b64encode(f"{_GRAFANA_USER}:{_GRAFANA_PASS}".encode()).decode()
ALERT_FOLDER = os.environ.get("ALERT_FOLDER_UID", "YOUR_ALERT_FOLDER_UID")  # Grafana folder UID

# Datasource UIDs — find these in Grafana → Connections → Data Sources → (select) → URL contains the UID
DS_WAZUH = os.environ.get("DS_WAZUH", "YOUR_WAZUH_DS_UID")
DS_SURICATA = os.environ.get("DS_SURICATA", "YOUR_SURICATA_DS_UID")
DS_PROMETHEUS = os.environ.get("DS_PROMETHEUS", "YOUR_PROMETHEUS_DS_UID")
DS_EXPR = "__expr__"

_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {GRAFANA_AUTH}",
}


def grafana_post(endpoint, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{GRAFANA_URL}{endpoint}",
        data=body,
        headers=_HEADERS,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def grafana_get(endpoint):
    req = urllib.request.Request(f"{GRAFANA_URL}{endpoint}", headers=_HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def opensearch_rule(title, group, query, ds_uid, window_secs, threshold,
                    severity, labels, annotations, for_duration="0s"):
    """Build a Grafana alert rule that queries an OpenSearch datasource."""
    return {
        "title": title,
        "ruleGroup": group,
        "folderUID": ALERT_FOLDER,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "Error",
        "for": for_duration,
        "labels": {**labels, "severity": severity},
        "annotations": annotations,
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": {"from": window_secs, "to": 0},
                "datasourceUid": ds_uid,
                "model": {
                    "query": query,
                    "timeField": "@timestamp",
                    "bucketAggs": [{
                        "type": "date_histogram",
                        "field": "@timestamp",
                        "id": "2",
                        "settings": {"interval": "auto"},
                    }],
                    "metrics": [{"type": "count", "id": "1"}],
                    "refId": "A",
                },
            },
            {
                "refId": "B",
                "relativeTimeRange": {"from": window_secs, "to": 0},
                "datasourceUid": DS_EXPR,
                "model": {
                    "expression": "A",
                    "reducer": "sum",
                    "refId": "B",
                    "type": "reduce",
                },
            },
            {
                "refId": "C",
                "relativeTimeRange": {"from": window_secs, "to": 0},
                "datasourceUid": DS_EXPR,
                "model": {
                    "expression": "B",
                    "refId": "C",
                    "type": "threshold",
                    "conditions": [{
                        "evaluator": {"type": "gt", "params": [threshold]},
                        "operator": {"type": "and"},
                        "query": {"params": ["C"]},
                    }],
                },
            },
        ],
    }


def prometheus_rule(title, group, expr, threshold, severity, labels,
                    annotations, for_duration="2m"):
    """Build a Grafana alert rule that queries Prometheus."""
    return {
        "title": title,
        "ruleGroup": group,
        "folderUID": ALERT_FOLDER,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "Error",
        "for": for_duration,
        "labels": {**labels, "severity": severity},
        "annotations": annotations,
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": DS_PROMETHEUS,
                "model": {
                    "expr": expr,
                    "instant": True,
                    "refId": "A",
                },
            },
            {
                "refId": "B",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": DS_EXPR,
                "model": {
                    "expression": "A",
                    "reducer": "last",
                    "refId": "B",
                    "type": "reduce",
                },
            },
            {
                "refId": "C",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": DS_EXPR,
                "model": {
                    "expression": "B",
                    "refId": "C",
                    "type": "threshold",
                    "conditions": [{
                        "evaluator": {"type": "gt", "params": [threshold]},
                        "operator": {"type": "and"},
                        "query": {"params": ["C"]},
                    }],
                },
            },
        ],
    }


# ============================================================================
# Alert Rule Definitions
# ============================================================================
RULES = [
    # --- Wazuh ---
    opensearch_rule(
        title="Wazuh Agent Disconnected",
        group="SIEM — Wazuh",
        query='rule.groups:"wazuh" AND rule.id:"503"',
        ds_uid=DS_WAZUH,
        window_secs=600,
        threshold=0,
        severity="critical",
        labels={"source": "wazuh"},
        annotations={
            "summary": "Wazuh agent disconnected",
            "description": (
                "Rule 503 (agent disconnected) fired in the last 10 minutes. "
                "Check Agent Health dashboard — is the host up? Is ossec-agentd running?"
            ),
        },
        for_duration="5m",
    ),
    opensearch_rule(
        title="High-Severity Alert Burst",
        group="SIEM — Wazuh",
        query="rule.level:>=10",
        ds_uid=DS_WAZUH,
        window_secs=300,
        threshold=50,
        severity="critical",
        labels={"source": "wazuh"},
        annotations={
            "summary": "Burst of high-severity Wazuh alerts",
            "description": (
                "More than 50 alerts with rule.level >= 10 in 5 minutes. "
                "Possible active attack. Check SIEM Overview and Network Security dashboards."
            ),
        },
    ),
    opensearch_rule(
        title="Authentication Failure Burst",
        group="SIEM — Wazuh",
        query='rule.groups:"authentication_failed" OR rule.groups:"authentication_failures"',
        ds_uid=DS_WAZUH,
        window_secs=300,
        threshold=20,
        severity="critical",
        labels={"source": "wazuh"},
        annotations={
            "summary": "Burst of authentication failures",
            "description": (
                "More than 20 auth failure events in 5 minutes. "
                "Possible brute-force attack. Check Network Security SSH panel."
            ),
        },
    ),
    opensearch_rule(
        title="Critical File Integrity Change",
        group="SIEM — Wazuh",
        query="rule.groups:syscheck AND rule.level:>=7",
        ds_uid=DS_WAZUH,
        window_secs=600,
        threshold=0,
        severity="warning",
        labels={"source": "wazuh"},
        annotations={
            "summary": "File integrity change on monitored path",
            "description": (
                "Wazuh FIM detected level 7+ file changes in the last 10 minutes. "
                "Review the File Integrity Monitoring dashboard."
            ),
        },
    ),

    # --- Suricata ---
    opensearch_rule(
        title="Suricata Critical Alert",
        group="SIEM — IDS",
        query="alert.severity:1",
        ds_uid=DS_SURICATA,
        window_secs=300,
        threshold=0,
        severity="critical",
        labels={"source": "suricata"},
        annotations={
            "summary": "Suricata severity 1 alerts detected",
            "description": (
                "One or more critical Suricata IDS alerts in the last 5 minutes. "
                "Check the Suricata and Network Security dashboards."
            ),
        },
    ),

    # --- pfSense (via Wazuh decoder) ---
    opensearch_rule(
        title="pfSense Firewall Block Surge",
        group="SIEM — Firewall",
        query='rule.id:"87701"',
        ds_uid=DS_WAZUH,
        window_secs=300,
        threshold=500,
        severity="warning",
        labels={"source": "pfsense"},
        annotations={
            "summary": "Surge of pfSense firewall blocks",
            "description": (
                "More than 500 firewall block events (rule 87701) in 5 minutes. "
                "Could indicate a scan, DDoS, or misconfigured rule."
            ),
        },
    ),

    # --- Docker (Prometheus) ---
    prometheus_rule(
        title="Docker Container Restart Loop",
        group="SIEM — Docker",
        expr='changes(container_start_time_seconds{name=~".+"}[10m])',
        threshold=2,
        severity="warning",
        labels={"source": "docker"},
        annotations={
            "summary": "Container {{ $labels.name }} is restart-looping",
            "description": (
                "Container {{ $labels.name }} on {{ $labels.instance }} "
                "has restarted 3+ times in 10 minutes. "
                "Check: docker logs {{ $labels.name }}"
            ),
        },
    ),
]


def main():
    # Get existing rules
    existing = grafana_get("/api/v1/provisioning/alert-rules")
    existing_titles = {r["title"] for r in existing}

    created = 0
    skipped = 0
    failed = 0

    for rule in RULES:
        title = rule["title"]
        if title in existing_titles:
            print(f"  ✓ '{title}' — already exists, skipping")
            skipped += 1
            continue

        result, status = grafana_post("/api/v1/provisioning/alert-rules", rule)
        if 200 <= status < 300:
            print(f"  ✓ '{title}' — created")
            created += 1
        else:
            msg = result.get("message", str(result))
            print(f"  ✗ '{title}' — {status}: {msg}")
            failed += 1

    print(f"\nDone: {created} created, {skipped} skipped, {failed} failed")


if __name__ == "__main__":
    main()
