#!/usr/bin/env bash
# =============================================================================
# deploy-n8n-soar.sh — Deploy N8N SOAR workflows and Grafana alerting rules
# =============================================================================
# Usage:
#   N8N_API_KEY="your-key" ./scripts/deploy-n8n-soar.sh [siem-server-ip]
#
# Or set the key in your environment / .env file.
# The script reads N8N_API_KEY from the environment — change it in one place.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — change these as needed
# ---------------------------------------------------------------------------
SIEM_SERVER="${1:-10.0.0.100}"
N8N_IP="172.20.0.16"          # N8N on siem-net (use docker inspect to verify)
N8N_PORT="80"
N8N_BASE="http://${N8N_IP}:${N8N_PORT}"
GRAFANA_URL="http://admin:changeme@localhost:3000"
SSH_USER="${SIEM_USER:-siem}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
N8N_DIR="${SCRIPT_DIR}/n8n"

# N8N API key — set via environment variable
if [[ -z "${N8N_API_KEY:-}" ]]; then
  echo "ERROR: N8N_API_KEY not set."
  echo "Usage: N8N_API_KEY='your-key-here' $0 [siem-server-ip]"
  exit 1
fi

# Grafana alert folder — create this in Grafana UI first, then copy the UID
ALERT_FOLDER_UID="${ALERT_FOLDER_UID:-YOUR_ALERT_FOLDER_UID}"  # "SIEM Alerts"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
n8n_api() {
  local method="$1" endpoint="$2"; shift 2
  ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X ${method} \
    -H 'Content-Type: application/json' \
    -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
    '${N8N_BASE}${endpoint}' \
    $*" 2>/dev/null
}

grafana_api() {
  local method="$1" endpoint="$2"; shift 2
  ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X ${method} \
    -H 'Content-Type: application/json' \
    '${GRAFANA_URL}${endpoint}' \
    $*" 2>/dev/null
}

echo "=== N8N SOAR & Grafana Alerting Deployment ==="
echo "SIEM Server: ${SIEM_SERVER}"
echo "N8N:         ${N8N_BASE}"
echo ""

# ---------------------------------------------------------------------------
# 1. Deploy N8N Workflows
# ---------------------------------------------------------------------------
echo "--- Step 1: Deploying N8N workflows ---"

# Get existing workflow IDs
EXISTING=$(n8n_api GET "/api/v1/workflows" || echo '{"data":[]}')
WAZUH_WF_ID=$(echo "$EXISTING" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for w in d.get('data', []):
  if 'Wazuh' in w.get('name', '') or 'SOAR' in w.get('name', ''):
    print(w['id']); break
else:
  print('')
" 2>/dev/null)

GRAFANA_WF_ID=$(echo "$EXISTING" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for w in d.get('data', []):
  if 'Grafana' in w.get('name', '') and 'SOAR' in w.get('name', ''):
    print(w['id']); break
else:
  print('')
" 2>/dev/null)

# Deploy Wazuh SOAR workflow
if [[ -f "${N8N_DIR}/wazuh-alert-triage.json" ]]; then
  WF_JSON=$(cat "${N8N_DIR}/wazuh-alert-triage.json")
  if [[ -n "$WAZUH_WF_ID" ]]; then
    echo "  Updating existing Wazuh SOAR workflow (ID: ${WAZUH_WF_ID})..."
    echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X PUT \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${WAZUH_WF_ID}' \
      -d @-" >/dev/null && echo "  ✓ Updated" || echo "  ✗ Failed"
  else
    echo "  Creating Wazuh SOAR workflow..."
    RESULT=$(echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows' \
      -d @-" 2>/dev/null)
    WAZUH_WF_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    echo "  ✓ Created (ID: ${WAZUH_WF_ID})"
  fi

  # Activate the workflow
  if [[ -n "$WAZUH_WF_ID" ]]; then
    ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${WAZUH_WF_ID}/activate'" >/dev/null 2>&1 && \
      echo "  ✓ Activated" || echo "  (already active or activation skipped)"
  fi
fi

# Deploy Grafana Alert Router workflow
if [[ -f "${N8N_DIR}/grafana-alert-router.json" ]]; then
  WF_JSON=$(cat "${N8N_DIR}/grafana-alert-router.json")
  if [[ -n "$GRAFANA_WF_ID" ]]; then
    echo "  Updating existing Grafana Alert Router (ID: ${GRAFANA_WF_ID})..."
    echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X PUT \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${GRAFANA_WF_ID}' \
      -d @-" >/dev/null && echo "  ✓ Updated" || echo "  ✗ Failed"
  else
    echo "  Creating Grafana Alert Router workflow..."
    RESULT=$(echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows' \
      -d @-" 2>/dev/null)
    GRAFANA_WF_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    echo "  ✓ Created (ID: ${GRAFANA_WF_ID})"
  fi

  # Activate
  if [[ -n "$GRAFANA_WF_ID" ]]; then
    ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${GRAFANA_WF_ID}/activate'" >/dev/null 2>&1 && \
      echo "  ✓ Activated" || echo "  (already active or activation skipped)"
  fi
fi

# Deploy CrowdSec SOAR workflow
CROWDSEC_WF_ID=$(echo "$EXISTING" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for w in d.get('data', []):
  if 'CrowdSec' in w.get('name', '') and 'SOAR' in w.get('name', ''):
    print(w['id']); break
else:
  print('')
" 2>/dev/null)

if [[ -f "${N8N_DIR}/crowdsec-alert-enrichment.json" ]]; then
  WF_JSON=$(cat "${N8N_DIR}/crowdsec-alert-enrichment.json" | python3 -c "
import sys, json
wf = json.load(sys.stdin)
wf.pop('active', None)
if 'settings' not in wf: wf['settings'] = {'executionOrder': 'v1'}
json.dump(wf, sys.stdout)
")
  if [[ -n "$CROWDSEC_WF_ID" ]]; then
    echo "  Updating existing CrowdSec SOAR workflow (ID: ${CROWDSEC_WF_ID})..."
    echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X PUT \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${CROWDSEC_WF_ID}' \
      -d @-" >/dev/null && echo "  ✓ Updated" || echo "  ✗ Failed"
  else
    echo "  Creating CrowdSec SOAR workflow..."
    RESULT=$(echo "$WF_JSON" | ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'Content-Type: application/json' \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows' \
      -d @-" 2>/dev/null)
    CROWDSEC_WF_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    echo "  ✓ Created (ID: ${CROWDSEC_WF_ID})"
  fi

  # Activate
  if [[ -n "$CROWDSEC_WF_ID" ]]; then
    ssh "${SSH_USER}@${SIEM_SERVER}" "curl -sf -X POST \
      -H 'X-N8N-API-KEY: ${N8N_API_KEY}' \
      '${N8N_BASE}/api/v1/workflows/${CROWDSEC_WF_ID}/activate'" >/dev/null 2>&1 && \
      echo "  ✓ Activated" || echo "  (already active or activation skipped)"
  fi
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Create N8N Webhook Contact Points in Grafana
# ---------------------------------------------------------------------------
echo "--- Step 2: Grafana contact points ---"

# Check if N8N contact point already exists
N8N_CP_EXISTS=$(grafana_api GET "/api/v1/provisioning/contact-points" | \
  python3 -c "import sys,json; cps=json.load(sys.stdin); print('yes' if any('N8N' in c.get('name','') for c in cps) else 'no')" 2>/dev/null || echo "no")

if [[ "$N8N_CP_EXISTS" == "no" ]]; then
  echo "  Creating N8N-SOAR webhook contact point..."
  grafana_api POST "/api/v1/provisioning/contact-points" \
    "-d '{
      \"name\": \"N8N-SOAR\",
      \"type\": \"webhook\",
      \"settings\": {
        \"url\": \"http://n8n/webhook/grafana-alerts\",
        \"httpMethod\": \"POST\"
      },
      \"disableResolveMessage\": false
    }'" && echo "  ✓ Created N8N-SOAR contact point" || echo "  ✗ Failed"
else
  echo "  ✓ N8N-SOAR contact point already exists"
fi

# Check if CrowdSec contact point already exists
CS_CP_EXISTS=$(grafana_api GET "/api/v1/provisioning/contact-points" | \
  python3 -c "import sys,json; cps=json.load(sys.stdin); print('yes' if any('CrowdSec' in c.get('name','') for c in cps) else 'no')" 2>/dev/null || echo "no")

if [[ "$CS_CP_EXISTS" == "no" ]]; then
  echo "  Creating N8N-CrowdSec webhook contact point..."
  grafana_api POST "/api/v1/provisioning/contact-points" \
    "-d '{
      \"name\": \"N8N-CrowdSec\",
      \"type\": \"webhook\",
      \"settings\": {
        \"url\": \"http://n8n/webhook/crowdsec-alerts\",
        \"httpMethod\": \"POST\"
      },
      \"disableResolveMessage\": false
    }'" && echo "  ✓ Created N8N-CrowdSec contact point" || echo "  ✗ Failed"
else
  echo "  ✓ N8N-CrowdSec contact point already exists"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. Deploy Grafana SIEM Alert Rules
# ---------------------------------------------------------------------------
echo "--- Step 3: Grafana SIEM alert rules ---"

# Get existing rules to avoid duplicates
EXISTING_RULES=$(grafana_api GET "/api/v1/provisioning/alert-rules" || echo "[]")

create_alert_rule() {
  local title="$1" rule_json="$2"
  local existing_uid
  existing_uid=$(echo "$EXISTING_RULES" | python3 -c "
import sys, json
rules = json.load(sys.stdin)
for r in rules:
  if r.get('title') == '$title':
    print(r.get('uid', ''))
    break
else:
  print('')
" 2>/dev/null || echo "")

  if [[ -n "$existing_uid" ]]; then
    echo "  Updating '$title' (uid: ${existing_uid})..."
    # Provisioning update endpoint expects the full rule body and preserves uid from URL.
    grafana_api PUT "/api/v1/provisioning/alert-rules/${existing_uid}" "-d '${rule_json}'" && \
      echo "  ✓ Updated" || echo "  ✗ Failed"
  else
    echo "  Creating '$title'..."
    grafana_api POST "/api/v1/provisioning/alert-rules" "-d '${rule_json}'" && \
      echo "  ✓ Created" || echo "  ✗ Failed"
  fi
}

# --- Rule: Wazuh Agent Disconnected ---
create_alert_rule "Wazuh Agent Disconnected" '{
  "title": "Wazuh Agent Disconnected",
  "ruleGroup": "SIEM — Wazuh",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "5m",
  "labels": { "severity": "critical", "source": "wazuh" },
  "annotations": {
    "summary": "Wazuh agent {{ $labels.agent_name }} disconnected",
    "description": "Agent {{ $labels.agent_name }} (ID {{ $labels.agent_id }}) has not reported to the Wazuh manager for >5 minutes. Check: is the host up? Is ossec-agentd running?"
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "YOUR_WAZUH_DS_UID",
      "model": {
        "query": "rule.groups:\"wazuh\" AND rule.id:\"503\"",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [0] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: High-Severity Wazuh Alert Burst ---
create_alert_rule "High-Severity Alert Burst" '{
  "title": "High-Severity Alert Burst",
  "ruleGroup": "SIEM — Wazuh",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "0s",
  "labels": { "severity": "critical", "source": "wazuh" },
  "annotations": {
    "summary": "Burst of high-severity Wazuh alerts detected",
    "description": "More than 50 alerts with rule.level >= 10 in the last 5 minutes. This may indicate an active attack or widespread issue. Check the SIEM Overview and Network Security dashboards."
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "YOUR_WAZUH_DS_UID",
      "model": {
        "query": "rule.level:>=10",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [50] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: Suricata Critical Alert ---
create_alert_rule "Suricata Critical Alert" '{
  "title": "Suricata Critical Alert",
  "ruleGroup": "SIEM — IDS",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "0s",
  "labels": { "severity": "critical", "source": "suricata" },
  "annotations": {
    "summary": "Suricata severity 1 alerts detected",
    "description": "One or more Suricata IDS alerts with severity 1 (critical) in the last 5 minutes. Check the Suricata dashboard and Network Security dashboard for details."
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "YOUR_SURICATA_DS_UID",
      "model": {
        "query": "alert.severity:1",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [0] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: pfSense Firewall Blocked Burst ---
create_alert_rule "pfSense Firewall Block Surge" '{
  "title": "pfSense Firewall Block Surge",
  "ruleGroup": "SIEM — Firewall",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "0s",
  "labels": { "severity": "warning", "source": "pfsense" },
  "annotations": {
    "summary": "Surge of pfSense firewall blocks detected (>1000 in 5m)",
    "description": "More than 1000 firewall block events in the last 5 minutes via Wazuh decoder. This could indicate a scan, DDoS attempt, or misconfigured rule."
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "YOUR_WAZUH_DS_UID",
      "model": {
        "query": "rule.id:\"87701\"",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [1000] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: Docker Container Restart Loop ---
create_alert_rule "Docker Container Restart Loop" '{
  "title": "Docker Container Restart Loop",
  "ruleGroup": "SIEM — Docker",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "2m",
  "labels": { "severity": "warning", "source": "docker" },
  "annotations": {
    "summary": "Container {{ $labels.name }} is restart-looping",
    "description": "Container {{ $labels.name }} on {{ $labels.instance }} has restarted 3+ times in 10 minutes. Check: docker logs {{ $labels.name }}"
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "YOUR_PROMETHEUS_DS_UID",
      "model": {
        "expr": "increase(container_start_time_seconds{name=~\".+\"}[10m]) > 0 and count_over_time(container_start_time_seconds{name=~\".+\"}[10m]) >= 3",
        "instant": true,
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "last", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [0] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: Authentication Failure Burst ---
create_alert_rule "Authentication Failure Burst" '{
  "title": "Authentication Failure Burst",
  "ruleGroup": "SIEM — Wazuh",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "0s",
  "labels": { "severity": "critical", "source": "wazuh" },
  "annotations": {
    "summary": "Burst of authentication failures detected",
    "description": "More than 20 authentication failure events in 5 minutes across Wazuh agents. Possible brute-force attack in progress. Check Network Security dashboard SSH panel."
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "YOUR_WAZUH_DS_UID",
      "model": {
        "query": "rule.groups:\"authentication_failed\" OR rule.groups:\"authentication_failures\"",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 300, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [20] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

# --- Rule: File Integrity Change (Critical Paths) ---
create_alert_rule "Critical File Integrity Change" '{
  "title": "Critical File Integrity Change",
  "ruleGroup": "SIEM — Wazuh",
  "folderUID": "'"${ALERT_FOLDER_UID}"'",
  "condition": "C",
  "for": "0s",
  "labels": { "severity": "warning", "source": "wazuh" },
  "annotations": {
    "summary": "File integrity change on critical path",
    "description": "Wazuh FIM detected file changes on monitored critical paths in the last 10 minutes. Review the File Integrity Monitoring dashboard."
  },
  "data": [
    {
      "refId": "A",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "YOUR_WAZUH_DS_UID",
      "model": {
        "query": "rule.groups:\"syscheck\" AND rule.level:>=7",
        "timeField": "@timestamp",
        "bucketAggs": [{ "type": "date_histogram", "field": "@timestamp", "id": "2", "settings": { "interval": "auto" } }],
        "metrics": [{ "type": "count", "id": "1" }],
        "refId": "A"
      }
    },
    {
      "refId": "B",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": { "expression": "A", "reducer": "sum", "refId": "B", "type": "reduce" }
    },
    {
      "refId": "C",
      "relativeTimeRange": { "from": 600, "to": 0 },
      "datasourceUid": "__expr__",
      "model": {
        "expression": "B",
        "refId": "C",
        "type": "threshold",
        "conditions": [{ "evaluator": { "type": "gt", "params": [0] }, "operator": { "type": "and" }, "query": { "params": ["C"] } }]
      }
    }
  ]
}'

echo ""

# ---------------------------------------------------------------------------
# 4. Update notification policy to include N8N
# ---------------------------------------------------------------------------
echo "--- Step 4: Notification policy ---"

grafana_api PUT "/api/v1/provisioning/policies" \
  "-d '{
    \"receiver\": \"Discord-SIEM\",
    \"group_by\": [\"grafana_folder\", \"alertname\"],
    \"group_wait\": \"30s\",
    \"group_interval\": \"5m\",
    \"repeat_interval\": \"4h\",
    \"routes\": [
      {
        \"receiver\": \"N8N-CrowdSec\",
        \"matchers\": [\"source=crowdsec\"],
        \"continue\": true,
        \"group_wait\": \"10s\"
      },
      {
        \"receiver\": \"N8N-SOAR\",
        \"matchers\": [\"source=wazuh\"],
        \"continue\": true,
        \"group_wait\": \"10s\"
      },
      {
        \"receiver\": \"N8N-SOAR\",
        \"matchers\": [\"source=suricata\"],
        \"continue\": true,
        \"group_wait\": \"10s\"
      }
    ]
  }'" && echo "  ✓ Updated notification policy — SIEM alerts routed to Discord, N8N-SOAR, and N8N-CrowdSec" || echo "  ✗ Failed to update notification policy"

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Workflows deployed to N8N:"
echo "  - Wazuh SOAR — Alert Triage & Routing (ID: ${WAZUH_WF_ID:-unknown})"
echo "  - Grafana SOAR — Alert Router (ID: ${GRAFANA_WF_ID:-unknown})"
echo "  - CrowdSec SOAR — Alert Enrichment (ID: ${CROWDSEC_WF_ID:-unknown})"
echo ""
echo "Grafana SIEM alert rules created:"
echo "  - Wazuh Agent Disconnected (5m, critical)"
echo "  - High-Severity Alert Burst (>50 in 5m, critical)"
echo "  - Suricata Critical Alert (severity 1, critical)"
echo "  - pfSense Firewall Block Surge (>1000 in 5m, warning)"
echo "  - Docker Container Restart Loop (3+ in 10m, warning)"
echo "  - Authentication Failure Burst (>20 in 5m, critical)"
echo "  - Critical File Integrity Change (level 7+, warning)"
echo ""
echo "Notification routing:"
echo "  - All alerts → Discord-SIEM (default)"
echo "  - source=crowdsec → N8N-CrowdSec (enriched alerts with OpenSearch lookup)"
echo "  - source=wazuh|suricata → N8N-SOAR (additional, continue=true)"
echo ""
echo "Next steps:"
echo "  1. Open N8N UI and verify workflows are active"
echo "  2. Edit workflow HTTP Request nodes — replace Discord webhook URL placeholders"
echo "  3. Test: trigger a level 10+ Wazuh alert or check Grafana Alerting page"
echo "  4. See docs/n8n-soar.md for full configuration and testing guide"
