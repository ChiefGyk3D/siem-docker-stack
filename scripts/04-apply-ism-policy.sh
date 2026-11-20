#!/bin/bash
# =============================================================================
# 04-apply-ism-policy.sh — Apply OpenSearch ISM hot/warm policy & templates
# =============================================================================
# Run after `docker compose up`, once OpenSearch is healthy.
#
# This script:
#   1. Applies the ISM (Index State Management) hot/warm/delete policy
#   2. Applies index templates for Suricata, pfBlockerNG, and Syslog
#   3. Verifies everything was applied correctly
#
# The cluster is secured (Phase F1): requests use HTTPS + admin basic auth.
# OPENSEARCH_ADMIN_PASSWORD is read from the environment or .env.
#
# Usage:
#   bash scripts/04-apply-ism-policy.sh https://10.0.0.100:9200
#   bash scripts/04-apply-ism-policy.sh   # defaults to https://localhost:9200
# =============================================================================

set -euo pipefail
# Before any external command runs: take the export attribute off the password (a caller may have
# exported it) and switch allexport off (an inherited `bash -a` would export every later assignment).
# Both are builtins. From here on no child of this script inherits the password. What no script can
# change: the environment this process itself was started with still holds whatever the launcher
# exported; pass the password in a .env file rather than the launch environment to avoid even that.
export -n OPENSEARCH_ADMIN_PASSWORD
set +a

OPENSEARCH_URL="${1:-https://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/.."
OPENSEARCH_DIR="${SCRIPT_DIR}/../docker/opensearch"

# Load OPENSEARCH_ADMIN_PASSWORD from .env if not already set. Plain `source` with allexport off: the
# assignments stay in this shell only; the attribute is taken off again in case the file exports.
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$envf" ]; then
            # shellcheck disable=SC1090
            source "$envf"
            set +a
            export -n OPENSEARCH_ADMIN_PASSWORD
            break
        fi
    done
fi
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    echo "ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env). See .env.example."
    exit 1
fi
# A line break would end the one-line curl config record below (and start a new directive), so refuse
# it before any request. The variable name is printed, never the value.
case "$OPENSEARCH_ADMIN_PASSWORD" in
    *$'\n'* | *$'\r'*)
        echo "ERROR: OPENSEARCH_ADMIN_PASSWORD contains a line break, which is not allowed in a password" >&2
        exit 1
        ;;
esac
# The credentials go to curl on standard input as a config (-K -), never in argv. Backslash and double
# quote are escaped for the curl config syntax. printf is a builtin, so no process holds the value.
OS_USER_CFG="admin:${OPENSEARCH_ADMIN_PASSWORD}"
OS_USER_CFG="${OS_USER_CFG//\\/\\\\}"
OS_USER_CFG="${OS_USER_CFG//\"/\\\"}"
# -k: cluster certs are self-signed (see scripts/07-generate-opensearch-certs.sh)
os_curl() { printf 'user = "%s"\n' "$OS_USER_CFG" | curl -sk -K - "$@"; }

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Applying OpenSearch ISM policy and templates...${NC}"
echo "  OpenSearch URL: ${OPENSEARCH_URL}"
echo ""

# Wait for OpenSearch
echo -e "${YELLOW}Waiting for OpenSearch...${NC}"
for i in {1..30}; do
    if os_curl -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
        HEALTH=$(os_curl -f "${OPENSEARCH_URL}/_cluster/health" | jq -r '.status')
        echo -e "${GREEN}✓ OpenSearch is up (cluster health: ${HEALTH})${NC}"
        break
    fi
    echo "  Waiting... (${i}/30)"
    sleep 5
done

if ! os_curl -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: OpenSearch not reachable at ${OPENSEARCH_URL}${NC}"
    exit 1
fi

CLUSTER_INFO=$(os_curl -f "${OPENSEARCH_URL}/_cluster/health")
NODE_COUNT=$(echo "$CLUSTER_INFO" | jq -r '.number_of_nodes')
echo "  Nodes: ${NODE_COUNT}"

# ── Apply ISM Policy ─────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[1/5] Applying ISM hot/warm/delete policy...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_plugins/_ism/policies/siem-hot-warm-delete" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/ism-hot-warm-policy.json" | jq .

echo -e "${GREEN}✓ ISM policy applied${NC}"

# ── Suricata Index Template ──────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/5] Applying Suricata index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/suricata-template" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-suricata.json" | jq .

echo -e "${GREEN}✓ Suricata template applied${NC}"

# ── pfBlockerNG Index Template ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/5] Applying pfBlockerNG index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/pfblockerng" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-pfblockerng.json" | jq .

echo -e "${GREEN}✓ pfBlockerNG template applied${NC}"

# ── Syslog Index Template ────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/5] Applying Syslog index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/syslog-template" \
    -H 'Content-Type: application/json' \
    -d '{
  "index_patterns": ["syslog-*", "pfsense-*", "unifi-syslog-*", "crowdsec-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.routing.allocation.require.temp": "hot",
      "plugins.index_state_management.policy_id": "siem-hot-warm-delete"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "host": { "type": "keyword" },
        "source_host": { "type": "keyword" },
        "program": { "type": "keyword" },
        "facility": { "type": "keyword" },
        "severity": { "type": "keyword" },
        "message": { "type": "text" }
      }
    }
  },
  "priority": 200
}' | jq .

echo -e "${GREEN}✓ Syslog template applied${NC}"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[5/5] Verifying...${NC}"

echo "  ISM policies:"
os_curl -f "${OPENSEARCH_URL}/_plugins/_ism/policies" | jq -r '.policies[].policy.description' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Index templates:"
os_curl -f "${OPENSEARCH_URL}/_index_template" | jq -r '.index_templates[].name' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Cluster allocation tags:"
os_curl -f "${OPENSEARCH_URL}/_cat/nodeattrs?v&h=node,attr,value" 2>/dev/null | grep temp || echo "    (waiting for nodes)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ISM Policy & Templates Applied          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "New indices matching suricata-*, syslog-*, pfblockerng-*, pfsense-*,"
echo "unifi-syslog-*, crowdsec-events-* will:"
echo "  1. Start on HOT tier (NVMe) — opensearch-hot node"
echo "  2. Move to WARM tier (SATA) after 30 days — opensearch-warm node"
echo "  3. Force-merge to 1 segment on WARM for read performance"
echo "  4. Delete after 365 days (1 year)"
