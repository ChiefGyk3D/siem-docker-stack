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
# Usage:
#   bash scripts/04-apply-ism-policy.sh http://10.0.0.100:9200
#   bash scripts/04-apply-ism-policy.sh   # defaults to localhost
# =============================================================================

set -euo pipefail

OPENSEARCH_URL="${1:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSEARCH_DIR="${SCRIPT_DIR}/../docker/opensearch"

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
    if curl -sf "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
        HEALTH=$(curl -sf "${OPENSEARCH_URL}/_cluster/health" | jq -r '.status')
        echo -e "${GREEN}✓ OpenSearch is up (cluster health: ${HEALTH})${NC}"
        break
    fi
    echo "  Waiting... (${i}/30)"
    sleep 5
done

if ! curl -sf "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: OpenSearch not reachable at ${OPENSEARCH_URL}${NC}"
    exit 1
fi

CLUSTER_INFO=$(curl -sf "${OPENSEARCH_URL}/_cluster/health")
NODE_COUNT=$(echo "$CLUSTER_INFO" | jq -r '.number_of_nodes')
echo "  Nodes: ${NODE_COUNT}"

# ── Apply ISM Policy ─────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[1/5] Applying ISM hot/warm/delete policy...${NC}"

curl -sf -X PUT "${OPENSEARCH_URL}/_plugins/_ism/policies/siem-hot-warm-delete" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/ism-hot-warm-policy.json" | jq .

echo -e "${GREEN}✓ ISM policy applied${NC}"

# ── Suricata Index Template ──────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/5] Applying Suricata index template...${NC}"

curl -sf -X PUT "${OPENSEARCH_URL}/_index_template/suricata-template" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-suricata.json" | jq .

echo -e "${GREEN}✓ Suricata template applied${NC}"

# ── pfBlockerNG Index Template ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/5] Applying pfBlockerNG index template...${NC}"

curl -sf -X PUT "${OPENSEARCH_URL}/_index_template/pfblockerng" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-pfblockerng.json" | jq .

echo -e "${GREEN}✓ pfBlockerNG template applied${NC}"

# ── Syslog Index Template ────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/5] Applying Syslog index template...${NC}"

curl -sf -X PUT "${OPENSEARCH_URL}/_index_template/syslog-template" \
    -H 'Content-Type: application/json' \
    -d '{
  "index_patterns": ["syslog-*", "pfsense-*", "unifi-syslog-*"],
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
curl -sf "${OPENSEARCH_URL}/_plugins/_ism/policies" | jq -r '.policies[].policy.description' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Index templates:"
curl -sf "${OPENSEARCH_URL}/_index_template" | jq -r '.index_templates[].name' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Cluster allocation tags:"
curl -sf "${OPENSEARCH_URL}/_cat/nodeattrs?v&h=node,attr,value" 2>/dev/null | grep temp || echo "    (waiting for nodes)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ISM Policy & Templates Applied          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "New indices matching suricata-*, syslog-*, pfblockerng-* will:"
echo "  1. Start on HOT tier (NVMe) — opensearch-hot node"
echo "  2. Move to WARM tier (SATA) after 30 days — opensearch-warm node"
echo "  3. Force-merge to 1 segment on WARM for read performance"
echo "  4. Delete after 365 days (1 year)"
