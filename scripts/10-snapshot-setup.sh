#!/bin/bash
# =============================================================================
# 10-snapshot-setup.sh — Register snapshot repo + daily SM policy (Phase F4)
# =============================================================================
# 1. Registers the filesystem snapshot repository "siem-snapshots"
#    (/mnt/snapshots inside both nodes = /data/warm/snapshots on the host —
#    see path.repo in docker/opensearch/opensearch-{hot,warm}.yml).
# 2. Creates/updates the OpenSearch Snapshot Management (SM) policy
#    "siem-daily": daily snapshot at 03:00 UTC of the SIEM event indices,
#    deletion run at 05:00 UTC keeping 14 days.
#
# Idempotent — safe to re-run; an existing policy is updated in place
# (SM updates require if_seq_no/if_primary_term, handled below).
#
# Requires OPENSEARCH_ADMIN_PASSWORD (env or .env). Restore procedure and
# drill: docs/backup-restore.md
#
# Usage:
#   bash scripts/10-snapshot-setup.sh
#   bash scripts/10-snapshot-setup.sh https://10.0.0.100:9200
# =============================================================================

set -euo pipefail

OPENSEARCH_URL="${1:-https://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/.."

REPO_NAME="siem-snapshots"
POLICY_NAME="siem-daily"
SNAPSHOT_INDICES="suricata-*,syslog-*,pfsense-*,pfblockerng-*,unifi-syslog-*,crowdsec-events-*"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  OpenSearch Snapshot Setup (F4)          ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

# Load OPENSEARCH_ADMIN_PASSWORD from .env if not already set
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$envf" ]; then
            # shellcheck disable=SC1090
            set -a; source "$envf"; set +a
            break
        fi
    done
fi
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    echo -e "${RED}ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env).${NC}"
    exit 1
fi
CURL=(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}")

# ── Wait for cluster ─────────────────────────────────────────────────────────
echo -e "${YELLOW}Waiting for OpenSearch at ${OPENSEARCH_URL}...${NC}"
if ! "${CURL[@]}" -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: OpenSearch not reachable/authenticated at ${OPENSEARCH_URL}${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Cluster reachable${NC}"

# ── [1/3] Register the fs repository ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[1/3] Registering snapshot repository '${REPO_NAME}'...${NC}"
REPO_RESULT=$("${CURL[@]}" -X PUT "${OPENSEARCH_URL}/_snapshot/${REPO_NAME}" \
    -H 'Content-Type: application/json' \
    -d '{
  "type": "fs",
  "settings": {
    "location": "/mnt/snapshots",
    "compress": true
  }
}')
if echo "$REPO_RESULT" | grep -q '"acknowledged":true'; then
    echo -e "${GREEN}✓ Repository registered${NC}"
else
    echo -e "${RED}✗ Repository registration failed:${NC}"
    echo "$REPO_RESULT" | jq . 2>/dev/null || echo "$REPO_RESULT"
    echo "  Check that /data/warm/snapshots exists, is owned by uid 1000, and"
    echo "  that path.repo includes /mnt/snapshots on BOTH nodes (restart needed"
    echo "  after config changes)."
    exit 1
fi

# Verify both nodes can see the repo
echo "  Verifying repository on all nodes..."
VERIFY=$("${CURL[@]}" -X POST "${OPENSEARCH_URL}/_snapshot/${REPO_NAME}/_verify")
NODE_COUNT=$(echo "$VERIFY" | jq -r '.nodes | length' 2>/dev/null || echo 0)
echo -e "  ${GREEN}✓ Verified on ${NODE_COUNT} node(s)${NC}"

# ── [2/3] Create/update the SM policy ────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/3] Applying Snapshot Management policy '${POLICY_NAME}'...${NC}"

SM_BODY=$(cat <<JSON
{
  "description": "Daily snapshot of SIEM event indices, 14-day retention (Phase F4)",
  "creation": {
    "schedule": {
      "cron": {
        "expression": "0 3 * * *",
        "timezone": "UTC"
      }
    },
    "time_limit": "1h"
  },
  "deletion": {
    "schedule": {
      "cron": {
        "expression": "0 5 * * *",
        "timezone": "UTC"
      }
    },
    "condition": {
      "max_age": "14d",
      "min_count": 3,
      "max_count": 21
    },
    "time_limit": "1h"
  },
  "snapshot_config": {
    "repository": "${REPO_NAME}",
    "indices": "${SNAPSHOT_INDICES}",
    "ignore_unavailable": true,
    "include_global_state": false,
    "partial": true
  }
}
JSON
)

EXISTING=$("${CURL[@]}" "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}")
if echo "$EXISTING" | jq -e '.sm_policy' > /dev/null 2>&1; then
    SEQ_NO=$(echo "$EXISTING" | jq -r '._seq_no')
    PRIMARY_TERM=$(echo "$EXISTING" | jq -r '._primary_term')
    echo "  Policy exists — updating (seq_no=${SEQ_NO}, primary_term=${PRIMARY_TERM})"
    RESULT=$("${CURL[@]}" -X PUT \
        "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}?if_seq_no=${SEQ_NO}&if_primary_term=${PRIMARY_TERM}" \
        -H 'Content-Type: application/json' -d "$SM_BODY")
else
    echo "  Policy does not exist — creating"
    RESULT=$("${CURL[@]}" -X POST "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}" \
        -H 'Content-Type: application/json' -d "$SM_BODY")
fi

if echo "$RESULT" | jq -e '.sm_policy' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ SM policy applied${NC}"
else
    echo -e "${RED}✗ SM policy failed:${NC}"
    echo "$RESULT" | jq . 2>/dev/null || echo "$RESULT"
    exit 1
fi

# ── [3/3] Show status ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/3] Current snapshot state:${NC}"
echo "  Policy:"
"${CURL[@]}" "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}" \
    | jq -r '.sm_policy | "    schedule: \(.creation.schedule.cron.expression) UTC | retention: \(.deletion.condition.max_age)"' 2>/dev/null || true
echo "  Existing snapshots:"
"${CURL[@]}" "${OPENSEARCH_URL}/_cat/snapshots/${REPO_NAME}?v&h=id,status,start_time,duration,indices" 2>/dev/null \
    | head -10 || echo "    (none yet — first run at 03:00 UTC)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Snapshot Setup Complete                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Manual snapshot now:"
echo "  curl -sk -u admin:... -X PUT '${OPENSEARCH_URL}/_snapshot/${REPO_NAME}/manual-\$(date +%Y%m%d)?wait_for_completion=false' \\"
echo "    -H 'Content-Type: application/json' -d '{\"indices\":\"${SNAPSHOT_INDICES}\",\"include_global_state\":false}'"
echo ""
echo "Restore drill + offsite copy guidance: docs/backup-restore.md"
echo "NOTE: the Wazuh indexer (wazuh-alerts-*) is a separate cluster and is"
echo "NOT covered by this policy — tracked as a Phase F follow-up."
