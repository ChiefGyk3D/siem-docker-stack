#!/bin/bash
# CrowdSec integration smoke test for siem-docker-stack.
# Verifies:
#   1) synthetic CrowdSec-like doc can be indexed into OpenSearch
#   2) doc is queryable
#   3) CrowdSec Grafana alert rule exists
#   4) CrowdSec dashboard exists

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/.."

# Load OPENSEARCH_ADMIN_PASSWORD (and Grafana creds) from .env when present.
for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
  if [ -f "$envf" ]; then
    # shellcheck disable=SC1090
    set -a; source "$envf"; set +a
    break
  fi
done

OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-${GRAFANA_ADMIN_PASS:-changeme}}"

if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
  echo "ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env). See .env.example."
  exit 1
fi
# -k: self-signed cluster certs (scripts/07-generate-opensearch-certs.sh)
OS_CURL=(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}")

# Use a dedicated smoketest index so the live crowdsec-events-YYYY.MM.dd
# indices are never polluted; it is deleted again on exit.
IDX="crowdsec-events-smoketest"
DOC_ID="crowdsec-smoke-$(date +%s)"

cleanup() {
  "${OS_CURL[@]}" -f -X DELETE "${OPENSEARCH_URL}/${IDX}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

payload=$(cat <<JSON
{
  "@timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "event": {"module": "crowdsec", "kind": "alert"},
  "crowdsec": {"type": "decision", "action": "ban", "scenario": "ssh-bf", "source_ip": "203.0.113.10"},
  "rule": {"groups": ["crowdsec", "crowdsec_decision"], "description": "CrowdSec ban decision issued"}
}
JSON
)

echo "[1/4] Index synthetic CrowdSec doc: ${IDX}/${DOC_ID}"
"${OS_CURL[@]}" -f -X PUT "${OPENSEARCH_URL}/${IDX}/_doc/${DOC_ID}?refresh=wait_for" \
  -H 'Content-Type: application/json' \
  -d "${payload}" >/dev/null

echo "[2/4] Verify doc query count"
count=$("${OS_CURL[@]}" -f -X POST "${OPENSEARCH_URL}/${IDX}/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"should":[{"term":{"event.module.keyword":"crowdsec"}},{"term":{"event.module":"crowdsec"}},{"match":{"event.module":"crowdsec"}}],"minimum_should_match":1}}}' | python3 -c 'import sys,json; print(json.load(sys.stdin).get("count",0))')
if [[ "${count}" -lt 1 ]]; then
  echo "ERROR: CrowdSec synthetic doc not found"
  exit 1
fi
echo "ok count=${count}"

echo "[3/4] Verify Grafana alert rule exists"
rule_found=$(curl -sf -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  "${GRAFANA_URL}/api/v1/provisioning/alert-rules" | \
  python3 -c 'import sys,json; rules=json.load(sys.stdin); print(any(r.get("title")=="CrowdSec Ban Decision Surge" for r in rules))')
if [[ "${rule_found}" != "True" ]]; then
  echo "ERROR: CrowdSec alert rule missing"
  exit 1
fi
echo "ok alert rule present"

echo "[4/4] Verify CrowdSec dashboard exists"
db_found=$(curl -sf -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  "${GRAFANA_URL}/api/search?query=CrowdSec%20Overview" | \
  python3 -c 'import sys,json; rows=json.load(sys.stdin); print(any((r.get("uid")=="crowdsec-overview" or r.get("title")=="CrowdSec Overview") for r in rows))')
if [[ "${db_found}" != "True" ]]; then
  echo "ERROR: CrowdSec dashboard missing"
  exit 1
fi
echo "ok dashboard present"

echo "CrowdSec smoke test passed"
