#!/bin/bash
# Replay pfSense CrowdSec fixture logs through syslog-ng and verify Logstash/OpenSearch indexing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/.."

# Load OPENSEARCH_ADMIN_PASSWORD from .env when present.
for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
  if [ -f "$envf" ]; then
    # shellcheck disable=SC1090
    set -a; source "$envf"; set +a
    break
  fi
done

SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
SYSLOG_PORT="${SYSLOG_PORT:-514}"
OPENSEARCH_URL="${OPENSEARCH_URL:-https://127.0.0.1:9200}"
FIXTURE="${FIXTURE:-tests/fixtures/crowdsec/pfsense-rfc5424.log}"

if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
  echo "ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env). See .env.example."
  exit 1
fi
# -k: self-signed cluster certs (scripts/07-generate-opensearch-certs.sh)
OS_CURL=(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}")

if [[ ! -f "${FIXTURE}" ]]; then
  echo "ERROR: fixture not found: ${FIXTURE}"
  exit 1
fi

echo "[1/3] Replaying fixture into syslog-ng ${SYSLOG_HOST}:${SYSLOG_PORT}"
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  printf '%s\n' "${line}" | nc -u -w1 "${SYSLOG_HOST}" "${SYSLOG_PORT}"
done < "${FIXTURE}"

sleep 3

echo "[2/3] Verifying fixture CrowdSec events indexed"
COUNT=$("${OS_CURL[@]}" -f -X POST "${OPENSEARCH_URL}/crowdsec-events-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.module.keyword":"crowdsec"}},{"term":{"source_host.keyword":"pfsense"}}],"should":[{"terms":{"program.keyword":["crowdsec","crowdsec-firewall-bouncer"]}},{"terms":{"crowdsec.scenario.keyword":["ssh-bf","http-probing"]}},{"terms":{"crowdsec.scenario":["ssh-bf","http-probing"]}}],"minimum_should_match":1}}}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("count",0))')

if [[ "${COUNT}" -lt 1 ]]; then
  echo "ERROR: fixture CrowdSec events not found in crowdsec-events-*"
  exit 1
fi

echo "ok fixture crowdsec-events count=${COUNT}"

echo "[3/3] Verifying parsed fields"
HIT=$("${OS_CURL[@]}" -f -X POST "${OPENSEARCH_URL}/crowdsec-events-*/_search?size=1&sort=@timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"source_host.keyword":"pfsense"}},{"exists":{"field":"program"}},{"exists":{"field":"crowdsec.action"}},{"exists":{"field":"source.ip"}}],"should":[{"terms":{"program.keyword":["crowdsec","crowdsec-firewall-bouncer"]}},{"terms":{"crowdsec.scenario.keyword":["ssh-bf","http-probing"]}}],"minimum_should_match":1}}}' \
  | python3 -c 'import sys,json; h=json.load(sys.stdin).get("hits",{}).get("total",{}); print(h.get("value",0) if isinstance(h,dict) else 0)')

if [[ "${HIT}" -lt 1 ]]; then
  echo "ERROR: parsed crowdsec.action/source.ip fields not found"
  exit 1
fi

echo "ok parsed fields verified"
echo "CrowdSec pfSense ingestion test passed"
