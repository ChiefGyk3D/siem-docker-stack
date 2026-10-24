#!/bin/bash
# =============================================================================
# check-env.sh — Refuse to deploy with missing or well-known secrets
# =============================================================================
# docker-compose.yml fails when a required secret is UNSET (${VAR:?}), but an
# .env copied from the example still has placeholder values that are set. This
# check rejects empty values and the well-known placeholders/old defaults.
# It prints variable names only, never values.
#
# Usage:
#   bash scripts/check-env.sh [path/to/.env]     # default: ./.env
# Exit: 0 all good, 1 problems found, 2 file not found.
# =============================================================================
set -euo pipefail

ENV_FILE="${1:-.env}"
[ -f "$ENV_FILE" ] || { echo "check-env: $ENV_FILE not found (cp .env.example .env)" >&2; exit 2; }

REQUIRED=(
    OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD
    OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD
    GRAFANA_ADMIN_PASS
    INFLUXDB_ADMIN_PASSWORD GRAFANA_INFLUX_PASSWORD UNPOLLER_INFLUX_PASSWORD
    WAZUH_INDEXER_PASSWORD WAZUH_API_PASSWORD WAZUH_DASHBOARD_PASSWORD
    UNIFI_PASS
)

# Lower-cased exact matches and prefixes that are known defaults or examples.
is_placeholder() {
    local v
    v="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$v" in
        changeme* | secretpassword | my[s]3cr3tp4ssw0rd | kibanaserver | admin | password | \
            "<"* | *"your-password"* | *"strong-password"*) return 0 ;;
    esac
    return 1
}

bad=0
for var in "${REQUIRED[@]}"; do
    line="$(grep -E "^${var}=" "$ENV_FILE" | tail -1 || true)"
    value="${line#*=}"
    value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
    if [ -z "$line" ] || [ -z "$value" ]; then
        echo "check-env: ${var} is missing or empty" >&2
        bad=1
    elif is_placeholder "$value"; then
        echo "check-env: ${var} still has a placeholder or known default value" >&2
        bad=1
    fi
done

if [ "$bad" -ne 0 ]; then
    echo "check-env: set strong unique values in $ENV_FILE (see README, Upgrade notes)" >&2
    exit 1
fi
echo "check-env: all required secrets are set and none is a known default"
