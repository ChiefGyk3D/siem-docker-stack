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
    WAZUH_GRAFANA_RO_PASSWORD
    UNIFI_PASS
    PROMETHEUS_OTLP_SENDER_PASSWORD PROMETHEUS_OTLP_GRAFANA_PASSWORD PROMETHEUS_OTLP_SCRAPE_PASSWORD
    PROMETHEUS_GRAFANA_PASSWORD PROMETHEUS_SELF_PASSWORD
)

# One placeholder rule for every shell script lives in lib-secrets.sh.
# shellcheck source=scripts/lib-secrets.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib-secrets.sh"
is_placeholder() { secret_is_placeholder "$1"; }

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

# The Grafana to n8n webhook secret (docs/update-alerting.md) also needs a
# minimum length. Docker Compose reads the same .env file, so the value is
# parsed the way Compose parses it for this variable: an unquoted value ends at
# whitespace followed by '#', matching single or double quotes are removed, and
# the quoted text may be followed by a comment. Anything ambiguous (a duplicate
# assignment, an unmatched quote, a backslash, a '$' Compose would interpolate,
# a carriage return) is rejected. The parsed value must be non-empty, not
# whitespace-only, not a placeholder and at least 32 characters. It is never
# printed.
var=GRAFANA_WEBHOOK_SECRET
count="$(grep -cE "^${var}=" "$ENV_FILE" || true)"
line="$(grep -E "^${var}=" "$ENV_FILE" | tail -1 || true)"
rest="${line#*=}"
rest="${rest#"${rest%%[![:space:]]*}"}"
re_dq='^"([^"\\]*)"([[:space:]]+#.*)?[[:space:]]*$'
re_sq="^'([^']*)'([[:space:]]+#.*)?[[:space:]]*\$"
parsed=""
single=0
parse_ok=1
case "$rest" in
    \"*)
        if [[ "$rest" =~ $re_dq ]]; then parsed="${BASH_REMATCH[1]}"; else parse_ok=0; fi ;;
    \'*)
        if [[ "$rest" =~ $re_sq ]]; then parsed="${BASH_REMATCH[1]}"; single=1; else parse_ok=0; fi ;;
    *)
        parsed="${rest%%[[:space:]]#*}"
        case "$rest" in "#"*) parsed="" ;; esac
        parsed="${parsed%"${parsed##*[![:space:]]}"}"
        case "$parsed" in *\"* | *\'*) parse_ok=0 ;; esac ;;
esac
trimmed="$(printf '%s' "$parsed" | tr -d '[:space:]')"
unsafe=0
case "$parsed" in
    *\\* | *$'\r'*) unsafe=1 ;;
    *\$*) [ "$single" -eq 0 ] && unsafe=1 ;;
esac
if [ -z "$line" ] || { [ "$parse_ok" -eq 1 ] && [ -z "$trimmed" ]; }; then
    echo "check-env: ${var} is missing, empty or only whitespace" >&2
    bad=1
elif [ "$count" -gt 1 ]; then
    echo "check-env: ${var} is assigned more than once; keep exactly one assignment" >&2
    bad=1
elif [ "$parse_ok" -eq 0 ]; then
    echo "check-env: ${var} has an unmatched quote or a quote inside an unquoted value" >&2
    bad=1
elif [ "$unsafe" -eq 1 ]; then
    echo "check-env: ${var} must not contain a backslash, carriage return or an unquoted dollar sign" >&2
    bad=1
elif is_placeholder "$trimmed"; then
    echo "check-env: ${var} still has a placeholder or known default value" >&2
    bad=1
elif [ "${#parsed}" -lt 32 ]; then
    echo "check-env: ${var} must be at least 32 characters (generate it with: openssl rand -base64 32)" >&2
    bad=1
fi

if [ "$bad" -ne 0 ]; then
    echo "check-env: set strong unique values in $ENV_FILE (see README, Required secrets)" >&2
    exit 1
fi
echo "check-env: all required secrets are set and none is a known default"

# Not an error: loopback ingest is the safe default. But on an upgraded stack it
# silently stops log intake from firewalls, sensors and agents on other hosts.
ingest="$(grep -E '^INGEST_BIND_ADDR=' "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
ingest="${ingest%\"}"; ingest="${ingest#\"}"; ingest="${ingest%\'}"; ingest="${ingest#\'}"
case "$ingest" in
    "" | 127.* | localhost | ::1)
        echo "check-env: WARNING: INGEST_BIND_ADDR is unset or loopback, so syslog, EVE, Beats, Wazuh agents and Telegraf from other hosts cannot reach this stack. Set INGEST_BIND_ADDR in $ENV_FILE to this host's interface address (see README, Network exposure)." >&2
        ;;
esac
