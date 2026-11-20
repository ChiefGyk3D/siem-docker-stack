#!/bin/bash -p
# =============================================================================
# 05-verify.sh — Verify all SIEM services are running and healthy
# =============================================================================
# Comprehensive health check for every service in the stack.
# Can run locally on the SIEM server or remotely against it.
#
# Usage:
#   bash scripts/05-verify.sh                        # defaults to localhost
#   bash scripts/05-verify.sh 10.0.0.100              # check remote server
#   bash scripts/05-verify.sh 10.0.0.100 myuser       # remote with custom SSH user
#   SIEM_USER=myuser bash scripts/05-verify.sh 10.0.0.100
# =============================================================================

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode (the -p shebang).
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs

SIEM_HOST="${1:-${SIEM_HOST:-localhost}}"
SIEM_USER="${2:-${SIEM_USER:-$(whoami)}}"
SCRIPT_DIR="$(/usr/bin/dirname -- "$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")")"  # the real directory, symlinks resolved
REPO_DIR="${SCRIPT_DIR}/.."

# Load credentials from .env when present (OPENSEARCH_ADMIN_PASSWORD,
# INFLUXDB_ADMIN_USER/PASSWORD) — Phase F1 secured the cluster and InfluxDB.
for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
    if [ -f "$envf" ]; then
        # shellcheck disable=SC1090
        set -a; source "$envf"; set +a
        break
    fi
done

# CONTAINER_ENGINE (docker by default, or podman) may come from the environment or that .env.
CE_LIB="${SCRIPT_DIR}/lib-container-engine.sh"
ce_boot_fail() { echo "refusing to source ${CE_LIB}: $1" >&2; exit 1; }
CE_UID="$(/usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null)" || CE_UID=
case "$CE_UID" in '' | *[!0-9]*) ce_boot_fail "cannot tell who is running (no numeric user number)" ;; esac
CE_UID=$((10#$CE_UID))  # asked of the kernel through id, never taken from an environment variable
CE_STRICT=0
[ "$CE_UID" != 0 ] || CE_STRICT=1
if [ "$CE_STRICT" = 1 ] && ! [[ "$-" == *p* ]]; then  # as root the privileged shebang must be in force
    ce_boot_fail "as root, run this script by its path (not as 'bash script'): the privileged shebang that keeps BASH_ENV and exported functions out is bypassed otherwise"
fi
if [ "$CE_STRICT" = 1 ]; then  # as root: the helper and every directory above it must be root-owned and not writable
    CE_P="$CE_LIB"
    while :; do
        [ "$(/usr/bin/stat -c %u -- "$CE_P")" = 0 ] && [ $((8#$(/usr/bin/stat -c %a -- "$CE_P") & 8#022)) -eq 0 ] ||
            ce_boot_fail "${CE_P} (or a directory above it) is not root-owned or is group or world writable"
        [ "$CE_P" = / ] && break
        CE_P="$(/usr/bin/dirname -- "$CE_P")"
    done
fi
[ -f "$CE_LIB" ] && [ ! -L "$CE_LIB" ] || ce_boot_fail "it is missing or is a link"
# Open the helper once, check the OPEN file (-L: the descriptor link points at the file), and source
# that same descriptor, so a rename or replacement of the path after this point changes nothing.
exec 9<"$CE_LIB" || ce_boot_fail "it cannot be opened"
CE_OWNER="$(/usr/bin/stat -L -c %u -- /proc/self/fd/9)"
CE_MODE="$(/usr/bin/stat -L -c %a -- /proc/self/fd/9)"
CE_MASK=002  # world write is never allowed; group write too when running as root
[ "$CE_STRICT" != 1 ] || CE_MASK=022
if [ ! -f /proc/self/fd/9 ] || { [ "$CE_OWNER" != 0 ] && [ "$CE_OWNER" != "$CE_UID" ]; } ||
    [ $((8#$CE_MODE & 8#$CE_MASK)) -ne 0 ]; then
    ce_boot_fail "it must be a regular file owned by root or by you, not world writable (and not group writable when run as root)"
fi
# shellcheck source=scripts/lib-container-engine.sh
source /proc/self/fd/9
exec 9<&-
ce_init_name || exit 1
OPENSEARCH_ADMIN_PASSWORD="${OPENSEARCH_ADMIN_PASSWORD:-}"
OS_AUTH="admin:${OPENSEARCH_ADMIN_PASSWORD}"
OS_URL="https://${SIEM_HOST}:9200"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  SIEM Stack Health Check                 ║${NC}"
echo -e "${YELLOW}║  Target: ${CYAN}${SIEM_HOST}${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

PASS=0
FAIL=0
WARN=0

check_http() {
    local name="$1"
    local url="$2"
    local expected="${3:-200}"

    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [ "$STATUS" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} ${name} — HTTP ${STATUS}"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} ${name} — HTTP ${STATUS} (expected ${expected})"
        ((FAIL++))
    fi
}

check_https() {
    local name="$1"
    local url="$2"
    local expected="${3:-200}"
    local auth="${4:-}"

    local curl_args="-sk"
    [ -n "$auth" ] && curl_args="$curl_args -u $auth"

    STATUS=$(curl $curl_args -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [ "$STATUS" = "$expected" ] || { [ "$expected" = "any" ] && [ "$STATUS" != "000" ]; }; then
        echo -e "  ${GREEN}✓${NC} ${name} — HTTP ${STATUS}"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} ${name} — HTTP ${STATUS} (expected ${expected})"
        ((FAIL++))
    fi
}

# ── OpenSearch Cluster ────────────────────────────────────────────────────────
echo -e "${YELLOW}OpenSearch Cluster:${NC}"
if [ -z "$OPENSEARCH_ADMIN_PASSWORD" ]; then
    echo -e "  ${YELLOW}⚠ OPENSEARCH_ADMIN_PASSWORD not set — authenticated checks will fail${NC}"
    ((WARN++))
fi
check_https "OpenSearch API (hot, authenticated)" "${OS_URL}" "200" "$OS_AUTH"
# Security regression check: anonymous access MUST be rejected now.
check_https "OpenSearch API (unauthenticated → 401)" "${OS_URL}" "401"
check_http "OpenSearch Dashboards" "http://${SIEM_HOST}:5601" "302"

CLUSTER_HEALTH=$(curl -sk -u "$OS_AUTH" "${OS_URL}/_cluster/health" 2>/dev/null || echo "")
if [ -n "$CLUSTER_HEALTH" ]; then
    CS=$(echo "$CLUSTER_HEALTH" | jq -r '.status')
    NODES=$(echo "$CLUSTER_HEALTH" | jq -r '.number_of_nodes')
    DATA_NODES=$(echo "$CLUSTER_HEALTH" | jq -r '.number_of_data_nodes')
    case "$CS" in
        green)  echo -e "  ${GREEN}●${NC} Cluster: ${GREEN}${CS}${NC} | Nodes: ${NODES} (${DATA_NODES} data)" ;;
        yellow) echo -e "  ${YELLOW}●${NC} Cluster: ${YELLOW}${CS}${NC} | Nodes: ${NODES} (${DATA_NODES} data)" ; ((WARN++)) ;;
        *)      echo -e "  ${RED}●${NC} Cluster: ${RED}${CS}${NC} | Nodes: ${NODES} (${DATA_NODES} data)" ; ((FAIL++)) ;;
    esac

    echo -e "  Node tiers:"
    curl -sk -u "$OS_AUTH" "${OS_URL}/_cat/nodeattrs?h=node,attr,value" 2>/dev/null | grep "temp" | while read -r line; do
        echo -e "    ${CYAN}${line}${NC}"
    done
fi

# ── Wazuh Stack ───────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Wazuh Stack:${NC}"
check_https "Wazuh Indexer" "https://${SIEM_HOST}:9202" "200" "admin:${WAZUH_INDEXER_PASSWORD:?set WAZUH_INDEXER_PASSWORD (export it from .env)}"
check_https "Wazuh Dashboard" "https://${SIEM_HOST}:443" "any"

echo -e "  ${YELLOW}NOTE: Change default Wazuh passwords after deployment!${NC}"

# ── Other Services ────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Services:${NC}"
check_http "Grafana" "http://${SIEM_HOST}:3000/api/health"
check_http "InfluxDB" "http://${SIEM_HOST}:8086/ping" "204"
# Prometheus requires basic auth; without a password HTTP 401 means it is up.
check_http "Prometheus" "http://${SIEM_HOST}:9090/-/healthy" "401"
# Alertmanager is bound to loopback — only checkable on the SIEM host itself.
if [ "$SIEM_HOST" = "localhost" ] || [ "$SIEM_HOST" = "127.0.0.1" ]; then
    check_http "Alertmanager" "http://127.0.0.1:9093/-/healthy"
fi

# ── Docker Containers ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Docker Containers:${NC}"
EXPECTED_CONTAINERS="alertmanager cadvisor elasticsearch-exporter grafana influxdb logstash opensearch-dashboards opensearch-hot opensearch-warm prometheus syslog-ng unifi-poller wazuh-dashboard wazuh-indexer wazuh-manager"

# Try the local container engine first (CONTAINER_ENGINE, found in fixed root-owned
# directories only), then SSH
CE_BIN="$(ce_resolve "$CE_NAME" || true)"
if [ -n "$CE_BIN" ] && ce_run ps > /dev/null 2>&1; then
    RUNNING_CONTAINERS=$(ce_run ps --format "{{.Names}}" 2>/dev/null | sort | tr '\n' ' ')
    DOCKER_CMD="$CE_NAME"
elif [ "$SIEM_HOST" != "localhost" ] && [ "$SIEM_HOST" != "127.0.0.1" ]; then
    RUNNING_CONTAINERS=$(ssh -o ConnectTimeout=5 "${SIEM_USER}@${SIEM_HOST}" "${CE_NAME}"' ps --format "{{.Names}}"' 2>/dev/null | sort | tr '\n' ' ')
    DOCKER_CMD="ssh ${SIEM_USER}@${SIEM_HOST} ${CE_NAME}"
else
    echo -e "  ${YELLOW}Cannot access Docker - skipping container check${NC}"
    RUNNING_CONTAINERS=""
    DOCKER_CMD=""
fi

for c in $EXPECTED_CONTAINERS; do
    if echo "$RUNNING_CONTAINERS" | grep -qw "$c"; then
        echo -e "  ${GREEN}✓${NC} ${c}"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} ${c} — NOT RUNNING"
        ((FAIL++))
    fi
done

# ── Disk Usage ────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Disk Usage:${NC}"
if mountpoint -q /data/hot 2>/dev/null; then
    echo "  /data/hot (NVMe): $(df -h /data/hot | awk 'NR==2{printf "%s used / %s total (%s)", $3, $2, $5}')"
    echo "  /data/warm (SATA): $(df -h /data/warm | awk 'NR==2{printf "%s used / %s total (%s)", $3, $2, $5}')"

    for mount in /data/hot /data/warm; do
        pct=$(df --output=pcent "$mount" 2>/dev/null | tail -1 | tr -d " %")
        if [ "$pct" -gt 90 ] 2>/dev/null; then
            echo -e "  ${RED}⚠ CRITICAL: ${mount} at ${pct}%${NC}"
            ((FAIL++))
        elif [ "$pct" -gt 80 ] 2>/dev/null; then
            echo -e "  ${YELLOW}⚠ WARNING: ${mount} at ${pct}%${NC}"
            ((WARN++))
        fi
    done
else
    echo "  (Disk info only available when running on the SIEM server)"
fi

# ── ISM Policy ────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}ISM Policy:${NC}"
ISM_POLICIES=$(curl -sk -u "$OS_AUTH" "${OS_URL}/_plugins/_ism/policies" 2>/dev/null || echo "")
if [ -n "$ISM_POLICIES" ]; then
    COUNT=$(echo "$ISM_POLICIES" | jq -r '.total_policies // 0')
    if [ "$COUNT" -gt 0 ]; then
        echo "$ISM_POLICIES" | jq -r '.policies[] | "  \(.policy_id): \(.policy.description // "no description")"' 2>/dev/null
    else
        echo -e "  ${YELLOW}No ISM policies — run 04-apply-ism-policy.sh${NC}"
    fi
fi

# ── InfluxDB Databases ───────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}InfluxDB Databases:${NC}"
INFLUX_DBS=$(curl -sf -u "${INFLUXDB_ADMIN_USER:-admin}:${INFLUXDB_ADMIN_PASSWORD:-}" "http://${SIEM_HOST}:8086/query?q=SHOW+DATABASES" 2>/dev/null || echo "")
if [ -n "$INFLUX_DBS" ]; then
    echo "$INFLUX_DBS" | jq -r '.results[0].series[0].values[][0]' 2>/dev/null | while read -r db; do
        echo -e "  ${GREEN}✓${NC} ${db}"
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo -e "  Passed: ${GREEN}${PASS}${NC}  |  Warnings: ${YELLOW}${WARN}${NC}  |  Failed: ${RED}${FAIL}${NC}"
echo -e "${YELLOW}═══════════════════════════════════════${NC}"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
