#!/bin/bash
# =============================================================================
# 05-verify.sh — Verify all SIEM services are running and healthy
# =============================================================================
# Comprehensive health check for every service in the stack.
# Can run locally on the SIEM server or remotely against it.
#
# Usage:
#   bash scripts/05-verify.sh              # defaults to localhost
#   bash scripts/05-verify.sh 10.0.0.100   # check remote server
# =============================================================================

set -uo pipefail

SIEM_HOST="${1:-${SIEM_HOST:-localhost}}"

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
check_http "OpenSearch API (hot)" "http://${SIEM_HOST}:9200"
check_http "OpenSearch Dashboards" "http://${SIEM_HOST}:5601" "302"

CLUSTER_HEALTH=$(curl -sf "http://${SIEM_HOST}:9200/_cluster/health" 2>/dev/null || echo "")
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
    curl -sf "http://${SIEM_HOST}:9200/_cat/nodeattrs?h=node,attr,value" 2>/dev/null | grep "temp" | while read -r line; do
        echo -e "    ${CYAN}${line}${NC}"
    done
fi

# ── Wazuh Stack ───────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Wazuh Stack:${NC}"
check_https "Wazuh Indexer" "https://${SIEM_HOST}:9202" "200" "admin:SecretPassword"
check_https "Wazuh Dashboard" "https://${SIEM_HOST}:443" "any"

echo -e "  ${YELLOW}NOTE: Change default Wazuh passwords after deployment!${NC}"

# ── Other Services ────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Services:${NC}"
check_http "Grafana" "http://${SIEM_HOST}:3000/api/health"
check_http "InfluxDB" "http://${SIEM_HOST}:8086/ping" "204"
check_http "Prometheus" "http://${SIEM_HOST}:9090/-/healthy"

# ── Docker Containers ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Docker Containers:${NC}"
EXPECTED_CONTAINERS="grafana influxdb logstash opensearch-dashboards opensearch-hot opensearch-warm portainer prometheus syslog-ng unifi-poller wazuh-dashboard wazuh-indexer wazuh-manager"

# Try local docker first, then SSH
if docker ps > /dev/null 2>&1; then
    RUNNING_CONTAINERS=$(docker ps --format "{{.Names}}" 2>/dev/null | sort | tr '\n' ' ')
    DOCKER_CMD="docker"
elif [ "$SIEM_HOST" != "localhost" ] && [ "$SIEM_HOST" != "127.0.0.1" ]; then
    RUNNING_CONTAINERS=$(ssh -o ConnectTimeout=5 "${SIEM_USER:-siem}@${SIEM_HOST}" 'docker ps --format "{{.Names}}"' 2>/dev/null | sort | tr '\n' ' ')
    DOCKER_CMD="ssh ${SIEM_USER:-siem}@${SIEM_HOST} docker"
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
ISM_POLICIES=$(curl -sf "http://${SIEM_HOST}:9200/_plugins/_ism/policies" 2>/dev/null || echo "")
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
INFLUX_DBS=$(curl -sf "http://${SIEM_HOST}:8086/query?q=SHOW+DATABASES" 2>/dev/null || echo "")
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
