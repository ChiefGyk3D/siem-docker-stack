#!/bin/bash
# =============================================================================
# 03-deploy.sh — Deploy Docker configs and start the SIEM stack
# =============================================================================
# Can be run:
#   A) From your workstation (deploys via SSH + rsync to the server)
#   B) Directly on the SIEM server (local mode)
#
# Usage:
#   # Remote deployment (from workstation):
#   bash scripts/03-deploy.sh 10.0.0.100 siem
#
#   # Local deployment (on the SIEM server):
#   bash scripts/03-deploy.sh local
# =============================================================================

set -euo pipefail

SIEM_HOST="${1:-${SIEM_HOST:-localhost}}"
SIEM_USER="${2:-${SIEM_USER:-siem}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/.."
DEPLOY_DIR="/opt/siem"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Deploy SIEM Stack                       ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

# Determine deployment mode
LOCAL_MODE=false
if [ "$SIEM_HOST" = "local" ] || [ "$SIEM_HOST" = "localhost" ] || [ "$SIEM_HOST" = "127.0.0.1" ]; then
    LOCAL_MODE=true
    echo "Mode: LOCAL deployment"
else
    echo "Mode: REMOTE deployment to ${SIEM_USER}@${SIEM_HOST}"
fi

run_on_server() {
    if $LOCAL_MODE; then
        eval "$1"
    else
        ssh "${SIEM_USER}@${SIEM_HOST}" "$1"
    fi
}

# Verify connectivity (remote mode only)
if ! $LOCAL_MODE; then
    echo -e "${YELLOW}Testing SSH connectivity...${NC}"
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${SIEM_USER}@${SIEM_HOST}" "echo ok" > /dev/null 2>&1; then
        echo -e "${RED}Cannot SSH to ${SIEM_USER}@${SIEM_HOST}${NC}"
        echo "  Ensure SSH key is configured and the server is reachable."
        exit 1
    fi
    echo -e "${GREEN}✓ SSH connection OK${NC}"
fi

# Verify data disks
echo -e "${YELLOW}Verifying data disks...${NC}"
run_on_server "mountpoint -q /data/hot && mountpoint -q /data/warm && echo 'DISKS_OK'" | grep -q DISKS_OK || {
    echo -e "${RED}Data disks not mounted. Run 01-disk-setup.sh first.${NC}"
    exit 1
}
echo -e "${GREEN}✓ Data disks mounted${NC}"

# Verify Docker
echo -e "${YELLOW}Verifying Docker...${NC}"
run_on_server "docker info > /dev/null 2>&1 && echo 'DOCKER_OK'" | grep -q DOCKER_OK || {
    echo -e "${RED}Docker not available. Run 02-bootstrap.sh first.${NC}"
    exit 1
}
echo -e "${GREEN}✓ Docker available${NC}"

# Deploy Docker configs
echo ""
echo -e "${YELLOW}Deploying Docker configs to ${DEPLOY_DIR}...${NC}"

run_on_server "sudo mkdir -p ${DEPLOY_DIR} && sudo chown \$(whoami):\$(whoami) ${DEPLOY_DIR}"

if $LOCAL_MODE; then
    # Local: just copy
    cp -r "${REPO_DIR}/docker/"* "${DEPLOY_DIR}/"
else
    # Remote: rsync
    rsync -avz --delete \
        "${REPO_DIR}/docker/" \
        "${SIEM_USER}@${SIEM_HOST}:${DEPLOY_DIR}/"
fi

# Copy .env if it exists
if [ -f "${REPO_DIR}/.env" ]; then
    if $LOCAL_MODE; then
        cp "${REPO_DIR}/.env" "${DEPLOY_DIR}/.env"
    else
        scp "${REPO_DIR}/.env" "${SIEM_USER}@${SIEM_HOST}:${DEPLOY_DIR}/.env"
    fi
    echo -e "${GREEN}✓ .env deployed${NC}"
else
    echo -e "${YELLOW}⚠ No .env found — using defaults from docker-compose.yml${NC}"
    echo "  Copy .env.example to .env, configure it, and re-run."
fi

echo -e "${GREEN}✓ Docker configs deployed${NC}"

# Fix data directory permissions
echo ""
echo -e "${YELLOW}Fixing data directory permissions...${NC}"
run_on_server "
    sudo chown -R 1000:1000 /data/hot/opensearch /data/warm/opensearch 2>/dev/null || true
    sudo chown -R 472:472 /data/warm/grafana 2>/dev/null || true
    sudo chown -R 65534:65534 /data/hot/prometheus 2>/dev/null || true
    sudo chown -R 1000:1000 /data/hot/wazuh/indexer 2>/dev/null || true
"
echo -e "${GREEN}✓ Permissions set${NC}"

# Start the stack
echo ""
echo -e "${YELLOW}Starting SIEM stack...${NC}"
run_on_server "cd ${DEPLOY_DIR} && docker compose pull && docker compose up -d"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  SIEM Stack Deployed                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""

if $LOCAL_MODE; then
    HOST_DISPLAY="localhost"
else
    HOST_DISPLAY="${SIEM_HOST}"
fi

echo "Services starting at http://${HOST_DISPLAY}:"
echo "  Grafana:               :3000"
echo "  OpenSearch:             :9200"
echo "  OpenSearch Dashboards:  :5601"
echo "  Wazuh Dashboard:        :443  (HTTPS)"
echo "  Prometheus:             :9090"
echo "  InfluxDB:               :8086"
echo "  Portainer:              :9443 (HTTPS)"
echo ""
echo "Next steps:"
echo "  1. Wait ~2 minutes for all services to start"
echo "  2. Run: bash scripts/04-apply-ism-policy.sh http://${HOST_DISPLAY}:9200"
echo "  3. Run: bash scripts/05-verify.sh ${HOST_DISPLAY}"
