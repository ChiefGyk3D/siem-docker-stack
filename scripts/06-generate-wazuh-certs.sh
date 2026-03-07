#!/bin/bash
# =============================================================================
# 06-generate-wazuh-certs.sh — Generate Wazuh TLS certificates
# =============================================================================
# Generates self-signed TLS certificates for the Wazuh stack using the
# official Wazuh certificate generator Docker image.
#
# Run this ONCE before the first `docker compose up`.
#
# Usage:
#   bash scripts/06-generate-wazuh-certs.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../docker/wazuh/certs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Generate Wazuh TLS Certificates         ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

# Check if certs already exist
if [ -f "${CERTS_DIR}/root-ca.pem" ]; then
    echo -e "${YELLOW}⚠ Certificates already exist in ${CERTS_DIR}${NC}"
    echo "  Delete them first if you want to regenerate."
    read -p "Overwrite? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    rm -f "${CERTS_DIR}"/*.pem
fi

mkdir -p "${CERTS_DIR}"

echo -e "${YELLOW}Generating certificates...${NC}"

docker run --rm \
    -v "${CERTS_DIR}:/certs" \
    -e INDEXER_NAME=wazuh-indexer \
    -e MANAGER_NAME=wazuh-manager \
    -e DASHBOARD_NAME=wazuh-dashboard \
    wazuh/wazuh-certs-generator:latest

echo ""
echo -e "${GREEN}✓ Certificates generated:${NC}"
ls -la "${CERTS_DIR}"/*.pem 2>/dev/null || echo "  (no .pem files found — check Docker output above)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Wazuh Certificates Ready                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Next: Run 03-deploy.sh to deploy the stack."
echo ""
echo -e "${RED}SECURITY:${NC}"
echo "  - Never commit private keys (*-key.pem) to version control."
echo "  - Back up root-ca-key.pem securely."
