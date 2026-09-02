#!/bin/bash
# =============================================================================
# render-alertmanager-config.sh — Render alertmanager.yml from its template
# =============================================================================
# Alertmanager does not interpolate environment variables, so the n8n webhook
# URL is baked into docker/alertmanager/alertmanager.yml by this script
# (envsubst over alertmanager.yml.template).
#
# Reads N8N_ALERTMANAGER_WEBHOOK_URL from the environment or .env; defaults
# to http://n8n/webhook/alertmanager-siem (the stack's macvlan n8n).
#
# Usage:
#   bash scripts/render-alertmanager-config.sh                # render repo copy
#   bash scripts/render-alertmanager-config.sh /opt/siem      # render deployed copy
#
# After rendering the deployed copy: docker compose restart alertmanager
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BASE="${1:-${REPO_DIR}/docker}"
TEMPLATE="${REPO_DIR}/docker/alertmanager/alertmanager.yml.template"
OUT="${TARGET_BASE}/alertmanager/alertmanager.yml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

command -v envsubst >/dev/null 2>&1 || {
    echo -e "${RED}envsubst not found — install gettext-base (apt install gettext-base).${NC}"
    exit 1
}

# Pick up N8N_ALERTMANAGER_WEBHOOK_URL from .env if not already set
if [ -z "${N8N_ALERTMANAGER_WEBHOOK_URL:-}" ]; then
    for candidate in "${TARGET_BASE}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$candidate" ] && grep -q '^N8N_ALERTMANAGER_WEBHOOK_URL=' "$candidate"; then
            N8N_ALERTMANAGER_WEBHOOK_URL="$(grep '^N8N_ALERTMANAGER_WEBHOOK_URL=' "$candidate" | tail -1 | cut -d= -f2-)"
            break
        fi
    done
fi
export N8N_ALERTMANAGER_WEBHOOK_URL="${N8N_ALERTMANAGER_WEBHOOK_URL:-http://n8n/webhook/alertmanager-siem}"

echo -e "${YELLOW}Rendering ${OUT}${NC}"
echo "  N8N_ALERTMANAGER_WEBHOOK_URL=${N8N_ALERTMANAGER_WEBHOOK_URL}"

mkdir -p "$(dirname "$OUT")"
# Only substitute the one variable so amtool matchers etc. survive untouched.
envsubst '${N8N_ALERTMANAGER_WEBHOOK_URL}' < "$TEMPLATE" > "$OUT"

echo -e "${GREEN}✓ alertmanager.yml rendered${NC}"
echo ""
echo "Validate (optional):"
echo "  docker run --rm --entrypoint amtool -v \"${OUT}\":/tmp/am.yml:ro \\"
echo "    prom/alertmanager:v0.27.0 check-config /tmp/am.yml"
echo ""
echo "Apply: docker compose restart alertmanager"
