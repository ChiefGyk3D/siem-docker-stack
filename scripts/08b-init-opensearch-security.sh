#!/bin/bash
# =============================================================================
# 08b-init-opensearch-security.sh — Bootstrap OpenSearch security config
# =============================================================================
# Renders docker/opensearch/security/internal_users.yml from the tracked
# template (bcrypt-hashing the OPENSEARCH_*_PASSWORD values from .env inside
# the opensearch-hot container), then applies the full security configuration
# to the running cluster with securityadmin.sh + the admin client cert.
#
# Idempotent: safe to re-run any time (e.g. after a password change or a
# redeploy). Requires:
#   - scripts/07-generate-opensearch-certs.sh already run (certs mounted)
#   - opensearch-hot container running (TLS up is enough — the security
#     index does NOT need to be initialized yet; that is what this does)
#   - OPENSEARCH_ADMIN_PASSWORD / OPENSEARCH_LOGSTASH_PASSWORD /
#     OPENSEARCH_READONLY_PASSWORD / OPENSEARCH_DASHBOARDS_PASSWORD in .env
#
# Usage:
#   bash scripts/08b-init-opensearch-security.sh
#   SIEM_DEPLOY_DIR=/opt/siem bash scripts/08b-init-opensearch-security.sh
#
# Target dir: the directory docker compose actually runs from. Defaults to
# /opt/siem when it exists (03-deploy.sh layout), otherwise the repo's
# docker/ directory (repo-local compose).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Initialize OpenSearch Security          ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Locate deploy dir + .env ─────────────────────────────────────────────────
if [ -n "${SIEM_DEPLOY_DIR:-}" ]; then
    DEPLOY_DIR="${SIEM_DEPLOY_DIR}"
elif [ -f /opt/siem/docker-compose.yml ]; then
    DEPLOY_DIR="/opt/siem"
else
    DEPLOY_DIR="${REPO_DIR}/docker"
fi
echo "Target compose dir: ${DEPLOY_DIR}"

ENV_FILE=""
for candidate in "${DEPLOY_DIR}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
    if [ -f "$candidate" ]; then
        ENV_FILE="$candidate"
        break
    fi
done

if [ -n "$ENV_FILE" ]; then
    echo "Loading passwords from ${ENV_FILE}"
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

MISSING=0
for var in OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD \
           OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD; do
    if [ -z "${!var:-}" ]; then
        echo -e "${RED}✗ ${var} is not set (add it to .env — see .env.example)${NC}"
        MISSING=1
    fi
done
[ "$MISSING" -eq 1 ] && exit 1

SECURITY_DIR="${DEPLOY_DIR}/opensearch/security"
TEMPLATE="${SECURITY_DIR}/internal_users.yml.template"
if [ ! -f "$TEMPLATE" ]; then
    echo -e "${RED}✗ ${TEMPLATE} not found — deploy configs first (03-deploy.sh).${NC}"
    exit 1
fi

# ── Wait for opensearch-hot to be up (TLS answering, auth optional) ──────────
echo ""
echo -e "${YELLOW}[1/4] Waiting for opensearch-hot HTTPS endpoint...${NC}"
UP=0
for i in {1..30}; do
    CODE=$(docker exec opensearch-hot \
        curl -sk -o /dev/null -w '%{http_code}' https://localhost:9200/ 2>/dev/null || echo "000")
    # 401 = security initialized, 503 = security index not initialized yet,
    # 200 would mean auth is off — any of these means TLS + HTTP are up.
    if [ "$CODE" != "000" ]; then
        echo -e "${GREEN}✓ opensearch-hot HTTPS is up (HTTP ${CODE})${NC}"
        UP=1
        break
    fi
    echo "  Waiting... (${i}/30)"
    sleep 5
done
if [ "$UP" -ne 1 ]; then
    echo -e "${RED}✗ opensearch-hot not answering on https://localhost:9200${NC}"
    echo "  Check: docker logs opensearch-hot"
    exit 1
fi

# ── Hash passwords inside the container ──────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/4] Generating bcrypt hashes...${NC}"

hash_password() {
    local pass="$1"
    docker exec -e HASH_PASS="$pass" opensearch-hot bash -c \
        'plugins/opensearch-security/tools/hash.sh -p "$HASH_PASS"' 2>/dev/null \
        | grep -E '^\$2[aby]\$' | tail -1
}

ADMIN_HASH=$(hash_password "$OPENSEARCH_ADMIN_PASSWORD")
LOGSTASH_HASH=$(hash_password "$OPENSEARCH_LOGSTASH_PASSWORD")
READONLY_HASH=$(hash_password "$OPENSEARCH_READONLY_PASSWORD")
DASHBOARDS_HASH=$(hash_password "$OPENSEARCH_DASHBOARDS_PASSWORD")

for h in "$ADMIN_HASH" "$LOGSTASH_HASH" "$READONLY_HASH" "$DASHBOARDS_HASH"; do
    if [ -z "$h" ]; then
        echo -e "${RED}✗ bcrypt hashing failed (hash.sh inside opensearch-hot)${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ 4 hashes generated${NC}"

# ── Render internal_users.yml (python for safe token replacement — bcrypt
#    hashes contain $ and / which break sed) ─────────────────────────────────
echo ""
echo -e "${YELLOW}[3/4] Rendering internal_users.yml...${NC}"
ADMIN_HASH="$ADMIN_HASH" LOGSTASH_HASH="$LOGSTASH_HASH" \
READONLY_HASH="$READONLY_HASH" DASHBOARDS_HASH="$DASHBOARDS_HASH" \
python3 - "$TEMPLATE" "${SECURITY_DIR}/internal_users.yml" <<'PYEOF'
import os, sys
template, out = sys.argv[1], sys.argv[2]
with open(template, encoding="utf-8") as f:
    content = f.read()
for token, env in [("__ADMIN_HASH__", "ADMIN_HASH"),
                   ("__LOGSTASH_HASH__", "LOGSTASH_HASH"),
                   ("__READONLY_HASH__", "READONLY_HASH"),
                   ("__DASHBOARDS_HASH__", "DASHBOARDS_HASH")]:
    content = content.replace(token, os.environ[env])
with open(out, "w", encoding="utf-8") as f:
    f.write(content)
os.chmod(out, 0o640)
print(f"  wrote {out}")
PYEOF
echo -e "${GREEN}✓ internal_users.yml rendered${NC}"

# ── Apply with securityadmin.sh (admin client cert) ──────────────────────────
# The security dir is bind-mounted into opensearch-hot at
# /usr/share/opensearch/config/opensearch-security, so the rendered file is
# already visible inside the container. -icl ignores clustername, -nhnv skips
# hostname verification (self-signed certs).
echo ""
echo -e "${YELLOW}[4/4] Applying security configuration (securityadmin.sh)...${NC}"
docker exec opensearch-hot bash -c '
    plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/opensearch/config/opensearch-security \
        -cacert /usr/share/opensearch/config/certs/root-ca.pem \
        -cert /usr/share/opensearch/config/certs/admin.pem \
        -key /usr/share/opensearch/config/certs/admin-key.pem \
        -h localhost -p 9200 \
        -icl -nhnv
' 2>&1 | tail -15

# ── Verify ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Verifying...${NC}"
AUTH_CODE=$(docker exec opensearch-hot curl -sk -o /dev/null -w '%{http_code}' \
    -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" https://localhost:9200/_cluster/health)
NOAUTH_CODE=$(docker exec opensearch-hot curl -sk -o /dev/null -w '%{http_code}' \
    https://localhost:9200/_cluster/health)

if [ "$AUTH_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Authenticated admin request: HTTP 200${NC}"
else
    echo -e "${RED}✗ Authenticated admin request failed: HTTP ${AUTH_CODE}${NC}"
    exit 1
fi
if [ "$NOAUTH_CODE" = "401" ]; then
    echo -e "${GREEN}✓ Unauthenticated request correctly rejected: HTTP 401${NC}"
else
    echo -e "${RED}✗ Unauthenticated request returned HTTP ${NOAUTH_CODE} (expected 401)${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  OpenSearch Security Initialized         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Users: admin (all_access), logstash (logstash_writer),"
echo "       readonly (siem_readonly), kibanaserver (kibana_server)"
echo ""
echo "Next:"
echo "  1. (Re)start the consumers so they pick up credentials:"
echo "       docker compose up -d logstash grafana opensearch-dashboards"
echo "  2. Apply ISM policy/templates: bash scripts/04-apply-ism-policy.sh"
echo "  3. Verify: bash scripts/05-verify.sh"
