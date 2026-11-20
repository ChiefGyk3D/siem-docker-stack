#!/bin/bash -p
# =============================================================================
# 03-deploy.sh — Deploy Docker configs and start the SIEM stack
# =============================================================================
# Can be run:
#   A) From your workstation (deploys via SSH + rsync to the server)
#   B) Directly on the SIEM server (local mode)
#
# Usage:
#   # Remote deployment (from workstation):
#   sudo scripts/03-deploy.sh 10.0.0.100 myuser
#
#   # Local deployment (on the SIEM server):
#   sudo scripts/03-deploy.sh local
#
# Start it by its path, never through an explicit `bash` (that bypasses the privileged shebang).
# =============================================================================

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode (the -p shebang).
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs

# Root decision, privileged-mode check and the trusted script and helper tree come FIRST,
# before anything is read, located or sourced.
SCRIPT_DIR="$(/usr/bin/dirname -- "$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")")"  # the real directory, symlinks resolved
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

SIEM_HOST="${1:-${SIEM_HOST:-localhost}}"
SIEM_USER="${2:-${SIEM_USER:-$(whoami)}}"
REPO_DIR="${SCRIPT_DIR}/.."
DEPLOY_DIR="/opt/siem"

# CONTAINER_ENGINE (docker by default, or podman): the validated name is one of two
# fixed words, so it is safe inside the command strings run on the target host.
ce_init_name || exit 1

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

# Verify the container engine
echo -e "${YELLOW}Verifying ${CE_NAME}...${NC}"
run_on_server "${CE_NAME} info > /dev/null 2>&1 && echo 'ENGINE_OK'" | grep -q ENGINE_OK || {
    echo -e "${RED}${CE_NAME} not available. Run 02-bootstrap.sh first (it installs Docker).${NC}"
    exit 1
}
echo -e "${GREEN}✓ ${CE_NAME} available${NC}"

# Deploy Docker configs
echo ""
echo -e "${YELLOW}Deploying Docker configs to ${DEPLOY_DIR}...${NC}"

run_on_server "sudo mkdir -p ${DEPLOY_DIR} && sudo chown \$(whoami):\$(whoami) ${DEPLOY_DIR}"

if $LOCAL_MODE; then
    # Local: just copy
    cp -r "${REPO_DIR}/docker/"* "${DEPLOY_DIR}/"
else
    # Remote: rsync. Protect generated/secret files on the server from
    # --delete when they don't exist in the repo working tree
    # (opensearch security bootstrap output — see 08b-init-opensearch-security.sh).
    rsync -avz --delete \
        --filter='P opensearch/security/internal_users.yml' \
        --filter='P opensearch/certs/*' \
        --filter='P prometheus/web.yml' \
        --filter='P prometheus/secrets/***' \
        --filter='P prometheus-otlp/web.yml' \
        --filter='P prometheus-otlp/tls/***' \
        --filter='P prometheus/otlp-ca/***' \
        "${REPO_DIR}/docker/" \
        "${SIEM_USER}@${SIEM_HOST}:${DEPLOY_DIR}/"
fi

# Prometheus basic-auth files are rendered on the server by
# scripts/render-prometheus-web-config.sh (never rsynced). If one is missing,
# Docker would create a directory in its place and Prometheus would not start,
# which silences the independent alert path, so stop here instead. The rendered
# directories are closed (0500, owned by the container user), so check with sudo.
run_on_server "sudo test -f ${DEPLOY_DIR}/prometheus/web.yml && sudo test -f ${DEPLOY_DIR}/prometheus-otlp/web.yml && sudo test -f ${DEPLOY_DIR}/prometheus/secrets/self-scrape-password && sudo test -f ${DEPLOY_DIR}/prometheus/secrets/otlp-scrape-password && sudo test -f ${DEPLOY_DIR}/prometheus-otlp/tls/server.key && sudo test -f ${DEPLOY_DIR}/prometheus/otlp-ca/otlp-ca.crt && echo 'PROM_AUTH_OK'" | grep -q PROM_AUTH_OK || {
    echo -e "${RED}Prometheus auth files are missing in ${DEPLOY_DIR}.${NC}"
    echo "  On the server run: sudo -E scripts/render-prometheus-web-config.sh ${DEPLOY_DIR}"
    echo "  (needs the TLS files in prometheus-otlp/tls/; see docs/prometheus-otlp.md)"
    exit 1
}

# Copy .env if it exists
if [ -f "${REPO_DIR}/.env" ]; then
    # Refuse to deploy with missing secrets or well-known default values
    bash "${SCRIPT_DIR}/check-env.sh" "${REPO_DIR}/.env" || {
        echo -e "${RED}Fix .env and re-run (see README, Upgrade notes).${NC}"
        exit 1
    }
    if $LOCAL_MODE; then
        cp "${REPO_DIR}/.env" "${DEPLOY_DIR}/.env"
    else
        scp "${REPO_DIR}/.env" "${SIEM_USER}@${SIEM_HOST}:${DEPLOY_DIR}/.env"
    fi
    echo -e "${GREEN}✓ .env deployed${NC}"
else
    echo -e "${RED}No .env found. The stack has no default secrets and will not start.${NC}"
    echo "  Copy .env.example to .env, set the required secrets, and re-run."
    exit 1
fi

echo -e "${GREEN}✓ Docker configs deployed${NC}"

# Fix data directory permissions
echo ""
echo -e "${YELLOW}Fixing data directory permissions...${NC}"
run_on_server "
    sudo chown -R 1000:1000 /data/hot/opensearch /data/warm/opensearch 2>/dev/null || true
    sudo chown -R 472:472 /data/warm/grafana 2>/dev/null || true
    sudo chown -R 65534:65534 /data/hot/prometheus /data/hot/prometheus-otlp 2>/dev/null || true
    sudo chown -R 1000:1000 /data/hot/wazuh/indexer 2>/dev/null || true
    # Alertmanager storage (Phase F3) + OpenSearch snapshots (Phase F4)
    sudo mkdir -p /data/hot/alertmanager /data/warm/snapshots 2>/dev/null || true
    sudo chown -R 65534:65534 /data/hot/alertmanager 2>/dev/null || true
    sudo chown -R 1000:1000 /data/warm/snapshots 2>/dev/null || true
    # OpenSearch TLS keys must be readable by the container user (uid 1000)
    if ls ${DEPLOY_DIR}/opensearch/certs/*-key.pem > /dev/null 2>&1; then
        sudo chown 1000:1000 ${DEPLOY_DIR}/opensearch/certs/*-key.pem 2>/dev/null || true
        sudo chmod 640 ${DEPLOY_DIR}/opensearch/certs/*-key.pem 2>/dev/null || true
    fi
"
echo -e "${GREEN}✓ Permissions set${NC}"

# Start the stack
echo ""
echo -e "${YELLOW}Starting SIEM stack...${NC}"
run_on_server "cd ${DEPLOY_DIR} && ${CE_NAME} compose pull && ${CE_NAME} compose up -d"

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

echo "Services starting. Ports bind to loopback unless BIND_ADDR / INGEST_BIND_ADDR"
echo "are set in .env (README, \"Network exposure\")."
echo "Services at http://${HOST_DISPLAY}:"
echo "  Grafana:               :3000"
echo "  OpenSearch:             :9200 (HTTPS + auth)"
echo "  OpenSearch Dashboards:  :5601"
echo "  Wazuh Dashboard:        :443  (HTTPS)"
echo "  Prometheus:             :9090"
echo "  Alertmanager:           :9093 (loopback only)"
echo "  InfluxDB:               :8086 (auth)"
echo "  Portainer:              opt-in: docker compose --profile portainer up -d (loopback :9443)"
echo ""
echo "Next steps:"
echo "  1. Wait ~2 minutes for all services to start"
echo "  2. First deploy only: sudo scripts/08b-init-opensearch-security.sh"
echo "     (initializes OpenSearch users/roles from .env passwords)"
echo "  2b. Wazuh indexer: bash scripts/11-wazuh-grafana-readonly.sh"
echo "     (creates the read-only account Grafana uses; then docker compose up -d grafana)"
echo "  3. Run: sudo scripts/04-apply-ism-policy.sh https://${HOST_DISPLAY}:9200"
echo "  4. Run: sudo scripts/05-verify.sh ${HOST_DISPLAY}"
echo "  5. Snapshots: sudo scripts/10-snapshot-setup.sh"
