#!/bin/bash -p
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

CERTS_DIR="${SCRIPT_DIR}/../docker/wazuh/certs"
ce_init || exit 1

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

ce_run run --rm \
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
