#!/bin/bash -p
# =============================================================================
# 04-apply-ism-policy.sh — Apply OpenSearch ISM hot/warm policy & templates
# =============================================================================
# Run after `docker compose up`, once OpenSearch is healthy.
#
# This script:
#   1. Applies the ISM (Index State Management) hot/warm/delete policy
#   2. Applies index templates for Suricata, pfBlockerNG, and Syslog
#   3. Verifies everything was applied correctly
#
# The cluster is secured (Phase F1): requests use HTTPS + admin basic auth.
# OPENSEARCH_ADMIN_PASSWORD is read from the environment or .env.
#
# Usage:
#   sudo scripts/04-apply-ism-policy.sh https://10.0.0.100:9200
#   sudo scripts/04-apply-ism-policy.sh   # defaults to https://localhost:9200
#
# Start it by its path, never through an explicit `bash` interpreter: run as root, an explicit
# interpreter reads BASH_ENV, imported functions, SHELLOPTS and BASHOPTS before line 1 and bypasses the
# privileged shebang. The privileged-mode check below is a diagnostic only: it cannot repair such a launch.
# =============================================================================

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode (the -p shebang).
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs
# Still before any external command runs: take the export attribute off the password (a caller may have
# exported it) and switch allexport off (an inherited `bash -a` would export every later assignment).
# Both are builtins. From here on no child inherits this named password through the launch environment
# (the .env loader below handles what the file exports). What no script can change: the environment this
# process itself was started with still holds whatever the launcher exported; pass the password in a
# .env file rather than the launch environment to avoid even that.
export -n OPENSEARCH_ADMIN_PASSWORD
set +a

# Root decision, privileged-mode check and the trusted script and helper tree come before anything is
# read, located or sourced (same bootstrap as 05-verify.sh; readlink, dirname and id run first, to find
# the script's own directory). The privileged-mode check is a DIAGNOSTIC only: when the script was
# started as `bash script`, bash has already run BASH_ENV, imported functions, SHELLOPTS and BASHOPTS,
# and nothing inside the script can repair that. Start it by its path.
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

OPENSEARCH_URL="${1:-https://localhost:9200}"
REPO_DIR="${SCRIPT_DIR}/.."
OPENSEARCH_DIR="${SCRIPT_DIR}/../docker/opensearch"

# Load OPENSEARCH_ADMIN_PASSWORD from .env if not already set. The .env is shell code, so loading it
# cannot be made to ignore an `export`, `declare -x` or `set -a` written inside it. Guaranteed, using
# shell builtins only: "noexport" keeps a plain assignment from being exported; then allexport and
# tracing are switched off, every variable NAME the file created is stripped of its export attribute,
# and so is the named password. NOT guaranteed: a variable that already existed before the file ran
# keeps whatever export attribute the file gave it (PATH, CE_TRUSTED_DIRS, this script's own
# variables), so write plain NAME=value lines only (docs/container-engine.md). A hostile file can run
# any shell code, so it must be trusted (as root it must be root-owned in a root-owned tree, enforced
# by ce_source_env).
# ce_names fills the array _NAMES with every variable name in the shell (the ${!x@} expansions list the
# names starting with one character; eval only ever sees the fixed characters of the loop).
ce_names() {
    local _c
    _NAMES=()
    for _c in {a..z} {A..Z} _; do
        eval '_NAMES+=(${!'"$_c"'@})'
    done
}
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    declare -A PRE_NAMES=()
    ce_names
    for _n in ${_NAMES[@]+"${_NAMES[@]}"}; do PRE_NAMES[$_n]=1; done
    for envf in /opt/siem/.env "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$envf" ]; then
            ce_source_env "$envf" noexport || exit 1  # root: only a root-owned file in a root-owned tree, via one descriptor
            break
        fi
    done
    set +x +a
    ce_names
    for _n in ${_NAMES[@]+"${_NAMES[@]}"}; do
        [ -n "${PRE_NAMES[$_n]:-}" ] || export -n "$_n"
    done
    export -n OPENSEARCH_ADMIN_PASSWORD
    unset _n _NAMES PRE_NAMES
fi
if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
    echo "ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env). See .env.example."
    exit 1
fi
# A line break would end the one-line curl config record below (and start a new directive), so refuse
# it before any request. The variable name is printed, never the value.
case "$OPENSEARCH_ADMIN_PASSWORD" in
    *$'\n'* | *$'\r'*)
        echo "ERROR: OPENSEARCH_ADMIN_PASSWORD contains a line break, which is not allowed in a password" >&2
        exit 1
        ;;
esac
# The credentials go to curl on standard input as a config (-K -), never in argv. Backslash and double
# quote are escaped for the curl config syntax. printf is a builtin, so no process holds the value.
OS_USER_CFG="admin:${OPENSEARCH_ADMIN_PASSWORD}"
OS_USER_CFG="${OS_USER_CFG//\\/\\\\}"
OS_USER_CFG="${OS_USER_CFG//\"/\\\"}"
# -k: cluster certs are self-signed (see scripts/07-generate-opensearch-certs.sh)
os_curl() { printf 'user = "%s"\n' "$OS_USER_CFG" | curl -sk -K - "$@"; }

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Applying OpenSearch ISM policy and templates...${NC}"
echo "  OpenSearch URL: ${OPENSEARCH_URL}"
echo ""

# Wait for OpenSearch
echo -e "${YELLOW}Waiting for OpenSearch...${NC}"
for i in {1..30}; do
    if os_curl -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
        HEALTH=$(os_curl -f "${OPENSEARCH_URL}/_cluster/health" | jq -r '.status')
        echo -e "${GREEN}✓ OpenSearch is up (cluster health: ${HEALTH})${NC}"
        break
    fi
    echo "  Waiting... (${i}/30)"
    sleep 5
done

if ! os_curl -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: OpenSearch not reachable at ${OPENSEARCH_URL}${NC}"
    exit 1
fi

CLUSTER_INFO=$(os_curl -f "${OPENSEARCH_URL}/_cluster/health")
NODE_COUNT=$(echo "$CLUSTER_INFO" | jq -r '.number_of_nodes')
echo "  Nodes: ${NODE_COUNT}"

# ── Apply ISM Policy ─────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[1/5] Applying ISM hot/warm/delete policy...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_plugins/_ism/policies/siem-hot-warm-delete" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/ism-hot-warm-policy.json" | jq .

echo -e "${GREEN}✓ ISM policy applied${NC}"

# ── Suricata Index Template ──────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/5] Applying Suricata index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/suricata-template" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-suricata.json" | jq .

echo -e "${GREEN}✓ Suricata template applied${NC}"

# ── pfBlockerNG Index Template ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/5] Applying pfBlockerNG index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/pfblockerng" \
    -H 'Content-Type: application/json' \
    -d @"${OPENSEARCH_DIR}/index-template-pfblockerng.json" | jq .

echo -e "${GREEN}✓ pfBlockerNG template applied${NC}"

# ── Syslog Index Template ────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/5] Applying Syslog index template...${NC}"

os_curl -f -X PUT "${OPENSEARCH_URL}/_index_template/syslog-template" \
    -H 'Content-Type: application/json' \
    -d '{
  "index_patterns": ["syslog-*", "pfsense-*", "unifi-syslog-*", "crowdsec-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.routing.allocation.require.temp": "hot",
      "plugins.index_state_management.policy_id": "siem-hot-warm-delete"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "host": { "type": "keyword" },
        "source_host": { "type": "keyword" },
        "program": { "type": "keyword" },
        "facility": { "type": "keyword" },
        "severity": { "type": "keyword" },
        "message": { "type": "text" }
      }
    }
  },
  "priority": 200
}' | jq .

echo -e "${GREEN}✓ Syslog template applied${NC}"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[5/5] Verifying...${NC}"

echo "  ISM policies:"
os_curl -f "${OPENSEARCH_URL}/_plugins/_ism/policies" | jq -r '.policies[].policy.description' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Index templates:"
os_curl -f "${OPENSEARCH_URL}/_index_template" | jq -r '.index_templates[].name' 2>/dev/null || echo "    (none yet)"

echo ""
echo "  Cluster allocation tags:"
os_curl -f "${OPENSEARCH_URL}/_cat/nodeattrs?v&h=node,attr,value" 2>/dev/null | grep temp || echo "    (waiting for nodes)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ISM Policy & Templates Applied          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "New indices matching suricata-*, syslog-*, pfblockerng-*, pfsense-*,"
echo "unifi-syslog-*, crowdsec-events-* will:"
echo "  1. Start on HOT tier (NVMe) — opensearch-hot node"
echo "  2. Move to WARM tier (SATA) after 30 days — opensearch-warm node"
echo "  3. Force-merge to 1 segment on WARM for read performance"
echo "  4. Delete after 365 days (1 year)"
