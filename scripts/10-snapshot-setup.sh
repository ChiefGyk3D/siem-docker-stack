#!/bin/bash -p
# =============================================================================
# 10-snapshot-setup.sh — Register snapshot repo + daily SM policy (Phase F4)
# =============================================================================
# 1. Registers the filesystem snapshot repository "siem-snapshots"
#    (/mnt/snapshots inside both nodes = /data/warm/snapshots on the host —
#    see path.repo in docker/opensearch/opensearch-{hot,warm}.yml).
# 2. Creates/updates the OpenSearch Snapshot Management (SM) policy
#    "siem-daily": daily snapshot at 03:00 UTC of the SIEM event indices,
#    deletion run at 05:00 UTC keeping 14 days.
#
# Idempotent — safe to re-run; an existing policy is updated in place
# (SM updates require if_seq_no/if_primary_term, handled below).
#
# Requires OPENSEARCH_ADMIN_PASSWORD (env or .env). Restore procedure and
# drill: docs/backup-restore.md
#
# Usage:
#   sudo scripts/10-snapshot-setup.sh
#   sudo scripts/10-snapshot-setup.sh https://10.0.0.100:9200
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
# read, located or sourced (same bootstrap as 05-verify.sh). The privileged-mode check is a DIAGNOSTIC
# only: when the script was started as `bash script`, bash has already run BASH_ENV, imported functions,
# SHELLOPTS and BASHOPTS, and nothing inside the script can repair that. Start it by its path.
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

REPO_NAME="siem-snapshots"
POLICY_NAME="siem-daily"
SNAPSHOT_INDICES="suricata-*,syslog-*,pfsense-*,pfblockerng-*,unifi-syslog-*,crowdsec-events-*"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  OpenSearch Snapshot Setup (F4)          ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

# Load OPENSEARCH_ADMIN_PASSWORD from .env if not already set. The .env is shell code, so loading it
# cannot be made to ignore an `export`, `declare -x` or `set -a` written inside it. Guaranteed, using
# shell builtins only: "noexport" keeps a plain assignment from being exported; then allexport and
# tracing are switched off, every variable NAME the file created is stripped of its export attribute,
# and so is the named password. NOT guaranteed: a variable that already existed before the file ran
# keeps whatever export attribute the file gave it, so write plain NAME=value lines only
# (docs/container-engine.md). A hostile file can run any shell code, so it must be trusted (as root it
# must be root-owned in a root-owned tree, enforced by ce_source_env).
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
    echo -e "${RED}ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env).${NC}"
    exit 1
fi
# A line break would end the one-line curl config record below (and start a new directive), so refuse
# it before any request. The variable name is printed, never the value.
case "$OPENSEARCH_ADMIN_PASSWORD" in
    *$'\n'* | *$'\r'*)
        echo -e "${RED}ERROR: OPENSEARCH_ADMIN_PASSWORD contains a line break, which is not allowed in a password${NC}" >&2
        exit 1
        ;;
esac
# The credentials go to curl on standard input as a config (-K -), never in argv. Backslash and double
# quote are escaped for the curl config syntax. printf is a builtin, so no process holds the value.
OS_USER_CFG="admin:${OPENSEARCH_ADMIN_PASSWORD}"
OS_USER_CFG="${OS_USER_CFG//\\/\\\\}"
OS_USER_CFG="${OS_USER_CFG//\"/\\\"}"
# -k: self-signed cluster certs (scripts/07-generate-opensearch-certs.sh)
os_curl() { printf 'user = "%s"\n' "$OS_USER_CFG" | curl -sk -K - "$@"; }

# ── Wait for cluster ─────────────────────────────────────────────────────────
echo -e "${YELLOW}Waiting for OpenSearch at ${OPENSEARCH_URL}...${NC}"
if ! os_curl -f "${OPENSEARCH_URL}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: OpenSearch not reachable/authenticated at ${OPENSEARCH_URL}${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Cluster reachable${NC}"

# ── [1/3] Register the fs repository ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[1/3] Registering snapshot repository '${REPO_NAME}'...${NC}"
REPO_RESULT=$(os_curl -X PUT "${OPENSEARCH_URL}/_snapshot/${REPO_NAME}" \
    -H 'Content-Type: application/json' \
    -d '{
  "type": "fs",
  "settings": {
    "location": "/mnt/snapshots",
    "compress": true
  }
}')
if echo "$REPO_RESULT" | grep -q '"acknowledged":true'; then
    echo -e "${GREEN}✓ Repository registered${NC}"
else
    echo -e "${RED}✗ Repository registration failed:${NC}"
    echo "$REPO_RESULT" | jq . 2>/dev/null || echo "$REPO_RESULT"
    echo "  Check that /data/warm/snapshots exists, is owned by uid 1000, and"
    echo "  that path.repo includes /mnt/snapshots on BOTH nodes (restart needed"
    echo "  after config changes)."
    exit 1
fi

# Verify both nodes can see the repo
echo "  Verifying repository on all nodes..."
VERIFY=$(os_curl -X POST "${OPENSEARCH_URL}/_snapshot/${REPO_NAME}/_verify")
NODE_COUNT=$(echo "$VERIFY" | jq -r '.nodes | length' 2>/dev/null || echo 0)
echo -e "  ${GREEN}✓ Verified on ${NODE_COUNT} node(s)${NC}"

# ── [2/3] Create/update the SM policy ────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/3] Applying Snapshot Management policy '${POLICY_NAME}'...${NC}"

SM_BODY=$(cat <<JSON
{
  "description": "Daily snapshot of SIEM event indices, 14-day retention (Phase F4)",
  "creation": {
    "schedule": {
      "cron": {
        "expression": "0 3 * * *",
        "timezone": "UTC"
      }
    },
    "time_limit": "1h"
  },
  "deletion": {
    "schedule": {
      "cron": {
        "expression": "0 5 * * *",
        "timezone": "UTC"
      }
    },
    "condition": {
      "max_age": "14d",
      "min_count": 3,
      "max_count": 21
    },
    "time_limit": "1h"
  },
  "snapshot_config": {
    "repository": "${REPO_NAME}",
    "indices": "${SNAPSHOT_INDICES}",
    "ignore_unavailable": true,
    "include_global_state": false,
    "partial": true
  }
}
JSON
)

EXISTING=$(os_curl "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}")
if echo "$EXISTING" | jq -e '.sm_policy' > /dev/null 2>&1; then
    SEQ_NO=$(echo "$EXISTING" | jq -r '._seq_no')
    PRIMARY_TERM=$(echo "$EXISTING" | jq -r '._primary_term')
    echo "  Policy exists — updating (seq_no=${SEQ_NO}, primary_term=${PRIMARY_TERM})"
    RESULT=$(os_curl -X PUT \
        "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}?if_seq_no=${SEQ_NO}&if_primary_term=${PRIMARY_TERM}" \
        -H 'Content-Type: application/json' -d "$SM_BODY")
else
    echo "  Policy does not exist — creating"
    RESULT=$(os_curl -X POST "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}" \
        -H 'Content-Type: application/json' -d "$SM_BODY")
fi

if echo "$RESULT" | jq -e '.sm_policy' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ SM policy applied${NC}"
else
    echo -e "${RED}✗ SM policy failed:${NC}"
    echo "$RESULT" | jq . 2>/dev/null || echo "$RESULT"
    exit 1
fi

# ── [3/3] Show status ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/3] Current snapshot state:${NC}"
echo "  Policy:"
os_curl "${OPENSEARCH_URL}/_plugins/_sm/policies/${POLICY_NAME}" \
    | jq -r '.sm_policy | "    schedule: \(.creation.schedule.cron.expression) UTC | retention: \(.deletion.condition.max_age)"' 2>/dev/null || true
echo "  Existing snapshots:"
os_curl "${OPENSEARCH_URL}/_cat/snapshots/${REPO_NAME}?v&h=id,status,start_time,duration,indices" 2>/dev/null \
    | head -10 || echo "    (none yet — first run at 03:00 UTC)"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Snapshot Setup Complete                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
# The hint is a function, printed by declare -f so the text shown is the text tested: it refuses a
# control character (CR or LF would start a new curl config directive), escapes backslash and double
# quote, and sends the credentials to curl on stdin as a config, never on the command line.
manual_snapshot() {
    local cred="admin:${OPENSEARCH_ADMIN_PASSWORD}"
    if [[ "$cred" == *[[:cntrl:]]* ]]; then
        echo "OPENSEARCH_ADMIN_PASSWORD contains a control character, refused" >&2
        return 1
    fi
    cred="${cred//\\/\\\\}"
    cred="${cred//\"/\\\"}"
    printf 'user = "%s"\n' "$cred" | curl -sk -K - -X PUT \
        "${1}/_snapshot/${2}/manual-$(printf '%(%Y%m%d)T' -1)?wait_for_completion=false" \
        -H 'Content-Type: application/json' \
        -d "{\"indices\":\"${3}\",\"include_global_state\":false}"
}
echo "Manual snapshot now (paste into a shell where OPENSEARCH_ADMIN_PASSWORD is set, not exported):"
echo "# --- paste begin"
declare -f manual_snapshot
echo "manual_snapshot '${OPENSEARCH_URL}' '${REPO_NAME}' '${SNAPSHOT_INDICES}'"
echo "# --- paste end"
echo ""
echo "Restore drill + offsite copy guidance: docs/backup-restore.md"
echo "NOTE: the Wazuh indexer (wazuh-alerts-*) is a separate cluster and is"
echo "NOT covered by this policy — tracked as a Phase F follow-up."
