#!/bin/bash -p
# =============================================================================
# 08-crowdsec-smoketest.sh - CrowdSec integration smoke test for siem-docker-stack
# =============================================================================
# Verifies:
#   1) synthetic CrowdSec-like doc can be indexed into OpenSearch
#   2) doc is queryable
#   3) CrowdSec Grafana alert rule exists
#   4) CrowdSec dashboard exists
#
# OPENSEARCH_ADMIN_PASSWORD and GRAFANA_PASS (or GRAFANA_ADMIN_PASS) are read from the environment or .env.
#
# Usage:
#   sudo scripts/08-crowdsec-smoketest.sh
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
# Still before any external command runs: take the export attribute off the passwords (a caller may have
# exported them) and switch allexport off (an inherited `bash -a` would export every later assignment).
# Both are builtins. From here on no child inherits these named passwords through the launch environment
# (the .env loader below handles what the file exports). What no script can change: the environment this
# process itself was started with still holds whatever the launcher exported; pass the passwords in a
# .env file rather than the launch environment to avoid even that.
export -n OPENSEARCH_ADMIN_PASSWORD GRAFANA_PASS GRAFANA_ADMIN_PASS
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

REPO_DIR="${SCRIPT_DIR}/.."

# Load OPENSEARCH_ADMIN_PASSWORD (and Grafana creds) from .env when present. The .env is shell code, so
# loading it cannot be made to ignore an `export`, `declare -x` or `set -a` written inside it.
# Guaranteed, using shell builtins only: "noexport" keeps a plain assignment from being exported; then
# allexport and tracing are switched off, every variable NAME the file created is stripped of its
# export attribute, and so are the named passwords. NOT guaranteed: a variable that already existed
# before the file ran keeps whatever export attribute the file gave it, so write plain NAME=value lines
# only (docs/container-engine.md). A hostile file can run any shell code, so it must be trusted (as root
# it must be root-owned in a root-owned tree, enforced by ce_source_env).
# ce_names fills the array _NAMES with every variable name in the shell (the ${!x@} expansions list the
# names starting with one character; eval only ever sees the fixed characters of the loop).
ce_names() {
    local _c
    _NAMES=()
    for _c in {a..z} {A..Z} _; do
        eval '_NAMES+=(${!'"$_c"'@})'
    done
}
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
export -n OPENSEARCH_ADMIN_PASSWORD GRAFANA_PASS GRAFANA_ADMIN_PASS
unset _n _NAMES PRE_NAMES

OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-${GRAFANA_ADMIN_PASS:-}}"
# The helper is opened once, the OPEN file and every directory above it are checked, and that same
# descriptor is sourced (docs/container-engine.md). The check stays inline: a shared loader would
# itself have to be sourced unchecked first.
SL_LIB="${SCRIPT_DIR}/lib-secrets.sh"
sl_fail() { echo "refusing to source ${SL_LIB}: $1" >&2; exit 1; }
[ -f "$SL_LIB" ] && [ ! -L "$SL_LIB" ] || sl_fail "it is missing or is a link"
exec 7<"$SL_LIB" || sl_fail "it cannot be opened"
SL_OWNER="$(/usr/bin/stat -L -c %u -- /proc/self/fd/7)"
SL_MODE="$(/usr/bin/stat -L -c %a -- /proc/self/fd/7)"
SL_LINKS="$(/usr/bin/stat -L -c %h -- /proc/self/fd/7)"
SL_MASK=002  # world write is never allowed; group write too when running as root
[ "$CE_STRICT" != 1 ] || SL_MASK=022
if [ ! -f /proc/self/fd/7 ] || { [ "$SL_OWNER" != 0 ] && [ "$SL_OWNER" != "$CE_UID" ]; } ||
    [ $((8#$SL_MODE & 8#$SL_MASK)) -ne 0 ] || [ "$SL_LINKS" != 1 ]; then
    sl_fail "it must be a regular file with one link, owned by root or by you, not world writable (and not group writable when run as root)"
fi
SL_P="$SCRIPT_DIR"
while :; do
    [ ! -L "$SL_P" ] || sl_fail "${SL_P} is a symlink"
    SL_PO="$(/usr/bin/stat -c %u -- "$SL_P")"
    SL_PM="$(/usr/bin/stat -c %a -- "$SL_P")"
    if [ "$CE_STRICT" = 1 ]; then  # as root: root-owned and closed to group and others, all the way up
        { [ "$SL_PO" = 0 ] && [ $((8#$SL_PM & 8#022)) -eq 0 ]; } ||
            sl_fail "${SL_P} (or a directory above it) is not root-owned or is group or world writable"
    else  # root or you; world write only on a sticky directory (/tmp)
        { [ "$SL_PO" = 0 ] || [ "$SL_PO" = "$CE_UID" ]; } &&
            { [ $((8#$SL_PM & 8#002)) -eq 0 ] || [ $((8#$SL_PM & 8#1000)) -ne 0 ]; } ||
            sl_fail "${SL_P} (or a directory above it) is not owned by root or by you or is world writable"
    fi
    [ "$SL_P" = / ] && break
    SL_P="$(/usr/bin/dirname -- "$SL_P")"
done
# shellcheck source=scripts/lib-secrets.sh
source /proc/self/fd/7
exec 7<&-
require_secret GRAFANA_PASS "$GRAFANA_PASS" || { echo "Set GRAFANA_PASS (or GRAFANA_ADMIN_PASS in .env)." >&2; exit 1; }

if [ -z "${OPENSEARCH_ADMIN_PASSWORD:-}" ]; then
  echo "ERROR: OPENSEARCH_ADMIN_PASSWORD not set (env or .env). See .env.example."
  exit 1
fi
# A line break would end the one-line curl config record below (and start a new directive), so refuse
# it before any request. The variable name is printed, never the value.
for var in OPENSEARCH_ADMIN_PASSWORD GRAFANA_PASS GRAFANA_USER; do
  case "${!var:-}" in
    *$'\n'* | *$'\r'*)
      echo "ERROR: ${var} contains a line break, which is not allowed in a credential" >&2
      exit 1
      ;;
  esac
done
# The credentials go to curl on standard input as a config (-K -), never in argv. Backslash and double
# quote are escaped for the curl config syntax. printf is a builtin, so no process holds the value.
OS_USER_CFG="admin:${OPENSEARCH_ADMIN_PASSWORD}"
OS_USER_CFG="${OS_USER_CFG//\\/\\\\}"
OS_USER_CFG="${OS_USER_CFG//\"/\\\"}"
GF_USER_CFG="${GRAFANA_USER}:${GRAFANA_PASS}"
GF_USER_CFG="${GF_USER_CFG//\\/\\\\}"
GF_USER_CFG="${GF_USER_CFG//\"/\\\"}"
# -k: self-signed cluster certs (scripts/07-generate-opensearch-certs.sh)
os_curl() { printf 'user = "%s"\n' "$OS_USER_CFG" | curl -sk -K - "$@"; }
gf_curl() { printf 'user = "%s"\n' "$GF_USER_CFG" | curl -sf -K - "$@"; }

# Use a dedicated smoketest index so the live crowdsec-events-YYYY.MM.dd
# indices are never polluted; it is deleted again on exit.
IDX="crowdsec-events-smoketest"
DOC_ID="crowdsec-smoke-$(date +%s)"

cleanup() {
  os_curl -f -X DELETE "${OPENSEARCH_URL}/${IDX}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

payload=$(cat <<JSON
{
  "@timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "event": {"module": "crowdsec", "kind": "alert"},
  "crowdsec": {"type": "decision", "action": "ban", "scenario": "ssh-bf", "source_ip": "203.0.113.10"},
  "rule": {"groups": ["crowdsec", "crowdsec_decision"], "description": "CrowdSec ban decision issued"}
}
JSON
)

echo "[1/4] Index synthetic CrowdSec doc: ${IDX}/${DOC_ID}"
os_curl -f -X PUT "${OPENSEARCH_URL}/${IDX}/_doc/${DOC_ID}?refresh=wait_for" \
  -H 'Content-Type: application/json' \
  -d "${payload}" >/dev/null

echo "[2/4] Verify doc query count"
count=$(os_curl -f -X POST "${OPENSEARCH_URL}/${IDX}/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"should":[{"term":{"event.module.keyword":"crowdsec"}},{"term":{"event.module":"crowdsec"}},{"match":{"event.module":"crowdsec"}}],"minimum_should_match":1}}}' | python3 -c 'import sys,json; print(json.load(sys.stdin).get("count",0))')
if [[ "${count}" -lt 1 ]]; then
  echo "ERROR: CrowdSec synthetic doc not found"
  exit 1
fi
echo "ok count=${count}"

echo "[3/4] Verify Grafana alert rule exists"
rule_found=$(gf_curl \
  "${GRAFANA_URL}/api/v1/provisioning/alert-rules" | \
  python3 -c 'import sys,json; rules=json.load(sys.stdin); print(any(r.get("title")=="CrowdSec Ban Decision Surge" for r in rules))')
if [[ "${rule_found}" != "True" ]]; then
  echo "ERROR: CrowdSec alert rule missing"
  exit 1
fi
echo "ok alert rule present"

echo "[4/4] Verify CrowdSec dashboard exists"
db_found=$(gf_curl \
  "${GRAFANA_URL}/api/search?query=CrowdSec%20Overview" | \
  python3 -c 'import sys,json; rows=json.load(sys.stdin); print(any((r.get("uid")=="crowdsec-overview" or r.get("title")=="CrowdSec Overview") for r in rows))')
if [[ "${db_found}" != "True" ]]; then
  echo "ERROR: CrowdSec dashboard missing"
  exit 1
fi
echo "ok dashboard present"

echo "CrowdSec smoke test passed"
