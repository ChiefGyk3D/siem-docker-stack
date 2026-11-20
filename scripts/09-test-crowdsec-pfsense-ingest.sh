#!/bin/bash -p
# =============================================================================
# 09-test-crowdsec-pfsense-ingest.sh - replay pfSense CrowdSec fixture logs
# =============================================================================
# Replays the fixture through syslog-ng and verifies Logstash/OpenSearch indexing.
# OPENSEARCH_ADMIN_PASSWORD is read from the environment or .env.
#
# Usage:
#   sudo scripts/09-test-crowdsec-pfsense-ingest.sh
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

REPO_DIR="${SCRIPT_DIR}/.."

# Load OPENSEARCH_ADMIN_PASSWORD from .env when present. The .env is shell code, so loading it cannot be
# made to ignore an `export`, `declare -x` or `set -a` written inside it. Guaranteed, using shell
# builtins only: "noexport" keeps a plain assignment from being exported; then allexport and tracing are
# switched off, every variable NAME the file created is stripped of its export attribute, and so is the
# named password. NOT guaranteed: a variable that already existed before the file ran keeps whatever
# export attribute the file gave it, so write plain NAME=value lines only (docs/container-engine.md). A
# hostile file can run any shell code, so it must be trusted (as root it must be root-owned in a
# root-owned tree, enforced by ce_source_env).
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
export -n OPENSEARCH_ADMIN_PASSWORD
unset _n _NAMES PRE_NAMES

SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
SYSLOG_PORT="${SYSLOG_PORT:-514}"
OPENSEARCH_URL="${OPENSEARCH_URL:-https://127.0.0.1:9200}"
FIXTURE="${FIXTURE:-tests/fixtures/crowdsec/pfsense-rfc5424.log}"

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
# -k: self-signed cluster certs (scripts/07-generate-opensearch-certs.sh)
os_curl() { printf 'user = "%s"\n' "$OS_USER_CFG" | curl -sk -K - "$@"; }

if [[ ! -f "${FIXTURE}" ]]; then
  echo "ERROR: fixture not found: ${FIXTURE}"
  exit 1
fi

echo "[1/3] Replaying fixture into syslog-ng ${SYSLOG_HOST}:${SYSLOG_PORT}"
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  printf '%s\n' "${line}" | nc -u -w1 "${SYSLOG_HOST}" "${SYSLOG_PORT}"
done < "${FIXTURE}"

sleep 3

echo "[2/3] Verifying fixture CrowdSec events indexed"
COUNT=$(os_curl -f -X POST "${OPENSEARCH_URL}/crowdsec-events-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.module.keyword":"crowdsec"}},{"term":{"source_host.keyword":"pfsense"}}],"should":[{"terms":{"program.keyword":["crowdsec","crowdsec-firewall-bouncer"]}},{"terms":{"crowdsec.scenario.keyword":["ssh-bf","http-probing"]}},{"terms":{"crowdsec.scenario":["ssh-bf","http-probing"]}}],"minimum_should_match":1}}}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("count",0))')

if [[ "${COUNT}" -lt 1 ]]; then
  echo "ERROR: fixture CrowdSec events not found in crowdsec-events-*"
  exit 1
fi

echo "ok fixture crowdsec-events count=${COUNT}"

echo "[3/3] Verifying parsed fields"
HIT=$(os_curl -f -X POST "${OPENSEARCH_URL}/crowdsec-events-*/_search?size=1&sort=@timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"source_host.keyword":"pfsense"}},{"exists":{"field":"program"}},{"exists":{"field":"crowdsec.action"}},{"exists":{"field":"source.ip"}}],"should":[{"terms":{"program.keyword":["crowdsec","crowdsec-firewall-bouncer"]}},{"terms":{"crowdsec.scenario.keyword":["ssh-bf","http-probing"]}}],"minimum_should_match":1}}}' \
  | python3 -c 'import sys,json; h=json.load(sys.stdin).get("hits",{}).get("total",{}); print(h.get("value",0) if isinstance(h,dict) else 0)')

if [[ "${HIT}" -lt 1 ]]; then
  echo "ERROR: parsed crowdsec.action/source.ip fields not found"
  exit 1
fi

echo "ok parsed fields verified"
echo "CrowdSec pfSense ingestion test passed"
