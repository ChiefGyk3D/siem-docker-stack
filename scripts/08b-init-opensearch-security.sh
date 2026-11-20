#!/bin/bash -p
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

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode (the -p shebang).
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs
# Still before any external command runs: take the export attribute off the four password variables (a
# caller may have exported them) and switch allexport off (an inherited `bash -a` or SHELLOPTS would
# export every later assignment). Both are builtins, so no child process exists yet. From this line on
# no child of this script inherits a password. What no script can change: the environment this process
# itself was started with still holds whatever the launcher exported (see /proc/PID/environ of this
# shell); pass the passwords in a .env file rather than the launch environment to avoid even that.
export -n OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD \
          OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD
set +a

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

# The .env is loaded with "noexport": its values stay in this shell and no child process (grep, tail,
# python3, ...) inherits them. No process is started to take an inventory of the environment.
if [ -n "$ENV_FILE" ]; then
    echo "Loading passwords from ${ENV_FILE}"
    ce_source_env "$ENV_FILE" noexport || exit 1  # root: only a root-owned file in a root-owned tree, via one descriptor
fi

# CONTAINER_ENGINE (docker by default, or podman) may come from the environment or that .env.
ce_init || exit 1

MISSING=0
for var in OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD \
           OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD; do
    if [ -z "${!var:-}" ]; then
        echo -e "${RED}✗ ${var} is not set (add it to .env — see .env.example)${NC}"
        MISSING=1
    fi
done
[ "$MISSING" -eq 1 ] && exit 1

# A line break in a password would end the one-line stdin record (and, in a curl config, start a new
# directive), so refuse it before any engine call. The variable name is printed, never the value.
for var in OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD \
           OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD; do
    case "${!var}" in
        *$'\n'* | *$'\r'*)
            echo -e "${RED}✗ ${var} contains a line break, which is not allowed in a password${NC}" >&2
            exit 1
            ;;
    esac
done

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
    CODE=$(ce_run exec opensearch-hot \
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

# The password goes to the container on standard input: never in an argument of the engine client, and
# never in the environment of the client. Inside the container the pinned hash tool (OpenSearch security
# 2.19.0.0, src/main/java/org/opensearch/security/tools/Hasher.java and tools/hash.sh, read 2026-11-20;
# the Hasher option names were read there, the real image was not run: UNVERIFIED on the live image)
# reads a password from one of three places: -p VALUE (a command-line argument, readable by every
# user), -env NAME (an environment variable of its own process), or an interactive console (it fails
# without a terminal, so piped input does not work). -env is the least exposed supported route. The
# wrapper hash.sh starts unrelated helper commands (realpath, dirname, pwd) and then runs java as a
# child, so the variable is NOT exported to the wrapper: a function named java (exported into the
# wrapper, which runs plain "java" once OPENSEARCH_JAVA_HOME and JAVA_HOME are unset, their value kept in
# J) reads the line from stdin itself and starts the real java with the variable set for that one
# process only. RESIDUAL EXPOSURE: for the well under a second java runs, the password is in that one
# process's environment inside the container: readable by processes of the same container user, by
# the container's root and by host root (all through /proc/PID/environ). It is in no argument list.
hash_password() {
    local pass="$1"
    printf '%s\n' "$pass" | ce_run exec -i opensearch-hot bash -c \
        'J="${OPENSEARCH_JAVA_HOME:-${JAVA_HOME:-/usr/share/opensearch/jdk}}"; export J
         unset OPENSEARCH_JAVA_HOME JAVA_HOME
         java() { local HASH_PASS; IFS= read -r HASH_PASS || return 1; HASH_PASS=$HASH_PASS "$J/bin/java" "$@"; }
         export -f java
         exec plugins/opensearch-security/tools/hash.sh -env HASH_PASS' \
        2>/dev/null | grep -E '^\$2[aby]\$' | tail -1
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
# The file holds password hashes: create it with its final mode from the first byte (a temporary
# file opened exclusively with 0640, then renamed over the target), never create-then-chmod.
tmp = f"{out}.tmp.{os.getpid()}"
old_umask = os.umask(0o137)  # the mode below is then exactly 0640 whatever umask the caller had
try:
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
finally:
    os.umask(old_umask)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, out)
except BaseException:
    if os.path.exists(tmp):
        os.unlink(tmp)
    raise
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
ce_run exec opensearch-hot bash -c '
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
# Credentials go to curl inside the container on standard input as a config (-K -), never in argv.
# Backslash and double quote are escaped for the curl config syntax; a line break was refused above.
ADMIN_CRED="admin:${OPENSEARCH_ADMIN_PASSWORD}"
ADMIN_CRED="${ADMIN_CRED//\\/\\\\}"
ADMIN_CRED="${ADMIN_CRED//\"/\\\"}"
AUTH_CODE=$(printf 'user = "%s"\n' "$ADMIN_CRED" | ce_run exec -i opensearch-hot curl -K - -sk \
    -o /dev/null -w '%{http_code}' https://localhost:9200/_cluster/health)
NOAUTH_CODE=$(ce_run exec opensearch-hot curl -sk -o /dev/null -w '%{http_code}' \
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
