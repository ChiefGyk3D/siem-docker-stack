#!/bin/bash -p
# =============================================================================
# render-prometheus-web-config.sh - Render the Prometheus basic-auth files
# =============================================================================
# Reads five passwords from the environment or .env, one per account, so each
# can be rotated or revoked alone:
#   SIEM Prometheus (9090):  PROMETHEUS_GRAFANA_PASSWORD   user "grafana"
#                            PROMETHEUS_SELF_PASSWORD      user "self"
#   OTLP receiver (9091):    PROMETHEUS_OTLP_SENDER_PASSWORD   user "sender"
#                            PROMETHEUS_OTLP_GRAFANA_PASSWORD  user "grafana"
#                            PROMETHEUS_OTLP_SCRAPE_PASSWORD   user "scrape"
# Each must be a strong value of at most 72 bytes (bcrypt ignores the rest) and
# must not contain "$" (Grafana and compose expand it); all five must differ.
#
# Also needs the receiver's TLS certificate and key, which you provide:
#   docker/prometheus-otlp/tls/server.crt and server.key (docs/prometheus-otlp.md)
#
# Writes (git-ignored): bcrypt hashes, plus the two passwords Prometheus must
# hold in plain text to authenticate its own scrapes:
#   docker/prometheus/web.yml                            hashes (grafana, self)
#   docker/prometheus-otlp/web.yml                       hashes + TLS block
#   docker/prometheus/secrets/self-scrape-password       "self" password
#   docker/prometheus/secrets/otlp-scrape-password       "scrape" password
#   docker/prometheus/otlp-ca/otlp-ca.crt               copy of the receiver certificate (no key)
# The other passwords are never written to disk by this script.
#
# Safety: everything is hashed and validated first; nothing is touched if that
# fails. Files are then staged in a private directory and installed one by one. Target directories must be real directories (no symlinks, no group
# or world write). Files end up owned by the container user (uid 65534), mode
# 0400, secrets and tls directories 0500, so no other user can read them. That
# needs root, so the script refuses to run otherwise. Run it on the deployed
# copy (/opt/siem), from a root-owned copy of this script, started by its path
# (never as `bash script`: the privileged-mode shebang keeps BASH_ENV and exported
# shell functions from running as root, an explicit interpreter bypasses it, so
# root refuses to continue that way):
# sudo /usr/local/libexec/siem/render-prometheus-web-config.sh /opt/siem
#
# Each password goes to htpasswd on stdin, never on a command line. Needs
# htpasswd (apt install apache2-utils); no container image ever sees a password.
#
# Trust: target directories must be owned by root or by the account that ran
# sudo (that account can become root anyway), never by anyone else. Staging
# happens in a private root-owned directory outside the target tree. A process
# running as the deploy account itself could still race the final placement, so
# keep the deployed tree out of reach of other software running as that account.
#
# Re-running is safe (rotation, recovery): it accepts the ownership and modes its
# own earlier run left, and still refuses symlinks and any other owner.
#
# After rendering: docker compose up -d prometheus prometheus-otlp grafana
# =============================================================================

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode.
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail

die() { echo "render-prometheus-web-config: $*" >&2; exit 1; }

# Who runs this is asked of the kernel through the absolute id program, never read from EUID or UID
# (bash imports both from the environment, so a caller could pick the branch). Only builtins run
# before this line.
RUN_UID="$(/usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null)" || RUN_UID=
case "$RUN_UID" in '' | *[!0-9]*) die "cannot tell who is running (no numeric user number)" ;; esac
RUN_UID=$((10#$RUN_UID))

# Root run: fixed PATH. Non-root run: the caller's PATH is kept, by design (the tests put a stub
# htpasswd on it and the owner's tools rely on it). Before this point only builtins and the absolute
# id program run, so nothing is resolved from the caller's PATH while the user number is read.
if [ "$RUN_UID" -eq 0 ]; then
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    # as root the privileged shebang must be in force; `bash script` bypasses it
    if ! [[ "$-" == *p* ]]; then
        die "as root, run this script by its path (not as 'bash script'): the privileged shebang that keeps BASH_ENV and exported functions out is bypassed otherwise"
    fi
fi

# Resolve every symlink first: the helper is the one next to the REAL script, never one next to a
# link someone else placed.
SELF="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")" || die "cannot resolve this script's real path"
SCRIPT_DIR="$(/usr/bin/dirname -- "$SELF")"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BASE="${1:-${REPO_DIR}/docker}"
MAIN_DIR="${TARGET_BASE}/prometheus"
OTLP_DIR="${TARGET_BASE}/prometheus-otlp"

# The uid the Prometheus container runs as. Root always uses 65534; the override
# exists only so the test can run unprivileged as its own uid.
if [ "$RUN_UID" -eq 0 ]; then
    OWNER_UID=65534
else
    OWNER_UID="${PROMETHEUS_FILE_UID:-65534}"
fi

# As root, run and source only code that no one else can edit: this script, the
# library it sources and every directory above them (through /) must be root-owned and not
# writable by group or others. Use a root-owned copy (docs/prometheus-otlp.md).
LIB_PATH="${SCRIPT_DIR}/lib-secrets.sh"
lib_fail() { die "refusing to source ${LIB_PATH}: $1"; }
if [ "$RUN_UID" -eq 0 ]; then
    for P in "$SELF" "$LIB_PATH"; do
        while :; do
            [ "$(/usr/bin/stat -c %u -- "$P")" = 0 ] && [ $((8#$(/usr/bin/stat -c %a -- "$P") & 8#022)) -eq 0 ] ||
                lib_fail "${P} (or a directory above it) is not root-owned or is group or world writable; run a root-owned copy of the script and lib-secrets.sh (docs/prometheus-otlp.md)"
            [ "$P" = / ] && break
            P="$(/usr/bin/dirname -- "$P")"
        done
    done
fi
[ -f "$LIB_PATH" ] && [ ! -L "$LIB_PATH" ] || lib_fail "it is missing or is a link"
# Open the helper once, check the OPEN file (-L: the descriptor link points at the file), and source
# that same descriptor, so a rename or replacement of the path after this point changes nothing.
exec 9<"$LIB_PATH" || lib_fail "it cannot be opened"
LIB_OWNER="$(/usr/bin/stat -L -c %u -- /proc/self/fd/9)"
LIB_MODE="$(/usr/bin/stat -L -c %a -- /proc/self/fd/9)"
LIB_LINKS="$(/usr/bin/stat -L -c %h -- /proc/self/fd/9)"
LIB_MASK=022  # group or world write on the opened file is never allowed, root or not: a peer could edit the open inode before it is sourced
if [ ! -f /proc/self/fd/9 ] || { [ "$LIB_OWNER" != 0 ] && [ "$LIB_OWNER" != "$RUN_UID" ]; } ||
    [ $((8#$LIB_MODE & 8#$LIB_MASK)) -ne 0 ] || [ "$LIB_LINKS" != 1 ]; then
    lib_fail "it must be a regular file with one link, owned by root or by you, and not group or world writable (fix: chmod g-w,o-w ${LIB_PATH})"
fi
# The checks above protect against a new open for writing (mode), a replaced or swapped path (the
# descriptor) and a planted ancestor. They cannot revoke a descriptor a peer already holds open for
# writing on this inode, and nothing here can: this only NARROWS that window. The file is read twice
# from the open inode (the second time through a fresh open of the same descriptor, from offset 0),
# size, mtime and ctime (nanoseconds) and device:inode are compared before and after, the two reads
# must match byte for byte, the byte count must equal the size, and the first copy is sourced, never
# the live inode. Not detected: a write before the first read, or a write between the reads that is
# put back before the second. The real protection is a root-owned release tree (docs/prometheus-otlp.md);
# running from a group-shared checkout accepts that residual risk.
# stat's %.9Y is GNU coreutils precision syntax (VERIFIED by running stat 9.7 here; INFERRED for the box).
LIB_FMT='%s %.9Y %.9Z %d:%i'
LIB_ST1="$(/usr/bin/stat -L -c "$LIB_FMT" -- /proc/self/fd/9)" || lib_fail "it cannot be examined"
LIB_SNAP="$(/bin/cat <&9 && printf x)" || lib_fail "it cannot be read"
LIB_SNAP2="$(/bin/cat < /proc/self/fd/9 && printf x)" || lib_fail "it cannot be read a second time"
LIB_ST2="$(/usr/bin/stat -L -c "$LIB_FMT" -- /proc/self/fd/9)" || lib_fail "it cannot be examined"
exec 9<&-
LIB_SNAP="${LIB_SNAP%x}"
LIB_SNAP2="${LIB_SNAP2%x}"
{ [ "$LIB_ST1" = "$LIB_ST2" ] && [ "$LIB_SNAP" = "$LIB_SNAP2" ]; } || lib_fail "it changed while it was being read"
LIB_SIZE="${LIB_ST1%% *}"
LIB_LEN="$(LC_ALL=C; echo "${#LIB_SNAP}")"  # bytes, not characters
{ [ "$LIB_SIZE" -gt 0 ] && [ "$LIB_LEN" = "$LIB_SIZE" ]; } ||
    lib_fail "it is empty or its content length (${LIB_LEN} bytes) differs from its size (${LIB_SIZE} bytes)"
# shellcheck source=scripts/lib-secrets.sh
source <(printf '%s' "$LIB_SNAP")

if [ "$RUN_UID" -ne 0 ] && [ "$RUN_UID" -ne "$OWNER_UID" ]; then
    die "run as root (sudo) so the files can be owned by uid ${OWNER_UID} with mode 0400; refusing to write a readable secret"
fi

# --- path safety: real directories only, not writable by group or others ------
trusted_owner() { # <path> [managed]: root or the sudo-invoking account (or ourselves
    # when unprivileged). A managed directory is one this script closes itself, so
    # it may also be owned by the container user from a previous run.
    local u
    u="$(stat -c '%u' "$1")"
    [ "${2:-}" != managed ] || [ "$u" -ne "$OWNER_UID" ] || return 0
    if [ "$RUN_UID" -eq 0 ]; then
        [ "$u" -eq 0 ] || { [ -n "${SUDO_UID:-}" ] && [ "$u" -eq "$SUDO_UID" ]; }
    else
        [ "$u" -eq "$RUN_UID" ]
    fi
}
check_dir() { # <dir> [managed]
    local d="$1" m
    [ ! -L "$d" ] || die "${d} is a symlink; refusing to write through it"
    if [ -e "$d" ]; then
        [ -d "$d" ] || die "${d} exists and is not a directory"
        trusted_owner "$d" "${2:-}" || die "${d} is owned by uid $(stat -c '%u' "$d"), which is not trusted; refusing"
        m="$(stat -c '%a' "$d")"
        [ $((8#${m} & 8#022)) -eq 0 ] || die "${d} is group or world writable (mode ${m}); refusing"
    fi
}
check_file_target() { # <path>: not a symlink; an empty directory stub from Docker is replaced
    local f="$1"
    [ ! -L "$f" ] || die "${f} is a symlink; refusing to write through it"
    if [ -d "$f" ]; then
        rmdir "$f" 2>/dev/null || die "${f} is a non-empty directory; remove it by hand"
    fi
}
[ ! -L "$TARGET_BASE" ] || die "${TARGET_BASE} is a symlink; refusing"
[ -d "$TARGET_BASE" ] || die "${TARGET_BASE} is not a directory"
trusted_owner "$TARGET_BASE" || die "${TARGET_BASE} is owned by uid $(stat -c '%u' "$TARGET_BASE"), which is not trusted; refusing"
check_dir "$MAIN_DIR"
check_dir "$OTLP_DIR"
check_dir "${MAIN_DIR}/secrets" managed
check_dir "${OTLP_DIR}/tls" managed
check_dir "${MAIN_DIR}/otlp-ca" managed
for f in "${MAIN_DIR}/web.yml" "${OTLP_DIR}/web.yml" \
    "${MAIN_DIR}/secrets/self-scrape-password" "${MAIN_DIR}/secrets/otlp-scrape-password" \
    "${OTLP_DIR}/tls/server.crt" "${OTLP_DIR}/tls/server.key" "${MAIN_DIR}/otlp-ca/otlp-ca.crt"; do
    [ ! -L "$f" ] || die "${f} is a symlink; refusing to write through it"
done
[ -f "${OTLP_DIR}/tls/server.crt" ] && [ -f "${OTLP_DIR}/tls/server.key" ] ||
    die "TLS files missing: put server.crt and server.key in ${OTLP_DIR}/tls/ (docs/prometheus-otlp.md)"

# --- read and validate the secrets -------------------------------------------
read_secret() { # <NAME>; same quote handling as check-env.sh
    local name="$1" value="${!1:-}" candidate
    if [ -z "$value" ]; then
        for candidate in "${TARGET_BASE}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
            if [ -f "$candidate" ] && grep -q "^${name}=" "$candidate"; then
                value="$(grep "^${name}=" "$candidate" | tail -1)"
                value="${value#*=}"
                value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
                break
            fi
        done
    fi
    if [ -z "$value" ] || secret_is_placeholder "$value"; then
        die "set ${name} to a strong unique value in .env"
    fi
    case "$value" in *'$'*) die "${name} must not contain a dollar sign (Grafana and compose expand it)" ;; esac
    # A strict subset that .env parsers agree on: no whitespace (CR included),
    # backslash, quote or backtick inside the value.
    case "$value" in
        *[[:space:]]* | *'\'* | *'"'* | *"'"* | *'`'*) die "${name} must not contain whitespace, backslashes, quotes or backticks" ;;
    esac
    [ "$(printf '%s' "$value" | LC_ALL=C wc -c)" -le 72 ] || die "${name} is longer than 72 bytes (bcrypt ignores the rest)"
    printf '%s' "$value"
}

hash_for() { # <user> <password>; prints the bcrypt hash only, fails on any error
    local out
    if command -v htpasswd >/dev/null 2>&1; then
        out="$(printf '%s' "$2" | htpasswd -niBC 12 "$1")" || return 1
    else
        echo "render-prometheus-web-config: need htpasswd (apt install apache2-utils)" >&2
        return 1
    fi
    out="${out#"$1":}"
    [[ "$out" =~ ^\$2[aby]\$12\$[./A-Za-z0-9]{53}$ ]] || return 1
    printf '%s' "$out"
}

sender_pw="$(read_secret PROMETHEUS_OTLP_SENDER_PASSWORD)"
otlp_grafana_pw="$(read_secret PROMETHEUS_OTLP_GRAFANA_PASSWORD)"
otlp_scrape_pw="$(read_secret PROMETHEUS_OTLP_SCRAPE_PASSWORD)"
grafana_pw="$(read_secret PROMETHEUS_GRAFANA_PASSWORD)"
self_pw="$(read_secret PROMETHEUS_SELF_PASSWORD)"
all_pw=("$sender_pw" "$otlp_grafana_pw" "$otlp_scrape_pw" "$grafana_pw" "$self_pw")
if [ "$(printf '%s\n' "${all_pw[@]}" | sort -u | wc -l)" -ne "${#all_pw[@]}" ]; then
    die "the five passwords must all differ (separate accounts)"
fi

# Hash everything before touching any file: a failure leaves the old set alone.
h_sender="$(hash_for sender "$sender_pw")" || die "hashing failed for the sender account; nothing was changed"
h_ograf="$(hash_for grafana "$otlp_grafana_pw")" || die "hashing failed for the receiver grafana account; nothing was changed"
h_oscrape="$(hash_for scrape "$otlp_scrape_pw")" || die "hashing failed for the scrape account; nothing was changed"
h_graf="$(hash_for grafana "$grafana_pw")" || die "hashing failed for the grafana account; nothing was changed"
h_self="$(hash_for self "$self_pw")" || die "hashing failed for the self account; nothing was changed"

# --- stage privately, then move into place -----------------------------------
umask 077
mkdir -p "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls" "${MAIN_DIR}/otlp-ca"
# The stage lives in a private directory we create ourselves (0700, ours) outside
# the target tree, in /run (root-owned). The caller's runtime and temp directory
# variables are ignored on purpose, and there is no fallback.
# Only a genuinely unprivileged run (the tests) may choose another base.
if [ "$RUN_UID" -ne 0 ] && [ -n "${PROMETHEUS_STAGE_BASE:-}" ]; then
    STAGE_BASE="$PROMETHEUS_STAGE_BASE"
else
    STAGE_BASE=/run
fi
STAGE_ROOT="$(TMPDIR=/nonexistent mktemp -d "${STAGE_BASE}/prom-render.XXXXXX")" || die "cannot create a private stage directory in ${STAGE_BASE}"
[ "$(stat -c '%u' "$STAGE_ROOT")" -eq "$RUN_UID" ] && [ "$(stat -c '%a' "$STAGE_ROOT")" = 700 ] ||
    die "the stage directory ${STAGE_ROOT} is not private to this user"
STAGE="${STAGE_ROOT}"
trap 'rm -rf "$STAGE_ROOT"' EXIT
HDR="# Rendered by scripts/render-prometheus-web-config.sh - do not commit."
{
    echo "$HDR"
    echo "basic_auth_users:"
    printf '  grafana: %s\n' "$h_graf"
    printf '  self: %s\n' "$h_self"
} > "${STAGE}/main-web.yml"
{
    echo "$HDR"
    echo "tls_server_config:"
    echo "  cert_file: /etc/prometheus/tls/server.crt"
    echo "  key_file: /etc/prometheus/tls/server.key"
    echo "  min_version: TLS12"
    echo "basic_auth_users:"
    printf '  sender: %s\n' "$h_sender"
    printf '  grafana: %s\n' "$h_ograf"
    printf '  scrape: %s\n' "$h_oscrape"
} > "${STAGE}/otlp-web.yml"
printf '%s' "$self_pw" > "${STAGE}/self-scrape-password"
printf '%s' "$otlp_scrape_pw" > "${STAGE}/otlp-scrape-password"

own() { # <paths...>: owner uid, no symlink following; a failure stops the script
    if ! chown -h "${OWNER_UID}:${OWNER_UID}" "$@" 2>/dev/null; then
        [ "$RUN_UID" -eq "$OWNER_UID" ] || die "could not change the owner of $* to uid ${OWNER_UID}"
    fi
}
verify_owner() { # <mode> <paths...>: final owner and mode check after placement
    local want="$1" f
    shift
    for f in "$@"; do
        [ ! -L "$f" ] || die "${f} became a symlink; refusing"
        [ "$(stat -c '%u' "$f")" -eq "$OWNER_UID" ] || die "${f} is not owned by uid ${OWNER_UID}"
        [ "$(stat -c '%a' "$f")" = "$want" ] || die "${f} does not have mode ${want}"
    done
}

# Reopen the directories a previous run closed, install the new files (each
# install replaces the destination file, never following a symlink at the leaf),
# then close them again. The set is not atomic: if a step fails midway, re-run.
chmod 0700 "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls" "${MAIN_DIR}/otlp-ca"
for pair in "main-web.yml ${MAIN_DIR}/web.yml" "otlp-web.yml ${OTLP_DIR}/web.yml" \
    "self-scrape-password ${MAIN_DIR}/secrets/self-scrape-password" \
    "otlp-scrape-password ${MAIN_DIR}/secrets/otlp-scrape-password"; do
    check_file_target "${pair#* }"
    install -m 0400 -T "${STAGE}/${pair%% *}" "${pair#* }"
    own "${pair#* }"
done
# A copy of the certificate (never the key) for the clients that verify the
# receiver, in a directory of its own so the key is mounted into the receiver only.
check_file_target "${MAIN_DIR}/otlp-ca/otlp-ca.crt"
install -m 0444 -T "${OTLP_DIR}/tls/server.crt" "${MAIN_DIR}/otlp-ca/otlp-ca.crt"
own "${MAIN_DIR}/otlp-ca/otlp-ca.crt" "${MAIN_DIR}/otlp-ca"
chmod 0555 "${MAIN_DIR}/otlp-ca"
own "${OTLP_DIR}/tls/server.crt" "${OTLP_DIR}/tls/server.key" "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
chmod 0400 "${OTLP_DIR}/tls/server.key"
chmod 0444 "${OTLP_DIR}/tls/server.crt"
chmod 0500 "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
verify_owner 400 "${MAIN_DIR}/web.yml" "${OTLP_DIR}/web.yml" \
    "${MAIN_DIR}/secrets/self-scrape-password" "${MAIN_DIR}/secrets/otlp-scrape-password" \
    "${OTLP_DIR}/tls/server.key"
verify_owner 500 "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
verify_owner 444 "${MAIN_DIR}/otlp-ca/otlp-ca.crt"
verify_owner 555 "${MAIN_DIR}/otlp-ca"

echo "rendered 4 files under ${TARGET_BASE} (owner uid ${OWNER_UID}, mode 0400)"
echo "Apply: docker compose up -d prometheus prometheus-otlp grafana"
