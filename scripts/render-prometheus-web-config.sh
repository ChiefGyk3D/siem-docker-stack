#!/bin/bash
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
# The other passwords are never written to disk by this script.
#
# Safety: everything is hashed and validated first; files are staged in a
# private directory and moved into place, so a failure leaves the previous set
# untouched. Target directories must be real directories (no symlinks, no group
# or world write). Files end up owned by the container user (uid 65534), mode
# 0400, secrets and tls directories 0500, so no other user can read them. That
# needs root, so the script refuses to run otherwise. Run it on the deployed
# copy (/opt/siem) as: sudo -E bash <this script> /opt/siem
#
# Each password goes to htpasswd on stdin, never on a command line. Needs
# htpasswd (apt install apache2-utils) or docker (uses the httpd image).
#
# After rendering: docker compose up -d prometheus prometheus-otlp grafana
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BASE="${1:-${REPO_DIR}/docker}"
MAIN_DIR="${TARGET_BASE}/prometheus"
OTLP_DIR="${TARGET_BASE}/prometheus-otlp"

# The uid the Prometheus container runs as. Root always uses 65534; the override
# exists only so the test can run unprivileged as its own uid.
if [ "$(id -u)" -eq 0 ]; then
    OWNER_UID=65534
else
    OWNER_UID="${PROMETHEUS_FILE_UID:-65534}"
fi

# shellcheck source=scripts/lib-secrets.sh
. "${SCRIPT_DIR}/lib-secrets.sh"

die() { echo "render-prometheus-web-config: $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ] && [ "$(id -u)" -ne "$OWNER_UID" ]; then
    die "run as root (sudo -E) so the files can be owned by uid ${OWNER_UID} with mode 0400; refusing to write a readable secret"
fi

# --- path safety: real directories only, not writable by group or others ------
check_dir() { # <dir>
    local d="$1" m
    [ ! -L "$d" ] || die "${d} is a symlink; refusing to write through it"
    if [ -e "$d" ]; then
        [ -d "$d" ] || die "${d} exists and is not a directory"
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
check_dir "$MAIN_DIR"
check_dir "$OTLP_DIR"
check_dir "${MAIN_DIR}/secrets"
check_dir "${OTLP_DIR}/tls"
for f in "${MAIN_DIR}/web.yml" "${OTLP_DIR}/web.yml" \
    "${MAIN_DIR}/secrets/self-scrape-password" "${MAIN_DIR}/secrets/otlp-scrape-password" \
    "${OTLP_DIR}/tls/server.crt" "${OTLP_DIR}/tls/server.key"; do
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
    [ "$(printf '%s' "$value" | LC_ALL=C wc -c)" -le 72 ] || die "${name} is longer than 72 bytes (bcrypt ignores the rest)"
    printf '%s' "$value"
}

hash_for() { # <user> <password>; prints the bcrypt hash only, fails on any error
    local out
    if command -v htpasswd >/dev/null 2>&1; then
        out="$(printf '%s' "$2" | htpasswd -niBC 12 "$1")" || return 1
    elif command -v docker >/dev/null 2>&1; then
        out="$(printf '%s' "$2" | docker run --rm -i httpd:2.4 htpasswd -niBC 12 "$1")" || return 1
    else
        echo "render-prometheus-web-config: need htpasswd (apt install apache2-utils) or docker" >&2
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
mkdir -p "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
STAGE="$(mktemp -d "${MAIN_DIR}/.render.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
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

own() { # <paths...>: owner uid, no symlink following
    chown -h "${OWNER_UID}:${OWNER_UID}" "$@" 2>/dev/null || [ "$(id -u)" -eq "$OWNER_UID" ]
}
for f in main-web.yml otlp-web.yml self-scrape-password otlp-scrape-password; do
    own "${STAGE}/${f}" && chmod 0400 "${STAGE}/${f}"
done

# Reopen the directories a previous run closed, move the new files in
# (rename replaces atomically), then close them again.
chmod 0700 "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
for pair in "main-web.yml ${MAIN_DIR}/web.yml" "otlp-web.yml ${OTLP_DIR}/web.yml" \
    "self-scrape-password ${MAIN_DIR}/secrets/self-scrape-password" \
    "otlp-scrape-password ${MAIN_DIR}/secrets/otlp-scrape-password"; do
    check_file_target "${pair#* }"
    mv -T "${STAGE}/${pair%% *}" "${pair#* }"
done
own "${OTLP_DIR}/tls/server.crt" "${OTLP_DIR}/tls/server.key" "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"
chmod 0400 "${OTLP_DIR}/tls/server.key"
chmod 0444 "${OTLP_DIR}/tls/server.crt"
chmod 0500 "${MAIN_DIR}/secrets" "${OTLP_DIR}/tls"

echo "rendered 4 files under ${TARGET_BASE} (owner uid ${OWNER_UID}, mode 0400)"
echo "Apply: docker compose up -d prometheus prometheus-otlp grafana"
