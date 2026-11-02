#!/bin/bash
# =============================================================================
# render-prometheus-web-config.sh - Render the OTLP receiver's basic-auth files
# =============================================================================
# Reads five passwords from the environment or .env, one per account, so each
# can be rotated or revoked alone:
#   SIEM Prometheus (9090):  PROMETHEUS_GRAFANA_PASSWORD   user "grafana"
#                            PROMETHEUS_SELF_PASSWORD      user "self"
#   OTLP receiver (9091):    PROMETHEUS_OTLP_SENDER_PASSWORD   user "sender"
#                            PROMETHEUS_OTLP_GRAFANA_PASSWORD  user "grafana"
#                            PROMETHEUS_OTLP_SCRAPE_PASSWORD   user "scrape"
#
# Writes (git-ignored): bcrypt hashes, plus the two passwords Prometheus must
# hold in plain text to authenticate its own scrapes:
#   docker/prometheus/web.yml                            hashes (grafana, self)
#   docker/prometheus-otlp/web.yml                       hashes (sender, grafana, scrape)
#   docker/prometheus/secrets/self-scrape-password       "self" password
#   docker/prometheus/secrets/otlp-scrape-password       "scrape" password
# The other passwords are never written to disk by this script.
#
# Permissions: the files are owned by the container user (uid 65534), mode 0400,
# and the secrets directory is 0500, so no other user can read them. That needs
# root (or already being that user), so the script refuses to run otherwise
# rather than leave a readable secret. Run it as: sudo -E bash <this script>
#
# Each password goes to htpasswd on stdin, never on a command line. Needs
# htpasswd (apt install apache2-utils) or docker (uses the httpd image).
#
# Usage:
#   sudo -E bash scripts/render-prometheus-web-config.sh                # repo copy
#   sudo -E bash scripts/render-prometheus-web-config.sh /opt/siem      # deployed copy
#
# After rendering the deployed copy: docker compose up -d prometheus prometheus-otlp grafana
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BASE="${1:-${REPO_DIR}/docker}"
MAIN_DIR="${TARGET_BASE}/prometheus"
OTLP_DIR="${TARGET_BASE}/prometheus-otlp"
# The uid the Prometheus container runs as. Overridable only so the test can
# run unprivileged as its own uid; the mode rules do not change.
OWNER_UID="${PROMETHEUS_FILE_UID:-65534}"

# shellcheck source=scripts/lib-secrets.sh
. "${SCRIPT_DIR}/lib-secrets.sh"

if [ "$(id -u)" -ne 0 ] && [ "$(id -u)" -ne "$OWNER_UID" ]; then
    echo "render-prometheus-web-config: run as root (sudo -E) so the files can be owned by uid ${OWNER_UID} with mode 0400; refusing to write a readable secret" >&2
    exit 1
fi

# Pick a password up from the environment first, then from .env.
read_secret() { # <NAME>
    local name="$1" value="${!1:-}" candidate
    if [ -z "$value" ]; then
        for candidate in "${TARGET_BASE}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
            if [ -f "$candidate" ] && grep -q "^${name}=" "$candidate"; then
                value="$(grep "^${name}=" "$candidate" | tail -1 | cut -d= -f2-)"
                break
            fi
        done
    fi
    if [ -z "$value" ] || secret_is_placeholder "$value"; then
        echo "render-prometheus-web-config: set ${name} to a strong unique value in .env" >&2
        exit 1
    fi
    printf '%s' "$value"
}

hash_for() { # <user> <password>; prints the bcrypt hash only
    local out
    if command -v htpasswd >/dev/null 2>&1; then
        out="$(printf '%s' "$2" | htpasswd -niBC 12 "$1")"
    elif command -v docker >/dev/null 2>&1; then
        out="$(printf '%s' "$2" | docker run --rm -i httpd:2.4 htpasswd -niBC 12 "$1")"
    else
        echo "render-prometheus-web-config: need htpasswd (apt install apache2-utils) or docker" >&2
        exit 1
    fi
    printf '%s' "${out#"$1":}"
}

sender_pw="$(read_secret PROMETHEUS_OTLP_SENDER_PASSWORD)"
otlp_grafana_pw="$(read_secret PROMETHEUS_OTLP_GRAFANA_PASSWORD)"
otlp_scrape_pw="$(read_secret PROMETHEUS_OTLP_SCRAPE_PASSWORD)"
grafana_pw="$(read_secret PROMETHEUS_GRAFANA_PASSWORD)"
self_pw="$(read_secret PROMETHEUS_SELF_PASSWORD)"
all_pw=("$sender_pw" "$otlp_grafana_pw" "$otlp_scrape_pw" "$grafana_pw" "$self_pw")
if [ "$(printf '%s\n' "${all_pw[@]}" | sort -u | wc -l)" -ne "${#all_pw[@]}" ]; then
    echo "render-prometheus-web-config: the five passwords must all differ (separate accounts)" >&2
    exit 1
fi

umask 077
mkdir -p "${MAIN_DIR}/secrets" "${OTLP_DIR}"
# A previous run leaves the directory 0500 and the files 0400; reopen to rewrite.
chmod 0700 "${MAIN_DIR}/secrets"
rm -f "${MAIN_DIR}/web.yml" "${OTLP_DIR}/web.yml" \
    "${MAIN_DIR}/secrets/self-scrape-password" "${MAIN_DIR}/secrets/otlp-scrape-password"

HDR="# Rendered by scripts/render-prometheus-web-config.sh - do not commit."
{
    echo "$HDR"
    echo "basic_auth_users:"
    printf '  grafana: %s\n' "$(hash_for grafana "$grafana_pw")"
    printf '  self: %s\n' "$(hash_for self "$self_pw")"
} > "${MAIN_DIR}/web.yml"
{
    echo "$HDR"
    echo "basic_auth_users:"
    printf '  sender: %s\n' "$(hash_for sender "$sender_pw")"
    printf '  grafana: %s\n' "$(hash_for grafana "$otlp_grafana_pw")"
    printf '  scrape: %s\n' "$(hash_for scrape "$otlp_scrape_pw")"
} > "${OTLP_DIR}/web.yml"
printf '%s' "$self_pw" > "${MAIN_DIR}/secrets/self-scrape-password"
printf '%s' "$otlp_scrape_pw" > "${MAIN_DIR}/secrets/otlp-scrape-password"

files=("${MAIN_DIR}/web.yml" "${OTLP_DIR}/web.yml"
    "${MAIN_DIR}/secrets/self-scrape-password" "${MAIN_DIR}/secrets/otlp-scrape-password")
chown "${OWNER_UID}:${OWNER_UID}" "${MAIN_DIR}/secrets" "${files[@]}" 2>/dev/null \
    || [ "$(id -u)" -eq "$OWNER_UID" ]
chmod 0400 "${files[@]}"
chmod 0500 "${MAIN_DIR}/secrets"

echo "rendered ${#files[@]} files under ${TARGET_BASE} (owner uid ${OWNER_UID}, mode 0400)"
echo "Apply: docker compose up -d prometheus prometheus-otlp grafana"
