#!/bin/bash
# =============================================================================
# render-prometheus-web-config.sh - Render Prometheus basic-auth files
# =============================================================================
# Prometheus needs a bcrypt hash in its web config, and the self-scrape needs the
# plain password in a file. Both come from PROMETHEUS_BASIC_AUTH_PASSWORD, read
# from the environment or .env, so the secret is set in one place.
#
# Writes (both git-ignored):
#   docker/prometheus/web.yml                      bcrypt hash, user "prometheus"
#   docker/prometheus/secrets/basic-auth-password  plain password, 0400 for uid 65534
#
# The password goes to htpasswd on stdin, never on a command line. Needs
# htpasswd (apt install apache2-utils) or docker (uses the httpd image).
#
# Usage:
#   bash scripts/render-prometheus-web-config.sh                # render repo copy
#   bash scripts/render-prometheus-web-config.sh /opt/siem      # render deployed copy
#
# After rendering the deployed copy: docker compose up -d prometheus grafana
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BASE="${1:-${REPO_DIR}/docker}"
OUT_DIR="${TARGET_BASE}/prometheus"

# shellcheck source=scripts/lib-secrets.sh
. "${SCRIPT_DIR}/lib-secrets.sh"

if [ -z "${PROMETHEUS_BASIC_AUTH_PASSWORD:-}" ]; then
    for candidate in "${TARGET_BASE}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$candidate" ] && grep -q '^PROMETHEUS_BASIC_AUTH_PASSWORD=' "$candidate"; then
            PROMETHEUS_BASIC_AUTH_PASSWORD="$(grep '^PROMETHEUS_BASIC_AUTH_PASSWORD=' "$candidate" | tail -1 | cut -d= -f2-)"
            break
        fi
    done
fi

if [ -z "${PROMETHEUS_BASIC_AUTH_PASSWORD:-}" ] || secret_is_placeholder "${PROMETHEUS_BASIC_AUTH_PASSWORD}"; then
    echo "render-prometheus-web-config: set PROMETHEUS_BASIC_AUTH_PASSWORD to a strong unique value in .env" >&2
    exit 1
fi

if command -v htpasswd >/dev/null 2>&1; then
    hash="$(printf '%s' "$PROMETHEUS_BASIC_AUTH_PASSWORD" | htpasswd -niBC 12 prometheus)"
elif command -v docker >/dev/null 2>&1; then
    hash="$(printf '%s' "$PROMETHEUS_BASIC_AUTH_PASSWORD" | docker run --rm -i httpd:2.4 htpasswd -niBC 12 prometheus)"
else
    echo "render-prometheus-web-config: need htpasswd (apt install apache2-utils) or docker" >&2
    exit 1
fi
hash="${hash#prometheus:}"

mkdir -p "${OUT_DIR}/secrets"
umask 077
{
    echo "# Rendered by scripts/render-prometheus-web-config.sh - do not commit."
    echo "basic_auth_users:"
    printf '  prometheus: %s\n' "$hash"
} > "${OUT_DIR}/web.yml"
printf '%s' "$PROMETHEUS_BASIC_AUTH_PASSWORD" > "${OUT_DIR}/secrets/basic-auth-password"

# The container runs as uid 65534 and must read both files and the directory.
chmod 0755 "${OUT_DIR}/secrets"
if [ "$(id -u)" -eq 0 ]; then
    chown 65534:65534 "${OUT_DIR}/web.yml" "${OUT_DIR}/secrets/basic-auth-password"
    chmod 0400 "${OUT_DIR}/web.yml" "${OUT_DIR}/secrets/basic-auth-password"
else
    chmod 0644 "${OUT_DIR}/web.yml" "${OUT_DIR}/secrets/basic-auth-password"
    echo "render-prometheus-web-config: not root, so the files are mode 0644 so the container can read them; re-run with sudo -E for 0400 owned by 65534" >&2
fi

echo "rendered ${OUT_DIR}/web.yml and ${OUT_DIR}/secrets/basic-auth-password"
echo "Apply: docker compose up -d prometheus grafana"
