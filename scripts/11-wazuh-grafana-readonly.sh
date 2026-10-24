#!/bin/bash
# =============================================================================
# 11-wazuh-grafana-readonly.sh — Give Grafana a read-only Wazuh indexer account
# =============================================================================
# The Wazuh indexer keeps its security config inside the container (it is not
# bind-mounted), so this script edits the in-container internal_users.yml,
# roles.yml and roles_mapping.yml the same way change-passwords.sh does, then
# applies each type with securityadmin.sh and the admin client cert:
#   - user    WAZUH_GRAFANA_RO_USER (default grafana_ro), bcrypt hash made at run
#             time from WAZUH_GRAFANA_RO_PASSWORD (stdin only, never argv)
#   - role    wazuh_grafana_readonly: read on wazuh-alerts/archives/monitoring/
#             statistics-* only (docker/wazuh/security/roles.fragment.yml)
#   - mapping user -> role
# It then proves the account can read and cannot write.
#
# Idempotent: re-run after changing the password, after recreating the
# wazuh-indexer container (its config files reset to the image), or after
# change-passwords.sh. Requires the wazuh-indexer container to be running.
#
# Usage:  bash scripts/11-wazuh-grafana-readonly.sh
#   SIEM_DEPLOY_DIR=/opt/siem bash scripts/11-wazuh-grafana-readonly.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
SEC_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
CERTS="/usr/share/wazuh-indexer/config/certs"
SEC_CFG="/usr/share/wazuh-indexer/config/opensearch-security"

if [ -n "${SIEM_DEPLOY_DIR:-}" ]; then
    DEPLOY_DIR="${SIEM_DEPLOY_DIR}"
elif [ -f /opt/siem/docker-compose.yml ]; then
    DEPLOY_DIR="/opt/siem"
else
    DEPLOY_DIR="${REPO_DIR}/docker"
fi
FRAG_DIR="${DEPLOY_DIR}/wazuh/security"

# Read the two variables from .env only when they are not already exported.
if [ -z "${WAZUH_GRAFANA_RO_PASSWORD:-}" ]; then
    for candidate in "${DEPLOY_DIR}/.env" "${REPO_DIR}/.env" "${REPO_DIR}/docker/.env"; do
        if [ -f "$candidate" ]; then
            line="$(grep -E '^WAZUH_GRAFANA_RO_PASSWORD=' "$candidate" | tail -1 || true)"
            value="${line#*=}"; value="${value%\"}"; value="${value#\"}"
            WAZUH_GRAFANA_RO_PASSWORD="$value"
            if [ -z "${WAZUH_GRAFANA_RO_USER:-}" ]; then
                uline="$(grep -E '^WAZUH_GRAFANA_RO_USER=' "$candidate" | tail -1 || true)"
                WAZUH_GRAFANA_RO_USER="${uline#*=}"
            fi
            break
        fi
    done
fi
if [ -z "${WAZUH_GRAFANA_RO_PASSWORD:-}" ]; then
    echo "ERROR: WAZUH_GRAFANA_RO_PASSWORD is not set (add it to .env; see README upgrade notes)" >&2
    exit 1
fi
RO_USER="${WAZUH_GRAFANA_RO_USER:-grafana_ro}"
if ! [[ "$RO_USER" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "ERROR: WAZUH_GRAFANA_RO_USER may only contain letters, digits, _ . -" >&2
    exit 1
fi
for f in roles.fragment.yml roles_mapping.fragment.yml internal_users.fragment.yml; do
    [ -f "${FRAG_DIR}/$f" ] || { echo "ERROR: ${FRAG_DIR}/$f not found (deploy configs first)" >&2; exit 1; }
done

echo "[1/4] Hashing the password inside wazuh-indexer..."
HASH=$(printf '%s' "$WAZUH_GRAFANA_RO_PASSWORD" | docker exec -i wazuh-indexer bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && IFS= read -r P && ${HASH_TOOL} -p \"\$P\"" \
    2>/dev/null | grep -E '^\$2[aby]\$' | tail -1 || true)
if [ -z "$HASH" ]; then
    echo "ERROR: bcrypt hashing failed (is wazuh-indexer running?)" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# upsert <file-in-container> <fragment>: replace the fragment's top-level key
# (and any older block with that key) in the file, keeping everything else.
upsert() {
    local name="$1" frag="$2"
    docker exec wazuh-indexer cp "${SEC_CFG}/${name}" "${SEC_CFG}/${name}.bak"
    docker exec wazuh-indexer cat "${SEC_CFG}/${name}" > "${WORK}/${name}"
    RO_USER="$RO_USER" RO_HASH="$HASH" python3 - "${WORK}/${name}" "${FRAG_DIR}/${frag}" <<'PYEOF'
import os, re, sys
path, frag = sys.argv[1], sys.argv[2]
text = open(frag, encoding="utf-8").read()
text = text.replace("__GRAFANA_RO_USER__", os.environ["RO_USER"]).replace("__GRAFANA_RO_HASH__", os.environ["RO_HASH"])
body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#")).strip("\n") + "\n"
key = re.match(r"([^\s:#][^:]*):", body).group(1)
content = open(path, encoding="utf-8").read()
# drop an existing block: its key line plus indented/blank lines after it
pattern = re.compile(r"^%s:[^\n]*\n(?:(?:[ \t]+[^\n]*)?\n)*" % re.escape(key), re.M)
content = pattern.sub("", content)
content = content.rstrip("\n") + "\n\n" + body
open(path, "w", encoding="utf-8").write(content)
PYEOF
    docker exec -i wazuh-indexer bash -c 'cat > "$0"' "${SEC_CFG}/${name}" < "${WORK}/${name}"
}

apply() { # <file> <type>
    local out
    out=$(docker exec wazuh-indexer bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${SEC_TOOL} \
        -f ${SEC_CFG}/$1 -t $2 \
        -cacert ${CERTS}/root-ca.pem -cert ${CERTS}/admin.pem -key ${CERTS}/admin-key.pem \
        -icl -nhnv" 2>&1) || { echo "$out" | tail -5 >&2; echo "ERROR: securityadmin failed for $2" >&2; exit 1; }
    echo "$out" | grep -q "Done with success" || { echo "$out" | tail -5 >&2; echo "ERROR: securityadmin did not confirm $2" >&2; exit 1; }
    echo "  applied $2"
}

echo "[2/4] Updating roles, mapping and user in the indexer security config..."
upsert roles.yml roles.fragment.yml
upsert roles_mapping.yml roles_mapping.fragment.yml
upsert internal_users.yml internal_users.fragment.yml

echo "[3/4] Applying with securityadmin.sh..."
apply roles.yml roles
apply roles_mapping.yml rolesmapping
apply internal_users.yml internalusers

# curl inside the container with credentials on stdin (-K -), never in argv.
probe() { # <method> <path>
    local cred="${RO_USER}:${WAZUH_GRAFANA_RO_PASSWORD}"
    cred="${cred//\\/\\\\}"; cred="${cred//\"/\\\"}"
    printf 'user = "%s"\n' "$cred" | docker exec -i wazuh-indexer curl -K - -sk \
        -o /dev/null -w '%{http_code}' -X "$1" "https://localhost:9200$2"
}

echo "[4/4] Verifying the account reads and cannot write..."
READ_CODE=$(probe GET "/wazuh-alerts-*/_count" || true)
if [ "$READ_CODE" != "200" ]; then
    echo "ERROR: ${RO_USER} cannot read wazuh-alerts-* (HTTP ${READ_CODE})" >&2
    exit 1
fi
WRITE_CODE=$(probe DELETE "/wazuh-alerts-readonly-probe" || true)
if [ "$WRITE_CODE" != "403" ]; then
    echo "ERROR: ${RO_USER} can write to the Wazuh indexer (DELETE returned HTTP ${WRITE_CODE}, expected 403)" >&2
    exit 1
fi
echo "OK: ${RO_USER} reads wazuh-alerts-* (200) and is refused writes (403)."
echo "Next: docker compose up -d grafana"
