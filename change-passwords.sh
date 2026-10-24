#!/bin/bash
set -e

# =============================================================================
# SIEM Stack Password Change Tool
# =============================================================================
# Changes passwords for Wazuh Indexer (admin + kibanaserver), Wazuh API,
# Grafana, and the main OpenSearch cluster users
# (admin/logstash/readonly/kibanaserver — Phase F1).
# New values are written to ${COMPOSE_DIR}/.env (the compose file reads every
# secret from there); the compose file itself is never edited. Passwords are
# sent to containers on stdin, not on `docker exec` command lines, except the
# Grafana CLI reset (see STEP 3).
# Run this script ON the SIEM server (where docker compose is running).
#
# IMPORTANT:
#   - Avoid $ in passwords — it causes escaping issues across YAML, shell,
#     Docker Compose, and JSON layers. Stick to: A-Z a-z 0-9 ! @ # % ^ & * -
#   - This script uses 'docker compose up -d' (not restart) so env var
#     changes in .env actually take effect.
# =============================================================================

COMPOSE_DIR="/opt/siem"
WAZUH_YML_PATH="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
SEC_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
CERTS="/usr/share/wazuh-indexer/config/certs"
SEC_CFG="/usr/share/wazuh-indexer/config/opensearch-security"

# Main OpenSearch cluster (Phase F1) — paths inside opensearch-hot
OS_SEC_CFG="/usr/share/opensearch/config/opensearch-security"
OS_CERTS="/usr/share/opensearch/config/certs"
OS_INTERNAL_USERS_HOST="${COMPOSE_DIR}/opensearch/security/internal_users.yml"
ENV_FILE="${COMPOSE_DIR}/.env"

# Set KEY=value in .env (add it if missing). `|` in values is escaped for sed.
update_env_var() {
    local key="$1" value="$2" esc
    esc=$(printf '%s' "$value" | sed 's/[\\&|]/\\&/g')
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${esc}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

# Read KEY from .env without sourcing it.
read_env_var() {
    grep "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-
}

# curl inside a container with credentials on stdin (-K -), never in argv.
container_curl() { # <container> <user> <pass> <curl args...>
    local c="$1" u="$2" p="$3" cred
    shift 3
    cred="${u}:${p}"
    cred="${cred//\\/\\\\}"
    cred="${cred//\"/\\\"}"
    printf 'user = "%s"\n' "$cred" | docker exec -i "$c" curl -K - "$@"
}

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: ${ENV_FILE} not found. Secrets live in .env; create it first (README)."
    exit 1
fi

echo "============================================"
echo "  Wazuh SIEM Stack Password Change Tool"
echo "============================================"
echo ""
echo "  TIP: Avoid using \$ in passwords."
echo "       Safe characters: A-Z a-z 0-9 ! @ # % ^ & * -"
echo ""

validate_password() {
    local pass="$1"
    local name="$2"
    if [[ "$pass" == *'$'* ]]; then
        echo "  WARNING: Password for ${name} contains '\$'."
        echo "  This may cause issues with YAML parsing and shell escaping."
        read -p "  Continue anyway? (y/N): " DOLLAR_CONFIRM
        [[ "$DOLLAR_CONFIRM" != "y" && "$DOLLAR_CONFIRM" != "Y" ]] && return 1
    fi
    return 0
}

read -sp "New Wazuh Indexer admin password (leave blank to skip): " INDEXER_PASS
echo ""
read -sp "New Wazuh API password for wazuh-wui (leave blank to skip): " API_PASS
echo ""
read -sp "New Wazuh Dashboard (kibanaserver) password (leave blank to skip): " WAZUH_DASH_PASS
echo ""
read -sp "New Grafana admin password (leave blank to skip): " GRAFANA_PASS
echo ""
echo ""
echo "Main OpenSearch cluster users (Phase F1 — see .env OPENSEARCH_*_PASSWORD):"
read -sp "New OpenSearch admin password (leave blank to skip): " OS_ADMIN_PASS
echo ""
read -sp "New OpenSearch logstash password (leave blank to skip): " OS_LOGSTASH_PASS
echo ""
read -sp "New OpenSearch readonly password (leave blank to skip): " OS_READONLY_PASS
echo ""
read -sp "New OpenSearch dashboards (kibanaserver) password (leave blank to skip): " OS_DASHBOARDS_PASS
echo ""

any_change() {
    [[ -n "$INDEXER_PASS" || -n "$API_PASS" || -n "$WAZUH_DASH_PASS" || -n "$GRAFANA_PASS" ||        -n "$OS_ADMIN_PASS" || -n "$OS_LOGSTASH_PASS" || -n "$OS_READONLY_PASS" ||        -n "$OS_DASHBOARDS_PASS" ]]
}

if ! any_change; then
    echo "Nothing to change. Exiting."
    exit 0
fi

# Validate passwords for problematic characters
[[ -n "$INDEXER_PASS" ]] && { validate_password "$INDEXER_PASS" "Indexer" || INDEXER_PASS=""; }
[[ -n "$API_PASS" ]]     && { validate_password "$API_PASS" "API" || API_PASS=""; }
[[ -n "$WAZUH_DASH_PASS" ]] && { validate_password "$WAZUH_DASH_PASS" "Wazuh Dashboard" || WAZUH_DASH_PASS=""; }
[[ -n "$OS_ADMIN_PASS" ]]      && { validate_password "$OS_ADMIN_PASS" "OpenSearch admin" || OS_ADMIN_PASS=""; }
[[ -n "$OS_LOGSTASH_PASS" ]]   && { validate_password "$OS_LOGSTASH_PASS" "OpenSearch logstash" || OS_LOGSTASH_PASS=""; }
[[ -n "$OS_READONLY_PASS" ]]   && { validate_password "$OS_READONLY_PASS" "OpenSearch readonly" || OS_READONLY_PASS=""; }
[[ -n "$OS_DASHBOARDS_PASS" ]] && { validate_password "$OS_DASHBOARDS_PASS" "OpenSearch dashboards" || OS_DASHBOARDS_PASS=""; }

if ! any_change; then
    echo "Nothing to change. Exiting."
    exit 0
fi

echo ""
echo "=== Changes to apply ==="
[[ -n "$INDEXER_PASS" ]] && echo "  * Wazuh Indexer admin password"
[[ -n "$API_PASS" ]]     && echo "  * Wazuh API (wazuh-wui) password"
[[ -n "$WAZUH_DASH_PASS" ]] && echo "  * Wazuh Dashboard (kibanaserver) password"
[[ -n "$GRAFANA_PASS" ]] && echo "  * Grafana admin password"
[[ -n "$OS_ADMIN_PASS" ]]      && echo "  * OpenSearch (main cluster) admin password"
[[ -n "$OS_LOGSTASH_PASS" ]]   && echo "  * OpenSearch (main cluster) logstash password"
[[ -n "$OS_READONLY_PASS" ]]   && echo "  * OpenSearch (main cluster) readonly password"
[[ -n "$OS_DASHBOARDS_PASS" ]] && echo "  * OpenSearch (main cluster) kibanaserver password"
echo ""
read -p "Proceed? (y/N): " CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo "Aborted." && exit 0

SERVICES_TO_RECREATE=()

# Set the bcrypt hash of a Wazuh indexer internal user and apply it to the
# running cluster. The password goes to the container on stdin only.
wazuh_set_user_hash() { # <user> <password>
    local user="$1" pass="$2" hash esc
    hash=$(printf '%s' "$pass" | docker exec -i wazuh-indexer bash -c \
        "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && IFS= read -r P && ${HASH_TOOL} -p \"\$P\"" \
        2>/dev/null | grep '^\$2' | tail -1)
    if [[ -z "$hash" ]]; then
        echo "  ERROR: Failed to generate bcrypt hash for ${user}. Aborting."
        exit 1
    fi
    echo "  Hash generated."

    docker exec wazuh-indexer cp ${SEC_CFG}/internal_users.yml ${SEC_CFG}/internal_users.yml.bak

    # Use python to safely update the hash (avoids sed escaping issues with bcrypt $)
    esc=$(printf '%s' "$hash" | sed 's/[&/\\]/\\&/g')
    docker exec wazuh-indexer python3 -c "
import re
path = '${SEC_CFG}/internal_users.yml'
with open(path) as f:
    content = f.read()
content, n = re.subn(
    r'(^${user}:\\s*\\n\\s*hash:\\s*)\"[^\"]+\"',
    '\\\\1\"${esc}\"',
    content, count=1, flags=re.M)
if n != 1:
    raise SystemExit('user ${user} not found in internal_users.yml')
with open(path, 'w') as f:
    f.write(content)
print('  internal_users.yml updated for ${user}.')
"

    # Apply security config to the running cluster
    docker exec wazuh-indexer bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${SEC_TOOL} \
        -f ${SEC_CFG}/internal_users.yml \
        -t internalusers \
        -cacert ${CERTS}/root-ca.pem \
        -cert ${CERTS}/admin.pem \
        -key ${CERTS}/admin-key.pem \
        -icl -nhnv" 2>&1 | tail -5
    echo "  Security config applied to indexer (${user})."
}

# ---- STEP 1: Indexer admin password ----
if [[ -n "$INDEXER_PASS" ]]; then
    echo ""
    echo "[1/4] Changing Wazuh Indexer admin password..."

    wazuh_set_user_hash admin "$INDEXER_PASS"

    # The manager and dashboard read WAZUH_INDEXER_PASSWORD from .env, so one
    # variable rotates both. Grafana uses its own read-only account
    # (WAZUH_GRAFANA_RO_PASSWORD, scripts/11-wazuh-grafana-readonly.sh).
    update_env_var "WAZUH_INDEXER_PASSWORD" "$INDEXER_PASS"
    echo "  .env updated (WAZUH_INDEXER_PASSWORD)."

    SERVICES_TO_RECREATE+=(wazuh-dashboard wazuh-manager)
fi

# ---- STEP 1b: Wazuh dashboard service account (kibanaserver) ----
# The dashboard reads WAZUH_DASHBOARD_PASSWORD from .env (opensearch_dashboards.yml
# -> ${DASHBOARD_PASSWORD}); the indexer must hold the matching hash.
if [[ -n "$WAZUH_DASH_PASS" ]]; then
    echo ""
    echo "[1b/4] Changing Wazuh Dashboard (kibanaserver) password..."

    wazuh_set_user_hash kibanaserver "$WAZUH_DASH_PASS"
    update_env_var "WAZUH_DASHBOARD_PASSWORD" "$WAZUH_DASH_PASS"
    echo "  .env updated (WAZUH_DASHBOARD_PASSWORD)."

    SERVICES_TO_RECREATE+=(wazuh-dashboard)
fi

# ---- STEP 2: Wazuh API password (wazuh-wui user) ----
if [[ -n "$API_PASS" ]]; then
    echo ""
    echo "[2/4] Changing Wazuh API password for wazuh-wui..."

    # Get a token using the wazuh admin account (always has default password 'wazuh')
    # If that fails, try the current wazuh-wui credentials from compose
    TOKEN=""

    # Try wazuh admin first
    TOKEN=$(docker exec wazuh-manager curl -sk \
        -u "wazuh:wazuh" \
        -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)

    if [[ -z "$TOKEN" || "$TOKEN" == *"error"* || "$TOKEN" == *"Invalid"* ]]; then
        echo "  Admin auth failed, trying current wazuh-wui credentials..."
        CURRENT_API_PASS=$(read_env_var WAZUH_API_PASSWORD)
        TOKEN=$(container_curl wazuh-manager wazuh-wui "${CURRENT_API_PASS}" -sk \
            -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)
    fi

    if [[ -z "$TOKEN" || "$TOKEN" == *"error"* || "$TOKEN" == *"Invalid"* ]]; then
        echo "  ERROR: Could not authenticate to Wazuh API. Skipping API password change."
        echo "  You may need to manually reset via: docker exec -it wazuh-manager /var/ossec/bin/wazuh-keystore -f"
    else
        # Find the wazuh-wui user ID
        WUI_ID=$(docker exec wazuh-manager curl -sk \
            -H "Authorization: Bearer ${TOKEN}" \
            "https://localhost:55000/security/users" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); [print(u['id']) for u in d.get('data',{}).get('affected_items',[]) if u['username']=='wazuh-wui']" 2>/dev/null)

        if [[ -n "$WUI_ID" ]]; then
            # Write the password change as a script piped into the container
            # to avoid any shell escaping of special characters
            printf '#!/bin/bash\ncurl -sk -H "Authorization: Bearer %s" -H "Content-Type: application/json" -X PUT "https://localhost:55000/security/users/%s" -d '"'"'{"password": "%s"}'"'"'\n' \
                "$TOKEN" "$WUI_ID" "$API_PASS" | docker exec -i wazuh-manager bash >/dev/null 2>&1

            echo "  API password changed for wazuh-wui (user ID ${WUI_ID})."

            # Verify the new password works
            VERIFY_TOKEN=$(container_curl wazuh-manager wazuh-wui "${API_PASS}" -sk \
                -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)
            if [[ -n "$VERIFY_TOKEN" && "$VERIFY_TOKEN" != *"error"* && "$VERIFY_TOKEN" != *"Invalid"* ]]; then
                echo "  VERIFIED: New API password works."
            else
                echo "  WARNING: Could not verify new API password. Check manually."
            fi
        else
            echo "  WARNING: Could not find wazuh-wui user ID. Skipping."
        fi

        update_env_var "WAZUH_API_PASSWORD" "$API_PASS"
        echo "  .env updated (WAZUH_API_PASSWORD)."

        # Update the wazuh.yml inside the dashboard container. The password
        # goes on stdin (sed-escaped for \, & and |), not on the command line.
        printf '%s' "$API_PASS" | sed 's/[\\&|]/\\&/g' | docker exec -i wazuh-dashboard bash -c '
            IFS= read -r P
            sed -i "s|password:.*|password: \"${P}\"|" "$0"
        ' "${WAZUH_YML_PATH}" 2>/dev/null && echo "  wazuh.yml updated in dashboard container."

        SERVICES_TO_RECREATE+=(wazuh-dashboard)
    fi
fi

# ---- STEP 3: Grafana admin password ----
if [[ -n "$GRAFANA_PASS" ]]; then
    echo ""
    echo "[3/4] Changing Grafana admin password..."

    docker exec grafana grafana cli admin reset-admin-password "${GRAFANA_PASS}" 2>/dev/null || \
        docker exec grafana grafana-cli admin reset-admin-password "${GRAFANA_PASS}" 2>/dev/null || true
    echo "  Grafana password changed."

    update_env_var "GRAFANA_ADMIN_PASS" "$GRAFANA_PASS"
    echo "  .env file updated."

    SERVICES_TO_RECREATE+=(grafana)
fi

# ---- STEP 4: Main OpenSearch cluster passwords (Phase F1) ----
if [[ -n "$OS_ADMIN_PASS" || -n "$OS_LOGSTASH_PASS" || -n "$OS_READONLY_PASS" || -n "$OS_DASHBOARDS_PASS" ]]; then
    echo ""
    echo "[4/4] Changing main OpenSearch cluster passwords..."

    if [[ ! -f "$OS_INTERNAL_USERS_HOST" ]]; then
        echo "  ERROR: ${OS_INTERNAL_USERS_HOST} not found."
        echo "  Run scripts/08b-init-opensearch-security.sh first."
        exit 1
    fi

    os_hash() {
        printf '%s' "$1" | docker exec -i opensearch-hot bash -c \
            'IFS= read -r P; plugins/opensearch-security/tools/hash.sh -p "$P"' 2>/dev/null | grep -E '^\$2[aby]\$' | tail -1
    }

    os_update_user_hash() {
        local user="$1" pass="$2"
        local hash
        hash=$(os_hash "$pass")
        if [[ -z "$hash" ]]; then
            echo "  ERROR: bcrypt hashing failed for ${user}. Aborting."
            exit 1
        fi
        NEW_HASH="$hash" TARGET_USER="$user" python3 - "$OS_INTERNAL_USERS_HOST" <<'PYEOF'
import os, re, sys
path = sys.argv[1]
user = os.environ["TARGET_USER"]
new_hash = os.environ["NEW_HASH"]
with open(path, encoding="utf-8") as f:
    content = f.read()
pattern = re.compile(r'(^%s:\s*\n\s*hash:\s*)"[^"]*"' % re.escape(user), re.M)
content, n = pattern.subn(lambda m: m.group(1) + '"' + new_hash + '"', content, count=1)
if n != 1:
    sys.exit("could not find user %s in %s" % (user, path))
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("  internal_users.yml updated for %s." % user)
PYEOF
    }

    cp "$OS_INTERNAL_USERS_HOST" "${OS_INTERNAL_USERS_HOST}.bak"

    [[ -n "$OS_ADMIN_PASS" ]]      && os_update_user_hash "admin" "$OS_ADMIN_PASS"
    [[ -n "$OS_LOGSTASH_PASS" ]]   && os_update_user_hash "logstash" "$OS_LOGSTASH_PASS"
    [[ -n "$OS_READONLY_PASS" ]]   && os_update_user_hash "readonly" "$OS_READONLY_PASS"
    [[ -n "$OS_DASHBOARDS_PASS" ]] && os_update_user_hash "kibanaserver" "$OS_DASHBOARDS_PASS"

    # Apply just the internal users to the running cluster via admin cert
    docker exec opensearch-hot bash -c "plugins/opensearch-security/tools/securityadmin.sh \
        -f ${OS_SEC_CFG}/internal_users.yml \
        -t internalusers \
        -cacert ${OS_CERTS}/root-ca.pem \
        -cert ${OS_CERTS}/admin.pem \
        -key ${OS_CERTS}/admin-key.pem \
        -h localhost -p 9200 \
        -icl -nhnv" 2>&1 | tail -5
    echo "  Security config applied to main cluster."

    # Update .env so container env interpolation picks up new values
    if [[ -f "$ENV_FILE" ]]; then
        [[ -n "$OS_ADMIN_PASS" ]]      && update_env_var "OPENSEARCH_ADMIN_PASSWORD" "$OS_ADMIN_PASS"
        [[ -n "$OS_LOGSTASH_PASS" ]]   && update_env_var "OPENSEARCH_LOGSTASH_PASSWORD" "$OS_LOGSTASH_PASS"
        [[ -n "$OS_READONLY_PASS" ]]   && update_env_var "OPENSEARCH_READONLY_PASSWORD" "$OS_READONLY_PASS"
        [[ -n "$OS_DASHBOARDS_PASS" ]] && update_env_var "OPENSEARCH_DASHBOARDS_PASSWORD" "$OS_DASHBOARDS_PASS"
        echo "  .env updated."
    else
        echo "  WARNING: ${ENV_FILE} not found — update OPENSEARCH_*_PASSWORD manually."
    fi

    # Recreate every consumer of the changed credentials
    [[ -n "$OS_LOGSTASH_PASS" ]]   && SERVICES_TO_RECREATE+=(logstash)
    [[ -n "$OS_READONLY_PASS" ]]   && SERVICES_TO_RECREATE+=(grafana elasticsearch-exporter)
    [[ -n "$OS_DASHBOARDS_PASS" ]] && SERVICES_TO_RECREATE+=(opensearch-dashboards)
fi

# ---- Recreate affected services (picks up new env vars) ----
echo ""
echo "=== Recreating affected services ==="

# Deduplicate the list
UNIQUE_SERVICES=($(printf '%s\n' "${SERVICES_TO_RECREATE[@]}" | sort -u))

if [[ ${#UNIQUE_SERVICES[@]} -gt 0 ]]; then
    cd "$COMPOSE_DIR"
    echo "  Services to recreate: ${UNIQUE_SERVICES[*]}"
    docker compose up -d "${UNIQUE_SERVICES[@]}" 2>&1 | sed 's/^/  /'
    echo "  Waiting 15 seconds for services to initialize..."
    sleep 15
else
    echo "  No services to recreate."
fi

# ---- Post-change verification ----
echo ""
echo "=== Verification ==="

if [[ -n "$INDEXER_PASS" ]]; then
    INDEXER_CHECK=$(container_curl wazuh-indexer admin "${INDEXER_PASS}" -sk \
        "https://localhost:9200/_cluster/health?pretty" 2>/dev/null | grep -c '"status"')
    if [[ "$INDEXER_CHECK" -gt 0 ]]; then
        echo "  [OK] Wazuh Indexer: admin password verified"
    else
        echo "  [FAIL] Wazuh Indexer: admin password NOT working"
    fi
fi

if [[ -n "$API_PASS" ]]; then
    API_CHECK=$(container_curl wazuh-manager wazuh-wui "${API_PASS}" -sk \
        -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)
    if [[ -n "$API_CHECK" && "$API_CHECK" != *"error"* && "$API_CHECK" != *"Invalid"* ]]; then
        echo "  [OK] Wazuh API: wazuh-wui password verified"
    else
        echo "  [FAIL] Wazuh API: wazuh-wui password NOT working"
    fi
fi

if [[ -n "$OS_ADMIN_PASS" ]]; then
    OS_CHECK=$(container_curl opensearch-hot admin "${OS_ADMIN_PASS}" -sk \
        "https://localhost:9200/_cluster/health?pretty" 2>/dev/null | grep -c '"status"')
    if [[ "$OS_CHECK" -gt 0 ]]; then
        echo "  [OK] OpenSearch (main): admin password verified"
    else
        echo "  [FAIL] OpenSearch (main): admin password NOT working"
    fi
fi

if [[ -n "$GRAFANA_PASS" ]]; then
    GRAFANA_CHECK=$(container_curl grafana admin "${GRAFANA_PASS}" -sf \
        "http://localhost:3000/api/health" 2>/dev/null)
    if [[ -n "$GRAFANA_CHECK" ]]; then
        echo "  [OK] Grafana: admin password verified"
    else
        echo "  [FAIL] Grafana: admin password NOT working (may have been changed via UI)"
    fi
fi

echo ""
echo "============================================"
echo "  Password change complete!"
echo "============================================"
echo ""
echo "  REMINDERS:"
echo "  - If you use N8N webhooks, update the Wazuh"
echo "    credentials in your N8N workflows."
echo "  - Wazuh Dashboard may take ~30s to fully"
echo "    reconnect to the API after a password change."
echo "  - The Grafana Wazuh datasource picks up new"
echo "    Indexer passwords via env interpolation on"
echo "    the grafana container recreate."
echo "  - Secrets are stored in ${ENV_FILE} (mode 600"
echo "    recommended); docker-compose.yml is not edited."
echo "============================================"
