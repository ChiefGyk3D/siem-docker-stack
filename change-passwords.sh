#!/bin/bash
set -e

# =============================================================================
# SIEM Stack Password Change Tool
# =============================================================================
# Changes passwords for Wazuh Indexer, Wazuh API, and Grafana.
# Run this script ON the SIEM server (where docker compose is running).
#
# IMPORTANT:
#   - Avoid $ in passwords — it causes escaping issues across YAML, shell,
#     Docker Compose, and JSON layers. Stick to: A-Z a-z 0-9 ! @ # % ^ & * -
#   - This script uses 'docker compose up -d' (not restart) so env var
#     changes in docker-compose.yml actually take effect.
# =============================================================================

COMPOSE_DIR="/opt/siem"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
DATASOURCES_FILE="${COMPOSE_DIR}/grafana/provisioning/datasources/datasources.yml"
WAZUH_YML_PATH="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
SEC_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
CERTS="/usr/share/wazuh-indexer/config/certs"
SEC_CFG="/usr/share/wazuh-indexer/config/opensearch-security"

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
read -sp "New Grafana admin password (leave blank to skip): " GRAFANA_PASS
echo ""

if [[ -z "$INDEXER_PASS" && -z "$API_PASS" && -z "$GRAFANA_PASS" ]]; then
    echo "Nothing to change. Exiting."
    exit 0
fi

# Validate passwords for problematic characters
[[ -n "$INDEXER_PASS" ]] && { validate_password "$INDEXER_PASS" "Indexer" || INDEXER_PASS=""; }
[[ -n "$API_PASS" ]]     && { validate_password "$API_PASS" "API" || API_PASS=""; }

if [[ -z "$INDEXER_PASS" && -z "$API_PASS" && -z "$GRAFANA_PASS" ]]; then
    echo "Nothing to change. Exiting."
    exit 0
fi

echo ""
echo "=== Changes to apply ==="
[[ -n "$INDEXER_PASS" ]] && echo "  * Wazuh Indexer admin password"
[[ -n "$API_PASS" ]]     && echo "  * Wazuh API (wazuh-wui) password"
[[ -n "$GRAFANA_PASS" ]] && echo "  * Grafana admin password"
echo ""
read -p "Proceed? (y/N): " CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo "Aborted." && exit 0

SERVICES_TO_RECREATE=()

# ---- STEP 1: Indexer admin password ----
if [[ -n "$INDEXER_PASS" ]]; then
    echo ""
    echo "[1/3] Changing Wazuh Indexer admin password..."

    # Generate bcrypt hash inside the container
    HASH=$(docker exec wazuh-indexer bash -c \
        "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${HASH_TOOL} -p '${INDEXER_PASS}'" \
        2>/dev/null | grep '^\$2')

    if [[ -z "$HASH" ]]; then
        echo "  ERROR: Failed to generate bcrypt hash. Aborting indexer change."
        exit 1
    fi
    echo "  Hash generated."

    # Backup internal_users.yml
    docker exec wazuh-indexer cp ${SEC_CFG}/internal_users.yml ${SEC_CFG}/internal_users.yml.bak

    # Use python to safely update the hash (avoids sed escaping issues with bcrypt $)
    ESCAPED_HASH=$(printf '%s' "$HASH" | sed 's/[&/\]/\\&/g')
    docker exec wazuh-indexer python3 -c "
import re
path = '${SEC_CFG}/internal_users.yml'
with open(path) as f:
    content = f.read()
content = re.sub(
    r'(admin:\\s*\\n\\s*hash:\\s*)\"[^\"]+\"',
    '\\\\1\"${ESCAPED_HASH}\"',
    content, count=1)
with open(path, 'w') as f:
    f.write(content)
print('  internal_users.yml updated.')
"

    # Apply security config to the running cluster
    docker exec wazuh-indexer bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk && ${SEC_TOOL} \
        -f ${SEC_CFG}/internal_users.yml \
        -t internalusers \
        -cacert ${CERTS}/root-ca.pem \
        -cert ${CERTS}/admin.pem \
        -key ${CERTS}/admin-key.pem \
        -icl -nhnv" 2>&1 | tail -5
    echo "  Security config applied to indexer."

    # Escape $ as $$ for docker-compose interpolation
    COMPOSE_SAFE_INDEXER=$(printf '%s' "$INDEXER_PASS" | sed 's/\$/\$\$/g')
    sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${COMPOSE_SAFE_INDEXER}|g" "$COMPOSE_FILE"
    sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${COMPOSE_SAFE_INDEXER}|g" "$COMPOSE_FILE"
    echo "  docker-compose.yml updated."

    # Update Grafana datasource provisioning (plain password, YAML handles it)
    if [[ -f "$DATASOURCES_FILE" ]]; then
        sed -i "s|basicAuthPassword: .*|basicAuthPassword: \"${INDEXER_PASS}\"|g" "$DATASOURCES_FILE"
        echo "  Grafana datasources updated."
    fi

    SERVICES_TO_RECREATE+=(wazuh-dashboard wazuh-manager grafana)
fi

# ---- STEP 2: Wazuh API password (wazuh-wui user) ----
if [[ -n "$API_PASS" ]]; then
    echo ""
    echo "[2/3] Changing Wazuh API password for wazuh-wui..."

    # Get a token using the wazuh admin account (always has default password 'wazuh')
    # If that fails, try the current wazuh-wui credentials from compose
    TOKEN=""

    # Try wazuh admin first
    TOKEN=$(docker exec wazuh-manager curl -sk \
        -u "wazuh:wazuh" \
        -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)

    if [[ -z "$TOKEN" || "$TOKEN" == *"error"* || "$TOKEN" == *"Invalid"* ]]; then
        echo "  Admin auth failed, trying current wazuh-wui credentials..."
        # Read current API_PASSWORD from compose (handle $$ escaping)
        CURRENT_API_PASS=$(grep 'API_PASSWORD=' "$COMPOSE_FILE" | head -1 | sed 's/.*API_PASSWORD=//' | sed 's/\$\$/\$/g' | tr -d '[:space:]')
        TOKEN=$(docker exec wazuh-manager curl -sk \
            -u "wazuh-wui:${CURRENT_API_PASS}" \
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
            VERIFY_TOKEN=$(docker exec wazuh-manager curl -sk \
                -u "wazuh-wui:${API_PASS}" \
                -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)
            if [[ -n "$VERIFY_TOKEN" && "$VERIFY_TOKEN" != *"error"* && "$VERIFY_TOKEN" != *"Invalid"* ]]; then
                echo "  VERIFIED: New API password works."
            else
                echo "  WARNING: Could not verify new API password. Check manually."
            fi
        else
            echo "  WARNING: Could not find wazuh-wui user ID. Skipping."
        fi

        # Update compose file (escape $ as $$ for Docker Compose)
        COMPOSE_SAFE_API=$(printf '%s' "$API_PASS" | sed 's/\$/\$\$/g')
        sed -i "s|API_PASSWORD=.*|API_PASSWORD=${COMPOSE_SAFE_API}|g" "$COMPOSE_FILE"
        echo "  docker-compose.yml updated."

        # Update the wazuh.yml inside the dashboard container (quote the password in YAML)
        docker exec wazuh-dashboard bash -c "
            sed -i 's|password:.*|password: \"${API_PASS}\"|' '${WAZUH_YML_PATH}'
        " 2>/dev/null && echo "  wazuh.yml updated in dashboard container."

        SERVICES_TO_RECREATE+=(wazuh-dashboard)
    fi
fi

# ---- STEP 3: Grafana admin password ----
if [[ -n "$GRAFANA_PASS" ]]; then
    echo ""
    echo "[3/3] Changing Grafana admin password..."

    docker exec grafana grafana cli admin reset-admin-password "${GRAFANA_PASS}" 2>/dev/null || \
        docker exec grafana grafana-cli admin reset-admin-password "${GRAFANA_PASS}" 2>/dev/null || true
    echo "  Grafana password changed."

    # Update .env file if it exists
    ENV_FILE="${COMPOSE_DIR}/.env"
    if [[ -f "$ENV_FILE" ]]; then
        sed -i "s|GRAFANA_ADMIN_PASS=.*|GRAFANA_ADMIN_PASS=${GRAFANA_PASS}|g" "$ENV_FILE"
        echo "  .env file updated."
    fi

    SERVICES_TO_RECREATE+=(grafana)
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
    INDEXER_CHECK=$(docker exec wazuh-indexer curl -sk \
        -u "admin:${INDEXER_PASS}" \
        "https://localhost:9200/_cluster/health?pretty" 2>/dev/null | grep -c '"status"')
    if [[ "$INDEXER_CHECK" -gt 0 ]]; then
        echo "  [OK] Wazuh Indexer: admin password verified"
    else
        echo "  [FAIL] Wazuh Indexer: admin password NOT working"
    fi
fi

if [[ -n "$API_PASS" ]]; then
    API_CHECK=$(docker exec wazuh-manager curl -sk \
        -u "wazuh-wui:${API_PASS}" \
        -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)
    if [[ -n "$API_CHECK" && "$API_CHECK" != *"error"* && "$API_CHECK" != *"Invalid"* ]]; then
        echo "  [OK] Wazuh API: wazuh-wui password verified"
    else
        echo "  [FAIL] Wazuh API: wazuh-wui password NOT working"
    fi
fi

if [[ -n "$GRAFANA_PASS" ]]; then
    GRAFANA_CHECK=$(docker exec grafana curl -sf \
        "http://admin:${GRAFANA_PASS}@localhost:3000/api/health" 2>/dev/null)
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
echo "  - Grafana datasources are auto-updated for"
echo "    Wazuh Indexer password changes."
echo "============================================"
