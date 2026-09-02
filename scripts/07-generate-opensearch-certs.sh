#!/bin/bash
# =============================================================================
# 07-generate-opensearch-certs.sh — Generate TLS certs for the main cluster
# =============================================================================
# Generates a self-signed root CA, per-node certificates (opensearch-hot,
# opensearch-warm) and an admin client certificate for securityadmin.sh,
# used by the OpenSearch security plugin (transport + HTTP TLS).
#
# Output: docker/opensearch/certs/ (gitignored, like docker/wazuh/certs)
#   root-ca.pem / root-ca-key.pem      — cluster CA (back up the key!)
#   opensearch-hot.pem / -key.pem      — hot node cert (PKCS#8 key)
#   opensearch-warm.pem / -key.pem     — warm node cert (PKCS#8 key)
#   admin.pem / admin-key.pem          — admin client cert (securityadmin.sh)
#
# The DNs below MUST match plugins.security.nodes_dn / authcz.admin_dn in
# docker/opensearch/opensearch-hot.yml and opensearch-warm.yml.
#
# Run this ONCE before the first `docker compose up` (after enabling the
# security plugin). Requires: openssl.
#
# Usage:
#   bash scripts/07-generate-opensearch-certs.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../docker/opensearch/certs"
DAYS_CA=3650
DAYS_CERT=3650
KEY_BITS=2048

# Subject components — keep in sync with nodes_dn/admin_dn in the node configs.
# RFC2253 form (as OpenSearch sees it): CN=<name>,OU=SIEM,O=siem-docker-stack,C=US
SUBJ_BASE="/C=US/O=siem-docker-stack/OU=SIEM"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Generate OpenSearch TLS Certificates    ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

command -v openssl >/dev/null 2>&1 || {
    echo -e "${RED}openssl not found — install it first (apt install openssl).${NC}"
    exit 1
}

# Check if certs already exist
if [ -f "${CERTS_DIR}/root-ca.pem" ]; then
    echo -e "${YELLOW}⚠ Certificates already exist in ${CERTS_DIR}${NC}"
    echo "  Regenerating invalidates the running cluster's TLS setup."
    read -r -p "Overwrite? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    rm -f "${CERTS_DIR}"/*.pem "${CERTS_DIR}"/*.srl "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*.ext
fi

mkdir -p "${CERTS_DIR}"

# If docker compose up ran before this script, Docker created DIRECTORIES at
# the missing cert bind-mount paths — clear them or the writes below fail.
for f in root-ca.pem opensearch-hot.pem opensearch-hot-key.pem \
         opensearch-warm.pem opensearch-warm-key.pem admin.pem admin-key.pem; do
    if [ -d "${CERTS_DIR}/${f}" ]; then
        echo -e "${YELLOW}Removing directory ${f} (created by docker compose before certs existed)${NC}"
        rmdir "${CERTS_DIR}/${f}"
    fi
done

cd "${CERTS_DIR}"

# ── Root CA ──────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/4] Generating root CA...${NC}"
openssl genrsa -out root-ca-key.pem ${KEY_BITS} 2>/dev/null
openssl req -new -x509 -sha256 -days ${DAYS_CA} \
    -key root-ca-key.pem \
    -subj "${SUBJ_BASE}/CN=siem-opensearch-root-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
    -out root-ca.pem
echo -e "${GREEN}✓ root-ca.pem${NC}"

# gen_node_cert <name> — node cert with SANs for service name + localhost
gen_node_cert() {
    local name="$1"
    local ip="$2"

    openssl genrsa -out "${name}-key-rsa.pem" ${KEY_BITS} 2>/dev/null
    # OpenSearch requires PKCS#8 keys
    openssl pkcs8 -topk8 -nocrypt -in "${name}-key-rsa.pem" -out "${name}-key.pem"
    rm -f "${name}-key-rsa.pem"

    openssl req -new -key "${name}-key.pem" \
        -subj "${SUBJ_BASE}/CN=${name}" \
        -out "${name}.csr"

    cat > "${name}.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:${name}, DNS:localhost, IP:127.0.0.1, IP:${ip}
EOF

    openssl x509 -req -sha256 -days ${DAYS_CERT} \
        -in "${name}.csr" \
        -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial \
        -extfile "${name}.ext" \
        -out "${name}.pem" 2>/dev/null

    rm -f "${name}.csr" "${name}.ext"
    echo -e "${GREEN}✓ ${name}.pem${NC}"
}

echo -e "${YELLOW}[2/4] Generating opensearch-hot node cert...${NC}"
gen_node_cert opensearch-hot 172.20.0.10

echo -e "${YELLOW}[3/4] Generating opensearch-warm node cert...${NC}"
gen_node_cert opensearch-warm 172.20.0.11

# ── Admin client cert (for securityadmin.sh / manual admin API access) ───────
echo -e "${YELLOW}[4/4] Generating admin client cert...${NC}"
openssl genrsa -out admin-key-rsa.pem ${KEY_BITS} 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in admin-key-rsa.pem -out admin-key.pem
rm -f admin-key-rsa.pem

openssl req -new -key admin-key.pem \
    -subj "${SUBJ_BASE}/CN=admin" \
    -out admin.csr

cat > admin.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -sha256 -days ${DAYS_CERT} \
    -in admin.csr \
    -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial \
    -extfile admin.ext \
    -out admin.pem 2>/dev/null
rm -f admin.csr admin.ext root-ca.srl
echo -e "${GREEN}✓ admin.pem${NC}"

# Permissions — the opensearch containers run as uid 1000 and must be able
# to read the node keys through the read-only bind mounts.
chmod 600 root-ca-key.pem
chmod 644 root-ca.pem opensearch-hot.pem opensearch-warm.pem admin.pem
chmod 640 opensearch-hot-key.pem opensearch-warm-key.pem admin-key.pem
chown 1000:1000 opensearch-hot-key.pem opensearch-warm-key.pem 2>/dev/null || {
    echo -e "${YELLOW}⚠ Could not chown node keys to uid 1000 (not root).${NC}"
    echo "  03-deploy.sh fixes ownership on the server; for a repo-local"
    echo "  'docker compose up', run:  sudo chown 1000:1000 ${CERTS_DIR}/*-key.pem"
}

echo ""
echo -e "${GREEN}✓ Certificates generated:${NC}"
ls -la "${CERTS_DIR}"/*.pem

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  OpenSearch Certificates Ready           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Next:"
echo "  1. Set OPENSEARCH_*_PASSWORD vars in .env (see .env.example)"
echo "  2. Start the cluster:  docker compose up -d opensearch-hot opensearch-warm"
echo "  3. Run scripts/08b-init-opensearch-security.sh to hash passwords and"
echo "     initialize the security index."
echo ""
echo -e "${RED}SECURITY:${NC}"
echo "  - Never commit private keys (*-key.pem) to version control (gitignored)."
echo "  - Back up root-ca-key.pem securely."
