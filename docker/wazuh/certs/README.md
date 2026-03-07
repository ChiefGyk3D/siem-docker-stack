# =============================================================================
# Wazuh TLS Certificates — Placeholder
# =============================================================================
#
# This directory must contain TLS certificates for the Wazuh stack.
# Generate them BEFORE first boot using the Wazuh certificate generator:
#
#   cd docker/wazuh/certs
#   docker run --rm -v $(pwd):/certs \
#     -e INDEXER_NAME=wazuh-indexer \
#     -e MANAGER_NAME=wazuh-manager \
#     -e DASHBOARD_NAME=wazuh-dashboard \
#     wazuh/wazuh-certs-generator:latest
#
# This will create the following files:
#   root-ca.pem              — Root CA certificate
#   root-ca-key.pem          — Root CA private key (keep secure!)
#   admin.pem                — Admin certificate
#   admin-key.pem            — Admin private key
#   wazuh-indexer.pem        — Indexer certificate
#   wazuh-indexer-key.pem    — Indexer private key
#   wazuh-dashboard.pem      — Dashboard certificate
#   wazuh-dashboard-key.pem  — Dashboard private key
#   filebeat.pem             — Filebeat certificate (for wazuh-manager)
#   filebeat-key.pem         — Filebeat private key
#
# SECURITY WARNING:
#   - Never commit private keys (*-key.pem) to version control
#   - The .gitignore in this repo excludes *.pem files
#   - Back up root-ca-key.pem securely; losing it means regenerating all certs
#
# For more info:
#   https://documentation.wazuh.com/current/deployment-options/docker/
