#!/bin/bash
# =============================================================================
# 02-bootstrap.sh — Install Docker, kernel tuning, prepare for SIEM stack
# =============================================================================
# Run on the SIEM server as root, AFTER 01-disk-setup.sh.
#
# What this script does:
#   1. Updates system packages and installs dependencies
#   2. Tunes kernel parameters for OpenSearch / SIEM workloads
#   3. Configures system limits (file descriptors, memlock)
#   4. Installs Docker CE with production-ready daemon config
#   5. Creates the deployment directory (/opt/siem)
#   6. Configures UFW firewall for all SIEM service ports
#   7. Verifies data disks are mounted
# =============================================================================

set -euo pipefail

# Set SIEM_USER via env var or default to current user
SIEM_USER="${SIEM_USER:-$(logname 2>/dev/null || echo "${SUDO_USER:-siem}")}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  SIEM Server — System Bootstrap          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root (sudo)${NC}"
    exit 1
fi

# ── System Updates ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/7] Updating system packages...${NC}"
apt update && apt upgrade -y
apt install -y \
    curl wget gnupg2 apt-transport-https software-properties-common \
    jq python3 python3-pip net-tools htop iotop \
    ca-certificates lsb-release gdisk
echo -e "${GREEN}✓ System updated${NC}"

# ── Kernel Tuning ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/7] Applying kernel tuning...${NC}"

cat > /etc/sysctl.d/99-siem.conf <<EOF
# OpenSearch requires vm.max_map_count >= 262144
vm.max_map_count=262144

# Minimize swap usage (keep minimal swap for OOM safety)
vm.swappiness=1

# Network buffer tuning for high-volume syslog/log ingestion
net.core.rmem_max=33554432
net.core.rmem_default=16777216
net.core.wmem_max=33554432
net.core.netdev_max_backlog=5000

# File descriptor limits
fs.file-max=1048576

# Increase inotify watchers (for log file monitoring, Grafana, etc.)
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
EOF

sysctl --system
echo -e "${GREEN}✓ Kernel tuning applied${NC}"

# ── System Limits ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/7] Configuring system limits...${NC}"

cat > /etc/security/limits.d/99-siem.conf <<EOF
# SIEM stack limits — required for OpenSearch memlock and file handles
* soft nofile 65536
* hard nofile 65536
* soft memlock unlimited
* hard memlock unlimited
* soft nproc 65536
* hard nproc 65536
EOF

echo -e "${GREEN}✓ System limits configured${NC}"

# ── Install Docker ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/7] Installing Docker...${NC}"

if command -v docker &>/dev/null; then
    echo -e "${GREEN}✓ Docker already installed: $(docker --version)${NC}"
else
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Add Docker repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Add your user to the docker group
    usermod -aG docker "${SIEM_USER}"

    # Production-ready Docker daemon config
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "50m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 65536,
            "Soft": 65536
        },
        "memlock": {
            "Name": "memlock",
            "Hard": -1,
            "Soft": -1
        }
    }
}
EOF

    systemctl enable docker
    systemctl restart docker
    echo -e "${GREEN}✓ Docker installed: $(docker --version)${NC}"
fi

# ── Deploy Directory ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/7] Setting up deployment directory...${NC}"

DEPLOY_DIR="/opt/siem"
mkdir -p "${DEPLOY_DIR}"
chown "${SIEM_USER}:${SIEM_USER}" "${DEPLOY_DIR}"

echo -e "${GREEN}✓ Deployment directory: ${DEPLOY_DIR}${NC}"

# ── Firewall ──────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[6/7] Configuring firewall...${NC}"

# WARNING: Docker-published ports BYPASS UFW — the DOCKER iptables chain is
# evaluated before ufw's rules, so any port published in docker-compose.yml is
# reachable regardless of these rules. The real control is the bind address:
# docker-compose.yml publishes management ports on ${BIND_ADDR} and ingestion
# ports on ${INGEST_BIND_ADDR}, both defaulting to 127.0.0.1 (see README,
# "Network exposure"). The ufw rules below are defense in depth for the case
# where you widen those on purpose, and every one names a source network.
#
#   SIEM_ALLOWED_CIDR=192.0.2.0/24 sudo -E bash scripts/02-bootstrap.sh
apt install -y ufw

# SSH (critical — don't lock yourself out!)
ufw allow 22/tcp comment "SSH"

if [ -z "${SIEM_ALLOWED_CIDR:-}" ]; then
    echo -e "${YELLOW}SIEM_ALLOWED_CIDR is not set - opening NO SIEM ports in ufw.${NC}"
    echo "  Re-run with SIEM_ALLOWED_CIDR=<your trusted network, e.g. 192.0.2.0/24>"
    echo "  to allow log ingestion and the web UIs from that network only."
else
    allow_from() { # <proto> <port> <comment>
        ufw allow from "${SIEM_ALLOWED_CIDR}" to any port "$2" proto "$1" comment "$3"
    }

    # Web UIs and APIs (only reachable if BIND_ADDR is widened)
    allow_from tcp 9200  "OpenSearch HTTP"
    allow_from tcp 5601  "OpenSearch Dashboards"
    allow_from tcp 3000  "Grafana"
    allow_from tcp 9090  "Prometheus"
    allow_from tcp 55000 "Wazuh API"
    allow_from tcp 443   "Wazuh Dashboard"

    # Log ingestion (only reachable if INGEST_BIND_ADDR is widened)
    allow_from tcp 8086  "InfluxDB (pfSense Telegraf writes)"
    allow_from tcp 1514  "Wazuh agent (TCP)"
    allow_from udp 1514  "Wazuh agent"
    allow_from tcp 1515  "Wazuh agent enrollment"
    allow_from udp 5140  "Logstash Suricata UDP"
    allow_from tcp 5044  "Logstash Beats"
    allow_from udp 514   "Syslog UDP"
    allow_from tcp 514   "Syslog TCP"
fi

# Portainer is opt-in (compose profile) and loopback-only by default. If you
# expose it on purpose, allow it from one admin host only, for example:
# ufw allow from 192.0.2.10 to any port 9443 proto tcp comment "Portainer"

ufw --force enable
ufw status numbered

echo -e "${GREEN}✓ Firewall configured${NC}"

# ── Verify Data Disks ────────────────────────────────────────────────────────
echo -e "${YELLOW}[7/7] Verifying data disks...${NC}"

for mount in /data/hot /data/warm; do
    if mountpoint -q "$mount"; then
        echo -e "${GREEN}✓ ${mount} is mounted ($(df -h "$mount" | awk 'NR==2{print $2}'))${NC}"
    else
        echo -e "${RED}✗ ${mount} is NOT mounted — run 01-disk-setup.sh first!${NC}"
        exit 1
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Bootstrap Complete                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "System info:"
echo "  OS:        $(lsb_release -ds)"
echo "  Kernel:    $(uname -r)"
echo "  Docker:    $(docker --version 2>/dev/null | cut -d' ' -f3)"
echo "  RAM:       $(free -h | awk '/^Mem:/{print $2}')"
echo "  Hot disk:  $(df -h /data/hot | awk 'NR==2{print $4 " available"}')"
echo "  Warm disk: $(df -h /data/warm | awk 'NR==2{print $4 " available"}')"
echo ""
echo -e "${GREEN}Next: Run 03-deploy.sh to deploy the Docker stack${NC}"
echo ""
echo -e "${YELLOW}NOTE: Log out and back in for docker group membership to take effect.${NC}"
