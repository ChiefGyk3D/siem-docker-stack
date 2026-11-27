#!/bin/bash -p
# =============================================================================
# 01-disk-setup.sh — Format & mount NVMe (Hot) and SATA (Warm) disks
# =============================================================================
# This script sets up the two-tier storage architecture:
#   - HOT tier (NVMe SSD): Active indices, recent logs, fast queries
#   - WARM tier (SATA SSD or HDD): Older indices, archival, bulk storage
#
# You MUST edit the device variables below to match YOUR hardware.
# Run `lsblk` to identify your disks.
#
# WARNING: This script WIPES the target disks. All existing data will be lost.
#
# Start it by its path (sudo scripts/01-disk-setup.sh), never as `bash script`: the
# privileged-mode shebang keeps BASH_ENV and exported shell functions from running
# as root, and an explicit interpreter bypasses it, so root refuses to continue that way.
# =============================================================================

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode.
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs

# Who runs this is asked of the kernel through the absolute id program, never read from EUID or UID
# (bash imports both from the environment, so a caller could pick the branch).
RUN_UID="$(/usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null)" || RUN_UID=
case "$RUN_UID" in '' | *[!0-9]*) echo "ERROR: cannot tell who is running (no numeric user number)" >&2; exit 1 ;; esac
RUN_UID=$((10#$RUN_UID))
if [ "$RUN_UID" -eq 0 ] && ! [[ "$-" == *p* ]]; then
    # `bash script` bypasses the privileged shebang that keeps BASH_ENV and exported functions out
    echo "ERROR: as root, run this script by its path (sudo scripts/01-disk-setup.sh), not as 'bash script'" >&2
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  SIEM Server — Disk Setup                ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════╝${NC}"
echo ""

if [ "$RUN_UID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root (sudo)${NC}"
    exit 1
fi

# =============================================================================
# !! EDIT THESE to match your hardware !!
# Run `lsblk` to identify your disks.
# =============================================================================
NVME_DEV="${NVME_DEVICE:-/dev/nvme0n1}"    # NVMe SSD for HOT tier
SATA_DEV="${SATA_DEVICE:-/dev/sda}"        # SATA SSD/HDD for WARM tier
HOT_MOUNT="/data/hot"
WARM_MOUNT="/data/warm"

# Verify disks exist
echo -e "${YELLOW}Verifying disks...${NC}"
for dev in "$NVME_DEV" "$SATA_DEV"; do
    if [ ! -b "$dev" ]; then
        echo -e "${RED}ERROR: $dev not found${NC}"
        echo "  Run 'lsblk' and update NVME_DEV / SATA_DEV in this script."
        exit 1
    fi
done

# Show plan
echo ""
echo "Disk plan:"
echo "  ${NVME_DEV} ($(lsblk -dno SIZE "${NVME_DEV}")) → ${HOT_MOUNT}  (HOT tier — NVMe)"
echo "  ${SATA_DEV} ($(lsblk -dno SIZE "${SATA_DEV}")) → ${WARM_MOUNT} (WARM tier — SATA)"
echo ""
echo -e "${RED}WARNING: This will WIPE all data on both disks!${NC}"
read -p "Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

# ── NVMe Setup (HOT tier) ────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Setting up NVMe (HOT tier)...${NC}"

echo "  Wiping existing signatures..."
wipefs -af "${NVME_DEV}" 2>/dev/null || true
sgdisk --zap-all "${NVME_DEV}" 2>/dev/null || true

echo "  Creating partition..."
sgdisk -n 1:0:0 -t 1:8300 "${NVME_DEV}"
sleep 2

# Determine partition name (nvme uses p1, sata uses 1)
if [[ "$NVME_DEV" == *nvme* ]]; then
    NVME_PART="${NVME_DEV}p1"
else
    NVME_PART="${NVME_DEV}1"
fi

echo "  Formatting ${NVME_PART} as ext4..."
mkfs.ext4 -L siem-hot -m 1 -O extent,flex_bg,huge_file,dir_nlink \
    -E stride=128,stripe-width=128,lazy_itable_init=0 "${NVME_PART}"

# ── SATA Setup (WARM tier) ───────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Setting up SATA (WARM tier)...${NC}"

echo "  Wiping existing signatures..."
wipefs -af "${SATA_DEV}" 2>/dev/null || true
sgdisk --zap-all "${SATA_DEV}" 2>/dev/null || true

echo "  Creating partition..."
sgdisk -n 1:0:0 -t 1:8300 "${SATA_DEV}"
sleep 2

SATA_PART="${SATA_DEV}1"
echo "  Formatting ${SATA_PART} as ext4..."
mkfs.ext4 -L siem-warm -m 1 -O extent,flex_bg,huge_file,dir_nlink "${SATA_PART}"

# ── Mount Points ──────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Creating mount points...${NC}"
mkdir -p "${HOT_MOUNT}" "${WARM_MOUNT}"

NVME_UUID=$(blkid -s UUID -o value "${NVME_PART}")
SATA_UUID=$(blkid -s UUID -o value "${SATA_PART}")

echo "  NVMe UUID: ${NVME_UUID}"
echo "  SATA UUID: ${SATA_UUID}"

# Add to fstab (idempotent)
sed -i '/siem-hot\|siem-warm\|\/data\/hot\|\/data\/warm/d' /etc/fstab

cat >> /etc/fstab <<EOF

# SIEM Server Data Disks
# HOT tier — NVMe SSD
UUID=${NVME_UUID}  ${HOT_MOUNT}   ext4  defaults,noatime,discard  0  2
# WARM tier — SATA SSD/HDD
UUID=${SATA_UUID}  ${WARM_MOUNT}  ext4  defaults,noatime,discard  0  2
EOF

mount -a

# ── Directory Structure ───────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Creating directory structure...${NC}"

# HOT tier directories (fast, frequently accessed data)
mkdir -p "${HOT_MOUNT}"/{opensearch,influxdb,prometheus,prometheus-otlp,alertmanager,wazuh/{indexer,manager/{data,etc,logs,queue,integrations,active-response}},logstash}

# WARM tier directories (older data, archives, backups)
mkdir -p "${WARM_MOUNT}"/{opensearch,grafana,archives/{syslog,suricata},backups,wazuh-archives,snapshots}

# Set ownership for container UIDs
# OpenSearch runs as UID 1000
chown -R 1000:1000 "${HOT_MOUNT}/opensearch" "${WARM_MOUNT}/opensearch"
# Grafana runs as UID 472
chown -R 472:472 "${WARM_MOUNT}/grafana"
# Prometheus runs as nobody (65534)
chown -R 65534:65534 "${HOT_MOUNT}/prometheus" "${HOT_MOUNT}/prometheus-otlp"
# Wazuh indexer runs as UID 1000
chown -R 1000:1000 "${HOT_MOUNT}/wazuh/indexer"

# ── I/O Scheduler Tuning ─────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Applying I/O scheduler tuning...${NC}"

# NVMe: 'none' scheduler (direct submission, best for NVMe)
NVME_BASENAME=$(basename "${NVME_DEV}")
NVME_SCHED="/sys/block/${NVME_BASENAME}/queue/scheduler"
if [ -f "$NVME_SCHED" ]; then
    echo "none" > "$NVME_SCHED"
    echo "  NVMe scheduler: none"
fi

# SATA: 'mq-deadline' (good for SATA SSDs with queuing)
SATA_BASENAME=$(basename "${SATA_DEV}")
SATA_SCHED="/sys/block/${SATA_BASENAME}/queue/scheduler"
if [ -f "$SATA_SCHED" ]; then
    echo "mq-deadline" > "$SATA_SCHED"
    echo "  SATA scheduler: mq-deadline"
fi

# Persist scheduler settings via udev rules
cat > /etc/udev/rules.d/60-io-scheduler.rules <<EOF
# NVMe: no scheduler (direct submission)
ACTION=="add|change", KERNEL=="nvme[0-9]*", ATTR{queue/scheduler}="none"
# SATA SSD: mq-deadline
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
EOF

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Disk Setup Complete                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Mount points:"
df -h "${HOT_MOUNT}" "${WARM_MOUNT}"
echo ""
echo "Directory structure:"
find /data -maxdepth 3 -type d | sort
echo ""
echo "fstab entries:"
grep '/data/' /etc/fstab
echo ""
echo -e "${GREEN}Next: Run 02-bootstrap.sh to install Docker and prepare the system${NC}"
