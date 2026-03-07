# SIEM Docker Stack

A production-ready, fully Dockerized SIEM/SOC stack with **hot/warm tiering** for home labs and small-to-medium businesses. Designed to run on a single server with two-tier storage (NVMe + SATA) for cost-effective log retention.

---

## Architecture

```
                                    ┌──────────────────────────────────────────────────────┐
                                    │              SIEM Docker Stack                        │
                                    │              (Docker Compose)                         │
  ┌─────────────┐                   │                                                      │
  │   pfSense   │──── Syslog ──────►│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
  │   Router    │     UDP 514       │  │ Syslog-ng │──►│ Logstash │──►│ OpenSearch (Hot)  │ │
  │             │                   │  └──────────┘   └──────────┘   │    NVMe SSD       │ │
  │  Suricata   │── EVE JSON ──────►│       ▲          UDP 5140 ──►  │    0-30 days      │ │
  │  IDS/IPS    │   UDP 5140        │       │                        └────────┬───────────┘ │
  │             │                   │       │                                 │ ISM 30d     │
  │  Telegraf   │── InfluxDB ──────►│  ┌────┴─────┐                   ┌──────▼───────────┐ │
  │  Metrics    │   HTTP 8086       │  │ InfluxDB │                   │ OpenSearch (Warm) │ │
  └─────────────┘                   │  └──────────┘                   │    SATA SSD       │ │
                                    │                                 │    30-365 days    │ │
  ┌─────────────┐                   │  ┌────────────┐                 └──────────────────┘ │
  │   UniFi     │── Poller ────────►│  │ Prometheus │                                      │
  │  Network    │                   │  └────────────┘                 ┌──────────────────┐ │
  └─────────────┘                   │                                 │     Grafana      │ │
                                    │  ┌─────────────────────────┐    │   Dashboards     │ │
  ┌─────────────┐                   │  │    Wazuh (EDR/SIEM)     │    └──────────────────┘ │
  │   Wazuh     │── Agent ─────────►│  │  Manager + Indexer +    │                         │
  │   Agents    │   UDP 1514        │  │  Dashboard              │    ┌──────────────────┐ │
  └─────────────┘                   │  └─────────────────────────┘    │   Portainer      │ │
                                    │                                 │   (optional)      │ │
                                    │                                 └──────────────────┘ │
                                    └──────────────────────────────────────────────────────┘
```

## Features

- **Hot/Warm Tiering** — Automatically migrates indices from NVMe → SATA after 30 days, deletes after 1 year
- **12+ Services** — OpenSearch (2-node cluster), Logstash, Grafana, InfluxDB, Prometheus, Wazuh (full EDR), Syslog-ng, UniFi Poller, Portainer
- **Pre-built Dashboards** — Wazuh Security Overview, Vulnerability Detection, File Integrity Monitoring, Docker Container Monitoring, Prometheus Stats
- **Automated Setup** — Numbered scripts (01-06) walk through disk formatting → system tuning → deployment → verification
- **ISM Lifecycle** — Index State Management handles the hot→warm→delete lifecycle automatically
- **pfSense Integration** — Suricata IDS/IPS logs, pfBlockerNG, syslog, and Telegraf metrics
- **Production-Ready** — Docker daemon tuned, kernel parameters optimized, firewall configured, systemd timers for updates

---

## Reference Build

This stack was built and tested on the following hardware. You do **not** need identical hardware — this is a reference for sizing.

| Component | Specification |
|-----------|--------------|
| **Server** | Supermicro SuperServer 5019A-FTN4 (1U Rackmount) |
| **CPU** | Intel Atom C3758 (8 cores, 2.2 GHz, 25W TDP) |
| **RAM** | 64 GB DDR4 ECC (4 × 16 GB) |
| **OS Disk** | 240 GB SanDisk SSD PLUS (SATA) |
| **HOT Storage** | 1 TB Samsung 970 EVO Plus (NVMe) |
| **WARM Storage** | 2 TB Samsung 870 EVO (SATA SSD) |
| **Network** | 4 × GbE (Intel I350-AM4) |
| **OS** | Ubuntu 24.04 LTS Server |

### Memory Budget (64 GB Reference)

| Service | JVM Heap | Notes |
|---------|----------|-------|
| OpenSearch Hot | 12 GB | Primary data node, cluster manager |
| OpenSearch Warm | 4 GB | Data-only node for older indices |
| Wazuh Indexer | 4 GB | Separate OpenSearch instance for Wazuh |
| Logstash | 2 GB | Log parsing pipeline |
| **Total JVM** | **22 GB** | |
| OS + Docker + Buffers | ~42 GB | File system cache benefits OpenSearch |

> **Minimum Requirements:** 16 GB RAM (with reduced heap sizes), 2 CPU cores, 100 GB SSD + any secondary disk. See [docs/troubleshooting.md](docs/troubleshooting.md) for memory budget guidelines at different RAM levels.

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| **Grafana** | 3000 | Dashboards & visualization |
| **OpenSearch** | 9200 | Log search & indexing (Hot node API) |
| **OpenSearch Dashboards** | 5601 | OpenSearch UI |
| **Wazuh Dashboard** | 443 | EDR/SIEM dashboard (HTTPS) |
| **Wazuh Manager** | 1514/udp | Agent enrollment & communication |
| **Wazuh API** | 55000 | Wazuh RESTful API |
| **Prometheus** | 9090 | Metrics scraping & alerting |
| **InfluxDB** | 8086 | Time-series metrics (pfSense, Telegraf, UniFi) |
| **Logstash** | 5140/udp | Suricata EVE JSON ingestion |
| **Syslog-ng** | 514/udp+tcp | Centralized syslog receiver |
| **Portainer** | 9443 | Docker management UI (HTTPS) |

---

## Quick Start

### Prerequisites

- Ubuntu 22.04+ (or any modern Linux with Docker support)
- Two storage devices: one fast (NVMe/SSD for HOT), one large (SATA SSD/HDD for WARM)
- At least 16 GB RAM (32+ GB recommended)
- Docker CE 24+ with Compose V2

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/ChiefGyk3D/siem-docker-stack.git
cd siem-docker-stack

# 2. Format and mount data disks (EDIT the script first!)
#    Change NVME_DEV and SATA_DEV to match your hardware.
#    Run `lsblk` to identify your disks.
sudo nano scripts/01-disk-setup.sh
sudo bash scripts/01-disk-setup.sh

# 3. Install Docker, tune kernel, configure firewall
sudo bash scripts/02-bootstrap.sh

# 4. Configure your environment
cp .env.example .env
nano .env    # Set YOUR IPs, passwords, and heap sizes

# 5. Generate Wazuh TLS certificates
bash scripts/06-generate-wazuh-certs.sh

# 6. Deploy the stack (local mode)
bash scripts/03-deploy.sh local

# 7. Wait ~2 minutes, then apply index templates and ISM policy
bash scripts/04-apply-ism-policy.sh http://localhost:9200

# 8. Verify everything is healthy
bash scripts/05-verify.sh localhost
```

### After Installation

1. **Grafana** → `http://your-server:3000` (default: admin / changeme)
2. **Wazuh Dashboard** → `https://your-server:443` (default: admin / SecretPassword)
3. **OpenSearch Dashboards** → `http://your-server:5601`
4. **Portainer** → `https://your-server:9443`

> **IMPORTANT:** Change ALL default passwords immediately after first login!

---

## Dashboards

Pre-built Grafana dashboards are included in the `dashboards/` directory:

| Dashboard | Description |
|-----------|-------------|
| `wazuh_security_overview.json` | Wazuh alerts, agent status, attack distribution |
| `wazuh_vulnerability_detection.json` | CVE tracking, vulnerable packages, severity breakdown |
| `wazuh_file_integrity_monitoring.json` | FIM alerts, file changes, affected agents |
| `docker_container_monitoring.json` | Container CPU, memory, network, disk I/O |
| `prometheus_stats.json` | Prometheus self-monitoring and scrape targets |
| `datasources_reference.json` | Quick reference for all configured datasources |

### Importing Dashboards

Dashboards are automatically provisioned via Grafana's provisioning system. If you need to import manually:

```bash
# Via Grafana API
for f in dashboards/*.json; do
    curl -X POST "http://admin:changeme@localhost:3000/api/dashboards/db" \
        -H 'Content-Type: application/json' \
        -d "{\"dashboard\": $(cat "$f"), \"overwrite\": true}"
done
```

Or import via the Grafana UI: **Dashboards → New → Import → Upload JSON file**.

---

## Hot/Warm Storage Strategy

```
Day 0         Day 30                Day 365
  │             │                      │
  ▼             ▼                      ▼
┌─────────┐  ┌──────────┐          ┌────────┐
│   HOT   │→ │   WARM   │ ──────→  │ DELETE │
│  NVMe   │  │   SATA   │          │        │
│ (fast)  │  │ (merged) │          │        │
└─────────┘  └──────────┘          └────────┘
```

- **HOT (0-30 days):** Active writes and queries on NVMe. Zero replicas (single-server setup).
- **WARM (30-365 days):** Force-merged to 1 segment for read-optimized queries on SATA.
- **DELETE (365+ days):** Automatically purged by ISM policy.

See [docs/disk-strategy.md](docs/disk-strategy.md) for detailed sizing guidelines.

---

## pfSense Integration

This stack is designed as the **server-side** receiver for a pfSense-based network. For the **pfSense-side** configuration (Suricata, Telegraf, pfBlockerNG, syslog forwarding), see the companion repository:

> **[pfsense_siem_stack](https://github.com/ChiefGyk3D/pfsense_siem_stack)** — pfSense packages, Telegraf configuration, SID management, syslog format requirements, and 30+ pages of documentation.

### Data Flow Summary

| Source | Protocol | Port | Pipeline | Index Pattern |
|--------|----------|------|----------|---------------|
| Suricata IDS/IPS | UDP | 5140 | pfSense → Logstash → OpenSearch | `suricata-*` |
| pfSense Syslog | UDP | 514 | pfSense → Syslog-ng → Logstash → OpenSearch | `pfsense-syslog-*` |
| pfSense Filterlog | UDP | 514 | pfSense → Syslog-ng → Logstash → OpenSearch | `pfsense-filterlog-*` |
| pfSense Filterlog | UDP | 514 | pfSense → Syslog-ng → Wazuh Manager → Wazuh Indexer | `wazuh-alerts-*` |
| pfBlockerNG | InfluxDB | 8086 | Telegraf → InfluxDB | `pfblockerng` |
| pfSense Metrics | InfluxDB | 8086 | Telegraf → InfluxDB | `pfsense` |
| UniFi Devices | Poller | — | UniFi Poller → InfluxDB | `unpoller` |
| Wazuh Agents | TCP | 1514 | Agent → Wazuh Manager → Wazuh Indexer | `wazuh-*` |

> **Note:** pfSense must be configured to send syslog in **RFC 5424 format** (with RFC 3339 timestamps). Syslog-ng parses RFC 5424 and re-formats as BSD syslog for Wazuh's pre-decoder, which requires the traditional `timestamp hostname program[pid]: message` format to match the built-in pfSense `pf` decoder.

---

## Directory Structure

```
siem-docker-stack/
├── .env.example                          # Environment template — copy to .env
├── README.md
├── LICENSE
├── docker/
│   ├── docker-compose.yml                # Full stack definition
│   ├── opensearch/
│   │   ├── opensearch-hot.yml            # Hot node config
│   │   ├── opensearch-warm.yml           # Warm node config
│   │   ├── ism-hot-warm-policy.json      # ISM lifecycle policy
│   │   ├── index-template-suricata.json  # Suricata field mappings
│   │   └── index-template-pfblockerng.json
│   ├── logstash/
│   │   ├── logstash.yml                  # Logstash config
│   │   └── pipeline/
│   │       ├── 01-suricata.conf          # Suricata EVE JSON parser
│   │       └── 02-syslog.conf            # Syslog router
│   ├── prometheus/
│   │   └── prometheus.yml                # Scrape targets
│   ├── grafana/
│   │   └── provisioning/
│   │       ├── datasources/
│   │       │   └── datasources.yml       # Auto-provisioned datasources
│   │       └── dashboards/
│   │           └── dashboards.yml        # Dashboard provisioning config
│   ├── syslog-ng/
│   │   └── syslog-ng.conf               # Syslog receiver & router
│   └── wazuh/
│       ├── wazuh-indexer.yml             # Wazuh OpenSearch config
│       ├── opensearch_dashboards.yml     # Wazuh Dashboard config
│       └── certs/                        # TLS certificates (generated)
│           └── README.md
├── scripts/
│   ├── 01-disk-setup.sh                  # Format & mount hot/warm disks
│   ├── 02-bootstrap.sh                   # Install Docker, kernel tuning
│   ├── 03-deploy.sh                      # Deploy stack (local or remote)
│   ├── 04-apply-ism-policy.sh            # Apply ISM policy & templates
│   ├── 05-verify.sh                      # Health check all services
│   └── 06-generate-wazuh-certs.sh        # Generate Wazuh TLS certs
├── dashboards/
│   ├── docker_container_monitoring.json
│   ├── prometheus_stats.json
│   ├── wazuh_security_overview.json
│   ├── wazuh_vulnerability_detection.json
│   ├── wazuh_file_integrity_monitoring.json
│   └── datasources_reference.json
├── docs/
│   ├── disk-strategy.md                  # Hot/warm tiering deep dive
│   ├── maintenance.md                    # Maintenance & backup guide
│   └── troubleshooting.md               # Common issues & fixes
└── media/
  ├── icons/                            # Social media icons for README
  └── screenshots/                      # Stack screenshots used in docs
```

---

## Screenshots

### Grafana Dashboards Home

![Grafana Dashboards Home](media/screenshots/Grafana_dashboards_home.png)

### Wazuh Security Overview

![Wazuh Security Overview](media/screenshots/Wazuh_Security_Overview.png)

### Wazuh Vulnerability Detection

![Wazuh Vulnerability Detection](media/screenshots/Wazuh_Vulnerability_Detection.png)

### Docker Container Monitoring

![Docker Container Monitoring](media/screenshots/Docker_Container_monitoring.png)

### Docker Compose Service Status

![Docker Compose Service Status](media/screenshots/docker_ps.png)

### Full Stack Verification Script Output

![05 Verify Output](media/screenshots/05-verify.png)

---

## Roadmap

- [ ] **N8N Integration** — AI-powered log analysis workflows using a dedicated AI inference server
- [ ] **Suricata Dashboard** — Dedicated Grafana dashboard for IDS/IPS alerts with GeoIP world map
- [ ] **pfSense Filterlog Dashboard** — Firewall rule hit visualization
- [ ] **Automated Backup Script** — Scheduled OpenSearch snapshots to remote storage
- [ ] **Alerting** — Grafana alert rules for critical security events
- [ ] **GeoIP Enrichment** — MaxMind GeoLite2 integration in Logstash pipelines
- [ ] **Node Exporter** — Add host-level metrics collection to the compose stack

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/disk-strategy.md](docs/disk-strategy.md) | Hot/warm tiering, directory layout, sizing guidelines |
| [docs/maintenance.md](docs/maintenance.md) | Systemd timers, backup strategy, service commands |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues, memory budgets, emergency procedures |
| [.env.example](.env.example) | All configurable environment variables with descriptions |

---

## Related Projects

| Repository | Description |
|-----------|-------------|
| [pfsense_siem_stack](https://github.com/ChiefGyk3D/pfsense_siem_stack) | pfSense-side SIEM integration (Suricata, Telegraf, pfBlockerNG, 30+ docs) |
| [PiNodeXMR_Grafana_Dashboard](https://github.com/ChiefGyk3D/PiNodeXMR_Grafana_Dashboard) | Monero node monitoring dashboard for Grafana |

### UniFi Network Monitoring

This stack includes **UniFi Poller** for collecting UniFi switch and AP telemetry, but UniFi Poller itself is a separate community project — not covered in depth here. I have contributed some dashboard fixes upstream. For setup, configuration, and dedicated UniFi dashboards, see the official project:

> **[UniFi Poller (unpoller)](https://unpoller.com/)** — [GitHub](https://github.com/unpoller/unpoller) — Purpose-built UniFi telemetry collector for Grafana + InfluxDB/Prometheus.

---

## License

This project is licensed under the [GNU GPL v2](LICENSE).

---

## Support This Project

If this project is useful to you, consider supporting continued development:

### Recurring Support

<table>
  <tr>
    <td align="center" width="200">
      <a href="https://www.patreon.com/chiefgyk3d">
        <img src="media/icons/patreon.svg" width="40" height="40" alt="Patreon"><br>
        <strong>Patreon</strong>
      </a>
    </td>
    <td align="center" width="200">
      <a href="https://streamelements.com/chiefgyk3d/tip">
        <img src="media/streamelements.png" width="40" height="40" alt="StreamElements"><br>
        <strong>StreamElements Tip</strong>
      </a>
    </td>
  </tr>
</table>

### Crypto Tips

<table>
  <tr>
    <td align="center" width="80">
      <img src="media/icons/bitcoin.svg" width="30" height="30" alt="Bitcoin">
    </td>
    <td>
      <strong>Bitcoin</strong><br>
      <code>bc1qztdzcy2wyavj2tsuandu4p0tcklzttvdnzalla</code>
    </td>
  </tr>
  <tr>
    <td align="center" width="80">
      <img src="media/icons/monero.svg" width="30" height="30" alt="Monero">
    </td>
    <td>
      <strong>Monero</strong><br>
      <code>84Y34QubRwQYK2HNviezeH9r6aRcPvgWmKtDkN3EwiuVbp6sNLhm9ffRgs6BA9X1n9jY7wEN16ZEpiEngZbecXseUrW8SeQ</code>
    </td>
  </tr>
  <tr>
    <td align="center" width="80">
      <img src="media/icons/ethereum.svg" width="30" height="30" alt="Ethereum">
    </td>
    <td>
      <strong>Ethereum</strong><br>
      <code>0x554f18cfB684889c3A60219BDBE7b050C39335ED</code>
    </td>
  </tr>
</table>

### Author & Socials

<table>
  <tr>
    <td align="center" width="100">
      <a href="https://social.chiefgyk3d.com/@chiefgyk3d">
        <img src="media/icons/mastodon.svg" width="30" height="30" alt="Mastodon"><br>
        <sub>Mastodon</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://bsky.app/profile/chiefgyk3d.com">
        <img src="media/icons/bluesky.svg" width="30" height="30" alt="Bluesky"><br>
        <sub>Bluesky</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://www.twitch.tv/chiefgyk3d">
        <img src="media/icons/twitch.svg" width="30" height="30" alt="Twitch"><br>
        <sub>Twitch</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://www.youtube.com/channel/UCvFY4KyqVBuYd7JAl3NRyiQ">
        <img src="media/icons/youtube.svg" width="30" height="30" alt="YouTube"><br>
        <sub>YouTube</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://kick.com/chiefgyk3d">
        <img src="media/icons/kick.svg" width="30" height="30" alt="Kick"><br>
        <sub>Kick</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://www.tiktok.com/@chiefgyk3d">
        <img src="media/icons/tiktok.svg" width="30" height="30" alt="TikTok"><br>
        <sub>TikTok</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://discord.chiefgyk3d.com">
        <img src="media/icons/discord.svg" width="30" height="30" alt="Discord"><br>
        <sub>Discord</sub>
      </a>
    </td>
    <td align="center" width="100">
      <a href="https://matrix-invite.chiefgyk3d.com">
        <img src="media/icons/matrix.svg" width="30" height="30" alt="Matrix"><br>
        <sub>Matrix</sub>
      </a>
    </td>
  </tr>
</table>
