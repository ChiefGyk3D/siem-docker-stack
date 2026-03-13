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
- **Pre-built Dashboards** — 14 dashboards covering Wazuh security/compliance/agents, SIEM overview, network security with GeoIP maps, O365 audit, Docker containers, Prometheus stats
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

### Changing Default Passwords

An interactive password change script is included to safely update credentials for all stack components:

```bash
# Run on the SIEM server
sudo bash /opt/siem/change-passwords.sh
```

The script handles:
- **Wazuh Indexer** — Generates bcrypt hash, applies to security config, updates compose + Grafana datasources
- **Wazuh API (wazuh-wui)** — Changes via REST API, updates compose + Dashboard wazuh.yml
- **Grafana** — Resets via Grafana CLI, updates .env file
- Automatically escapes `$` as `$$` in docker-compose.yml
- Uses `docker compose up -d` (not restart) so env var changes take effect
- Verifies each password change worked before finishing

> **TIP:** Avoid using `$` in passwords — it causes escaping issues across YAML, shell, Docker Compose, and JSON layers.

---

## Dashboards

Pre-built Grafana dashboards are included in the `dashboards/` directory:

| Dashboard | Description |
|-----------|-------------|
| `wazuh_security_overview.json` | Wazuh alerts, agent status, attack distribution |
| `wazuh_vulnerability_detection.json` | CVE tracking, vulnerable packages, severity breakdown |
| `wazuh_file_integrity_monitoring.json` | FIM alerts, file changes, affected agents |
| `wazuh_agent_health.json` | Agent health, SCA compliance, Docker events, VirusTotal, O365 summary |
| `wazuh_compliance.json` | PCI DSS, NIST 800-53, HIPAA, GDPR compliance dashboards |
| `wazuh_network_security.json` | MITRE ATT&CK, SSH/Auth, pfSense alerts, GeoIP threat map |
| `wazuh_office365.json` | Office 365 SharePoint, Exchange, Azure AD, Copilot audit monitoring |
| `siem_overview.json` | Unified SIEM overview — cross-source correlation, Suricata, Wazuh, pfSense |
| `siem_plus_overview.json` | Extended SIEM+ overview — adds CrowdSec, JumpCloud, and Office 365 panels |
| `crowdsec_overview.json` | CrowdSec ban decisions, bouncer events, LAPI alerts, source analysis |
| `docker_container_monitoring.json` | Container CPU, memory, network, disk I/O via cAdvisor/Prometheus |
| `prometheus_stats.json` | Prometheus self-monitoring and scrape targets |
| `datasources_reference.json` | Quick reference for all configured datasources |
| `pfsense_firewall.json` | pfSense firewall rules, traffic by interface/protocol, blocked connections, pfBlockerNG |
| `suricata_ids.json` | Suricata IDS alerts, severity breakdown, GeoIP map, top signatures, protocol analysis |
| `unifi_network.json` | UniFi AP/switch metrics, client count, throughput, errors, rogue APs |

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

## CrowdSec (Phase 1)

CrowdSec is supported in this stack, but the recommended production path is **pfSense-hosted CrowdSec** for edge enforcement.

- Primary: install CrowdSec on pfSense (bouncer + log processor, optional LAPI)
- This repo: ingest CrowdSec events, alerting, dashboards, and notification workflows
- Local `crowdsec` service profile: optional lab/testing mode only

### Optional Local CrowdSec Service (Lab Mode)

```bash
cd /opt/siem
docker compose -f docker-compose.yml --profile crowdsec up -d crowdsec
```

### Deploy CrowdSec Alert Rule + Dashboard

```bash
DS_WAZUH="<your_wazuh_datasource_uid>" \
ALERT_FOLDER_UID="<your_grafana_folder_uid>" \
GRAFANA_URL="http://localhost:3000" \
GRAFANA_USER="admin" \
GRAFANA_PASS="changeme" \
python3 scripts/deploy-grafana-alerts.py

DS_WAZUH="<your_wazuh_datasource_uid>" \
GRAFANA_URL="http://localhost:3000" \
GRAFANA_USER="admin" \
GRAFANA_PASS="changeme" \
python3 scripts/deploy-crowdsec-dashboard.py
```

### Run Smoke Test

```bash
OPENSEARCH_URL="http://localhost:9200" \
GRAFANA_URL="http://localhost:3000" \
GRAFANA_USER="admin" \
GRAFANA_PASS="changeme" \
bash scripts/08-crowdsec-smoketest.sh
```

The smoke test verifies synthetic CrowdSec events can be indexed and that the CrowdSec Grafana alert rule/dashboard are present.

For pfSense install/config/testing steps, see your pfSense repo runbook:

- `pfsense_siem_stack/docs/crowdsec-phase1.md`

---

## Optional JumpCloud Bridge

JumpCloud support is intentionally split into a separate optional repo so non-JumpCloud users are not forced to deploy extra components:

> **[jumpcloud-wazuh-bridge](https://github.com/ChiefGyk3D/jumpcloud-wazuh-bridge)** — Polls JumpCloud Directory Insights and writes JSONL for Wazuh ingestion. Includes its own Grafana dashboard, Dockerfile, Doppler support, and CI/CD.

The **SIEM+ Overview** dashboard in this repo includes summary JumpCloud panels (auth failures, events by service) that pull from the same Wazuh index. The dedicated JumpCloud IdP Security dashboard (14 panels) lives in the bridge repo.

Wazuh decoders and rules for JumpCloud events are in `wazuh/jumpcloud_decoders.xml` and `wazuh/jumpcloud_rules.xml`.

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
│   ├── 06-generate-wazuh-certs.sh        # Generate Wazuh TLS certs
│   ├── deploy-n8n-soar.sh               # Deploy N8N workflows + Grafana alerts
│   ├── deploy-n8n-grafana-router.py      # Deploy Grafana alert router to N8N
│   └── deploy-grafana-alerts.py          # Deploy Grafana SIEM alert rules
├── n8n/
│   ├── grafana-alert-router.json         # N8N workflow: Grafana → Discord
│   └── wazuh-alert-triage.json           # N8N workflow: Wazuh → severity triage → Discord
├── change-passwords.sh                   # Interactive password change tool
├── dashboards/
│   ├── siem_overview.json                # Cross-source SIEM correlation
│   ├── wazuh_security_overview.json       # Wazuh alerts & attack distribution
│   ├── wazuh_vulnerability_detection.json # CVE tracking & severity breakdown
│   ├── wazuh_file_integrity_monitoring.json # FIM alerts & file changes
│   ├── wazuh_agent_health.json            # Agent health, SCA, Docker events
│   ├── wazuh_compliance.json              # PCI DSS, NIST, HIPAA, GDPR
│   ├── wazuh_network_security.json        # MITRE, SSH, pfSense, GeoIP map
│   ├── wazuh_office365.json               # O365 audit monitoring & GeoIP map
│   ├── docker_container_monitoring.json   # Container metrics via cAdvisor
│   ├── prometheus_stats.json              # Prometheus self-monitoring
│   ├── siem_plus_overview.json             # Extended SIEM+ with CrowdSec, JumpCloud, O365
│   ├── crowdsec_overview.json              # CrowdSec decisions & bouncer activity
│   ├── datasources_reference.json         # Datasource UID reference
│   ├── pfsense_firewall.json
│   ├── suricata_ids.json
│   └── unifi_network.json
├── docs/
│   ├── disk-strategy.md                  # Hot/warm tiering deep dive
│   ├── maintenance.md                    # Maintenance & backup guide
│   ├── n8n-soar.md                       # N8N SOAR deployment & workflow reference
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

- [x] **Suricata Dashboard** — IDS/IPS alerts with GeoIP map, severity breakdown, protocol analysis
- [x] **pfSense Firewall Dashboard** — Firewall rule visualization, traffic analysis, pfBlockerNG stats
- [x] **UniFi Network Dashboard** — AP/switch metrics, client monitoring, throughput analysis
- [x] **SIEM Overview Dashboard** — Unified cross-source threat overview with correlation
- [x] **Wazuh Agent Health Dashboard** — Agent status, SCA compliance, Docker events, VirusTotal, O365
- [x] **Wazuh Compliance Dashboard** — PCI DSS, NIST 800-53, HIPAA, GDPR compliance panels
- [x] **Wazuh Network Security Dashboard** — MITRE ATT&CK, SSH/Auth, pfSense alerts, GeoIP threat map
- [x] **Wazuh Office 365 Dashboard** — SharePoint, Exchange, Azure AD, Copilot audit monitoring with GeoIP map
- [x] **Dashboard Templating** — All dashboards use datasource template variables (portable across instances)
- [x] **Password Management** — Interactive script to change all default passwords safely
- [x] **N8N SOAR Integration** — Automated alert triage and Discord notification workflows via N8N webhooks
- [x] **Alerting** — 7 Grafana alert rules for Wazuh, Suricata, pfSense, and Docker events
- [x] **CrowdSec Integration** — CrowdSec overview dashboard, alert rules, pfSense deployment
- [x] **SIEM+ Overview** — Extended overview dashboard with CrowdSec, JumpCloud, and Office 365 panels
- [x] **JumpCloud Bridge** — Optional [jumpcloud-wazuh-bridge](https://github.com/ChiefGyk3D/jumpcloud-wazuh-bridge) with Wazuh decoders/rules in this repo
- [ ] **Automated Backup Script** — Scheduled OpenSearch snapshots to remote storage
- [ ] **GeoIP Enrichment** — MaxMind GeoLite2 integration in Logstash pipelines
- [ ] **Node Exporter** — Add host-level metrics collection to the compose stack

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/roadmap.md](docs/roadmap.md) | Phased roadmap with status badges (Wazuh tuning, JumpCloud, CrowdSec, SOAR, LLM) |
| [docs/detection-ownership.md](docs/detection-ownership.md) | Detection-to-workflow mapping, Grafana alert rules, n8n SOAR reference |
| [docs/alert-enrichment-standard.md](docs/alert-enrichment-standard.md) | Alert enrichment requirements — context fields, evidence, resolve reasons |
| [docs/n8n-soar.md](docs/n8n-soar.md) | N8N SOAR deployment, workflow reference, env var setup |
| [docs/disk-strategy.md](docs/disk-strategy.md) | Hot/warm tiering, directory layout, sizing guidelines |
| [docs/maintenance.md](docs/maintenance.md) | Systemd timers, backup strategy, service commands |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues, memory budgets, emergency procedures |
| [docs/crowdsec.md](docs/crowdsec.md) | CrowdSec integration — pfSense deployment, Wazuh rules, n8n enrichment |
| [docs/jumpcloud.md](docs/jumpcloud.md) | JumpCloud IdP bridge — setup, Wazuh rules, Doppler secrets |
| [docs/gpu-monitoring.md](docs/gpu-monitoring.md) | NVIDIA GPU monitoring — Prometheus exporters for Linux and Windows |
| [.env.example](.env.example) | All configurable environment variables with descriptions |

---

## Related Projects

| Repository | Description |
|-----------|-------------|
| [pfsense_siem_stack](https://github.com/ChiefGyk3D/pfsense_siem_stack) | pfSense-side SIEM integration (Suricata, Telegraf, pfBlockerNG, 30+ docs) |
| [jumpcloud-wazuh-bridge](https://github.com/ChiefGyk3D/jumpcloud-wazuh-bridge) | JumpCloud Directory Insights → Wazuh bridge with Grafana dashboard, Docker, Doppler |
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
