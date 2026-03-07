# Disk Strategy — Hot/Warm Tiering

## Overview

This SIEM stack uses a two-tier storage architecture to balance **performance** and **capacity**:

| Tier | Storage Type | Mount Point | Purpose |
|------|-------------|-------------|---------|
| **HOT** | NVMe SSD | `/data/hot` | Active indices (0-30 days), InfluxDB, Prometheus |
| **WARM** | SATA SSD/HDD | `/data/warm` | Older indices (30-365 days), Grafana, Archives |

## How It Works

### OpenSearch ISM (Index State Management)

The `siem-hot-warm-delete` ISM policy automatically manages the index lifecycle:

```
Day 0-30:   HOT   (NVMe)  — Fast reads/writes, active queries
Day 30-365: WARM  (SATA)  — Force-merged to 1 segment, read-optimized
Day 365+:   DELETE         — Automatically purged after 1 year
```

1. **New indices** are created on the HOT node (`node.attr.temp=hot`) with NVMe-backed storage
2. **After 30 days**, ISM migrates the index to the WARM node (`node.attr.temp=warm`)
3. **On WARM**, indices are force-merged to a single segment for better read performance
4. **After 365 days**, indices are deleted to free space

### Why Two Nodes?

OpenSearch routes data to nodes based on `node.attr.temp` allocation tags. Having two separate nodes (even on the same host) allows ISM to physically move data between drives:

- `opensearch-hot` → reads/writes to `/data/hot/opensearch` (NVMe)
- `opensearch-warm` → reads/writes to `/data/warm/opensearch` (SATA)

## Directory Layout

```
/data/hot/                    # NVMe SSD
├── opensearch/               # Active OpenSearch indices
├── influxdb/                 # InfluxDB time-series data
├── prometheus/               # Prometheus TSDB
├── logstash/                 # Logstash persistent queues
└── wazuh/
    ├── indexer/              # Wazuh indexer data
    └── manager/              # Wazuh manager data
        ├── data/
        ├── etc/
        ├── logs/
        └── queue/

/data/warm/                   # SATA SSD or HDD
├── opensearch/               # Older OpenSearch indices (30d+)
├── grafana/                  # Grafana database & plugins
├── archives/
│   ├── syslog/               # Syslog-ng raw log archives
│   └── suricata/             # Suricata log archives
├── backups/                  # Manual backups
└── wazuh-archives/           # Wazuh alert archives
```

## Sizing Guidelines

| Component | Storage Estimate | Notes |
|-----------|-----------------|-------|
| Suricata indices | ~2-5 GB/day | Depends on traffic volume and rules |
| Syslog indices | ~500 MB-2 GB/day | Depends on number of logging sources |
| pfBlockerNG | ~100-500 MB/day | Depends on block activity |
| InfluxDB | ~50-200 MB/day | pfSense + UniFi metrics |
| Prometheus | ~100-500 MB/day | Depends on scrape targets |
| Wazuh | ~1-3 GB/day | Depends on agent count |

### Example: 1TB NVMe + 2TB SATA
- HOT (1TB NVMe): ~30 days of all active data → comfortably handles 5-15 GB/day
- WARM (2TB SATA): ~11 months of archived data after force-merge compression

## Tuning I/O Schedulers

The `01-disk-setup.sh` script configures optimal I/O schedulers:

- **NVMe**: `none` (direct submission, no scheduler overhead)
- **SATA SSD**: `mq-deadline` (fair queuing for SATA command queue)

These are persisted via udev rules in `/etc/udev/rules.d/60-io-scheduler.rules`.

## Monitoring Disk Health

Check disk usage from Grafana (Docker Container Monitoring dashboard) or manually:

```bash
# Check mount usage
df -h /data/hot /data/warm

# Check OpenSearch index sizes
curl -s 'http://localhost:9200/_cat/indices?v&s=store.size:desc&h=index,store.size,pri.store.size'

# Check ISM policy status
curl -s 'http://localhost:9200/_plugins/_ism/explain/*' | jq '.[] | {index: .index, state: .info.message}'
```
