# Alert Enrichment Standard (Grafana + n8n + Discord)

> Standard for enriching SIEM alerts before delivery to notification channels.
> Ensures every alert carries enough context for triage without switching tabs.

---

## Problem

Default alert notifications forward mostly static annotation text from Grafana/n8n.
The message shows the alert name/severity but not enough event-level context (host, file path,
username, source IP, sample events). Analysts end up clicking through to dashboards for every alert.

## Design Principles

1. **Every alert must explain WHY it fired** — include the metric value that crossed the threshold.
2. **Every alert must identify WHAT is affected** — hostname, IP, VLAN, user when available.
3. **Every alert must include EVIDENCE** — top 3-5 matching events with timestamps.
4. **Every resolved alert must explain WHY it resolved** — not just "condition no longer met."
5. **Every alert must include LINKS** — Grafana panel URL and OpenSearch/Discover link.

---

## Required Context Fields

Every Discord/Matrix alert message should include these fields when available:

### For All Alerts
- **Trigger logic**: Rule query, threshold, and evaluation window
- **Affected asset**: Agent/hostname, IP, VLAN if known
- **Event identity**: Wazuh rule ID, rule level, rule groups
- **Investigation links**: Grafana panel URL and OpenSearch Discover link pre-filtered to the incident

### For Authentication Alerts
- **Actor/source**: Source IP, username, service (sshd/sudo/etc)
- **Fail count**: Number of failures in the evaluation window
- **Top source IPs**: Ranked by hit count
- **Top usernames**: Ranked by hit count

### For FIM (File Integrity Monitoring) Alerts
- **Event type**: Added / modified / deleted
- **File path**: Full path of changed file
- **File hash**: SHA256 old/new if available
- **Owner/permissions**: Before and after values

### For Network/IDS Alerts
- **Source/destination IPs**: With GeoIP/ASN if enriched
- **Signature**: Suricata SID, classification, severity
- **Protocol/ports**: Connection details
- **CrowdSec context**: If IP has a CrowdSec decision

---

## n8n Enrichment Model

For each incoming alert, n8n should enrich before posting to Discord:

1. **Parse** webhook payload (`alerts[]`, labels, annotations, values)
2. **Build query** from alert labels (rule group, rule ID, host, time range)
3. **Query** Wazuh/OpenSearch for top matching events
4. **Render** Discord embed with structured fields and evidence
5. **For resolved alerts**: include previous vs. current metric value and clear resolve reason

---

## Discord Embed Examples

### Authentication Failure Burst

| Field | Value |
|-------|-------|
| Why fired | `auth_failed_count=27 (>20) over 5m` |
| Likely cause | `Repeated SSH failures from external IP against root` |
| Affected hosts | `host-a, host-b` |
| Top source IPs | `203.0.113.44 (19), 198.51.100.12 (8)` |
| Top usernames | `root (21), admin (6)` |
| Evidence | 3 sample events with timestamp + host + srcip + user |

### Critical File Integrity Change

| Field | Value |
|-------|-------|
| Why fired | `syscheck level>=7 events=12 over 10m` |
| Likely cause | `Package update changed binaries under /usr/bin` |
| Affected hosts | `siem-server` |
| Changed files | `/etc/ssh/sshd_config (modified), /usr/bin/curl (modified)` |
| Ownership/perm changes | `root:root, 0644->0600` |
| Evidence | 3 sample FIM events with sha256 old/new if present |

---

## Resolved Alert Format

Resolved messages must not be generic. Include:

| Field | Purpose |
|-------|---------|
| **Why resolved** | Metric value now below threshold (e.g., `auth_failed_count now 4 (<=20) for 2 evaluations`) |
| **Recovery window** | Duration with no threshold violation (e.g., `no violation for last 10m`) |
| **Residual risk** | Whether the source is still active at low volume, or fully stopped |
| **Incident duration** | First-fire timestamp to resolve timestamp |

---

## Implementation Checklist

- [ ] Add dynamic labels/annotations in Grafana rules (host, rule ID/group, threshold, window)
- [ ] Add n8n enrichment query step to Wazuh/OpenSearch
- [ ] Include top evidence events in Discord payload
- [ ] Add explicit resolved-cause field using metric comparison
- [ ] Add direct dashboard/drilldown links
- [ ] Test with synthetic auth burst + controlled FIM file touch
- [ ] Add Matrix delivery in parallel with Discord (Phase 2A)
