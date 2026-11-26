# Detection Ownership and Workflow Reference

> Purpose: Map detections to owners, workflows, and response expectations.
>
> Alert payload/detail standard: `docs/alert-enrichment-standard.md`.

---

## Grafana Alert Rules

### SIEM Folder — Wazuh/OpenSearch-Based

| Detection Name | Datasource | Query Summary | Automation Level | Notes |
|---|---|---|---|---|
| CrowdSec Alert Detected | Wazuh-Alerts | `rule.groups:"crowdsec"` count > 0 in 5m | SOAR (n8n CrowdSec Enrichment) | execErrState=OK |
| Docker Security Event | Wazuh-Alerts | `rule.groups:"docker"` AND `rule.level>=8` count > 0 in 5m | Alert only | — |
| JumpCloud Security Alert | Wazuh-Alerts | `rule.groups:"jumpcloud"` AND `rule.level>=7` count > 0 in 5m | Alert only | — |
| Office 365 Security Alert | Wazuh-Alerts | `rule.groups:"office365"` AND `rule.level>=8` count > 0 in 5m | Alert only | — |
| Suricata High-Severity Alert | OpenSearch-Suricata | `alert.severity<=2` count > 3 in 5m, for 5m | SOAR (n8n Grafana Alert Router) | Threshold raised from >0 to >3, added `for: 5m` to reduce noise |
| Wazuh Agent Disconnected | Wazuh-Alerts | `rule.id:"504"` count > 0 in 5m | Alert only | Exclude known-offline hosts in your environment |
| Wazuh Critical Alert (Level 12+) | Wazuh-Alerts | `rule.level>=12` count > 0 in 5m | SOAR (n8n Wazuh Alert Triage) | — |
| Wazuh High Alert (Level 10-11) | Wazuh-Alerts | `rule.level>=10` AND `rule.level<=11` count > 0 in 5m | Alert only | — |

### SIEM Alerts Folder — Prometheus Infrastructure

| Detection Name | Datasource | Query Summary | noDataState | Notes |
|---|---|---|---|---|
| Host Down | Prometheus | `up{job=~"node_exporter\|windows_exporter"} == 0` | NoData (intentional — no data means host unreachable) | Alerts if any monitored host stops responding |
| High CPU Usage | Prometheus | CPU usage > 90% for 5m | OK | — |
| High Memory Usage | Prometheus | Memory usage > 90% for 5m | OK | — |
| Disk Usage Critical | Prometheus | Disk usage > 90% | OK | — |
| Network Interface Errors | Prometheus | Interface errors > 100 in 5m | OK | — |
| Systemd Service Failed | Prometheus | `node_systemd_unit_state{state="failed"} == 1` | OK | Exclude known-transient services |

### All Rules — Common Settings
- **execErrState**: OK (all rules) — execution errors do NOT trigger alerts
- **Notification**: Discord (primary), n8n SOAR webhooks (for high-severity)
- **Evaluation interval**: 5m (all rules)


### Drift known 2026-11-26

> **Do not trust the tables above as the deployed state.** This document and `scripts/deploy-grafana-alerts.py` disagree, and no rule was changed to hide it. The live Grafana export is the source of truth. Reconciling this document, the script and `docs/roadmap.md` against that export is tracked under issue #225.

| Item | This document | Script or other file |
|---|---|---|
| Execution error state | line 36: `execErrState` is OK for all rules (and line 15 for CrowdSec) | `scripts/deploy-grafana-alerts.py` lines 115 and 189: `"execErrState": "Error"` for every rule it deploys |
| Evaluation interval | line 38: 5m for all rules | `scripts/deploy-grafana-alerts.py` line 144: query `interval` is `"auto"`; the script sets no rule-group evaluation interval |
| Rule names | lines 15-22 and 28-33: CrowdSec Alert Detected, Docker Security Event, JumpCloud Security Alert, Office 365 Security Alert, Suricata High-Severity Alert, Wazuh Critical Alert (Level 12+), Wazuh High Alert (Level 10-11), Host Down, High CPU Usage, High Memory Usage, Disk Usage Critical, Network Interface Errors, Systemd Service Failed | script lines 253-386: Wazuh Agent Disconnected, High-Severity Alert Burst, Authentication Failure Burst, Critical File Integrity Change, Suricata Critical Alert, pfSense Firewall Block Surge, CrowdSec Ban Decision Surge, Docker Container Restart Loop. Only Wazuh Agent Disconnected matches by name |
| Suricata | line 19: `alert.severity<=2` count > 3 in 5m, for 5m | script lines 326-331: `alert.severity:1`, window 300s, threshold 0 |
| Wazuh Agent Disconnected | line 20: count > 0 in 5m | script lines 257-268: window 600s, threshold 0, `for` 5m |
| pfSense block surge | not listed | script line 351: threshold 1000; `docs/roadmap.md` line 22 lists the "Current" value as >500 and the "Suggested" as >1000 |
| Folders | lines 11 and 26: "SIEM" and "SIEM Alerts" | script groups: "SIEM — Wazuh", "SIEM — IDS", "SIEM — Firewall", "SIEM — CrowdSec", "SIEM — Docker" (rule groups; the folder comes from `ALERT_FOLDER_UID`) |

---

## n8n SOAR Workflows

| Workflow Name | Trigger | Purpose | Status |
|---|---|---|---|
| Grafana SOAR Alert Router | Grafana webhook | Routes Grafana alert notifications to appropriate response workflows | ✅ Active |
| Wazuh SOAR Alert Triage & Routing | Wazuh webhook | Triages Wazuh alerts and routes based on rule level/groups | ✅ Active |
| CrowdSec SOAR Alert Enrichment | Grafana alert (CrowdSec rule) | Enriches CrowdSec detections with IP reputation data | ✅ Active |

---

## Wazuh Custom Rules & Decoders

| Rule File | Rule IDs | Purpose | Notes |
|---|---|---|---|
| JumpCloud Rules (`jumpcloud_rules.xml`) | 120600-120681 | JumpCloud LDAP auth events | 17 rules: auth success/failure, account changes, admin events |
| CrowdSec Rules (`crowdsec_rules.xml`) | 120500-120503 | CrowdSec alerts, bans, credential abuse, lifecycle | Correlates with CrowdSec bouncer decisions |
| Local Rules (`local_rules.xml`) | Various | Custom overrides | Customize for your environment |
| JumpCloud Decoder (`jumpcloud_decoders.xml`) | — | JSON decoder for JumpCloud bridge events | Uses `decoded_as: json` with field match |
| CrowdSec Decoder (`crowdsec_decoders.xml`) | — | JSON decoder for CrowdSec events | Parses decision type, IP, scenario |

---

## VirusTotal Integration

The Wazuh manager includes a built-in VirusTotal integration that triggers on `syscheck` (FIM) alerts:

| Component | Location | Purpose |
|---|---|---|
| Integration script | `/var/ossec/integrations/virustotal.py` | Queries VT API for file hashes from FIM events |
| Cache layer | `/var/ossec/integrations/cache/vt_cache.db` | SQLite cache — reduces API calls with verdict-based TTL |
| Configuration | `ossec.conf` `<integration>` block | API key, trigger group (syscheck), alert format |

**Cache Architecture:** See `docs/roadmap.md` Phase 0B for details on TTL per verdict, upgrade safety,
and monitoring commands.

---

## Notification Destinations

| Severity | Discord | Matrix | n8n SOAR | Notes |
|---|---|---|---|---|
| Informational | No | No | No | Not alerted |
| Low | No | No | No | Not alerted |
| Medium | Yes | Planned | No | Discord-only for Wazuh level 7-9, infra warnings |
| High | Yes | Planned | Yes | Discord + n8n triage for Wazuh level 10-11, Suricata sev 1-2 |
| Critical | Yes | Planned | Yes | Discord + n8n full response for Wazuh level 12+, CrowdSec |

---

## Response Guardrails

- Do not auto-disable admin or production accounts from low-confidence detections.
- Do not auto-quarantine critical infrastructure (firewall, SIEM, NAS).
- Do not let honeypot-only events trigger destructive changes.
- Prefer temporary and reversible controls first.
- Always log workflow actions and expirations.
- Exclude known-offline hosts from agent-disconnected alerts.
- Exclude known-transient services from systemd-failed alerts.
