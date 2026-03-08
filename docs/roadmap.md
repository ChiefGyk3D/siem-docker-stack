# SIEM Stack Roadmap

Phased plan for Wazuh noise reduction, JumpCloud IdP integration, SOAR expansion, and N8N automations.

---

## Phase 0 — Wazuh Alert Noise Reduction

**Goal:** Reduce alert fatigue without missing real threats.

### Tuning Points

| What | Current | Suggested | Why |
|------|---------|-----------|-----|
| `integratord` level threshold | `<level>7</level>` | `<level>8</level>` or keep 7 with N8N filtering | Level 7 catches a lot of informational FIM/syscheck noise |
| pfSense block surge threshold | >500 blocks/5m | >1000 blocks/5m | Active networks easily hit 500 from routine scans |
| Auth failure burst threshold | >20 failures/5m | >40 failures/5m | Brute-force scanners generate bursts quickly |
| High-severity alert burst | >50 level≥10/5m | >100 level≥10/5m | Reduces noise from cascading events |
| FIM (syscheck) alerts | Any level≥7 syscheck | Add path exclusions in Wazuh `local_rules.xml` for known-noisy paths (`/var/log`, `/tmp`, package manager dirs) |

### Actions

1. **Create `config/wazuh/local_rules.xml`** in the repo — override noisy default rules:
   - Suppress or reduce level for routine FIM paths (package updates, log rotation)
   - Suppress pfSense routine block noise (rule 87701) from known scanner sources
   - Add frequency-based composite rules for auth failures (alert on pattern, not each event)
2. **Adjust Grafana alert thresholds** in `deploy-grafana-alerts.py` and `deploy-n8n-soar.sh`
3. **Add Wazuh exclusion lists** — document which rule IDs to tune for common noisy environments
4. **N8N dedup/batching** — modify Wazuh triage workflow to batch similar alerts within a time window instead of firing per-event

### Deliverables
- `config/wazuh/local_rules.xml` — custom rule overrides
- Updated thresholds in deploy scripts
- Documentation in `docs/n8n-soar.md` for tuning guidance

---

## Phase 1 — JumpCloud IdP Integration

**Goal:** Ingest JumpCloud identity events into Wazuh for centralized auth monitoring.

### Research Summary

The existing project [wazuh-jumpcloud-integration](https://github.com/lbrictson/wazuh-jumpcloud-integration) is a Go binary that:
- Polls JumpCloud Directory Insights API every 5 minutes
- Writes JSON events to a log file Wazuh reads via `<localfile>`
- Includes 10 basic Wazuh rules (IDs 866000–866010) for login success/fail, user create/delete
- Covers Directory, System, SSO, LDAP, RADIUS, and Admin events

**Concerns:**
- Low maintenance (last commit ~2 years ago, v0.0.4)
- Known config corruption bug (issue #9)
- Only 10 Wazuh rules — no coverage for SSO failures, LDAP, RADIUS, group/policy changes
- No log rotation, no retry logic, plaintext API key, x86_64 only
- Read-only JumpCloud API key is sufficient (Directory Insights read access)

### Approach Options

**Option A: Use the existing project as-is + extend**
- Deploy the Go binary on Wazuh manager
- Add our own rules for gaps (SSO failures, RADIUS, group changes, device compliance)
- Add logrotate config
- Wrap the API key in a file permissions guard or Docker secret

**Option B: Rewrite the poller in Python**
- Python is already used throughout the stack
- Simpler to maintain, no Go toolchain needed
- Can add pagination, retry logic, better error handling
- Could run as N8N workflow (scheduled HTTP poll → write to Wazuh API or log)
- More portable (no binary build)

**Recommended: Option B** — Write a Python JumpCloud poller that:
1. Calls JumpCloud Directory Insights API
2. Writes events to Wazuh `active-responses.log` or a `<localfile>` JSON path
3. Runs as an N8N scheduled workflow OR cron/systemd timer
4. Ships with comprehensive Wazuh rules (extending the original 10)

### Dashboards Needed

1. **JumpCloud Security Dashboard** (Grafana)
   - Login success/failure rates (portal, SSO, system agent)
   - User provisioning timeline (creates, deletes, modifications)
   - MFA status and enforcement
   - SSO application usage
   - LDAP/RADIUS authentication
   - GeoIP map of login locations
   - Device compliance status

2. **SIEM Overview update** — Add a JumpCloud panel row to the existing SIEM Overview dashboard:
   - JumpCloud auth failures count
   - JumpCloud user changes count
   - Recent JumpCloud events table
   - (Keep it small — not everyone uses JumpCloud)

### Environment Variables

```bash
# JumpCloud IdP (Optional)
JUMPCLOUD_API_KEY=your-read-only-api-key
JUMPCLOUD_ORG_ID=             # Only needed for multi-tenant JumpCloud orgs
JUMPCLOUD_POLL_INTERVAL=300   # Seconds between polls (default: 5 minutes)
```

### Deliverables
- `scripts/jumpcloud-poller.py` — Python poller script
- `config/wazuh/jumpcloud_rules.xml` — Extended Wazuh rules (beyond the original 10)
- `config/wazuh/jumpcloud_decoders.xml` — Custom decoder if needed
- `dashboards/jumpcloud_security.json` — Grafana dashboard
- Updated SIEM Overview dashboard with optional JumpCloud row
- `n8n/jumpcloud-poller.json` — Optional N8N scheduled workflow version
- Documentation in `docs/jumpcloud.md`

### Phase 1 Add-On — CrowdSec ✅ DEPLOYED

**Status:** CrowdSec v1.7.6 installed and running on pfSense (2026-03-08).

**Deployment:**
- **pfSense** (`PFSENSE_HOST`): Full "Large" setup — Remediation bouncer + Log Processor + Local API (port 8088)
- **Collections installed:** pfsense, pfsense-gui, pf, sshd, nginx, http-cve, base-http-scenarios, freebsd, whitelist-good-actors (9 collections, 774 scenarios)
- **pf tables:** `crowdsec_blacklists` (IPv4) + `crowdsec6_blacklists` (IPv6) active on all interfaces
- **Logging:** `log_media: syslog` — CrowdSec events flow via pfSense remote syslog → SIEM syslog-ng → Logstash → `crowdsec-events-*` index
- **pf rule logging:** Enabled — CrowdSec blocks appear in filter.log → `pfsense-filterlog-*` index
- **Metrics:** Prometheus endpoint at 127.0.0.1:6060

**SIEM Integration (verified):**
- Logstash `02-syslog.conf`: Routes `program =~ /^crowdsec/` to `crowdsec-events-*` index
- Wazuh decoders: `crowdsec_decoders.xml` (crowdsec-json, crowdsec-alert, crowdsec-decision)
- Wazuh rules: `crowdsec_rules.xml` (IDs 120500-120503: alerts, bans, credential abuse, lifecycle)
- Grafana dashboard: `crowdsec_overview.json`
- Smoketest: `scripts/08-crowdsec-smoketest.sh`

**Remaining:**
- [x] Register with CrowdSec Console (CAPI) for community blocklists
- [x] N8N branch for CrowdSec events (high-confidence decision notifications)
- [ ] CrowdSec Console web enrollment (optional — `cscli console enroll <key>`)
- [ ] Capstone docs: architecture diagram, baseline metrics

**CAPI Status (2026-03-08):**
- Registered with Central API — sharing signals and pulling community blocklists
- All console options enabled: custom ✅, manual ✅, tainted ✅, context ✅

**N8N Integration (2026-03-08):**
- Workflow: `CrowdSec SOAR — Alert Enrichment` (n8n/crowdsec-alert-enrichment.json)
- Webhook: `/crowdsec-alerts` — triggered by Grafana `source=crowdsec` alerts
- Enrichment: queries OpenSearch `crowdsec-events-*` for recent ban decisions, banned IPs, programs
- Discord: sends enriched embed with IP list, ban count, program breakdown
- Grafana contact point: `N8N-CrowdSec` → `http://n8n/webhook/crowdsec-alerts`
- Notification route: `source="crowdsec"` → N8N-CrowdSec (continue=true, also goes to Discord-SIEM)

---

## Phase 2 — SOAR Workflow Expansion

**Goal:** Expand N8N from alerting-only to multi-channel notifications + automated remediation + LLM-assisted analysis.

### 2A: Multi-Channel Alert Delivery

Currently: Discord only. Add Matrix as a second notification target.

**Matrix Integration:**
- N8N has a built-in Matrix node, or use HTTP Request to the Matrix Client-Server API
- Need: Matrix homeserver URL, access token, room ID (already in `.env.example` template)
- Create a dedicated Matrix bot account on your server
- Dual-post: every Discord alert also goes to Matrix (or configurable per severity)

**Implementation:**
- Fork existing Grafana Alert Router → add Matrix HTTP Request nodes in parallel with Discord
- Fork existing Wazuh Triage → add Matrix nodes for critical/high severity
- Add env vars: `MATRIX_HOMESERVER`, `MATRIX_ACCESS_TOKEN`, `MATRIX_ROOM_ID`

**New workflows:**
| Workflow | Trigger | Channels |
|----------|---------|----------|
| `grafana-alert-router.json` (updated) | Grafana webhook | Discord + Matrix |
| `wazuh-alert-triage.json` (updated) | Wazuh integratord | Discord + Matrix |

### 2B: Automated Remediation Actions

Safe, reversible actions N8N can perform:

| Trigger | Action | Risk | Method |
|---------|--------|------|--------|
| Container restart loop (3+ in 10m) | Stop container, notify | Low | SSH/Docker API |
| Brute-force auth burst | Add source IP to pfSense alias blocklist | Medium | pfSense API |
| Wazuh agent disconnected | Attempt SSH check + restart ossec-agentd | Low | SSH command |
| High-severity Wazuh alert | Create incident ticket/log entry | None | Local DB/file |
| Certificate expiring (<7 days) | Trigger cert renewal, notify | Low | certbot/ACME |

**Safety model:** LLM proposes → rules verify → N8N executes → human approves for anything destructive.

For the pfSense blocklist action:
- Use pfSense REST API to add IP to an alias
- Auto-expire after configurable time (1h/24h/7d based on severity)
- Always notify before and after
- Never permanent-block without human approval

### 2C: Ollama/LLM-Assisted Analysis

**Prerequisites:** Ollama server accessible from N8N container (network route or Docker network).

**LLM use cases (judgment-lite, safe):**

| Use Case | Input | LLM Task | Output |
|----------|-------|----------|--------|
| Alert summary | Raw Wazuh JSON | Summarize in plain English | Discord/Matrix message |
| False positive scoring | Alert + context | "Likely FP / suspicious / urgent" | Severity label |
| Log translation | Ugly log line | Human-readable explanation | Enriched alert |
| Incident timeline | Multiple related alerts | Chronological narrative | Markdown summary |
| Runbook suggestion | Alert type + labels | Match to remediation steps | Action suggestions |

**Architecture:**
```
Wazuh alert → N8N webhook → Enrich (GeoIP, asset lookup)
                          → Ollama HTTP Request (summarize/classify)
                          → Route by classification
                          → Discord + Matrix + optional remediation
```

**N8N → Ollama integration:** Simple HTTP Request to `http://ollama:11434/api/generate` with:
```json
{
  "model": "llama3.2",
  "prompt": "Summarize this security alert for a SOC analyst: <alert JSON>",
  "stream": false
}
```

### Deliverables
- Updated `grafana-alert-router.json` with Matrix nodes
- Updated `wazuh-alert-triage.json` with Matrix + LLM enrichment
- `n8n/wazuh-remediation.json` — Automated response workflow
- `n8n/pfsense-auto-block.json` — pfSense blocklist automation
- LLM integration documentation
- Updated `.env.example` with Ollama and Matrix variables

---

## Phase 3 — N8N Utility Automations

**Goal:** Day-to-day homelab management workflows. Picked from [ideas.md](../n8n/ideas.md) — easy wins first.

### Tier 1: Easy Wins (rule-based, no LLM needed)

| # | Workflow | Trigger | What It Does | ideas.md ref |
|---|----------|---------|--------------|--------------|
| 1 | **Daily Homelab Health Brief** | Cron (7 AM) | Collect CPU/RAM/disk/temps/UPS/container health/uptime → single Discord+Matrix post | #11 |
| 2 | **Docker Crash Loop Detector** | N8N webhook from Grafana rule | Grab container name, exit code, recent logs → summarize cause → notify | #13 |
| 3 | **Certificate Expiration Watcher** | Cron (daily) | Scan certs, notify at 30/14/7/3 days with renewal steps | #8 |
| 4 | **Backup Verification** | Cron (after backup window) | Confirm backup job status, file count, optional test restore → report | #14 |
| 5 | **Internet Outage Timeline** | WAN ping monitor | Record outage start, test alternate paths, log duration, post timeline on recovery | #15 |
| 6 | **UPS/Power Event Handler** | UPS webhook/SNMP | Announce outage, snapshot metrics, graceful shutdown if low → restoration summary | #16 |
| 7 | **GitHub Release Announcer** | GitHub webhook | New release/tag → changelog summary → Discord+Matrix+Mastodon+Bluesky | #61 |

### Tier 2: Medium Complexity (some enrichment or multi-source)

| # | Workflow | Trigger | What It Does | ideas.md ref |
|---|----------|---------|--------------|--------------|
| 8 | **"Was This Just Me?" Login Check** | Wazuh auth alert | Check source IP against known IPs/VPN/devices/schedule → suppress or escalate | #4 |
| 9 | **pfSense Repeated Offender Blocker** | Wazuh alert burst | Count hits from same source, auto-block alias + auto-expire | #3 |
| 10 | **Asset Drift Detection** | Cron (weekly) | Query hosts for packages/ports/images/kernel → diff → report changes | #7 |
| 11 | **Multi-Signal Anomaly Detector** | Multiple Grafana alerts | High CPU + disk IO + packet loss + log spike together = escalate | #12 |
| 12 | **VLAN/Service Exposure Audit** | Cron (weekly) | Verify exposed ports match design, alert on wrong-network exposure | #20 |

### Tier 3: LLM-Enhanced (requires Ollama)

| # | Workflow | Input | LLM Does | ideas.md ref |
|---|----------|-------|----------|--------------|
| 13 | **Log-to-English Translator** | Ugly log lines | Plain English summary + severity + next step | #21 |
| 14 | **Alert Dedup & Clustering** | Batch of similar alerts | Cluster → single incident summary | #22 |
| 15 | **Config Diff Explainer** | Git diff or file compare | Human-readable explanation of what changed | #24 |
| 16 | **Weekly Executive Summary** | All week's alerts/metrics | CISO-style homelab report | #74 |
| 17 | **Incident Timeline Writer** | Multiple related alerts | Chronological narrative + root cause hypothesis | #27 |
| 18 | **SOC Analyst for Homelab** | Enriched alerts | Intake → enrichment → scoring → case → postmortem | #72 |

### Tier 4: Content & Social (lower priority for SIEM repo)

| # | Workflow | ideas.md ref |
|---|----------|--------------|
| 19 | YouTube publish → cross-post pipeline | #31 |
| 20 | Stream live → multi-platform announcement | #32 |
| 21 | Incident-to-content pipeline | #70 |
| 22 | Community question clustering | #42 |

---

## Environment Variables to Add

These need to go in `.env.example` as the phases roll out:

```bash
# ── N8N Automation Engine ─────────────────────────────────────────────────────
# N8N_BASE=http://172.20.0.16:80
# N8N_API_KEY=your-n8n-api-key

# ── Ollama / LLM Server ──────────────────────────────────────────────────────
# OLLAMA_BASE_URL=http://ollama:11434
# OLLAMA_MODEL=llama3.2

# ── JumpCloud IdP (Optional) ─────────────────────────────────────────────────
# JUMPCLOUD_API_KEY=your-read-only-api-key
# JUMPCLOUD_ORG_ID=
# JUMPCLOUD_POLL_INTERVAL=300
```

---

## Suggested Execution Order

Working through this in priority order:

1. **Phase 0** — Tune Wazuh noise (quick, high-value, unblocks everything else)
2. **Phase 2A** — Add Matrix to existing workflows (quick win, already have Discord working)
3. **Phase 3 Tier 1 #1** — Daily Homelab Health Brief (high value, no dependencies)
4. **Phase 1** — JumpCloud integration (needs API key, builds on tuned alerting)
5. **Phase 2C** — Ollama integration (needs network route, enables Tier 3 workflows)
6. **Phase 2B** — Automated remediation (needs confidence in alerting quality first)
7. **Phase 3 Tier 2–3** — Advanced automations (build on everything above)
8. **Phase 3 Tier 4** — Content/social workflows (nice-to-have, independent)

---

## Dependency Graph

```
Phase 0 (Noise Reduction)
  │
  ├──► Phase 2A (Matrix alerts) ──► Phase 2B (Remediation)
  │                                      │
  │                                      ▼
  ├──► Phase 1 (JumpCloud) ───────► Dashboard + Rules
  │
  └──► Phase 3 Tier 1 (Health Brief, Cert Watch, etc.)
              │
              ▼
       Phase 2C (Ollama) ──► Phase 3 Tier 3 (LLM workflows)
```
