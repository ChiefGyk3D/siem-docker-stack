# SIEM/SOAR/SOC/NOC Game Plan

**Updated:** 2026-08-29 · Cross-stack plan covering [siem-docker-stack](https://github.com/ChiefGyk3D/siem-docker-stack), [pfsense-siem-stack](https://github.com/ChiefGyk3D/pfsense-siem-stack), and [jumpcloud-wazuh-bridge](https://github.com/ChiefGyk3D/jumpcloud-wazuh-bridge).

This document is the strategy layer. [roadmap.md](roadmap.md) stays the detailed phase-by-phase build plan for this repo; the other repos carry their own `ROADMAP.md`. This file exists because an August 2026 full-stack review found that the biggest risks aren't missing features — they're foundation gaps that the feature phases (MISP, Velociraptor, Zeek, SOC platform) would inherit. Issue [#6](https://github.com/ChiefGyk3D/siem-docker-stack/issues/6) already says it: *"we need a stable foundation."* This plan defines what "stable foundation" means concretely.

---

## Where the stack stands

**Working and genuinely good:** the ingest data plane (Suricata/pfSense/syslog/Wazuh/JumpCloud/CrowdSec/Twingate into hot/warm OpenSearch with ISM lifecycle), the dashboard library, the VirusTotal cache (Phase 0B ✅), and the curated Suricata SID tuning. The engineering quality of the pipeline itself is solid.

**The gaps, in order of how much they'd hurt:**

1. **The SIEM can't defend itself.** OpenSearch runs with the security plugin disabled and ports published network-wide; InfluxDB auth is off; Grafana/Wazuh default credentials are baked into scripts and docs as the working path; Docker's published ports bypass UFW entirely, so the firewall rules are cosmetic for containerized services; Portainer exposes the Docker socket. Anyone on the LAN can read or delete the evidence a SIEM exists to preserve.
2. **Nobody gets told when it breaks.** Alert delivery depends on Grafana → n8n → Discord, with no independent Alertmanager path, no alert on "a log source went silent," no pipeline-health detection (Logstash backpressure, cluster RED, disk). A silent pipeline looks identical to a quiet network.
3. **A single disk failure is total evidence loss.** Zero replicas by design (fine for a homelab) but also zero OpenSearch snapshots, and backups cover configs but not data. There is no restore procedure at all.
4. **Some detections literally cannot fire.** Agent-disconnect alerts watch Wazuh rule 503 (agent *started*) instead of 504; the n8n SOAR deploy script posts placeholder datasource UIDs; the container-restart alert queries cAdvisor metrics with no cAdvisor deployed; the bridge repo's Wazuh ruleset had a decoder mismatch making all 15 rules dead. Detection content needs the same testing discipline as code.
5. **The SOAR layer isn't reproducible.** n8n — half the "SIEM/SOAR" name — exists only as workflow exports; no compose service, no documented macvlan setup. Docs describe the live deployment, not something a fresh clone can build.
6. **Duplicate/conflicting content across repos.** Two JumpCloud rulesets (100300s here… actually in the bridge repo, 120600s here) that would double-alert if both installed; two copies of the JumpCloud dashboard with the stale one clobbering the newer on deploy; env var names that differ between the bridge's code and this repo's docs; pfsense-siem-stack's bare-metal installer duplicating this stack's backend role.
7. **Docs drift.** Counts, ports, paths, and statuses that disagree with the tree and with each other. Nothing mechanical (CI) holds README claims to reality.

Many of the concrete instances above were fixed in the 2026-08 review PRs across all three repos. What follows is the plan for the rest.

---

## Revised execution order

The feature phases in [roadmap.md](roadmap.md) stay, but a foundation phase cuts in line. Rule of thumb: **don't add a new intel/DFIR/SOC component while the layer under it can't authenticate, alert, or restore.**

### Phase F — Foundation (before new components) 🔥

| # | Work | Why first |
|---|------|-----------|
| F1 | **Enable OpenSearch security plugin** on the main cluster (users/roles/TLS/audit log), enable InfluxDB auth, bind remaining internal ports to loopback, document `DOCKER-USER` firewalling | Everything else assumes the log store is trustworthy |
| F2 | **Doppler secrets migration** (Phase 1B, [#4](https://github.com/ChiefGyk3D/siem-docker-stack/issues/4)) + purge `changeme`/`SecretPassword` defaults from every script and doc | Kills the default-credential working path; prerequisite pattern for F1 credentials |
| F3 | **Independent alerting path**: Prometheus `rule_files` + Alertmanager for pipeline health (ingest-rate-zero per source, cluster health, ISM failures, Logstash backpressure, disk, n8n execution failures) | Grafana dying must not take alerting with it; "monitoring the monitoring" |
| F4 | **Snapshots + restore drill**: OpenSearch snapshot repo (`path.repo` → offsite/S3-compatible), scheduled snapshots for both clusters (main + Wazuh indexer), documented and *tested* restore | Converts "disk failure = total loss" into a bounded RPO |
| F5 | **Ship n8n in the repo**: compose service (or documented macvlan), clean workflow exports, credential bootstrap; settle the port-80-vs-5678 question in one place | Makes the SOAR half reproducible; unblocks Phase 2 work ([#1](https://github.com/ChiefGyk3D/siem-docker-stack/issues/1)) |
| F6 | **Phase 0 noise reduction** (already ranked #1 in roadmap.md, still a stub): thresholds, FIM suppressions, auth-failure grouping | Signal quality gates every SOAR/SOC phase; issue #6 depends on it |
| F7 | **CI everywhere**: compose config validation, `promtool check`, `logstash --config.test_and_exit`, shellcheck, dashboard-JSON datasource validation, README-claim link checks (this repo); keep the new lint workflows green in the other two repos | Every drift bug found in review was mechanically detectable |

### Then the feature phases (unchanged order, from roadmap.md)

Phase 2 SOAR workflows ([#1](https://github.com/ChiefGyk3D/siem-docker-stack/issues/1)) → Phase 3 Tier 1 automations → Phase 2C Ollama → Phase 2B auto-remediation → Phase 4 Velociraptor ([#2](https://github.com/ChiefGyk3D/siem-docker-stack/issues/2)) → Phase 5 MISP ([#5](https://github.com/ChiefGyk3D/siem-docker-stack/issues/5)) → Phase 6 SOC/IR platform ([#6](https://github.com/ChiefGyk3D/siem-docker-stack/issues/6)) → Phase 7 Zeek ([#7](https://github.com/ChiefGyk3D/siem-docker-stack/issues/7), hardware-blocked) → T-Pot honeypot ([#8](https://github.com/ChiefGyk3D/siem-docker-stack/issues/8), pairs naturally with MISP + auto-remediation).

---

## GitHub issue map

| Issue | Status | Plan |
|-------|--------|------|
| [#1](https://github.com/ChiefGyk3D/siem-docker-stack/issues/1) n8n workflows (Discord/Matrix) | Open | Blocked on F5 (reproducible n8n); alert-rule correctness fixes landed in review PR |
| [#2](https://github.com/ChiefGyk3D/siem-docker-stack/issues/2) Velociraptor | Open | After Phase F; n8n integration needs Phase 2 |
| [#3](https://github.com/ChiefGyk3D/siem-docker-stack/issues/3) VT caching | **Closed (completed)** | Shipped as Phase 0B (SQLite TTL cache in `wazuh/integrations/virustotal.py`) |
| [#4](https://github.com/ChiefGyk3D/siem-docker-stack/issues/4) Doppler | Open | Promoted to F2; the bridge repo already implements the Doppler pattern to copy |
| [#5](https://github.com/ChiefGyk3D/siem-docker-stack/issues/5) MISP | Open | After Phase F; feeds Wazuh + n8n enrichment; coordinate with pfSense threat-intel plans |
| [#6](https://github.com/ChiefGyk3D/siem-docker-stack/issues/6) SOC enhancement | Open | Its own precondition ("stable foundation") = Phase F + Phase 0; then DFIR-IRIS vs TheHive eval |
| [#7](https://github.com/ChiefGyk3D/siem-docker-stack/issues/7) Zeek | Open (hardware-blocked) | Unchanged; revisit when hardware lands |
| [#8](https://github.com/ChiefGyk3D/siem-docker-stack/issues/8) T-Pot honeypot | Open | Sequence after MISP (#5) so honeypot intel has somewhere to go; auto-blocking needs 2B guardrails |

---

## Cross-repo decisions (need an owner: you)

1. **JumpCloud detection ownership** — one ruleset must win. Recommendation: **this repo owns detections** (120600–120681, already documented in [detection-ownership.md](detection-ownership.md)); the bridge repo's `wazuh/` (100300s) gets deleted or clearly marked as the standalone-only alternative. Never install both. Same for the JumpCloud dashboard: one repo owns the JSON (recommendation: this repo's newer copy; stop `deploy-dashboards.py` importing the bridge's stale copy — fixed in review PR).
2. **pfsense-siem-stack positioning** — its `install.sh` builds a bare-metal OpenSearch/Logstash/Grafana stack that duplicates this repo's backend. Recommendation: this stack is the canonical backend; pfsense-siem-stack focuses on the pfSense side (forwarder, Telegraf plugins, SID tuning, dashboards) with its installer kept as a standalone alternative. Its ROADMAP.md now says this.
3. **Env-var contract with the bridge** — the bridge's actual names (`JUMPCLOUD_OUTPUT_FILE`, `JUMPCLOUD_STATE_FILE`, `JUMPCLOUD_POLL_SECONDS`) are now reflected here; any future rename happens in the bridge first, docs second.
4. **Roadmap vs deployment journal** — roadmap.md mixes reproducible plans with dated, IP-specific deployment logs (Phase 1C). Fine for a personal stack; if outside users are an audience, split the journal into a private ops log and keep the repo roadmap parameterized.

---

## Operating principles going forward

- **Detections are code.** A new rule/alert ships with the query verified against a real event (or a replayed fixture — see `scripts/09-test-crowdsec-pfsense-ingest.sh`), a named owner doc entry, and the right rule IDs. No placeholder UIDs, ever.
- **One owner per artifact.** Every dashboard, ruleset, and env var has exactly one home repo; the others link to it.
- **Docs describe the tree, not memories.** Counts and paths in READMEs must be CI-checkable or omitted.
- **New component checklist**: authenticated? TLS? retention policy for its indices? health alert if it stops? in compose (reproducible)? secrets from Doppler? Then it can merge.
