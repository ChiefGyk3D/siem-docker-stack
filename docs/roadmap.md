# Roadmap

This roadmap replaces the previous phase plan. Historical phase details remain available in Git history.

## Legacy Phase Status

| Phase | Status | Basis |
|---|---|---|
| 0 Noise reduction | PARTIAL | local_rules.xml exists; thresholds and tuning not verified |
| 0B VirusTotal cache | DONE | shipped, issue #3 closed |
| 1 JumpCloud | DONE | decoders, rules, dashboard, docs present |
| 1 add-on CrowdSec | DONE | decoders, rules, dashboard, n8n enrichment present |
| 1C Twingate | DONE | rules, dashboards, scrape targets present; one n8n alert box stale |
| 1B Doppler | PARTIAL | secrets library and design doc exist; no wrapper script or doppler doc |
| 2A Matrix | PARTIAL | Grafana contact point examples exist; n8n Matrix nodes not done |
| 2B Remediation | NOT STARTED | no workflows or artifacts |
| 2C Ollama triage | NOT STARTED | no service or workflow |
| 3 Utility automations | PARTIAL | expiry watch and weekly digest exist; the rest not seen |
| 4 Velociraptor | NOT STARTED | no artifacts |
| 5 MISP | NOT STARTED | no artifacts |
| 6 SOC enhancement | NOT STARTED | no artifacts |
| 7 Zeek | NOT STARTED | hardware-blocked |
| F1 OpenSearch security | PARTIAL | configs and init script present; enabled-in-compose not verified |
| F2 Doppler | PARTIAL | same as 1B |
| F3 Alertmanager | DONE | service and rules present |
| F4 Snapshots and restore | PARTIAL | main cluster done; Wazuh indexer snapshots open |
| F5 n8n in repo | PARTIAL | example compose only; not a compose service |
| F6 Noise reduction | PARTIAL | same as Phase 0 |
| F7 CI | PARTIAL | CI exists; shellcheck is non-blocking |

Statuses reflect repository evidence summarized in the final plan. They do not preserve the obsolete phase sequencing or duplicate its detailed task lists. Consult Git history for the retired roadmap text.

## Final Re-baselined Plan

The final execution order is:

`R0 -> R1a -> R2 -> R1b -> R3 -> R5 -> R4 -> R6 -> R7 -> R8 -> R9 -> R10`

| Phase | Goal | Depends on | Effort | Cost gates | Primary risk |
|---|---|---|---:|---|---|
| R0 | Reconcile documentation with the repository tree and attach every issue to an epic. | None | S | None | Incorrect status or ownership data could distort later priorities. |
| R1a | Confirm OpenSearch security is enabled and make CI blocking, including shellcheck and secret scanning. | R0 | M | Private-repository CI minutes, if applicable | A nominally green workflow could permit unverified changes. |
| R2 | Add a Doppler dev-first secrets wrapper and supporting documentation. | R1a | M | Doppler tier requires owner approval | Secret handling could remain inconsistent or grant excessive access. |
| R1b | Add Wazuh indexer snapshots and prove restoration on a documented cadence. | R2 | M | Off-site storage and egress require owner approval | Backups could exist without being restorable. |
| R3 | Add rule fixtures and tests, per-source silence alerts, ATT&CK coverage mapping and noise tuning. | R1b | L | Private-repository CI minutes, if applicable | Untested detections or excessive noise could hide real incidents. |
| R5 | Add Wazuh vulnerability detection, SCA and CIS posture checks, plus asset and agent fleet views. | R3 | L | None identified | Incomplete inventory could make posture results misleading. |
| R4 | Run n8n reproducibly in Compose and deliver notifications through Matrix. Start monitor-only with no response nodes. | R5 | M | None identified | Workflow automation could become an unintended response path. |
| R6 | Build the constrained AI security track, beginning alert-only. | R4 | XL | Any paid model API requires fresh owner approval; local Ollama is the default; private-repository CI minutes may apply | Gateway bypass, sensitive-data exposure, classifier evasion or unsafe availability behavior |
| R7 | Add remediation and local-LLM triage with human approval for destructive actions. | R6 | L | Any paid model API requires fresh owner approval; local Ollama is the default | Automated action could affect the wrong identity, route or credential. |
| R8 | Integrate MISP, then Velociraptor. | R7 | XL | Any service, storage or infrastructure spend requires owner approval | Added integrations increase trust boundaries and operational load. |
| R9 | Add case management. | R8 | L | Any selected paid service requires owner approval | Case records could expose sensitive operational data or diverge from alert state. |
| R10 | Add Zeek after the hardware gate is satisfied. | Hardware gate (owner decision) | L | Zeek hardware requires owner approval | Insufficient hardware could cause packet loss or destabilize monitoring. |

Nothing in this plan authorizes spending. Cost gates are:

| Cost gate | Approval requirement |
|---|---|
| Off-site snapshot storage | Owner approval for per-GB storage and egress charges |
| Doppler | Owner approval for the required tier |
| Model APIs | Fresh owner approval for every paid API; local Ollama remains the default |
| Zeek | Owner approval before hardware purchase or allocation |
| CI | Owner approval if private-repository CI minutes create a charge |

## R1a Completion Gate

R1a is complete only when default-branch protection is verified to require the head-SHA-pinned `CI green` check. Shellcheck and secret scanning must be mandatory dependencies of that gate. A deliberately failing pull request must prove the protection before R2 begins.

## Wazuh 5.0 Decision Gate

Hold Filebeat, agentless and Sigma-converter work until Wazuh 5.0 reaches general availability.

Before general availability, work is limited to vendor-neutral event schemas, threat cases, fixtures, policies, redaction tests and transport adapters. Wazuh-specific integration must remain behind a versioned adapter.

The 5.x plan assumes a fresh deployment rather than an in-place upgrade. Before implementation, the owner must decide what historical data will be retained, migrated, archived or allowed to expire. No 4.x custom decoder or index-mapping work should begin unless a time-boxed 4.x deployment specifically requires it.

## Verified Baseline

The baseline was verified on 2026-11-28. Version information was read through page extracts from the relevant project or vendor pages.

| Area | Verified baseline |
|---|---|
| Wazuh | 4.14.11 was the latest stable release. 5.0.0 was at rc2, with no general-availability release. |
| Wazuh 5.0 migration | No in-place upgrade from 4.x was inferred. Engine replaces `analysisd`; Wazuh Common Schema is ECS-derived and rejects unknown fields; Sigma support moves to indexer detectors; Filebeat and agentless support are removed; installation paths and API user names change; `authd` requires TLS 1.3. |
| OpenSearch | Major version 3.10 |
| Grafana | Major version 13 |
| n8n | Major version 2.x |
| Zeek | Major version 9 |
| Suricata | Major version 8 |
| Velociraptor | Version 0.77 |
| MISP | Version family 2.5.5x |
| AI guardrails | LLM Guard and Rebuff were archived. Active options included NeMo Guardrails, Guardrails AI, LiteLLM guardrails and Prompt Guard 2 under the Llama community license. |
| AI validation | garak and PyRIT were active validation options. |
| Repository | Phase F was mostly built. Alertmanager, OpenSearch snapshots and security configurations were present. Wazuh indexer snapshots, n8n as a Compose service, blocking shellcheck, the Doppler wrapper and related documentation remained open. |
| Planning data | Phases 2B, 2C, 4, 5, 6 and 7 had no artifacts. At review time, 42 of 88 open issues had no epic. |

Statements about unreleased Wazuh 5.0 behavior must be reverified at the decision gate.

## Tracking Issues

- Issue #266 is the epic, Roadmap 2027 refresh.
- Issue #267 is the assessment task that produced this plan and the AI security track design.

## Review Record

| Review | Result |
|---|---|
| Review tier | Daybreak cyber-program tier |
| Round 1 | No Critical findings; five High findings |
| Round 2 | One High finding |
| Round 3 | No Critical or High findings |
| Final disposition | All High findings were addressed in the final plan. No accepted residual risk is above Low. |
