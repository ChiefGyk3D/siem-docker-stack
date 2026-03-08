# CrowdSec Phase 1 Integration

This document defines the CrowdSec integration model for this repository.

Primary model: **pfSense-hosted CrowdSec** (recommended).
Secondary model: **local Docker CrowdSec** for lab testing only.

## Goals

- Reduce alert fatigue by converting repeated low-value events into high-confidence decisions.
- Feed CrowdSec alerts/decisions into Wazuh/OpenSearch and Grafana.
- Keep rollout reversible.

## Files Added

- `docker/crowdsec/acquis.yaml`
- `wazuh/crowdsec_decoders.xml`
- `wazuh/crowdsec_rules.xml`
- `scripts/08-crowdsec-smoketest.sh`

## Recommended Deployment (pfSense-first)

1. Install and configure CrowdSec on pfSense.
2. Enable remediation and log processor (and Local API when suitable).
3. Validate bans/decisions on pfSense.
4. Forward CrowdSec-relevant logs/events into SIEM ingestion.
5. Use Wazuh + Grafana + N8N for analytics and notifications.

See pfSense-side runbook: `pfsense_siem_stack/docs/crowdsec-phase1.md`.

## Optional Local Lab Mode

Use this only for local testing when pfSense integration is not yet available.

```bash
cd /opt/siem
docker compose -f docker-compose.yml --profile crowdsec up -d crowdsec
```

## Wazuh Integration

1. Copy decoders and rules to Wazuh manager local config path.
2. Include them from Wazuh `ossec.conf` local files/rules section.
3. Restart Wazuh manager and confirm no parser errors.

Example checks:

```bash
docker logs wazuh-manager --tail 200
```

## pfSense CrowdSec Parser Path (Logstash)

`docker/logstash/pipeline/02-syslog.conf` includes a CrowdSec normalization branch for pfSense logs:

- Detects `program` values like `crowdsec` and `crowdsec-firewall-bouncer`
- Parses JSON payloads in `message` into `crowdsec.*`
- Parses fallback key/value messages (`action=... scenario=...`) into `crowdsec.*`
- Promotes `crowdsec.source_ip` (or `crowdsec.value`) into `source.ip`
- Routes to `crowdsec-events-*` index

## Replay Test for pfSense Fixtures

Use the fixture replay script to validate parser behavior end-to-end:

```bash
bash scripts/09-test-crowdsec-pfsense-ingest.sh
```

Fixture source:

- `tests/fixtures/crowdsec/pfsense-rfc5424.log`

## Grafana Panels (Phase 1)

Add these to a new `CrowdSec Overview` dashboard:

- Top scenarios (count by scenario)
- Top source IPs with decisions
- Active decisions by action
- Decision TTL expirations (next 24h)

## Rollback

- If using pfSense-first model:
  - disable bouncer/enforcement in pfSense CrowdSec UI first;
  - keep event forwarding enabled for analysis if needed.

- If using local lab mode:

```bash
docker compose -f docker-compose.yml --profile crowdsec stop crowdsec
```

- Remove CrowdSec decoder/rule includes and restart Wazuh manager.

## Notes

- Start in detect-only mode before enforcing network blocking.
- Route only high-confidence decisions to Discord/Matrix in N8N.
