# Phase F — Machine Testing Checklist

Ordered, copy-pasteable checklist for testing the Phase F foundation work
(F1 OpenSearch security + InfluxDB auth, F3 Alertmanager path, F4 snapshots)
on the real machine. Run one full cycle per iteration; the [Rollback](#rollback)
section reverts to the pre-security state if a cycle fails.

> **Breaking changes on this branch** (all covered below):
> - OpenSearch `:9200` is now **HTTPS + basic auth** — every client needs
>   credentials (Logstash, Grafana, scripts, dashboards, exporter).
> - InfluxDB has **auth enabled** — remote Telegraf and unifi-poller writers
>   need credentials; live deployments must create the admin user *before*
>   the flip.
> - The Prometheus scrape jobs `opensearch-hot`/`opensearch-warm`
>   (`/_prometheus/metrics`) were removed — they required the aiven
>   prometheus-exporter plugin that was never installed (they never returned
>   metrics). OpenSearch metrics now come from the new
>   `elasticsearch-exporter` service.
> - OpenSearch Dashboards now requires login (admin / `$OPENSEARCH_ADMIN_PASSWORD`).

---

## 0. Pre-flight (on the workstation / repo checkout)

```bash
git fetch && git checkout claude/phase-f-foundation
```

Add ALL of the following to `.env` (one block — see `.env.example` for docs):

```bash
# --- Phase F additions ---
OPENSEARCH_ADMIN_PASSWORD=<strong-password>        # no $ characters
OPENSEARCH_LOGSTASH_PASSWORD=<strong-password>
OPENSEARCH_READONLY_PASSWORD=<strong-password>
OPENSEARCH_DASHBOARDS_PASSWORD=<strong-password>
INFLUXDB_ADMIN_USER=admin
INFLUXDB_ADMIN_PASSWORD=<strong-password>
# Optional (defaults shown):
# ALERTMANAGER_VERSION=v0.27.0
# ALERTMANAGER_PORT=9093
# ES_EXPORTER_VERSION=v1.7.0
# N8N_ALERTMANAGER_WEBHOOK_URL=http://n8n/webhook/alertmanager-siem
```

- [ ] `.env` updated (both the repo copy used by scripts and `/opt/siem/.env`
      end up in sync — `03-deploy.sh` copies the repo `.env` over).

## 1. Certificates

```bash
bash scripts/07-generate-opensearch-certs.sh
ls docker/opensearch/certs/    # root-ca, opensearch-hot, opensearch-warm, admin (+keys)
```

- [ ] 8 PEM files present; `git status` shows none of them as tracked.

## 2. MIGRATION — live existing deployment (ORDER MATTERS)

Skip to step 3 for a fresh install.

### 2a. InfluxDB: create the admin user BEFORE the auth flip

```bash
# On the SIEM host, against the still-unauthenticated influxdb:
docker exec influxdb influx -execute \
  "CREATE USER admin WITH PASSWORD '<INFLUXDB_ADMIN_PASSWORD>' WITH ALL PRIVILEGES"
docker exec influxdb influx -execute "SHOW USERS"
```

- [ ] `admin` listed with `admin true`.
- [ ] Remote writers ready: pfSense **Telegraf** config gets
      `username`/`password` for the influxdb output; any other Telegraf hosts
      likewise. (unifi-poller in this compose file is wired automatically.)
      They will error from the moment auth flips until updated — do them
      right after step 4.

### 2b. Deploy the new configs (does NOT restart into the secured world yet)

```bash
bash scripts/03-deploy.sh <SIEM_IP> <user>     # or: bash scripts/03-deploy.sh local
```

`03-deploy.sh` runs `docker compose up -d`, which **recreates changed
services** — from here the cluster restarts with security enabled. That is
expected; the next step initializes the users the clients need.

### 2c. Initialize OpenSearch security BEFORE clients can work again

```bash
bash scripts/08b-init-opensearch-security.sh
```

- [ ] Script ends with `Authenticated admin request: HTTP 200` and
      `Unauthenticated request correctly rejected: HTTP 401`.

### 2d. Restart the credential consumers

```bash
cd /opt/siem
docker compose up -d logstash grafana opensearch-dashboards elasticsearch-exporter influxdb unifi-poller
```

## 3. Fresh-install bring-up order (skip if you did step 2)

```bash
bash scripts/01-disk-setup.sh          # now also creates /data/hot/alertmanager, /data/warm/snapshots
bash scripts/02-bootstrap.sh
bash scripts/06-generate-wazuh-certs.sh
bash scripts/07-generate-opensearch-certs.sh
bash scripts/03-deploy.sh local
# opensearch-hot stays "unhealthy" (HTTP 503) until the next line runs — expected:
bash scripts/08b-init-opensearch-security.sh
docker compose up -d                   # in /opt/siem — starts remaining services
bash scripts/04-apply-ism-policy.sh
```

## 4. Verification — F1 (auth everywhere)

```bash
set -a; source /opt/siem/.env; set +a

# Authenticated curl works:
curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" https://localhost:9200/_cluster/health | jq .status
# Unauthenticated curl MUST FAIL with 401:
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9200/          # expect 401
# Plain http MUST FAIL (TLS now required):
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9200/ || echo "conn-fail OK"
# Warm node too:
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9201/          # expect 401

# Least privilege sanity: logstash user cannot read, readonly cannot write
curl -sk -u "logstash:${OPENSEARCH_LOGSTASH_PASSWORD}" \
  -o /dev/null -w '%{http_code}\n' "https://localhost:9200/syslog-*/_search"   # expect 403
curl -sk -u "readonly:${OPENSEARCH_READONLY_PASSWORD}" -X POST \
  -H 'Content-Type: application/json' -d '{}' \
  -o /dev/null -w '%{http_code}\n' "https://localhost:9200/syslog-test/_doc"   # expect 403
```

- [ ] 200 / 401 / conn-fail / 401 / 403 / 403 as annotated.

**Logstash still indexing** (doc count increases):

```bash
C1=$(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" "https://localhost:9200/syslog-*,pfsense-*,suricata-*/_count" | jq .count)
sleep 60
C2=$(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" "https://localhost:9200/syslog-*,pfsense-*,suricata-*/_count" | jq .count)
echo "$C1 -> $C2"      # C2 > C1 (assuming sources are sending)
docker logs logstash --tail 20   # no auth/TLS errors
```

- [ ] Doc count increased; no `401`/`SSL` errors in logstash logs.
- [ ] Fixture replay passes: `bash scripts/09-test-crowdsec-pfsense-ingest.sh`

**Grafana datasources healthy:**

- [ ] Grafana → Connections → Data sources → each OpenSearch datasource
      (Suricata/Syslog/pfBlockerNG/CrowdSec) “Save & test” succeeds; a
      dashboard panel renders recent data.
- [ ] InfluxDB + InfluxDB-UniFi datasources test OK (auth now on).
- [ ] OpenSearch Dashboards `:5601` presents a login page; admin login works.
      *(If the dashboards container crash-loops on the security plugin config,
      see the design note in the PR — fallback is binding it to 127.0.0.1
      with the plugin disabled.)*
- [ ] InfluxDB unauthenticated query fails:
      `curl -s 'http://localhost:8086/query?q=SHOW+DATABASES' | jq .` → auth error.
- [ ] pfSense Telegraf + any remote writers updated with credentials and
      writing again (check `pfsense` DB measurements timestamp).
- [ ] `bash scripts/05-verify.sh` — all green (includes the 401 check).

## 5. Verification — F3 (independent alerting)

```bash
# Exporter metrics visible:
docker exec prometheus wget -qO- http://elasticsearch-exporter:9114/metrics | grep -m3 elasticsearch_cluster_health
# Prometheus sees its targets and rules:
curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
curl -s localhost:9090/api/v1/rules | jq '.data.groups[].name'
# Alertmanager healthy (loopback only):
curl -s http://127.0.0.1:9093/-/healthy
```

- [ ] `elasticsearch-exporter`, `alertmanager`, `cadvisor`, `grafana`,
      `prometheus` targets all `up`.
- [ ] Rule groups `siem-cluster-health`, `siem-stack-health`, `siem-host-disk` listed.

**Forced test alert reaching Alertmanager:**

```bash
# Inject a synthetic alert directly (v2 API) and confirm routing:
curl -s -XPOST http://127.0.0.1:9093/api/v2/alerts -H 'Content-Type: application/json' -d '[{
  "labels": {"alertname":"PhaseFTestAlert","severity":"critical","source":"siem-health"},
  "annotations": {"summary":"Phase F test alert — ignore"},
  "generatorURL": "http://localhost:9090"
}]'
curl -s http://127.0.0.1:9093/api/v2/alerts | jq '.[].labels.alertname'
# → n8n should receive a webhook POST on N8N_ALERTMANAGER_WEBHOOK_URL
```

- [ ] Alert visible in Alertmanager; n8n execution log shows the webhook
      (or, if n8n isn't wired yet, alertmanager logs show the delivery attempt:
      `docker logs alertmanager --tail 20`).
- [ ] Organic path: stop logstash for >30 min → `IngestRateZero` fires
      (optional, long) — or `docker stop cadvisor` for 6 min → `TargetDown`.

## 6. Verification — F4 (snapshots + restore drill)

```bash
bash scripts/10-snapshot-setup.sh
# Take a manual snapshot right now instead of waiting for 03:00 UTC:
curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" -X PUT \
  "https://localhost:9200/_snapshot/siem-snapshots/manual-test?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"syslog-*","include_global_state":false}' | jq '.snapshot.state'
```

- [ ] Repository registered + verified on 2 nodes; policy `siem-daily` shown.
- [ ] Manual snapshot state `SUCCESS`; files appear under `/data/warm/snapshots`.
- [ ] **Restore drill** from [docs/backup-restore.md](backup-restore.md)
      (restore one index renamed → verify count → delete) passes.
- [ ] Delete the test snapshot:
      `curl -sk -u admin:... -X DELETE https://localhost:9200/_snapshot/siem-snapshots/manual-test`

## 7. Housekeeping checks

- [ ] `docker ps` — no crash-looping containers (watch `opensearch-dashboards`,
      `alertmanager`, `elasticsearch-exporter`, `influxdb`).
- [ ] `bash scripts/08-crowdsec-smoketest.sh` passes.
- [ ] Reboot test (optional but recommended): `docker compose restart` in
      /opt/siem — cluster comes back green without re-running 08b (security
      config persists in the `.opendistro_security` index).
- [ ] Password rotation dry-run: `bash change-passwords.sh` — rotate the
      OpenSearch readonly password, confirm Grafana datasources still test OK
      after the recreate.

---

## Rollback

If a cycle fails and you need the pre-security state back:

```bash
cd ~/siem-docker-stack
git checkout master                      # restores http configs, old compose
bash scripts/03-deploy.sh <SIEM_IP> <user>   # redeploys master configs; compose up -d recreates
cd /opt/siem && docker compose up -d --remove-orphans   # drops alertmanager/exporter
```

Then undo the two stateful changes:

```bash
# InfluxDB: master's compose sets INFLUXDB_HTTP_AUTH_ENABLED=false again on
# recreate — the admin user remains but is ignored. (Remote Telegraf configs
# with credentials keep working against no-auth InfluxDB.)

# OpenSearch: master's opensearch-{hot,warm}.yml have plugins.security.disabled=true
# again, so the nodes come back with security off. The .opendistro_security
# index remains in the data dir (harmless, ignored while the plugin is disabled):
curl -s http://localhost:9200/_cluster/health | jq .status   # http works again
# Optional cleanup: curl -XDELETE 'http://localhost:9200/.opendistro_security'
```

Notes:
- Snapshots taken during the cycle stay valid in `/data/warm/snapshots`.
- `.env` additions are harmless to keep for the next cycle.
- If the cluster will not form after the rollback (rare — TLS-era cluster
  state), stop both nodes and start hot first, then warm.
