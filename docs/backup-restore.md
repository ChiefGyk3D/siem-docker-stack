# Backup & Restore — OpenSearch Snapshots (Phase F4)

The main OpenSearch cluster runs with **zero replicas by design** (homelab
disk budget), so before Phase F a single disk failure meant total evidence
loss. Snapshots convert that into a bounded RPO: **daily snapshots, 14-day
retention**, stored on the warm-tier disk and (recommended) rsync'd offsite.

All commands below assume the secured cluster (Phase F1):

```bash
# Convenience: load credentials, define an authenticated curl
set -a; source /opt/siem/.env; set +a
osc() { curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" "$@"; }
OS=https://localhost:9200
```

---

## What is (and isn't) covered

| Data | Covered | How |
|------|---------|-----|
| `suricata-*`, `syslog-*`, `pfsense-*`, `pfblockerng-*`, `unifi-syslog-*`, `crowdsec-events-*` | ✅ | SM policy `siem-daily` |
| ISM policies / index templates | ❌ (by snapshot) | Re-apply with `scripts/04-apply-ism-policy.sh`; `include_global_state` is false |
| Security config (users/roles) | ❌ | Regenerate with `scripts/08b-init-opensearch-security.sh` from `.env` |
| **Wazuh indexer (`wazuh-alerts-*`)** | ❌ **follow-up** | Separate cluster — needs its own `path.repo` + repo + policy. Tracked as a Phase F follow-up. |
| InfluxDB, Grafana DB, Prometheus TSDB | ❌ | Out of scope here (see `/data/warm/backups` conventions in docs/maintenance.md) |

---

## Architecture

- Both nodes mount the **warm-tier** host path `/data/warm/snapshots` at
  `/mnt/snapshots` (docker-compose.yml) — an fs repository must be visible to
  **every** node, and both node configs declare `path.repo: [/mnt/snapshots]`.
- `scripts/10-snapshot-setup.sh` registers the repo (`siem-snapshots`) and
  creates the Snapshot Management (SM) policy `siem-daily`:
  - creation: daily `0 3 * * *` UTC
  - deletion: daily `0 5 * * *` UTC, keep max 14 days (min 3 / max 21 snapshots)
  - `include_global_state: false`, `partial: true`

```bash
bash scripts/10-snapshot-setup.sh          # idempotent — re-run any time
```

### Check status

```bash
osc "$OS/_plugins/_sm/policies/siem-daily" | jq .sm_policy
osc "$OS/_plugins/_sm/policies/siem-daily/_explain" | jq .
osc "$OS/_cat/snapshots/siem-snapshots?v&h=id,status,start_time,duration,indices"
```

---

## Manual snapshot

```bash
osc -X PUT "$OS/_snapshot/siem-snapshots/manual-$(date +%Y%m%d-%H%M)?wait_for_completion=false" \
  -H 'Content-Type: application/json' -d '{
    "indices": "suricata-*,syslog-*,pfsense-*,pfblockerng-*,unifi-syslog-*,crowdsec-events-*",
    "include_global_state": false,
    "partial": true
  }'

# Watch progress
osc "$OS/_snapshot/siem-snapshots/_current" | jq .
```

---

## RESTORE DRILL (run this quarterly — an untested backup is not a backup)

Restores one index from the latest snapshot **to a renamed index**, verifies
the doc count, then deletes the drill copy. Production indices are never
touched.

```bash
# 1. Pick the latest successful snapshot
SNAP=$(osc "$OS/_cat/snapshots/siem-snapshots?h=id,status" | awk '$2=="SUCCESS"{id=$1} END{print id}')
echo "Using snapshot: $SNAP"

# 2. Pick one index inside it (e.g. yesterday's syslog index)
IDX=$(osc "$OS/_snapshot/siem-snapshots/$SNAP" | jq -r '.snapshots[0].indices[]' | grep '^syslog-' | sort | tail -1)
echo "Restoring index: $IDX"

# 3. Record the live doc count
LIVE_COUNT=$(osc "$OS/$IDX/_count" | jq .count)

# 4. Restore to a renamed index (restored-<original>)
osc -X POST "$OS/_snapshot/siem-snapshots/$SNAP/_restore?wait_for_completion=true" \
  -H 'Content-Type: application/json' -d "{
    \"indices\": \"$IDX\",
    \"rename_pattern\": \"(.+)\",
    \"rename_replacement\": \"restored-\$1\",
    \"include_global_state\": false,
    \"index_settings\": { \"index.routing.allocation.require.temp\": null }
  }"

# 5. Verify the doc count matches the snapshot-time count
#    (live count can be higher if the index was still ingesting when snapped)
RESTORED_COUNT=$(osc "$OS/restored-$IDX/_count" | jq .count)
echo "live=$LIVE_COUNT restored=$RESTORED_COUNT"
# PASS: restored > 0 and restored <= live for an active index,
#       restored == live for an index that was already read-only/warm.

# 6. Clean up the drill index
osc -X DELETE "$OS/restored-$IDX"
```

Log the date and result of each drill (a line in your ops journal is enough).

### Full restore (disaster scenario)

After rebuilding the host (01→03 scripts, certs, 08b security init):

```bash
# Close/delete any conflicting empty indices first, then:
osc -X POST "$OS/_snapshot/siem-snapshots/<snapshot>/_restore?wait_for_completion=false" \
  -H 'Content-Type: application/json' -d '{
    "indices": "suricata-*,syslog-*,pfsense-*,pfblockerng-*,unifi-syslog-*,crowdsec-events-*",
    "include_global_state": false
  }'
```

If `/data/warm` itself died, first copy the offsite snapshot directory back to
`/data/warm/snapshots` (ownership `1000:1000`), then re-register the repo with
`scripts/10-snapshot-setup.sh` before restoring.

---

## Offsite copy

The snapshot directory is plain files — copy it with rsync/rclone **after** the
daily creation window (snapshot at 03:00 UTC, deletion at 05:00 UTC; copy at
e.g. 06:00 UTC):

```bash
# rsync to another machine (systemd timer or cron on the SIEM host)
rsync -a --delete /data/warm/snapshots/ backup-host:/backups/siem-snapshots/

# or rclone to S3-compatible/cloud storage
rclone sync /data/warm/snapshots remote:siem-snapshots
```

Notes:
- Always copy the **whole directory** — snapshots are incremental and share
  segment files; a partial copy is unrestorable.
- Don't run the copy while a snapshot is in progress (`_current` shows any
  running snapshot).
- `--delete`/`sync` keeps the offsite copy consistent with the 14-day
  retention; drop it if you want longer offsite retention (repo metadata will
  still only know about the local 14 days — for true long-term archives, copy
  to dated directories instead).

---

## Known gaps / follow-ups

- **Wazuh indexer is not snapshotted.** It is a separate single-node cluster;
  the same pattern applies (add `path.repo` to `docker/wazuh/wazuh-indexer.yml`,
  bind-mount a snapshot dir, register a repo with the indexer's admin creds).
  Tracked as a Phase F follow-up.
- SM policy failures are visible in `_plugins/_sm/policies/siem-daily/_explain`;
  there is no alert on snapshot failure yet — candidate for a future
  Prometheus/n8n check.
