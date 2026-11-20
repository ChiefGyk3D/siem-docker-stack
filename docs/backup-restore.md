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
| InfluxDB, Prometheus TSDB | ❌ | Out of scope here (see `/data/warm/backups` conventions in docs/maintenance.md) |
| Grafana DB, n8n workflows and credentials | see below | `scripts/backup-state.py` (n8n and Grafana state backup section) |

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
sudo scripts/10-snapshot-setup.sh          # idempotent - re-run any time
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

---

# n8n and Grafana state backup (issue #83)

Separate from the OpenSearch snapshots above. `scripts/backup-state.py` writes
an **age-encrypted** archive of the n8n and Grafana state, optionally copies it
to an rclone remote, and keeps the newest N. `scripts/restore-state.py` restores
it, as a dry run unless you pass `--apply`. Python 3.11+ and the standard
library only; the tools you install are `age` (required) and `rclone`
(optional, for an off-host copy). Nothing is host-specific: containers, paths,
recipients and retention all come from one TOML config.

> **Secret material warning.** Every archive contains n8n's encryption key, the
> n8n credentials export and the Grafana database (which holds datasource and
> API secrets). Whoever can decrypt an archive owns your alerting stack. The
> script therefore refuses to write anything that is not age output, accepts
> public recipients only, and never uses `--decrypted`, so the credentials
> inside stay encrypted by n8n's own key as well. Keep the age identity
> (private key) off the host that runs the backup, ideally offline.

## Quick start

```bash
# 1. Install age (and rclone if you want an off-host copy)
sudo apt install age            # or your platform's package; verify the version
# 2. Make a key pair on a machine you trust, NOT on the server
age-keygen -o ~/siem-backup-identity.txt     # prints the public key (age1...)
# 3. Config: copy the example, set destination_dir and age_recipients (public keys only)
sudo cp docs/examples/siem-state-backup.example.toml /etc/siem-state-backup.toml
# 4. First run by hand
python3 scripts/backup-state.py --config /etc/siem-state-backup.toml
# 5. Schedule it: docs/examples/siem-state-backup.service + .timer (or .cron)
```

## Config reference

All keys live in the TOML file; see
`docs/examples/siem-state-backup.example.toml` for comments.

| Key | Default | Meaning |
|-----|---------|---------|
| `destination_dir` | required | Local directory for archives (created 0700) |
| `age_recipients` | required (or file) | Public age or ssh keys; secret keys are rejected |
| `age_recipients_file` | empty | File of public recipients passed to `age -R` |
| `rclone_remote` | empty | `remote:path` for an off-host copy and remote retention |
| `retention` | 14 | Newest N archives kept, locally and on the remote (min 1) |
| `n8n_container` / `n8n_key_file` | `n8n` / `/home/node/.n8n/config` | Container and key file path inside it |
| `allow_missing_n8n_key` | false | Only if n8n uses `N8N_ENCRYPTION_KEY` (you then keep that key yourself) |
| `grafana_container` / `grafana_db_path` | `grafana` / `/var/lib/grafana/grafana.db` | Grafana container and database path |
| `grafana_data_host_dir` | empty | Host directory mounted at `/var/lib/grafana` |
| `grafana_db_method` | `auto` | `host-sqlite`, `container-sqlite3`, `stop-copy` or `auto` |
| `helper_image` | empty | Small image (for example `alpine`) used by restore to chown, chmod and rename files inside a stopped container's volumes |
| `grafana_uid` / `grafana_gid` / `grafana_db_mode` | unset / unset / `"0600"` | Owner and mode for the restored `grafana.db` (the Grafana image runs as a fixed non-root user; check yours) |
| `n8n_uid` / `n8n_gid` / `n8n_key_mode` | unset / unset / `"0600"` | Owner and mode for a restored n8n key file (used only with `--restore-n8n-key`) |
| `max_member_bytes` / `max_total_bytes` / `max_archive_bytes` | 1 GiB / 2 GiB / 2 GiB | Ceilings checked before and during restore; raise `max_member_bytes` and `max_total_bytes` if your Grafana database is larger |
| `components` | both | Subset of `["n8n", "grafana"]` |
| `temp_dir` | system temp | Private 0700 scratch dir, removed on exit and on error |
| `container_runtime` | `CONTAINER_ENGINE`, else `docker` | `docker` or `podman`. The file value wins over `CONTAINER_ENGINE`. The binary is found only in `/usr/bin`, `/usr/local/bin`, `/bin` and `/snap/bin` (root-owned, not writable by others), never through `PATH` |

Grafana copy methods (a plain `cp` of a live database is never used):

- `host-sqlite`: SQLite's online backup API on the host path. Safe while
  Grafana runs and needs no tool in the image. Recommended.
- `container-sqlite3`: runs `sqlite3 <db> ".backup ..."` in the container. Needs
  the `sqlite3` CLI in the image and fails loudly when it is absent.
- `stop-copy`: stops Grafana, copies the file, starts it again (always, even
  on error). Brief downtime.
- `auto`: `host-sqlite` when `grafana_data_host_dir` is set, else
  `container-sqlite3`.

## What is and is not covered

| Data | Covered | How |
|------|---------|-----|
| n8n workflows | yes | `n8n export:workflow --all` inside the container |
| n8n credentials | yes, still encrypted by n8n | `n8n export:credentials --all` (never `--decrypted`) |
| n8n encryption key | yes | the key file from the n8n volume; without it credentials cannot be decrypted |
| Grafana database (`grafana.db`) | yes | consistent copy, see methods above |
| Grafana provisioning, dashboards, alert rules | no | they live in this repo (`docker/grafana/provisioning`) |
| n8n execution history, other files in the n8n volume | no | not needed to rebuild the router |
| Grafana plugins, other files in the Grafana volume | no | reinstalled from `GF_INSTALL_PLUGINS` |
| `.env` and its secrets | no | back up with your secret manager |
| OpenSearch, InfluxDB, Prometheus | no | see the snapshot sections above |

Files written: `siem-state-<UTC timestamp>.tar.gz.age` plus
`<name>.manifest.json` (archive SHA-256, size, member names). Inside the
archive is `MANIFEST.json` with a SHA-256 and size per member. Restore checks
both, but they are not equal:

- The `.manifest.json` next to the archive is **advisory**. Anyone who can write
  the directory can rewrite it, so it only catches bit rot and truncation. It is
  written with a private temp file and a no-overwrite link (never through a
  symlink), and the destination directory must be a real directory you own that
  is not writable by group or others.
- Authenticity comes from age (the archive cannot be altered without the
  identity) plus the inner manifest, which restore treats as hostile input:
  strict schema, no duplicate or extra members, the manifest first, sizes and
  digests checked while streaming, and `max_member_bytes`, `max_total_bytes`
  and `max_archive_bytes` ceilings so an archive made with only your public key
  cannot fill the disk. The decompressed stream itself is capped (payload caps
  plus a small header allowance), because `tarfile` reads GNU long-name and PAX
  records into memory before it shows a member; archives are written in plain
  USTAR format and any extended header is refused.
- The "starts with the age header" check on output is a format sanity check,
  **not proof** of encryption. It catches a missing or broken `age`, not a
  hostile one. Install `age` from your OS package manager or a verified
  release, and consider a periodic decrypt test with your identity.

## Restore

```bash
# Dry run (the default): decrypts into a private temp dir, verifies both
# manifests, lists what would be restored, changes nothing.
python3 scripts/restore-state.py --config /etc/siem-state-backup.toml \
  --identity ~/siem-backup-identity.txt /var/backups/siem-state/siem-state-<timestamp>.tar.gz.age

# Real restore
python3 scripts/restore-state.py --config /etc/siem-state-backup.toml \
  --identity ~/siem-backup-identity.txt --apply <archive>
```

With `--apply` it first writes an encrypted safety backup of what is about to be
replaced (`siem-prerestore-*.age`; retention never prunes these, so delete old
ones yourself once a drill has passed), then imports n8n credentials and
workflows through the n8n CLI, then stops Grafana and puts the database back,
leaving Grafana stopped. Before touching anything it checks the Grafana
database with `PRAGMA integrity_check` and that ownership settings exist. It
stops at the first error. Options: `--only n8n|grafana`, and
`--restore-n8n-key` (needed on a fresh host, where the running n8n key differs
from the backup's). The n8n restore refuses to start, before any change, if the n8n container is
not running (start n8n and re-run), and also refuses if n8n stops before the
key swap begins. The temporary key file is removed with `docker exec`, falling
back to the helper container; if both fail, the restore stops with a
`RECOVERY NEEDED` error naming the leftover file, which holds the backup's key
and must be removed by hand.

File ownership: `docker cp` gives no useful owner, so in container mode the
restored `grafana.db` (and n8n key) is copied to a temp name, then a throwaway
`helper_image` container started with `--volumes-from` runs `chown` and `chmod`
on it, moves the old `grafana.db`, `-wal` and `-shm` aside as one set, renames
the new file into place, and only then deletes the old set. The aside names
carry a random token, and the helper refuses to start if any of them already
exists (file, directory or symlink), so it never overwrites earlier recovery
material. If anything fails
before the final rename, the old set is put back (on the host path too), so a
failed restore never leaves the old database without its WAL.
Set `helper_image` and the uid/gid keys (`grafana_uid`, `grafana_gid`,
`n8n_uid`, `n8n_gid`) or the restore refuses to start; the files must live on a
volume, not in the container's writable layer. With `grafana_data_host_dir` set
the restore happens on the host instead (same steps, no helper image), and a
fresh host needs `grafana_uid` and `grafana_gid`. With `--restore-n8n-key`, n8n
is stopped only for the final rename and a start is always attempted (but a
container that was already stopped when found stays stopped; the state is read
with `docker inspect` first and the run fails before changing anything if that
read fails), even if
the stop reported an error (a stop can succeed and still report failure). If the
start fails you get a `RECOVERY NEEDED` error that keeps both the restart error
and the earlier one. The same rule covers the `stop-copy` Grafana backup method.

Manual steps printed afterward:

1. Imported workflows are inactive. Publish each:
   `docker exec n8n n8n publish:workflow --id=<id>`.
2. Restart n8n: `docker restart n8n`.
3. Start Grafana: `docker start grafana`.
4. Send a test alert end to end and confirm delivery.

## Restore drill (do this after setup, then quarterly)

1. Take a backup and copy the archive plus its identity to a scratch machine
   or a throwaway compose project with a second n8n and Grafana (not production).
2. Run the dry run; confirm it lists both components and reports checksums ok.
3. Flip one byte in a copy of the archive and confirm the dry run aborts.
4. Run with `--apply --restore-n8n-key` against the scratch containers.
5. Publish the workflows, restart n8n, start Grafana, open a credential in the
   n8n UI and confirm it decrypts, log in to Grafana and confirm dashboards and
   the contact point exist.
6. Record the date and result.

## Not verified (no live run yet)

This was built and tested against fakes. The following have **not** been
exercised against real containers or the real `age` binary:

- the exact `docker exec`, `docker cp`, `n8n export:*` and `import:*`
  invocations (flag spelling follows n8n's CLI as observed, but no live run);
- real `age` encrypt and decrypt (tests use a reversible stand-in; the magic
  header check assumes age's binary format, not `--armor`);
- `rclone copyto`, `lsf`, `deletefile` and remote retention;
- whether the Grafana image ships `sqlite3` (so `container-sqlite3` may fail;
  prefer `host-sqlite`);
- the helper-container install (`docker run --volumes-from ... sh -c`, with
  the dropped capabilities CHOWN, DAC_OVERRIDE and FOWNER kept) and whether it
  can see files in your volumes;
- `docker inspect -f '{{.State.Running}}'` output handling, and the helper
  script under busybox or alpine `sh`/`mv`/`chown` (tested only with the
  local `sh`);
- the `--restore-n8n-key` path and publish-after-import behavior on a live n8n;
- that `docker cp` out of a container returns a plain file for every path used
  (the code refuses anything else but this was never seen live);
- that `os.link` (used to publish without overwriting) works on your
  destination filesystem; some network or FUSE filesystems lack hard links;
- the systemd sandbox settings in the example unit.

Run the drill above before relying on this.
