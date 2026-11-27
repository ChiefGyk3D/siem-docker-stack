# UniFi Pi backup sync and backup health alerts

Copies the UniFi OS auto-backups of the Pi to a NAS share, keeps a real 90 day history there,
and reports how fresh the backups are so Grafana can alert. Tracked in issue #228 (epic #62).

Nothing here is deployed by this repo, and **nothing in this change was verified on a real Pi, a
real NAS or real systemd**. The tests run the script against fake `mount`, `umount`, `mountpoint`,
`cp` and `id` binaries. See "Not verified" at the end.

## What it does

`scripts/unifi-backup-sync.sh` runs as root from the systemd unit `unifi-backup-sync.service`:

1. Checks its settings and refuses to run if anything is odd (not root, bad path, retention out of
   range, credentials file not owned by root with mode 600).
2. Looks at the source folder. A missing folder, or a folder without a single `.unf` file that
   matches the exact name `autobackup_<version>_<date>_<time>_<epoch>.unf`, is a **failure**, not
   a success.
3. Mounts the NAS share read-write for the run only (or uses an already mounted path, see
   `NAS_USE_EXISTING_MOUNT`). It unmounts on every exit path, including errors and a signal.
4. Stages each source file (see "Links and races"), checks size and SHA-256, and then:
   - if a file of that name already exists on the NAS, its content is hashed and must equal the
     staged copy. Same bytes: nothing to do. Anything else (a different size, or the same size with
     other bytes, or a symlink or other non-plain file) is a **failure with code 5**: the NAS file
     is never overwritten and never deleted, and the run says so in the journal. To re-copy, move
     the NAS file aside by hand;
   - otherwise the staged copy is uploaded to a fresh temporary name (`.partial-<name>`), checked
     again (type, link count, size, SHA-256), given the backup's own file time and only then renamed
     to its final name. A file that fails a check is never published.
5. Removes NAS copies older than `RETENTION_DAYS` (default 90), only files that match the exact
   name pattern, never the newest copy, and never when a copy failed in the same run.
6. Prints metric lines on stdout (journal logs go to stderr) and records the last success time in
   its state directory.

It never deletes anything from the source. The old nightly script (`unifi-backup-to-nas.sh`)
used `rsync --delete`, which mirrors deletions, so its claimed 90 day retention was false: a file
removed on the Pi was removed on the NAS too. That mirror-delete is gone. The old script also read a
wrong, empty folder, so it never copied a backup.

## Links and races

The source folder belongs to a container uid and the NAS share may be writable by someone else, and
the script runs as root, so it does not trust paths between a check and a use.

- A source folder that is a symlink, and a source file that is a symlink, has more than one hard
  link, or is not a plain file, is refused (result code 2). A swapped file is refused (code 5).
- Each source file is bound to ONE open file. A small `perl` helper (perl-base is Essential on
  Debian, so `/usr/bin/perl` is there; the script uses that fixed path) opens it once with
  `O_NOFOLLOW` and `O_NONBLOCK`: a symlink cannot be followed and a FIFO swapped in after the check
  cannot block the root service. The open file itself (fstat, not the path) must be a plain file with
  the device, inode, size and time the path showed before, and a link count of 1. It reads only from
  that descriptor, at most size+1 bytes (an endless or growing file cannot fill the disk), into a
  new root-only staging file (`O_EXCL`) in the state directory (`/var/lib/unifi-backup-sync/stage`,
  removed after every file and on every exit), then checks the descriptor again. The script checks
  the path metadata again after the read (code 5 on any difference, including a helper exit that
  says the opened file was not the checked one). The staged copy must have exactly the size the
  lstat reported; only the staged copy is hashed and uploaded, and the upload is verified again
  against the staged hash.
- Layering (shown by the revert proofs): removing only the helper's identity check, or only the
  path re-check, still stops a hard-link swap; both are needed to lose it. Not verified on a real Pi:
  a swap in and out of another plain file between the helper's open and its final check is stopped
  by the second descriptor check, not by anything stronger.
- Size bounds (the state filesystem is shared with the Pi): a file larger than `MAX_BACKUP_BYTES`
  (default 1 GiB) is refused (code 2) before anything is read; free space on the state filesystem
  must be at least the file size plus `MIN_FREE_BYTES` (default 256 MiB), else it is refused (code
  4); a folder with more than 1000 backup files is refused (code 2). At most one file is staged at a
  time, so the peak is one file. Put `/var/lib/unifi-backup-sync` on a filesystem with a quota if
  you want a hard cap: systemd's `StateDirectory=` sets none by itself.
- The temporary upload file is never trusted: a leftover or planted `.partial-<name>` (a symlink
  included) is removed as a name (never followed), `dd` creates the new one with `conv=excl` and
  `oflag=nofollow`, the result is checked by lstat (plain file, one link, same size and hash) and
  again just before the final `mv -T`, and the time is set with `touch -h`. The checks and the
  rename are separate steps on a share that someone else may write: a writer who swaps the partial
  file between the last check and the rename can still replace what gets published (it is then an
  attacker-chosen plain file in the backup folder, never a write outside it). That is why the share
  should only be writable by the sync account.
- On the NAS the destination folder must not be a symlink, must resolve (physical path) to
  `<mount point>/<NAS_DEST_SUBDIR>`, and must be on the same device as the mount point. A prune
  candidate must be a plain file (a symlink is never followed or removed) on that same device and
  match the exact backup name; otherwise it is left alone and the run fails with code 6.
- The share is mounted with `nosymfollow`. Source: `mount(8)`, util-linux 2.41.5, read 2026-11-27
  on the build machine: "nosymfollow: Do not follow symlinks when resolving paths", a VFS flag
  applied to the mount point. That the CIFS client of your Pi kernel honors it (and which kernel
  version added it) is **inferred**, not read from a vendor page, and not tested on a real mount.
  `mount.cifs(8)` documents `mfsymlinks` (off unless set); it is not set.
- With `NAS_USE_EXISTING_MOUNT=1` the script does not know your mount options. It cannot check
  `nosymfollow` there; the destination, device and partial-file rules above still apply, but the
  mount safety is yours: mount it without symlink following (and with the sync account only) if you
  use that mode. Not checked by the script.

## Settings

Set them in `/etc/unifi-backup-sync/unifi-backup-sync.env` (root-owned, mode 600 is sensible, it
holds no secret).

| Variable | Default | Meaning |
|----------|---------|---------|
| `UNIFI_BACKUP_SRC` | `/home/uosserver/.local/share/containers/storage/volumes/uosserver_var_lib_unifi/_data/backup/autobackup` | Source folder (UniFi OS rootless container volume) |
| `NAS_SHARE` | none | `//host/share`, for example `//nas.example.internal/unifi-backups`; needed unless the mount is existing |
| `NAS_MOUNT_POINT` | `/mnt/unifi-backup-nas` | Existing empty directory to mount on |
| `NAS_USE_EXISTING_MOUNT` | `0` | `1` = use an already mounted `NAS_MOUNT_POINT`, never mount or unmount it |
| `NAS_DEST_SUBDIR` | `unifi-autobackup` | One folder name on the share that receives the copies |
| `SMB_CREDENTIALS_FILE` | `/etc/unifi-backup-sync/smb-credentials` | Root-owned, mode 600, in `mount.cifs` format |
| `SMB_VERS` | `3.0` | SMB protocol version |
| `RETENTION_DAYS` | `90` | Whole days, 1 to 3650 |
| `MAX_BACKUP_BYTES` | `1073741824` | Largest accepted backup file, 1 to 99999999999 bytes |
| `MIN_FREE_BYTES` | `268435456` | Free space that must remain on the state filesystem after staging a file |

## Metrics

InfluxDB line protocol on stdout, no timestamp (the writer assigns it):

```
unifi_backup_newest_age_seconds,where=local value=<n>i
unifi_backup_newest_age_seconds,where=nas value=<n>i
unifi_backup_count,where=local value=<n>i
unifi_backup_count,where=nas value=<n>i
unifi_backup_sync_last_success_timestamp value=<epoch>i
unifi_backup_sync_success value=1i
unifi_backup_sync_result_code value=0i
```

Ages come from the file times of the backups (the NAS copy keeps the source file time). On a
failure the script prints only `unifi_backup_sync_success value=0i`, the result code and, when one
is on record, the old last-success time: never zero-valued ages or counts, so a broken run cannot
look healthy.

Result codes: 0 ok; 1 bad setting or precondition; 2 source missing, empty, unreadable, too large,
refused (symlink, hard link, not a plain file) or with too many files; 3 mount, unmount or
destination problem; 4 copy failed or not enough free space; 5 size or checksum mismatch, a source
that changed while it was read, or an existing NAS copy with different content;
6 prune failed; 7 unexpected internal error; 8 interrupted by a signal; 9 state file could not be
written.

### Delivery route is not decided

This repo does not pick how the metric lines reach InfluxDB, exactly like the host update collector.
The unit sends stdout to the journal. Options still open: a Telegraf `exec` input on the Pi (the
Pi already runs `prometheus-node-exporter`, but whether the SIEM scrapes it is **unverified** and
this change does not rely on it), or a small writer fed by a drop-in of the unit. Whatever carries
them, keep credentials in the secret manager and never in argv. The alert rules ship **paused** for
this reason and read nothing until the route exists.

## Alerts

`docker/grafana/provisioning/alerting/unifi-backup-alert-rule.yml`, folder "Backup Alerts", all
three rules `isPaused: true` (like the pfSense rules) until the delivery route is live. Owner
decision 2026-11-27: warn at 8 days, critical at 15.

| Rule | Fires when | Labels | Repeat |
|------|-----------|--------|--------|
| UniFi backup older than 8 days | newest backup age above 691200 s and up to 1296000 s, on the Pi or on the NAS | `severity=warning`, `tier=P2`, `phone=true` | 84h (twice a week) |
| UniFi backup older than 15 days | newest backup age above 1296000 s (15 days), on the Pi or on the NAS | `severity=critical`, `tier=P1`, `phone=true` | 24h (daily) |
| UniFi backup sync failed or not reporting | `unifi_backup_sync_success` is 0, or no report for 36 hours | `severity=critical`, `tier=P1`, `phone=true` | 24h (daily) |

All carry `alert_group=backup` and `source=unifi`. No label outside the existing set is used, and
`phone=true` stays the only way to the phone. The warning and critical age rules are exclusive (no
inhibit rule exists in Grafana-managed alerting), so one stale backup raises one alert.

The repeat intervals live in `unifi-backup-notification-policy.yml.example`: Grafana has one policy
tree for the whole organization, so it ships as an example. Merge its `alert_group = backup` route
into your tree. Until you do, the default policy's repeat applies.

Things to know:

- `ALLOWED_ALERTNAMES` in the n8n router is **not** changed. A critical alert whose name is not on
  that list reaches Pushover at priority 1, not at emergency priority 2. Adding the two critical
  titles is a one-line decision for the owner (it also changes `docs/update-alerting.md` and its
  test); it is deliberately not part of this change.
- The warning carries `phone=true` by the owner's decision, as `tier=P2`. The alert taxonomy
  (`docs/alert-taxonomy.md`) now allows that on purpose: this change adds `alert_group=backup` to
  the allowed groups (and as a policy matcher value) and lets a `backup` P2 warning page, next to
  the pending-update warning exception. `tests/python/test_alert_taxonomy.py` was extended in the
  same change.
- The queries assume the InfluxDB datasource `influxdb-pfsense` (database `pfsense`). Change them if
  the route writes elsewhere.

## Install (owner, on the Pi)

Everything below is for root-owned paths. Run it on the Pi, in order. Do the dry run first and read
its output before the real run.

1. Pick the share, the credentials and a mount point. Create the folder on the NAS for the copies.
   Replace the placeholder names with yours.

```
sudo install -d -m 755 /etc/unifi-backup-sync
sudo install -d -m 700 /mnt/unifi-backup-nas
sudo install -m 755 -o root -g root scripts/unifi-backup-sync.sh /usr/local/bin/unifi-backup-sync.sh
sudo install -m 644 -o root -g root docs/systemd/unifi-backup-sync.service /etc/systemd/system/unifi-backup-sync.service
sudo install -m 644 -o root -g root docs/systemd/unifi-backup-sync.timer /etc/systemd/system/unifi-backup-sync.timer
```

2. The credentials file, written by you with an editor so the password never appears in a command
   line or in the shell history (`mount.cifs` format: two lines, `username=...` and `password=...`):

```
sudo install -m 600 -o root -g root /dev/null /etc/unifi-backup-sync/smb-credentials
sudo nano /etc/unifi-backup-sync/smb-credentials
```

3. The settings file:

```
sudo install -m 600 -o root -g root /dev/null /etc/unifi-backup-sync/unifi-backup-sync.env
sudo nano /etc/unifi-backup-sync/unifi-backup-sync.env
```

   Put at least this line in it (your share, not this placeholder):

```
NAS_SHARE=//nas.example.internal/unifi-backups
```

4. Check that the fixed command paths exist on the Pi. The script uses absolute paths and the
   paths of a Debian-family system; if any line prints nothing, tell the owner of the repo before
   going on:

```
for c in id date stat dd df perl mv rm touch mkdir sha256sum mount umount mountpoint; do ls -l "/usr/bin/$c"; done
ls -l /sbin/mount.cifs
```

5. Dry run (mounts read-only, changes nothing, prints what it would copy). `STATE_DIRECTORY` is not
   needed for a dry run:

```
sudo sh -c 'set -a; . /etc/unifi-backup-sync/unifi-backup-sync.env; set +a; exec /usr/local/bin/unifi-backup-sync.sh --dry-run'
```

6. Real run through systemd, then read the journal (look for the metric lines and for "copied and
   verified"):

```
sudo systemctl daemon-reload
sudo systemctl start unifi-backup-sync.service
sudo journalctl -u unifi-backup-sync.service --no-pager -n 60
```

7. Check the NAS copies are complete and listed, then enable the timer:

```
sudo ls -l /mnt/unifi-backup-nas
sudo systemctl enable --now unifi-backup-sync.timer
systemctl list-timers unifi-backup-sync.timer
```

   (`/mnt/unifi-backup-nas` is empty between runs because the share is unmounted; check the share
   from the NAS side or add `NAS_USE_EXISTING_MOUNT=1` with a mount you manage yourself.)

8. Retire the old script and its crontab line once the first real run succeeded:

```
crontab -l
```

   Remove the line that runs `/usr/local/bin/unifi-backup-to-nas.sh` with `crontab -e`, and move the
   script away. Its `rsync --delete` must not run against the NAS folder again.

The UniFi backup time in the timer (`Mon 06:30`) is an assumption. Read the `<time>` part of the
file names in the source folder and keep the Monday run at least one hour after it.

## Restore note

A backup file is a `.unf`. To restore, copy the chosen file from the NAS back to the controller
(or upload it in the UniFi OS settings, Backups, Restore). Restoring is the owner's manual step and
this change never does it. Check the version in the file name (`autobackup_<version>_...`): a
restore needs a compatible controller version. Test a restore once before you need it.

## Honest limits

- **Credentials.** The SMB password sits in a root-only file on the Pi. The script never reads or
  prints it; it only passes the path to `mount.cifs` (`credentials=<path>`), so the password is
  not in argv. Anyone with root on the Pi can read it, and a lost Pi means a rotated NAS account.
  Use a NAS account that can write only to that one share.
- **Not a mirror.** Copies are only added. Retention prunes by file age, only for exact backup
  names. A backup removed on the Pi stays on the NAS until it is older than the retention.
- **The age is the file time.** The NAS copy keeps the source file time. If a share cannot set file
  times, the copy fails (code 4) rather than reporting a wrong age.
- **Reads of the NAS copies.** Every run hashes each existing NAS copy to prove it is intact (about
  25 files of 21 MB over the LAN each day with the default timer).
- **Stale temp files.** A run killed with SIGKILL can leave a `.partial-*` file on the NAS. The next
  run removes that name and creates a fresh file; the prune does not touch it.
- **Route undecided.** Metrics reach no database yet, and the alert rules are paused.
- **Source can still be wrong.** The script proves the files in the source folder were copied
  intact. It cannot prove the controller's backups restore. Test a restore.
- **Next step.** NAS to S3 and pfSense backup checks are not part of this change.

## Not verified

- The perl copy helper, `dd conv=excl`, `touch -h`, `mv -T` and `df -Pk` were run only against the
  fake-binary tests on the build machine (GNU coreutils, perl 5.40), not on the Pi.
- Nothing ran on a real Pi, a real NAS or real systemd. The mount options, the capability set of
  the unit, `ProtectSystem=strict` together with a CIFS mount inside the unit's namespace and
  `SystemCallFilter=@mount` are written from the man pages and may need adjusting; run
  `systemd-analyze security` and the dry run first.
- The UniFi OS backup time and the unit of the epoch in the file names are not known; the age uses
  file times, not the name.
- The Grafana rule files were checked for structure only, not loaded into a live Grafana. The
  math expression in the warning rule has not run against real data.
- Whether the SIEM scrapes the Pi's `prometheus-node-exporter` is unverified.
- Tests: `tests/python/test_unifi_backup_sync.py` (fake binaries, scratch directory under the
  worktree), plus `shellcheck -s sh scripts/unifi-backup-sync.sh`.
