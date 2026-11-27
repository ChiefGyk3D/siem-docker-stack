# pfSense configuration backup: NAS first, S3 second (design note)

Status: design for review, nothing deployed. Issue #236, epic #62.
Owner decisions of 2026-11-27 are recorded below and marked **DECIDED**; what
is still undecided is marked **OPEN**. Open items: the Doppler config for the
backup secrets (section 7.4), F4 Public Key Only and the optional Auto Config
Backup copy (section 7.1).
All hostnames and addresses are placeholders: `fw.example.internal` is the
firewall, `nas.example.internal` is the NAS, `mon.example.internal` is the
host that runs monitoring.

Every claim is labeled **VERIFIED** (with the source page and the date it was
read) or **INFERRED** (reasoned or remembered, not read from a source, to be
checked before the step that depends on it). The list of every INFERRED claim
is at the end.

Sources read on 2026-11-27 (Netgate pfSense documentation, `latest`):

| Short name | Page |
|------------|------|
| P-BACKUP | `https://docs.netgate.com/pfsense/en/latest/backup/index.html` (Backup and Recovery) |
| P-ACB | `.../backup/acb.html`, `acb-info.html`, `acb-config.html`, `acb-status.html` (Automatic Configuration Backup) |
| P-REMOTE | `.../backup/remote-backup.html` (Alternate Remote Backup Techniques) |
| P-RESTORE | `.../backup/restore.html` (Restoring from Backups) |
| P-XML | `.../config/xml-configuration-file.html` |
| P-ADMIN | `.../config/advanced-admin.html` (Secure Shell section) |
| P-PKG | `.../packages/backup.html` (Backup package) |

Repo prior art read: `docs/backup-restore.md` (OpenSearch snapshots and
offsite copy, the 3-2-1 and restore-drill habit), `docs/update-alerting.md`
and `scripts/pfsense-update-metric.sh` (the Telegraf exec to InfluxDB to
Grafana to n8n alert path, pfSense rules shipped paused, `noDataState` and
`execErrState` set to Alerting), `docs/heartbeat.md`, and `.env.example`
(secrets live in Doppler project `homelab`, config `prd_network`). The Pi
UniFi backup design was NOT found in this repo or in the local notes I could
search; I used only the owner's stated rule for it (newest NAS copy age,
warning at 8 days, critical at 15 days for weekly UniFi backups). If that
design lives elsewhere, section 4 should be reconciled with it.

## 1. Goal and threat model

Goal: a restorable copy of the firewall configuration exists off the firewall,
is no more than one day behind, survives loss of the firewall, the NAS, or
either site, and nobody can read its secrets who should not.

What is in the file (P-XML, VERIFIED): all settings, including package
settings, are held in one XML file, `/conf/config.xml`. P-BACKUP (VERIFIED)
says one file restores a system to a working state in the vast majority of
cases, that backups "can contain sensitive information", and that packages
may keep files outside `config.xml` (so those need their own backup).
P-RESTORE (VERIFIED) gives the location as `/cf/conf/config.xml`. That
`/conf` is a link to `/cf/conf` is INFERRED. That the file holds VPN keys,
certificate private keys, pre-shared keys and API tokens (password hashes
only for local users) is INFERRED from how pfSense works; treat the whole file
as a secret of the highest class.

Assets: the config file (C: secrets, topology; I: it is what a restore
trusts; A: needed to rebuild after loss). Actors: a thief of a NAS disk or of
a cloud bucket; an attacker who has compromised the NAS; an attacker on the
LAN trying to reach the firewall's SSH; a mistake (a bad config change, a
deleted backup, a lost key); ransomware on the NAS.

| Property | Risk | Control |
|----------|------|---------|
| C in transit, firewall to NAS | Sniffing | SSH only (encrypted), over the management network, never a WAN path. P-REMOTE (VERIFIED) warns the wget and curl pull methods run over HTTPS with certificate checking disabled and are open to man in the middle, and says non-encrypting techniques should use a non-WAN link or a VPN. |
| C at rest on the NAS | Stolen disk, NAS compromise, over-broad share access | Encrypt each file on arrival with a public key (age or GPG) so the NAS holds only ciphertext and only the public half. Share restricted to two accounts. Optional DSM shared folder encryption: it adds a key-on-reboot availability cost (INFERRED that DSM offers it), so it is not required when the files are already encrypted. |
| C in S3 | Bucket exposure, provider access | Only the already-encrypted file is uploaded. The S3 side never sees plaintext or the decryption key. Block public access, TLS-only bucket policy, default server-side encryption as a second layer (INFERRED, check at build). |
| C on the firewall | Pull key abuse | The pull key is restricted: one command, one source address, no shell, no forwarding. Read-only on the file. The firewall holds no NAS credential at all (owner direction). |
| I | Tampered or truncated backup; bad file restored | SHA-256 of each ciphertext recorded in a manifest and in the S3 object metadata; the pull verifies the received file is well-formed XML with the expected root before it is accepted (a partial `cat` over a dropped link must never replace a good copy). |
| I | Attacker deletes history | NAS: pull account can only add files; S3: versioning, no delete permission for the writer, Object Lock (INFERRED, needs enabling at bucket creation). |
| A | Firewall dead | NAS copy and S3 copy; the firewall also keeps its own history (P-RESTORE VERIFIED: the previous 30 configurations by default). That is not disaster recovery (P-BACKUP VERIFIED). |
| A | NAS dead | S3 copy. |
| A | Decryption key lost | Key custody (below). Without the key the offsite copy is useless; this is the real single point of failure of the design. |

Key custody (the age or GPG private key, "restore key"):

- Generated on the owner's own workstation, never on the NAS or the firewall.
- The NAS and the puller hold only the public key (recipient). A compromised
  NAS therefore cannot decrypt past backups. Honest limit: it can still use
  the pull key to read the live `config.xml`, so the pull key's restriction
  (section 2) is what protects the live file.
- Stored in Doppler (`homelab`, `prd_network`) and in one offline copy under
  the owner's physical control, so losing Doppler or the laptop cannot lose
  all copies. The restore drill (section 6) proves the key works.
- Rotation: a new key pair means new backups use the new recipient; old
  ciphertext needs the old key kept. Never delete an old key while any
  ciphertext made with it exists.

## 2. Options compared

### Recommendation: NAS pull over SSH with a restricted read-only key, plus S3 copy of the encrypted file

1. The NAS pulls `/cf/conf/config.xml` daily over SSH as a dedicated,
   non-root user whose key can run exactly one read command.
2. On arrival the file is validated, hashed and encrypted to the public key;
   new revisions only (unchanged hash means no new file).
3. The NAS copies each new ciphertext to S3 with add-only credentials.
4. Freshness is measured from outside the puller, alerting like the Pi UniFi
   backup (section 4).
5. The firewall holds no NAS or S3 credential; Auto Config Backup is verified
   and kept as an optional third copy.

| | A. NAS pull over SSH, restricted key (recommended) | B. Auto Config Backup package | C. Firewall pushes (scp or rsync) |
|---|---|---|---|
| What it is | The NAS runs `ssh backup-ro@fw.example.internal` and reads the file. | Core pfSense feature: on change or on a schedule it encrypts the config (AES-256-CBC with your password) and uploads it over HTTPS to Netgate, which keeps the newest 100 per device key (P-ACB, VERIFIED). | A cron on the firewall copies the file out. P-REMOTE (VERIFIED) documents `scp` push, and a cron plus a passphrase-less key. |
| Credentials on the firewall | None for the NAS. | Device key and encryption password, stored in the config itself (INFERRED: it must, to encrypt). | A passphrase-less private key to the NAS. P-REMOTE (VERIFIED) calls this "insecure", "adds risk", and says to isolate the remote user. |
| Confidentiality | Encrypt on arrival to a public key; NAS holds no decrypt key. | Encrypted before leaving, but a third party (Netgate) holds the ciphertext and the keys are yours to keep. Free for Plus and CE (P-ACB, VERIFIED). | Plain file leaves the firewall unless you add encryption on the firewall; the NAS user is reachable from a compromised firewall. |
| Integrity and history | You control retention, hashes, immutability. | 100 entries max, 50 manual (P-ACB, VERIFIED); you cannot attach your own freshness check to the server side (INFERRED). | Same as A once stored, but a compromised firewall can overwrite or delete NAS files it can write to. |
| Availability | Needs the NAS and the management path up; a missed run is caught by the monitor. | Works without your NAS. Depends on Netgate service and the firewall's Internet. | Fails silently if the firewall's cron or key breaks. |
| Fits "NAS then S3" | Yes, exactly. | No (it is a third party, not the NAS). | Yes, but against the owner's direction (firewall holds no NAS credential). |
| Cost | None. | None (VERIFIED, free). | None. |

Verdict: A as the primary. B is worth enabling after it is verified working,
as an independent third copy that survives loss of both the NAS and the S3
account; it does not replace A because the owner wants NAS and S3 under his
control and a freshness signal he can alert on. C is rejected: it puts a
standing credential for the NAS on the most exposed device.

Also considered and rejected: pulling the GUI with wget or curl (P-REMOTE
VERIFIED: needs the GUI admin login in a script and often disables
certificate checks), and `ssh root@fw cat ...` as written in P-REMOTE
(VERIFIED text), because that needs an administrative key on the NAS.

How the restricted pull works (design):

- A local user `backup-ro` created in the User Manager with only the
  privilege "User - System: Shell account access". P-ADMIN (VERIFIED): users
  with that privilege may log in over SSH, do not have root privileges and
  do not get the menu.
- Its Authorized Keys entry carries options so the key can do one thing:
  `from="<NAS address>",command="cat /cf/conf/config.xml",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... pfpull@nas`.
  P-ADMIN (VERIFIED) says keys are pasted into the Authorized Keys field of
  the user; that the field accepts these option prefixes and that the daemon
  honors them is INFERRED (standard OpenSSH behavior, not on the page), and
  must be tested.
- Open question that decides the design: can a non-root user read
  `/cf/conf/config.xml`? INFERRED that the file is world-readable by default,
  which is also a finding in itself. If it is not readable, the fallback is
  the sudo package (P-ADMIN VERIFIED mentions it for extra shell privileges)
  with a rule for exactly `cat /cf/conf/config.xml`. A root key restricted
  with `command=` is the last resort and needs the owner's explicit OK. The
  verification commands in section 7 settle this.
- Anti-lockout (P-ADMIN, VERIFIED) allows the SSH port from the whole LAN
  regardless of your rules, so the `from=` option is what pins the source
  address; add an explicit firewall rule allowing only the NAS address if
  the NAS is on another interface.
- Optional hardening (**OPEN**, owner decision pending): "SSHd Key Only" set
  to "Public Key Only" (P-ADMIN VERIFIED options exist). It also removes password login for the admin
  account, so the owner must confirm his own key works first.

Pull schedule: once a day at a fixed time, plus on demand. Reason: the
firewall config changes rarely, a one-day RPO is acceptable for a homelab,
and an unchanged hash writes nothing. P-BACKUP (VERIFIED) advises a backup
after each change and before and after major changes, so the owner triggers
the pull by hand around planned work (one command on the NAS). The daily
pull from the firewall by the NAS is **DECIDED** (owner, 2026-11-27).

## 3. What the backup does not cover

- Files outside `config.xml`: P-BACKUP and P-PKG (VERIFIED) say some
  packages store data elsewhere and that custom system file changes are not
  in the built-in backup. The Backup package (Diagnostics, Backup Files/Dir)
  can add paths; RRD data is excluded from the config backup by default
  (P-BACKUP VERIFIED). Decision for the owner later: RRD data is not needed
  for a rebuild, so it is out of scope here.
- The repo's own `pfsense-update-metric.sh` and its Telegraf exec snippet live
  on the firewall outside the XML file (INFERRED); the repo is their backup
  (`docs/update-alerting.md`).
- pfBlockerNG lists and other package data (INFERRED): re-fetched after a
  restore, listed so the drill can confirm.

## 4. Freshness measurement and alerting

The Pi UniFi backup rule the owner gave: age of the newest NAS copy, warning at
8 days, critical at 15 days (weekly backups: one period plus a day, then two
periods plus a day).

A pfSense backup is change driven in content, so the age of the newest file
is the wrong number: a quiet month leaves a 30-day-old newest file and a
healthy system. Measure these instead, from outside the puller:

| Metric (InfluxDB measurement, tags `dest`) | Meaning |
|---|---|
| `pfsense_backup_last_pull_age_seconds` (`dest=nas`) | Age of the last successful pull-and-verify run, read from the modification time of a status file the puller rewrites only on success (even if the config was unchanged). This is the freshness signal. |
| `pfsense_backup_newest_copy_age_seconds` (`dest=nas`, `dest=s3`) | Age of the newest ciphertext. Informational, never alerts alone. |
| `pfsense_backup_s3_behind_count` | NAS ciphertext files not present in S3. |
| `pfsense_backup_check_success` | The check itself ran (1) or failed (0). |

Thresholds for the pull, the S3 copy and the silent monitor are **DECIDED**
(owner, 2026-11-27). Only the restore drill age thresholds in section 6 stay a
proposal.

| Alert | Condition | Severity | Why |
|---|---|---|---|
| NAS pull stale | last pull age over 2 days | warning | Daily job: one period plus a day of grace, the same shape as 8 days for weekly UniFi. One missed run is tolerated, two raise it. |
| NAS pull stale | last pull age over 3 days | critical | Two periods plus a day, the same shape as 15 days for UniFi, and it is still inside a normal long weekend. |
| S3 behind | `s3_behind_count` over 0 for more than 1 day | warning | A new revision should be in S3 within the day. |
| S3 behind | `s3_behind_count` over 0 for more than 3 days | critical | Same two-period shape. |
| Check failing | `check_success` is 0, or no data for 36 hours | critical | A silent monitor must alert, as in the existing pfSense update rules (`noDataState` and `execErrState` set to Alerting). |

A per-run rule also alerts on any non-zero pull exit (bad XML, ssh failure,
hash mismatch), because a "fresh" status on a corrupt file is worse than a
stale one.

Delivery is **DECIDED** (owner, 2026-11-27): critical alerts page the phone;
warnings go to chat only (Discord and Matrix), with no phone for warnings.

Where it runs (same path as `docs/update-alerting.md`): a Telegraf exec input
on the monitoring host mounts the backup share read-only (a separate NAS
account), reads the status file mtime and the newest ciphertext mtime
itself, and prints InfluxDB line protocol. The monitor does not trust the
puller's own claim: if the puller dies, the status file stops aging
forward and the alert fires. The NAS therefore holds no InfluxDB or Grafana
credential, matching the pull principle. Grafana rules go in the existing
`influxdb-pfsense` alerting datasource, labels `severity`,
`alert_group=backup`, shipped paused until data arrives, delivered through
the existing `n8n-grafana-router` contact point. Phone push (`phone=true`)
is set for critical only, per the decision above. A later PR adds the script, the
rules file and tests (not part of this note).

### Where the tools live (DECIDED, owner, 2026-11-27)

The backup tools and scripts will live in the public repo
`homelab-backup-tools`, with placeholders only in the repo and real values in a
private config or the secret manager. The pull script, the NAS-side script and
the metric script go there. Their alert rules stay in this repo
(`siem-docker-stack`). Tracked in issue #241.

## 5. Retention

- NAS: keep every distinct revision for 365 days, and never fewer than the
  newest 30 files regardless of age. Files are small (INFERRED: a few hundred
  kilobytes at most), so a year is cheap, and a quiet firewall must not age
  out its only copies. Pruning is done by the pull account's own script and
  never by the monitoring account. Consider Btrfs snapshots of the share as a
  second layer (INFERRED that DSM Snapshot Replication supports immutable
  snapshots on this model).
- S3: versioning on, nothing deleted by the writer. Lifecycle expires
  non-current versions after 365 days only. The writer's policy has no delete
  permission, so a stolen writer credential cannot erase history.
- Firewall: the on-box history (30 by default, P-RESTORE VERIFIED) is left
  alone; it is a convenience for undo, not part of this design.
- Auto Config Backup, if enabled: server keeps the newest 100, 50 manual
  (P-ACB VERIFIED).

## 6. Restore test procedure

P-BACKUP (VERIFIED): backups must be tested, periodically, on a non-production
machine or virtual machine. P-ACB status page (VERIFIED) says the same and
describes making a change after a backup and checking the restore does not
contain it. Quarterly, matching the drill in `docs/backup-restore.md`:

1. Pick the newest ciphertext on the NAS, and separately the newest object in
   S3 (this proves the offsite path, not just the NAS).
2. Fetch the restore key from Doppler on the owner's workstation (no copy on
   the NAS). Decrypt. Confirm the SHA-256 matches the manifest.
3. Check it is XML (`xmllint --noout`) and the root element is `pfsense`.
   Print only counts and versions, never the content.
4. Restore it into a spare or virtual pfSense of the same major version, using
   Diagnostics, Backup and Restore (P-RESTORE VERIFIED location). Check the
   caveat in P-RESTORE (VERIFIED): a backup from a lower or higher
   configuration revision is handled differently, so the drill VM matches the
   firewall version.
5. Confirm the interface assignments prompt, the rule count, a VPN or
   certificate entry and the update-metric Telegraf entry exist.
6. Key-loss drill once a year: decrypt using only the offline copy of the key.
7. Record the date and result (one line in the ops journal). A drill older
   than 100 days is a warning and older than 130 days is critical (proposal;
   quarterly plus grace, same shape as above, for the owner to approve).

Never restore a test file onto the production firewall. Never drill with the
real firewall's network reachable from the VM (a restored config would try to
take over addresses): isolate the VM.

## 7. ACCESS LIST (one list, ask once)

Everything the whole job needs. Nothing broader is requested as a fallback.
Items marked OWNER need the owner's hands or consent; LEAD can be done by the
lead session through an implementer agent with no owner credential. Cost gates:
only S3 storage and requests (cents per month, INFERRED), nothing else is
paid; Auto Config Backup is free (P-ACB VERIFIED).

### 7.1 Firewall (fw.example.internal)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| F1 | Local user `backup-ro` | A dedicated identity for the pull; audit trail | Privilege "User - System: Shell account access" only, no root, no admin group; long random password that is never used; key login only | OWNER (GUI) |
| F2 | Authorized key line on `backup-ro` | Lets the NAS, and only the NAS, read the config | `from=` NAS address, `command="cat /cf/conf/config.xml"`, `no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`; ed25519; public half only travels | OWNER (paste), LEAD drafts the exact line |
| F3 | SSH enabled, port known | The pull needs it | Already on (the owner has read the box over SSH); no change unless F4 | OWNER |
| F4 | "SSHd Key Only" to Public Key Only (**OPEN**) | Removes password SSH for all accounts | Optional hardening; owner confirms his own key first | OWNER (decision pending) |
| F5 | Firewall rule NAS address to SSH port | Only needed if the NAS is not on the LAN interface | Source one NAS address, destination the firewall address, one port | OWNER |
| F6 | sudo package with one rule | Only if the config file is not readable by `backup-ro` | `cat /cf/conf/config.xml` only | OWNER, only if needed |
| F7 | (Optional, **OPEN**) Enable Auto Config Backup | Independent third copy | Frequency "On Every Configuration Change" (P-ACB VERIFIED option); a long encryption password; device key saved. Both are secrets: they go into Doppler, never into a file or chat | OWNER |

### 7.2 NAS (nas.example.internal)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| N1 | Shared folder `pfsense-backup` | One home for ciphertext, manifest, status file | No guest access; not shared with anything else | OWNER |
| N2 | Account `svc-pfpull` | Runs the scheduled pull and S3 copy | Read and write on that folder only; no admin rights; no inbound login by SMB; holds the SSH private key (ed25519, mode 0600, no passphrase so it can run unattended; usable only from the NAS address and only to read one file) | OWNER |
| N3 | Account `svc-pfmon-ro` | The monitor reads status and file ages | Read-only on that folder; SMB use only | OWNER |
| N4 | Task Scheduler entry, daily | Runs the pull (INFERRED that DSM Task Scheduler can run a user script as a chosen user) | Runs as `svc-pfpull`, not root | OWNER |
| N5 | Encryption tool on the NAS (age or GPG), public recipient only | Encrypt on arrival | No private key present. If installing a binary, inspect first (owner rule: inspect before install) | OWNER installs, LEAD supplies script and pinned hash |
| N6 | (Optional) snapshots of the share | A second integrity layer | Snapshot only; no extra account | OWNER |

### 7.3 S3 (bucket `fw-config-backup-example`; S3 or S3-compatible, policy shown in AWS terms)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| S1 | Bucket | Offsite copy | Block all public access; versioning on; Object Lock enabled at creation (INFERRED: cannot be added later on some providers); TLS-only policy (deny when not secure transport); default encryption on | OWNER |
| S2 | Writer credential `pfbackup-put` | The NAS copies new files | `s3:PutObject` and `s3:ListBucket` on the one prefix; no delete, no bucket policy, no lifecycle changes | OWNER creates, value into Doppler |
| S3 | Reader credential `pfbackup-read` | Restore drill only | `s3:GetObject`, `s3:GetObjectVersion`, `s3:ListBucket` on the prefix; used from the owner's workstation, never stored on the NAS | OWNER |
| S4 | Lifecycle rule | Expire non-current versions after 365 days | Bucket setting, no credential | OWNER |

### 7.4 Doppler (project `homelab`, config `prd_network`, as named by the owner)

**OPEN** (owner decision pending): whether the backup secrets go in config
`prd_network` or a dev config first.

Note: the dev-before-prd rule applies to new projects; this is an existing
live project and config the owner named, so no dev config is proposed. Reject
if you want a dev first.

| # | Secret name | Why | Holder |
|---|-------------|-----|--------|
| D1 | `PFSENSE_BACKUP_AGE_IDENTITY` | Restore key (private half), for drills and disaster recovery only | Owner reads it; never on the NAS or in CI |
| D2 | `PFSENSE_BACKUP_S3_PUT_KEY_ID`, `PFSENSE_BACKUP_S3_PUT_SECRET` | The NAS upload (copied to the NAS task by the owner) | Source of truth for rotation |
| D3 | `PFSENSE_BACKUP_S3_READ_KEY_ID`, `PFSENSE_BACKUP_S3_READ_SECRET` | Restore drill | Owner |
| D4 | `PFSENSE_BACKUP_MON_SMB_PASSWORD` | The monitor's read-only mount of the share | The monitoring host reads it with its existing secret-reader pattern |
| D5 | (Optional) `PFSENSE_ACB_DEVICE_KEY`, `PFSENSE_ACB_ENCRYPTION_PASSWORD` | Third copy recovery; P-ACB (VERIFIED) says a lost encryption password makes backups unrecoverable | Owner |

Not stored in Doppler: the NAS-to-firewall SSH private key. It is rebuildable
(generate a new pair, paste a new public line) and a copy elsewhere only widens
exposure.

Setting a secret: `doppler secrets set NAME` can echo the value, so every
command given to the owner ends `> /dev/null`, and the value is entered at a
prompt, never put on the command line (the prompt behavior is INFERRED; the
exact command will be given in full with each request).

### 7.5 Metric and Grafana side

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| M1 | Telegraf exec input on the monitoring host | Emits the metrics | Runs the checker script; reads the share through D4; writes InfluxDB with the existing Telegraf credential (no new token; INFERRED that one exists for the existing inputs) | LEAD writes the script and test, OWNER deploys |
| M2 | Grafana alert rules file (paused) | Alerts in section 4 | Repo file only; existing `influxdb-pfsense` datasource and `n8n-grafana-router` contact point | LEAD (PR) |
| M3 | Unpause after data arrives | Avoid false alerts | One click or one line | OWNER or LEAD with OK |

### 7.6 Read-only verification the owner runs on the firewall first

The firewall shell is csh, so each line is wrapped in `sh -c` with single
quotes and contains no `!` or `$`. None prints a secret (they print counts,
file names, sizes, dates, element names, log lines). Run each at the firewall
shell and send me the output. Together they answer whether Auto Config Backup
works and where config revisions are written.

1. Is Auto Config Backup logging? (P-ACB status page VERIFIED: success and
   failure lines are in the System log, General tab, and mention
   `acbupload.php` and `services_acb_backup.php`.)
   ```
   sh -c 'grep -i acb /var/log/system.log | tail -n 20'
   ```
2. How big is the log, did it rotate? (explains "no lines seen")
   ```
   sh -c 'ls -l /var/log/system.log*'
   ```
3. Which Auto Config Backup elements exist in the config (names only, no
   values)?
   ```
   sh -c 'grep -o -i "<[a-z_]*acb[a-z_]*>" /cf/conf/config.xml | sort -u'
   ```
4. Is there an Auto Config Backup staging area or file anywhere?
   ```
   sh -c 'find /cf /var /tmp -maxdepth 3 -iname "*acb*" 2>/dev/null'
   ```
5. Which cron line runs the upload job?
   ```
   sh -c 'grep -i acb /etc/crontab'
   ```
6. Where are config revisions written, and how many?
   ```
   sh -c 'ls -ld /conf /cf/conf /cf/conf/backup'
   ```
   ```
   sh -c 'ls -lt /cf/conf/backup | head -n 6'
   ```
   ```
   sh -c 'ls /cf/conf/backup | wc -l'
   ```
7. Can a non-root user read the config (decides F6)? Owner, group and mode:
   ```
   sh -c 'ls -l /cf/conf/config.xml'
   ```
8. SSH daemon settings relevant to the pull (names and values, no keys):
   ```
   sh -c 'grep -E "^(PermitRootLogin|PasswordAuthentication|AuthenticationMethods|PubkeyAuthentication|AuthorizedKeysFile|AllowUsers)" /etc/ssh/sshd_config'
   ```
9. In the GUI, the Restore tab of Services, Auto Config Backup lists backups
   on the server and notes staged entries (P-ACB status page VERIFIED). If it
   is empty or the menu shows it disabled, ACB is not running. A screenshot
   of that tab is enough.

After the user and key exist, the proof of the whole pull from the NAS
(prints only a byte count, never content):
```
ssh -i ~/.ssh/pfpull_ed25519 backup-ro@fw.example.internal | wc -c
```

What I read earlier about the box, interpreted (all labeled):

- The every-minute cron line is consistent with P-ACB (VERIFIED: once per
  minute AutoConfigBackup checks for staged backups). That the line exists
  even when ACB is disabled is INFERRED.
- The newest revision dated 26 November is the on-box history, not an
  uploaded backup: P-RESTORE (VERIFIED) says the firewall keeps previous
  configurations itself. The directory is INFERRED to be `/cf/conf/backup`
  until command 6 confirms it.
- The ACB state is unknown (UNVERIFIED) until commands 1 to 5 and 9 are read.
  The owner's statement that no backup is set up matches ACB being off.

## 8. Build order and who does what

| Step | Who | Depends on |
|------|-----|------------|
| 1. Run 7.6 commands, send output | OWNER | none |
| 2. Approve this note, thresholds and the access list in one answer | OWNER | 1 |
| 3. Draft pull script, encrypt step, status file, checker script, Grafana rules, tests (repo PRs) | LEAD via implementer | 2 |
| 4. Create F1, F2, N1 to N5, S1 to S4, D1 to D4 | OWNER (LEAD supplies each full command or exact text) | 2 |
| 5. Dry run of the pull with `wc -c`, then first real pull, then first restore drill | OWNER runs on the live hosts, LEAD verifies the output | 3, 4 |
| 6. Unpause the rules once metrics arrive | LEAD with OK | 5 |
| 7. Optional: ACB as a third copy | OWNER | 1 |

## 9. INFERRED claims in this note (check before relying on them)

1. `/conf` is a link to `/cf/conf`. P-XML says `/conf/config.xml`, P-RESTORE and P-REMOTE say `/cf/conf/config.xml`.
2. `config.xml` contains VPN, certificate private keys, pre-shared keys and tokens, and only password hashes for local users.
3. The on-box config history directory is `/cf/conf/backup` (taken from the brief, not from a page).
4. The every-minute cron line exists even when ACB is disabled.
5. The firewall's log file is plain text at `/var/log/system.log` (page says "System Logs, General" only).
6. The Authorized Keys field accepts option prefixes (`from=`, `command=`) and sshd enforces them; the pfSense user needs no extra step.
7. `/cf/conf/config.xml` is readable by a non-root user.
8. ACB stores its device key and encryption password inside `config.xml`; the server side offers no custom freshness hook.
9. DSM offers shared folder encryption, Task Scheduler with a user script, and immutable snapshots on this model; the NAS can run `age` or `gpg`, `rclone` or the AWS CLI.
10. S3 Object Lock must be enabled when the bucket is created; default encryption, versioning and the described policy behave as in AWS; S3 cost is cents per month; the provider may be S3-compatible rather than AWS.
11. The firewall config file is a few hundred kilobytes at most.
12. `doppler secrets set NAME` prompts for the value when none is given.
13. A Telegraf write credential already exists for the monitoring host's InfluxDB; the existing monitoring secret-reader pattern can read D4.
14. Pfblockerng and other package data are re-fetched after restore; the update-metric script and Telegraf snippet live outside `config.xml`.
15. The Pi UniFi backup design was not available; its alerting shape is taken only from the owner's stated 8-day and 15-day rule.
