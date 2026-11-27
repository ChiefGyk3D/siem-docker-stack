# pfSense configuration backup: encrypt on the firewall, NAS first, S3 second (design note, revision 2)

Status: design for review, nothing deployed. Issue #236, epic #62. Revision 2
answers the round 1 adversarial review of PR #242 (four High, seven Medium).
Owner decisions are marked **DECIDED**; what is undecided is marked **OPEN**;
what only the owner may accept is marked **OWNER DECISION**. All hostnames and
addresses are placeholders: `fw.example.internal` is the firewall,
`nas.example.internal` is the NAS, `mon.example.internal` is the host that
runs monitoring.

Every claim is labeled **VERIFIED** (source page and the date it was read) or
**INFERRED** (reasoned or remembered, not read from a source, to be checked
before the step that depends on it). A vendor fact that has not been read is
never written as fact: it is an **OPEN** question with the exact question
(section 10) and the design below it holds for each plausible answer (a
decision table). The list of every INFERRED claim is in section 9.

## 0. Review findings map (round 1, PR #242)

| Id | Sev | Fixed in | How, in one line |
|----|-----|----------|------------------|
| R1-01 | High | 1.2, 2.2 | The forced command on the firewall encrypts to a recipient pinned on the firewall; the NAS only ever receives ciphertext. **DECIDED** (owner, 2026-11-27, "Encrypt on the firewall"). |
| R1-02 | High | 1.3, 2.2, 6 | Recipient pinned in a root-owned file on the firewall; its fingerprint is recorded outside NAS control; restore drill and monitor reject any other recipient. |
| R1-03 | High | 4 | Monitor trusts only a firewall-signed receipt (verification key held by the monitor) and independent S3 state; NAS mtime is liveness only. |
| R1-04 | High | 5.2, 7.3, 10 (Q8, Q9) | Object Lock mode, retention, mechanism, bypass denial and a negative test specified; provider and mode confirmation are **OPEN**, irreversible mode is an **OWNER DECISION**. |
| R1-05 | Med | 3, 4.2 | Signed, chained receipts (sequence, hashes, recipient fingerprint, previous-receipt hash); monitor keeps its own head. |
| R1-06 | Med | 4.4, 7.3 (S5) | A separate monitor-only S3 identity (list and read on the prefix); the NAS never computes S3 state for the monitor. |
| R1-07 | Med | 2.3, 7.2 (N7) | Firewall host key pinned in an admin-owned `known_hosts` on the NAS, strict checking, fail closed; the receipt signature is a second check. |
| R1-08 | Med | 2.1, 2.4, 7.1, 8.1 | Absolute-path root-owned wrapper, `restrict` plus forced command, exact no-argument sudo rule, negative tests; the mechanism facts stay **OPEN** until proven on the appliance. |
| R1-09 | Med | 7.4 | Per-role configs and readers; project layout is an **OWNER DECISION** (dedicated project versus the decided `homelab` dev config). |
| R1-10 | Med | 3, 4.3, 6 | Semantic checks on the firewall, signed size and count facts, monitor bounds and change-rate alerts, three distinct validity levels. |
| R1-11 | Med | 5.1, 7.2 (N2, N8) | Create-only ingest identity, no automated pruning on the NAS, immutable snapshots required; unavailable snapshots are an **OWNER DECISION**. |
| Tests | n/a | 8 | Required negative tests: SSH key abuse, wrong recipient, forged monitor input, lock bypass. |
| R2-01 | Med | 2.2 steps 0, 4, 5; 8.5 (C1 to C3) | Exclusive non-blocking lock; reserve `seq` and persist the exact receipt hash atomically before emitting; `pending` flag and carry-over records after an interrupted emission. |
| R2-02 | Med | 4.2, 4.3 | Every pull uploads its own ciphertext; no dedupe, so check 5 has no exception; change detection by `change_marker`. Tests U1, U2. |
| R2-03 | Med | 2.2 steps 1 to 3; 8.5 (P1 to P4) | One snapshot from one descriptor for validate, hash and encrypt; no persistent-disk plaintext (memory-backed scratch, or stop); trap cleanup; post-encrypt re-read guard. |
| R2-04 | Med | 4.2 (canonical encoding and signing); 8.5 (G1 to G7) | Fixed-order text receipt, signed raw bytes, one configured algorithm, strict parse after verify. **Gate:** not approved until Q7 closes with the exact commands. |
| R2-05 | Med | 4.2 (Time), 4.3, 4.4; 8.5 (K1 to K4) | Freshness from the earlier of `fw_time` and the monitor's own first-seen time; future `fw_time` is receipt-invalid and critical. |
| R2-06 | Med | 7.6; 12; 8.5 (X1) | `wc -c` proof removed; stateless self-test script plus the first real pull as the production ingest with pinned host key. |
| R2-07 | Low | 1.2, 1.4, 4.2; D-R8 | Receipt metadata described honestly and minimized (bands, keyed change marker, inner encrypted record); remaining exposure is an **OWNER DECISION**. |
| Commands | n/a | 7.6 | Command 1 no longer prints raw log lines; readability is tested as the real user; tool checks added. |

Round 1 also asked for these to be stated. Detection can lag the goal: with a
warning at 2 days and a critical at 3 days, a backup can be more than one day
old before anything alerts (section 4.5).

## Sources

Read on 2026-11-27 (Netgate pfSense documentation, `latest`):

| Short name | Page |
|------------|------|
| P-BACKUP | `https://docs.netgate.com/pfsense/en/latest/backup/index.html` (Backup and Recovery) |
| P-ACB | `.../backup/acb.html`, `acb-info.html`, `acb-config.html`, `acb-status.html` (Automatic Configuration Backup) |
| P-REMOTE | `.../backup/remote-backup.html` (Alternate Remote Backup Techniques) |
| P-RESTORE | `.../backup/restore.html` (Restoring from Backups) |
| P-XML | `.../config/xml-configuration-file.html` |
| P-ADMIN | `.../config/advanced-admin.html` (Secure Shell section) |
| P-PKG | `.../packages/backup.html` (Backup package) |

Also read on 2026-11-27 (S-names are used below):

| Short name | Page |
|------------|------|
| S-SSHD | `https://man.openbsd.org/sshd.8`, AUTHORIZED_KEYS FILE FORMAT (upstream OpenSSH; the build on the firewall may be older or patched, so every option behavior is also a test in section 8; that FreeBSD's sshd matches is INFERRED) |
| S-FBSD-OSSL | `https://man.freebsd.org/cgi/man.cgi?query=openssl&sektion=1&manpath=FreeBSD+14.0-RELEASE` (FreeBSD 14.0 openssl(1)) |
| S-NG-REL | `https://docs.netgate.com/pfsense/en/latest/releases/25-11.html` (Plus 25.11 notes) |
| S-OSSL-CMS | `https://docs.openssl.org/3.0/man1/openssl-cms/` |
| S-NG-PKGLIST | `https://docs.netgate.com/pfsense/en/latest/packages/list.html` and `.../packages/index.html` |
| S-NG-FBPKG | `https://docs.netgate.com/pfsense/en/latest/recipes/freebsd-pkg-repo.html` |
| S-NG-PRIV | `https://docs.netgate.com/pfsense/en/latest/usermanager/privileges.html` |
| S-NG-SSHREC | `https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html` |
| S-NG-SUDO | `https://docs.netgate.com/pfsense/en/latest/packages/sudo.html` |
| S-AGE | `https://raw.githubusercontent.com/FiloSottile/age/main/README.md` |
| S-AWS-OL | `https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html` and `.../object-lock-configure.html` |
| S-B2-OL | `https://www.backblaze.com/docs/cloud-storage-object-lock` |
| S-WAS-OL | `https://docs.wasabi.com/docs/object-locking` |
| S-R2 | `https://developers.cloudflare.com/r2/api/s3/api/` |
| S-FORUM | `https://forum.netgate.com/post/752086` (a forum post, weak evidence) |

Facts from the researcher agent were read from these pages on 2026-11-27;
S-B2-OL and S-WAS-OL are tool extracts and S-NG-PKGLIST is a tool extract.

Repo prior art read: `docs/backup-restore.md` (OpenSearch snapshots and
offsite copy, the 3-2-1 and restore-drill habit), `docs/update-alerting.md`
and `scripts/pfsense-update-metric.sh` (the Telegraf exec to InfluxDB to
Grafana to n8n alert path, pfSense rules shipped paused, `noDataState` and
`execErrState` set to Alerting), `docs/heartbeat.md`, and `.env.example`
(secrets live in Doppler project `homelab`, config `prd_network`). The local
notes under `~/src/*/docs` hold no prior art on age, GPG, Object Lock or
authorized_keys for this job. The Pi UniFi backup design was NOT found in this
repo or the local notes; I used only the owner's stated rule for it (newest
NAS copy age, warning at 8 days, critical at 15 days for weekly UniFi
backups).

## 1. Goal and threat model

Goal: a restorable copy of the firewall configuration exists off the
firewall, is no more than one day behind, survives loss of the firewall, the
NAS, or either site, and nobody can read its secrets who should not, including
someone who has taken over the NAS.

### 1.1 What is in the file

P-XML (VERIFIED): all settings, including package settings, are held in one
XML file, `/conf/config.xml`. P-BACKUP (VERIFIED) says one file restores a
system to a working state in the vast majority of cases, that backups "can
contain sensitive information", and that packages may keep files outside
`config.xml`. P-RESTORE (VERIFIED) gives the location as
`/cf/conf/config.xml`. That `/conf` is a link to `/cf/conf` is INFERRED. That
the file holds VPN keys, certificate private keys, pre-shared keys and API
tokens (password hashes for local users) is INFERRED from how pfSense works;
treat the whole file as a secret of the highest class.

### 1.2 Actors and what each gains (round 1: R1-01)

| Actor | Gains under this design | Residual |
|-------|-------------------------|----------|
| Thief of a NAS disk or of the bucket | The configuration is ciphertext only. Receipt metadata is visible (R2-07): pull timing, ciphertext size, coarse size and count bands, epoch and sequence, and whether the configuration changed between pulls (a keyed change marker, not a hash anyone can recompute). Exact counts, revision and the plaintext hash are in an encrypted inner record. | Metadata exposure is **OWNER DECISION** D-R8; otherwise none beyond the cipher |
| Attacker who controls the NAS (root, or the `svc-pfpull` account) | Can use the pull key to fetch the current ciphertext. Cannot read it: no private key exists on the NAS and the recipient is pinned on the firewall, not the NAS. Can delete or roll back NAS copies (section 5.1), withhold uploads, replay old receipts. Cannot forge a receipt, cannot make the monitor believe a fresh backup exists. | Availability of the NAS copy only; S3 holds the locked copy. |
| Attacker on the management LAN | Reaches the firewall SSH port; the key is bound to the NAS source address and one command | Source address pinning depends on what sshd observes (section 2.4) |
| Attacker who controls the firewall (root) | Can encrypt or sign anything, so can poison future backups, and can read the config anyway | **OWNER DECISION** D-R1: accepted by nature (the firewall is the data source); bounded by retention of older versions, semantic and change-rate alerts (4.3) and the restore drill |
| Attacker who controls the monitor host | Can silence alerts | Out of scope of this note; the monitor host is a trust anchor (verification key, expected recipient fingerprint) |
| Owner mistake: lost restore key, wrong recipient, bad config | Unrecoverable offsite copy | Key custody (1.3), fingerprint check (1.3), drill (6) |

The plaintext `config.xml` therefore exists only on the firewall and, briefly,
on the owner's workstation during a restore. It never exists on the NAS, on
the wire between the firewall and the NAS other than inside the ciphertext
(SSH still encrypts the transport), or in S3.

### 1.3 Key custody and recipient pinning (R1-02)

- The restore key pair is generated on the owner's workstation, never on the
  NAS or the firewall. The firewall receives only the public recipient.
- The recipient is pinned in a root-owned, not-user-writable file on the
  firewall (path **OPEN**, Q3). The pull user `backup-ro` cannot modify it.
  Changing it needs firewall root, which already equals full compromise of the
  config, so the NAS cannot swap the recipient (**DECIDED** direction).
- The recipient fingerprint is recorded in three places outside NAS control:
  the owner's offline record, the monitor's root-owned config on
  `mon.example.internal`, and every signed receipt (4.2). It is never read
  from the NAS when it is used to judge a backup.
- The restore drill and the monitor reject a ciphertext or receipt whose
  recipient fingerprint is not the expected one (tests W1 to W4, section 8).
- Stored in the secret manager (section 7.4) and in one offline copy under the
  owner's physical control. Anyone who can read the restore key can read every
  backup, so its config has the narrowest reader list of all (7.4).
- Rotation: a new key pair means a new recipient pinned on the firewall, a new
  expected fingerprint on the monitor, and a receipt `epoch` increment (4.2);
  old ciphertext needs the old key kept. Never delete an old key while any
  ciphertext made with it exists.

### 1.4 Property table

| Property | Risk | Control |
|----------|------|---------|
| C in transit | Sniffing | SSH only, over the management network. P-REMOTE (VERIFIED) warns the wget and curl pull methods run over HTTPS with certificate checking disabled; non-encrypting techniques should use a non-WAN link or a VPN. The payload is also ciphertext before it enters SSH. |
| C at rest, NAS and S3 | Stolen disk, NAS compromise, bucket exposure | Ciphertext only for the configuration, produced on the firewall (2.2); receipt metadata is limited as in 1.2 and 4.2. Block public access, TLS-only bucket policy, default server-side encryption as a second layer (INFERRED, check at build). |
| C on the firewall | Pull key abuse | `restrict` plus forced command to a no-argument root-owned wrapper (2.1), no NAS or S3 credential on the firewall. |
| I | Tampered, truncated, poisoned or rolled back backup | Signed chained receipts, semantic checks, monitor-side state and S3 object lock (sections 3, 4, 5). |
| I | History deleted | S3 versioning, Object Lock with retention, writer cannot delete or change retention; NAS history is a convenience copy (5.1). |
| A | Firewall dead | NAS copy and S3 copy; the firewall also keeps its own history (P-RESTORE VERIFIED: the previous 30 configurations by default), which is not disaster recovery (P-BACKUP VERIFIED). |
| A | NAS dead or rolled back | S3 copy, independently checked by the monitor. |
| A | Restore key lost | Key custody (1.3). Without the key the offsite copy is useless; the real single point of failure. |

## 2. Options compared and the pull design

### 2.1 Recommendation

NAS pull over SSH with a restricted key whose forced command is a root-owned
wrapper on the firewall that validates, encrypts to the pinned recipient and
signs a receipt. Options B (Auto Config Backup) and C (firewall push) stay as
before, with this change to the verdict on A.

| | A. NAS pull, forced command encrypts on the firewall (recommended) | B. Auto Config Backup package | C. Firewall pushes (scp or rsync) |
|---|---|---|---|
| What it is | The NAS runs `ssh backup-ro@fw.example.internal`; the forced command prints receipt plus ciphertext. | Core pfSense feature: on change or schedule it encrypts the config (AES-256-CBC with your password) and uploads it over HTTPS to Netgate, newest 100 per device key (P-ACB, VERIFIED). | A cron on the firewall copies the file out. P-REMOTE (VERIFIED) documents `scp` push, and a cron plus a passphrase-less key. |
| Credentials on the firewall | A receipt signing key and a public recipient; no NAS or S3 credential. | Device key and encryption password, stored in the config itself (INFERRED). | A passphrase-less private key to the NAS; P-REMOTE (VERIFIED) calls this "insecure", "adds risk". |
| Confidentiality | NAS never sees plaintext. | Encrypted before leaving; Netgate holds the ciphertext. Free for Plus and CE (P-ACB, VERIFIED). | Plain unless encrypted on the firewall; the NAS user is reachable from a compromised firewall. |
| Integrity and history | Signed receipts, locked S3 history. | 100 entries max, 50 manual (P-ACB, VERIFIED); no custom freshness hook (INFERRED). | A compromised firewall can overwrite or delete what it can write. |
| Availability | Needs the NAS and management path; a missed run is caught by the monitor. | Works without your NAS; depends on Netgate and the firewall's Internet. | Fails silently if the cron or key breaks. |
| Cost | None | None (VERIFIED, free) | None |

Verdict: A is the primary. B is worth enabling after it is verified working,
as an independent third copy. C is rejected: it puts a standing credential for
the NAS on the most exposed device. Also rejected: GUI pulls with wget or curl
(P-REMOTE VERIFIED: needs the GUI admin login in a script, often disables
certificate checks) and `ssh root@fw cat ...` as written in P-REMOTE (VERIFIED
text), because it needs an administrative key on the NAS and returns plaintext.

### 2.2 The forced command and the encryption (R1-01, R1-02)

The forced command is one absolute path to a root-owned wrapper script
(`<wrapper-path>`, placeholder; location **OPEN**, Q3, because it must survive
a firmware upgrade). It takes no arguments and ignores the command the client
sent: S-SSHD (VERIFIED) says the user-supplied command is ignored when
`command=` is set and is only exposed in `SSH_ORIGINAL_COMMAND`; the wrapper
never reads it. The wrapper does, in order and failing closed on any error:

0. **Single writer (R2-01).** Takes an exclusive, non-blocking lock first
   (lock file in the root-owned state directory). If it cannot, it exits
   non-zero at once without reading anything, so two concurrent pulls can never
   both reserve the same `seq`. The lock must be released by the operating
   system when the process dies, so a crash cannot wedge the job (INFERRED for
   the chosen lock tool, **OPEN** Q16).
1. **One snapshot (R2-03).** Reads `/cf/conf/config.xml` exactly once, from one
   open file descriptor (as root through the exact sudo rule of F6 when
   needed, 2.4), into a snapshot. Validation, hashing, counting and encryption
   all use that snapshot and nothing else. Plaintext never touches persistent
   disk: the snapshot lives in process memory or, if the implementation needs
   a file, in a mode 0600 file under a root-only directory on a memory-backed
   filesystem (availability **OPEN**, Q16; if none exists the design stops and
   returns to the owner, it does not fall back to disk), removed by a trap on
   every exit path including failure. As a consistency guard the wrapper
   re-reads the live file after encrypting and compares its hash with the
   snapshot's hash; on a difference it retries once, then fails closed.
2. Semantic checks (R1-10, section 3) on the snapshot. On failure: prints
   nothing on stdout, an error line on stderr, exits non-zero, state unchanged.
3. Encrypts the snapshot to the pinned recipient from the root-owned file.
   The ciphertext is held in the same kind of memory-backed, root-only,
   trap-cleaned buffer until its hash is known; it is not emitted before the
   receipt is signed.
4. **Reserve, then emit (R2-01).** Builds the receipt (4.2) with the next
   `seq` and the hash of the previous receipt, signs it, and persists to the
   state directory, atomically (write a new file, flush, rename over the old
   one): the new `seq`, the exact receipt hash, and a `pending` flag. Only
   then writes the stream (a fixed-length header line with the receipt length,
   the receipt, then the ciphertext; exact framing fixed in the
   implementation PR).
5. Clears `pending` only if every byte was written without error. If the
   client disconnected or a write failed, `pending` stays set and the receipt
   is kept (receipts only, no plaintext, in the root-only state directory).
   The next run begins its stream with every pending receipt as carry-over
   records, followed by its own receipt and ciphertext, so the chain the
   monitor sees is unbroken and the lost emission is visible as a warning (the
   ciphertext of an interrupted emission is not retained; the new run covers
   the current state). A write error being observable when the client
   disconnects is INFERRED and is test C2.

**Tool choice (lead decision, security lean, least unsupported change):**
`openssl cms -encrypt` with an explicit cipher (`-aes256`) to a recipient
**certificate**, public half only on the firewall. Why: the `openssl`
subcommands `cms`, `smime`, `pkeyutl` and `enc` exist in the FreeBSD base
(VERIFIED, S-FBSD-OSSL), pfSense Plus 25.11 notes say OpenSSL 3.5.3 (VERIFIED,
S-NG-REL), so nothing needs installing. Not stated on any page: the OpenSSL
version of the owner's firewall (CE does not state one); it stays INFERRED
until the owner runs `openssl version` (command 11). The Netgate package list
shows Sudo and no age, gnupg or openssl package (VERIFIED, S-NG-PKGLIST), and
installing FreeBSD packages from the shell is "not recommended or supported by
Netgate" (VERIFIED, S-NG-FBPKG), so age and gpg are not the primary.

Facts about `openssl cms -encrypt` (VERIFIED, S-OSSL-CMS): it defaults to
triple DES unless a cipher such as `-aes256` is given, so the cipher is always
explicit and a test (W6, section 8.2) fails if it is missing; recipients are
certificates and `-recip` can be repeated (a second, offline recipient is
possible and is an option the owner may take for key-loss insurance); decrypt
needs the private key. Pin the recipient by the SHA-256 fingerprint of the
certificate (`openssl x509 -fingerprint -sha256`, INFERRED as the way to print
it), compared over a second channel at restore time (INFERRED). The
certificate is self-signed or from a private CA generated on the owner's
workstation, with the private key staying there. Signing the receipt is done
with the same tool family (the `cms` or `pkeyutl` subcommand; exact signing
flags **OPEN**, Q7).

| If the firewall's check (commands 10 and 11) shows | Then encryption | Then signing | Notes |
|---|---|---|---|
| `openssl` with `cms` and a cipher such as AES-256 | **Primary.** `openssl cms -encrypt -aes256` to the pinned certificate | Detached signature with a dedicated firewall signing key, same tool | No new software on the firewall. |
| `openssl cms` missing or too old to behave as above | Fallback: `age` as a static binary or a FreeBSD port package (exists, S-AGE README; that it runs on pfSense is INFERRED; unsupported by Netgate) | age does not sign; sign the receipt with `openssl pkeyutl` if present, else a second small signing tool. A MAC with a shared secret is **not allowed** (the secret would sit on the firewall) | Needs inspect-before-install first; **OWNER DECISION** D-R2. age has no fingerprint feature: pin the full `age1...` recipient string and compare it over a second channel (INFERRED). Whether an age file reveals its recipient is not established; the recipient is then asserted inside the signed receipt. |
| only `gpg` (not in the Netgate package list) | Encrypt to a pinned public key, pinned by full fingerprint (INFERRED) | Detached signature with a signing subkey | Same install caveat. |
| none | Stop; either D-R2 or option B only, and record that the NAS-compromise gap (R1-01) is then open again | | |

Read-only commands 10 and 11 in section 7.6 settle which row applies.

### 2.3 NAS side of the pull (R1-07)

- The NAS pulls with a dedicated key and a pinned firewall host key: the host
  key fingerprint is read on the firewall console by the owner (command 12,
  7.6), written to a `known_hosts` file that is root-owned on the NAS and not
  writable by `svc-pfpull`, and the ssh client is run with strict host key
  checking and that file only (option names **OPEN**, Q10, to be taken from the
  ssh_config page). A host key change fails the job closed, does not advance
  anything and raises critical through the monitor (no new receipt).
- `from=` authenticates the client's address to the server; it does not
  authenticate the server to the NAS. Server authenticity therefore rests on
  the pinned host key plus the receipt signature: an impersonating server
  cannot produce a receipt that verifies under the monitor's key.
- The NAS script splits the stream, stores the receipt and the ciphertext,
  uploads both to S3, and never decrypts, never validates content (it cannot).

### 2.4 The restricted key and what must be proven

Authorized key line (placeholder address):

`from="<NAS address>",restrict,command="<wrapper-path>" ssh-ed25519 AAAA... pfpull@nas`

- S-SSHD (VERIFIED, upstream page, 2026-11-27): `restrict` disables port,
  agent and X11 forwarding, PTY allocation and `~/.ssh/rc`, and any future
  restriction added upstream; `command=` applies to shell, command and
  subsystem execution; the client command is ignored and exposed only as
  `SSH_ORIGINAL_COMMAND`; `from=` matches the remote host's canonical name or
  its IP address and accepts CIDR; a `ForceCommand` in `sshd_config` can
  supersede `command=`; `environment=` is off unless `PermitUserEnvironment`
  is enabled; `no-pty` is advised when an 8-bit clean channel is needed (our
  stream is binary, so `restrict` already implies it, and tests V1 and V2
  prove the channel is clean). Keep `no-agent-forwarding`, `no-port-forwarding`,
  `no-X11-forwarding` and `no-pty` explicitly in the line as well, so a build
  that lacks `restrict` still refuses them (**INFERRED** that the installed
  OpenSSH knows `restrict`; test T1 to T6 prove it).
- P-ADMIN and S-NG-PRIV (VERIFIED): the privilege "User - System - Shell
  account access" gives SSH login without root and without the console menu;
  by default only admin and root can use SSH. The Authorized Keys field is
  documented as one public key per line. **Nothing is documented about
  `command=`, `from=` or `restrict` surviving a save or a reboot** (VERIFIED
  absence); forum posts suggest keys are written from `config.xml` (INFERRED,
  weak); S-NG-SSHREC (VERIFIED) says not to manage keys from the shell
  directly. The shell such a user gets is **not documented** (Q5). So the
  option behavior is a **required pre-implementation lab test** (7.6 lab
  list, tests T1 to T7 on a lab firewall first, and a reboot check), not an
  assumption. If the GUI strips the options, the forced command moves to
  another mechanism chosen after the test (for example a per-user
  `ForceCommand` in a `Match` block, availability **OPEN**), and this note is
  revised before anything is built.
- Who can read `config.xml`: mode and owner are **not documented**; a forum
  post says it was world-readable on 2.4.2 (S-FORUM, weak, old). `ls -l` is
  not proof of effective access. If the user cannot read it (to be proven as
  that user, 7.6), the wrapper runs through sudo. The Sudo package exists
  (VERIFIED, S-NG-PKGLIST); its rules are under System > sudo, full paths are
  required, arguments listed there become mandatory, a blank command list
  means ALL (so a blank rule is forbidden), and files in `sudoers.d` are not
  included in backups (VERIFIED, S-NG-SUDO). Therefore: one rule, `backup-ro`
  may run exactly `<wrapper-path>` as root with the full path and no
  arguments, configured through the package (so it is in `config.xml` and
  restored), reset environment and no `SETENV` where the package allows
  (INFERRED). A generic `cat` rule is forbidden. A root key restricted with
  `command=` is the last resort and needs the owner's explicit OK.
- `from=` matches what sshd observes. If the NAS reaches the firewall through
  NAT or a VPN, the observed address is the egress or tunnel address and the
  restriction then covers everything behind it. The observed address is
  recorded before go-live (command in 8.1, **OPEN** Q13).
- Anti-lockout (P-ADMIN, VERIFIED) allows the SSH port from the whole LAN
  regardless of your rules, so a firewall rule cannot be relied on to narrow
  the LAN; the key restrictions are the decisive client boundary.
- Optional hardening (**OPEN**, owner decision pending): "SSHd Key Only" set to
  "Public Key Only" (P-ADMIN VERIFIED options exist). It also removes password
  login for the admin account, so the owner must confirm his own key first.

Pull schedule: once a day at a fixed time, plus on demand (**DECIDED**, owner,
2026-11-27). P-BACKUP (VERIFIED) advises a backup after each change and before
and after major changes, so the owner triggers the pull by hand around
planned work (one command on the NAS).

## 3. Validity levels (R1-10) and what the backup does not cover

A file is not "valid" because it parses. Three distinct levels, each recorded
in the receipt or the drill log:

| Level | Check | Where | Proves |
|-------|-------|-------|--------|
| L1 well-formed | Wrapper: file non-empty, size within bounds, ends with the root closing tag and starts with the `pfsense` root element; `xmllint` when it exists on the firewall (Q1), else the minimal textual check. | Firewall, before encrypting | Not truncated, not empty |
| L2 plausible | Wrapper: required top-level sections present (system, interfaces, filter, ...: the exact list is fixed from the real file, structure only, never values), counts of interfaces, rules and users above a floor; the configuration revision field (name **OPEN**, Q14) not lower than the previous receipt. These facts go into the signed receipt as numbers only. | Firewall; re-checked by the monitor from the receipt | Not an empty or minimal config; not an older revision presented as new |
| L3 restorable | The restore drill into an isolated matching-version VM (section 6) | Owner's workstation | It really restores |

The monitor adds change-rate rules from the receipts: size shrinking by more
than a set fraction, counts dropping, or revision going backwards raises a
warning for the owner to look at (a legitimate large cleanup is possible, so
it is a warning, never a block). A compromised firewall can still pass L1 and
L2 with a crafted file; that is the accepted D-R1 residual, bounded by locked
older versions and by L3.

What the backup does not cover:

- Files outside `config.xml`: P-BACKUP and P-PKG (VERIFIED) say some packages
  store data elsewhere and custom system file changes are not in the built-in
  backup. The Backup package (Diagnostics, Backup Files/Dir) can add paths;
  RRD data is excluded by default (P-BACKUP VERIFIED); out of scope here.
- The repo's own `pfsense-update-metric.sh` and its Telegraf exec snippet live
  on the firewall outside the XML file (INFERRED); the repo is their backup.
- The new wrapper, recipient file, signing key and sequence state live on the
  firewall outside `config.xml` (INFERRED). They must be rebuilt after a
  firewall rebuild from the runbook in `homelab-backup-tools`; the signing key
  is regenerated and the monitor's verification key updated by the owner at
  that time (receipt `epoch`, 4.2).
- pfBlockerNG lists and other package data (INFERRED): re-fetched after a
  restore.

## 4. Freshness measurement and alerting (R1-03, R1-05, R1-06)

### 4.1 Trust rule

Reading a file the puller wrote is trusting the puller. Round 1 found the
earlier sentence "the monitor does not trust the puller" unsupported, and it is
removed. New rule: **a file's mtime on the NAS is liveness information only,
never proof of a valid backup.** Proof comes from two sources the NAS cannot
forge: a receipt signed by a key the NAS cannot use, and independent S3 state
read with an identity the NAS does not hold.

### 4.2 The signed receipt

Produced by the wrapper on the firewall, one per pull, signed with a dedicated
firewall signing key (private half in a root-only file on the firewall; no
other copy). Fields:

Clear fields (readable by anyone holding the receipt, R2-07): `receipt_version`,
`epoch` (set by the owner at install and after a rebuild), `seq` (monotonic
within an epoch), `fw_time` (firewall clock, UTC), `cipher_sha256`,
`cipher_size`, `recipient_fingerprint`, `size_band` and `count_bands`
(coarse bands, not exact values, enough for the L2 and change-rate rules),
`change_marker` (a keyed hash of the plaintext, using a key that exists only
on the firewall; the monitor only compares it with the previous receipt's, it
cannot recompute it, and it cannot confirm a guessed configuration),
`prev_receipt_sha256` (hash of the previous receipt in this chain).

Inner fields (R2-07): `plain_sha256`, exact `plain_size`, exact counts,
`config_revision` (Q14) and `tool_versions` are placed in a second record
encrypted to the same recipient and referenced from the signed receipt by its
hash. Only the owner, who holds the restore key, reads them (restore drill
steps 2 to 4). The monitor never needs them.

Metadata that remains visible to a thief of the NAS disk or the bucket, stated
honestly: the existence and timing of each pull, the ciphertext size (which
approximates the configuration size), the coarse bands, the epoch and `seq`,
and whether the configuration changed between pulls. This is **OWNER DECISION**
D-R8 (accept it, or coarsen further at the cost of weaker monitor rules).

**Canonical encoding and signing (R2-04).**

- The receipt is ASCII text: one `name=value` field per line, LF line ends,
  fields in one fixed order, each field exactly once, values limited to a
  small character set (letters, digits, `.`, `_`, `-`, `:`), no leading or
  trailing space, a final LF.
- The signed bytes are exactly the receipt bytes as emitted, nothing
  re-serialized. The signature is a separate detached record, in a fixed
  binary or text encoding fixed in the implementation PR.
- The monitor first verifies the signature over the raw received bytes with
  the one algorithm and key it is configured with (the algorithm is never read
  from the receipt or the signature record), and only then parses those same
  bytes with a strict parser that rejects unknown, duplicate, reordered or
  missing fields, a wrong `receipt_version`, and trailing bytes.
- Key type and signature scheme (requirements, because the installed
  OpenSSL's signing flags are not yet read, Q7): an Ed25519 key if the
  installed OpenSSL supports it (INFERRED), else ECDSA P-256 with SHA-256,
  else RSA at 3072 bits or more with SHA-256. Exactly one is configured on
  the monitor. **Gate: this section is not approved until Q7 is closed** with
  the exact signing and verification commands from the OpenSSL manual of the
  installed version, and those commands are the ones the tests in 8.5 run.
- Tests G1 to G7 in 8.5 prove field reordering, duplicates, algorithm
  substitution and a signature over different bytes are all rejected.

- The verification (public) key is held by the monitor, in a root-owned
  config on `mon.example.internal`, and by the owner offline. It is installed
  on the monitor by the owner from the offline record, never fetched over the
  network from the firewall or the NAS. The NAS holds no trust anchor and
  cannot sign: the private half exists only on the firewall. The monitor host
  must not share administrators, credentials or a compromise domain with the
  NAS (a requirement, test X2); otherwise the independence claimed in 4.1 does
  not hold. Signing tool and key type follow the 2.2 table (**OPEN**, Q1, Q7).
- The monitor keeps its own state (last accepted `epoch`, `seq`,
  `prev_receipt_sha256`, `recipient_fingerprint`) on the monitoring host, not
  on the NAS. A NAS rollback to an older receipt set is then visible: the head
  the NAS shows is behind the monitor's head (test M4).
- Every receipt is stored on the NAS and uploaded to S3 under the same lock as
  the ciphertext. The S3 receipts are the independent chain.
- **Every pull stores and uploads its receipt and its own ciphertext (R2-02).**
  Unchanged configurations are not deduplicated: encryption is randomized
  (INFERRED), so each pull has a new ciphertext, and the receipt's
  `cipher_sha256` describes exactly that object. This keeps check 5 uniform
  with no exception that could mask a missing upload. Cost: a few hundred
  kilobytes a day, under a gigabyte a year, cents (INFERRED, cost gate in 7).
  "Did the configuration change" comes from `change_marker`, not from skipping
  an upload.
- **Time (R2-05).** `fw_time` is corroborating metadata, not the clock the
  freshness alert trusts. The monitor records, in its own state, the time of
  its own clock when it first verified each receipt (`seen_time`). A receipt
  whose `fw_time` is later than the monitor's clock plus a bound is
  receipt-invalid and critical (a clock jump forward would otherwise make
  every later backup look newer than it is). A `fw_time` far behind `seen_time`
  is a warning (clock or withheld upload). The freshness age is the monitor's
  now minus the earlier of `fw_time` and `seen_time` of the newest verified
  receipt, so neither a forward clock jump nor a withheld-then-late upload can
  make a stale backup look fresh. A backwards `fw_time` with a higher `seq` is
  a warning. The bounds are set in the implementation.

### 4.3 What the monitor checks, from outside the NAS

Per run, on `mon.example.internal`, with the receipts and the newest ciphertext
read from S3 using the monitor-only identity (S5), never from the NAS:

1. Receipt signature verifies under the monitor's key.
2. `recipient_fingerprint` equals the expected fingerprint held by the monitor.
3. `epoch` and `seq` are not lower than the monitor's state; a gap or a
   repeated `seq` with a different hash is a warning or critical (4.5).
4. `prev_receipt_sha256` chains to the previous accepted receipt.
5. The ciphertext object for that receipt in S3 (every receipt has its own,
   R2-02) has size and SHA-256 equal to the receipt's. Carry-over receipts
   from an interrupted emission (2.2 step 5) have no ciphertext and are
   counted as a warning, not as a missing upload.
6. The object has an Object Lock retain-until date in the future and the
   expected mode (S1); anything else is critical.
7. Bands within bounds, no shrink beyond the change-rate rule; the
   `change_marker` is compared with the previous receipt's.
8. Freshness age from the earlier of `fw_time` and the monitor's own
   `seen_time` (4.2, R2-05), and a `fw_time` too far in the future is
   receipt-invalid.

The monitor reads only ciphertext and receipts, never plaintext, so it needs no
decryption key. It checks content equality, not that the ciphertext decrypts:
only the drill (6) proves decryption. That is stated as a limit, not a gap.

### 4.4 Metrics

| Metric (InfluxDB measurement, tag `dest`) | Meaning |
|---|---|
| `pfsense_backup_last_receipt_age_seconds` | Age of the newest verified receipt: the monitor's now minus the earlier of the signed `fw_time` and the monitor's own first-seen time (4.2). **This is the freshness signal**; NAS mtime is not used for alerting. |
| `pfsense_backup_receipt_verify_ok` | 1 when checks 1 to 5 above pass for the newest receipt, else 0, with reason as a field. |
| `pfsense_backup_s3_state_ok` (`dest=s3`) | S3 has the receipt and the matching ciphertext (when one was due) with a valid lock. Replaces `s3_behind_count` computed from the NAS (R1-06). |
| `pfsense_backup_seq_gap_count` | Missing or repeated sequence numbers since the last accepted state. |
| `pfsense_backup_nas_liveness_age_seconds` (`dest=nas`) | Age of the NAS status file mtime. Informational only. |
| `pfsense_backup_check_success` | The check itself ran (1) or failed (0). |

### 4.5 Alerts

The Pi UniFi rule the owner gave: age of the newest copy, warning at 8 days,
critical at 15 days for weekly backups. Thresholds for the pull, the S3 copy
and the silent monitor are **DECIDED** (owner, 2026-11-27); only the drill
thresholds in section 6 are a proposal.

| Alert | Condition | Severity | Why |
|---|---|---|---|
| Backup stale | `last_receipt_age` over 2 days | warning | One missed run is tolerated. |
| Backup stale | `last_receipt_age` over 3 days | critical | Two periods plus a day. |
| Receipt invalid | `receipt_verify_ok` is 0 (bad signature, wrong recipient, chain break, hash mismatch, rollback) | critical | An invalid or forged receipt is worse than a stale one. |
| S3 state | `s3_state_ok` is 0 for more than 1 day | warning | |
| S3 state | `s3_state_ok` is 0 for more than 3 days, or any lock check failing | critical | Same two-period shape. |
| Sequence | `seq_gap_count` over 0 | warning | |
| Change rate | size or counts drop beyond the rule | warning | A legitimate cleanup can trigger it. |
| Check failing | `check_success` is 0, or no data for 36 hours | critical | A silent monitor must alert (`noDataState` and `execErrState` set to Alerting). |

Honest limit (round 1): detection lags the goal. The goal is no more than one
day behind; the first alert is at 2 days. A per-run rule also alerts on any
non-zero pull exit, because a fresh status on a corrupt file is worse than a
stale one. Delivery is **DECIDED** (owner, 2026-11-27): critical alerts page
the phone; warnings go to chat only (Discord and Matrix).

Where it runs (same path as `docs/update-alerting.md`): a Telegraf exec input
on the monitoring host reads S3 with the monitor-only identity, verifies
receipts with its own key and state, and prints InfluxDB line protocol. The
NAS holds no InfluxDB or Grafana credential. The monitor mounts nothing from
the NAS for alerting; an optional read-only NAS mount is liveness only. Grafana
rules go in the existing `influxdb-pfsense` alerting datasource, labels
`severity`, `alert_group=backup`, shipped paused until data arrives, through
the existing `n8n-grafana-router` contact point. Phone push (`phone=true`) is
critical only. A later PR adds the script, rules file and tests.

### 4.6 Where the tools live (DECIDED, owner, 2026-11-27)

The backup tools and scripts live in the public repo `homelab-backup-tools`,
with placeholders only in the repo and real values in a private config or the
secret manager. The wrapper, the NAS-side script, the receipt verifier and the
metric script go there. Their alert rules stay in this repo
(`siem-docker-stack`). Tracked in issue #241.

## 5. Retention and Object Lock (R1-04, R1-11)

### 5.1 NAS (convenience copy, not the authority)

- Ingest identity `svc-pfpull` gets create-only semantics on the share (what
  DSM can express is **OPEN**, Q11): it cannot overwrite, rename or delete.
  The NAS-side script is never given a prune step. Retention on the NAS is
  manual by the owner, with a separate identity used only for that, so no
  scheduled job holds delete power. The files are small (INFERRED: a few
  hundred kilobytes at most), so keeping everything for a year is cheap.
- Immutable snapshots of the share are required, not optional (N8). If the NAS
  cannot make them, the NAS history is deletable by a compromised NAS and the
  authoritative copy is S3 only: **OWNER DECISION** D-R3 (accept, or choose a
  different NAS target).
- Consequence stated plainly: a compromised NAS can delete or roll back its
  own copies. That is detected by the monitor (4.3) and recovered from S3.

### 5.2 S3 (the authoritative offsite copy)

Provider is not yet chosen: **OPEN** and an **OWNER DECISION** (D-R4, a vendor
choice and a cost). What was read on 2026-11-27:

| Provider | Object Lock facts | Price on the page | Verdict |
|----------|-------------------|-------------------|---------|
| AWS S3 | Compliance mode cannot be overridden by any user including root; Governance needs `s3:BypassGovernanceRetention` plus the bypass header; versioning required; per-object retention overrides the bucket default; lock can be enabled on an existing bucket (versioning on) and cannot be disabled; a lifecycle rule cannot delete a locked version, but delete markers still work and are not protected (VERIFIED, S-AWS-OL) | AWS rate not found | Candidate |
| Backblaze B2 | Governance overridable by keys with the right capability, Compliance not removable, enable on an existing bucket allowed, retention 1 to 3000 days (VERIFIED, tool extract, S-B2-OL) | $6.95 per TB per month, page footer 2024 (no effective date) | Candidate |
| Wasabi | Lock only while creating the bucket, versioning first (VERIFIED, tool extract, S-WAS-OL; conflicts with the other two on enabling later, not cross-checked) | $7.99 per TB per month, 90-day minimum storage, footer 2026 | Needs a new bucket; 90-day minimum billing; weaker fit |
| Cloudflare R2 | No Object Lock (VERIFIED, S-R2) | n/a | Out |

The config is a few hundred kilobytes (INFERRED), so storage cost is cents per
month at any of them; the real cost gate is that a Compliance lock cannot be
undone for its whole retention, and Wasabi's 90-day minimum. Recommendation:
AWS S3 or Backblaze B2, both of which allow the lock on an existing bucket.
Delete markers are not protected by the lock (S-AWS-OL), so the monitor also
checks that the newest version is not a delete marker (test L7). Selection
checklist (every item must be shown on the chosen provider's own
documentation before go-live; Q8, Q9):

1. Object Lock with a **Compliance-equivalent** mode that no principal,
   including the account root, can shorten or bypass.
2. If only a Governance-equivalent mode exists: the bypass permission is
   denied to every identity except one break-glass identity that is not used
   day to day and whose use pages the phone; retention is then not tamper-proof
   against that identity and it is recorded as an accepted residual by the
   owner.
3. A default retention on the bucket, so every uploaded version is locked
   without the writer asking, and per-object retention supported.
4. Versioning on, enabled at bucket creation if the provider requires it.
5. Lifecycle rules that cannot expire a version before its retention ends.
6. Separate permissions for put, list, get-version and retention, so the
   writer, the monitor and the owner reader can be distinct.
7. TLS-only, server-side encryption, no public access.
8. Cost: storage, request and any minimum-storage-duration or early-delete
   billing for locked data (cost gate, section 7 header).

Recommendation (reasoned, not verified for any provider): choose Compliance
mode, default retention **90 days**, applied as the bucket default at bucket
creation by the owner's admin credential (never by the writer); lifecycle
expires non-current versions after **365 days**, which is later than the
retention end, so the lock is never what blocks the lifecycle and the lifecycle
never races it. 90 days is chosen because the critical alert fires at 3 days
and a drill runs quarterly, so a poisoned or deleted history is noticed long
before 90 days; a longer lock only adds cost and a longer irreversible
commitment. The files are small, so even a long retention costs cents
(INFERRED). Compliance mode cannot be undone once applied, which is why the
mode and the duration are an **OWNER DECISION** D-R5, and the lock is first
exercised on a throwaway bucket with the shortest allowed retention (test L1
to L6, section 8).

The writer credential `pfbackup-put` can create versions (and so inherits the
default retention) and cannot delete versions, change retention, change the
bucket policy or lifecycle, or disable versioning. It does not hold the
bypass permission. The action names for retention and bypass come from the
provider's documentation (Q8), not from this note.

Other retention lines:

- Firewall: the on-box history (30 by default, P-RESTORE VERIFIED) is left
  alone; it is a convenience for undo, not part of this design.
- Auto Config Backup, if enabled: server keeps the newest 100, 50 manual
  (P-ACB VERIFIED).

## 6. Restore test procedure

P-BACKUP (VERIFIED): backups must be tested, periodically, on a non-production
machine or virtual machine. P-ACB status page (VERIFIED) says the same and
describes making a change after a backup and checking the restore does not
contain it. Quarterly, matching `docs/backup-restore.md`:

1. Pick the newest ciphertext on the NAS, and separately the newest object
   version in S3 with its receipt (this proves the offsite path).
2. On the owner's workstation, **before decrypting**: verify the receipt
   signature with the offline copy of the verification key; compare the
   `recipient_fingerprint` with the owner's offline record, not with anything
   read from the NAS or the monitor; refuse and stop on any mismatch (this is
   the "expected recipient" check, test W2). Confirm the ciphertext SHA-256
   equals the receipt's.
3. Fetch the restore key from the secret manager on the workstation (no copy
   on the NAS). Decrypt the ciphertext and the inner record (4.2). Confirm the
   plaintext SHA-256 equals the inner record's, and that the inner record's
   hash is the one the signed receipt references.
4. L1 and L2 checks again on the result (`xmllint --noout`, root `pfsense`,
   the counts). Print only counts and versions, never content.
5. L3: restore into a spare or virtual pfSense of the same major version,
   using Diagnostics, Backup and Restore (P-RESTORE VERIFIED location). Check
   the caveat in P-RESTORE (VERIFIED): a backup from a lower or higher
   configuration revision is handled differently, so the drill VM matches the
   firewall version.
6. Confirm the interface assignments prompt, the rule count, a VPN or
   certificate entry and the update-metric Telegraf entry exist.
7. Key-loss drill once a year: decrypt using only the offline copy of the key.
8. Wrong-recipient drill once a year: run the verifier against a ciphertext
   deliberately made to another recipient and confirm it is rejected.
9. Record date and result (one line in the ops journal). A drill older than
   100 days is a warning and older than 130 days is critical (proposal for
   the owner to approve).

Never restore a test file onto the production firewall. Never drill with the
real firewall's network reachable from the VM (a restored config would try to
take over addresses): isolate the VM.

## 7. ACCESS LIST (one list, ask once)

Everything the whole job needs. Nothing broader is requested as a fallback.
Items marked OWNER need the owner's hands or consent; LEAD can be done by the
lead session through an implementer agent with no owner credential. Cost gates
(one list): S3 storage, requests and any minimum-storage or early-delete
billing on locked data (cents per month, INFERRED, provider **OPEN**); a
Compliance lock is a commitment for its whole retention; nothing else is paid;
Auto Config Backup is free (P-ACB VERIFIED).

### 7.1 Firewall (fw.example.internal)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| F1 | Local user `backup-ro` | A dedicated identity for the pull | Privilege "User - System: Shell account access" only, no root, no admin group; long random password never used; key login only | OWNER (GUI) |
| F2 | Authorized key line on `backup-ro` | Lets the NAS, and only the NAS, run the wrapper | `from=` NAS address (as sshd observes it), `restrict`, `command="<wrapper-path>"` plus the explicit `no-*` options (2.4); ed25519 | OWNER (paste), LEAD drafts the exact line |
| F3 | SSH enabled, port known | The pull needs it | Already on (the owner has read the box over SSH); no change unless F4 | OWNER |
| F4 | "SSHd Key Only" to Public Key Only (**OPEN**) | Removes password SSH for all accounts | Optional hardening; owner confirms his own key first | OWNER (decision pending) |
| F5 | Firewall rule NAS address to SSH port | Only needed if the NAS is not on the LAN interface | One NAS address, one destination, one port; does not override anti-lockout (P-ADMIN VERIFIED) | OWNER |
| F6 | Sudo rule for the wrapper, only if `backup-ro` cannot read the config | Root read | Exactly `<wrapper-path>`, no arguments, reset environment, no setenv; never a generic `cat`. Package and syntax **OPEN** (Q5) | OWNER, only if needed |
| F7 | (Optional, **OPEN**) Enable Auto Config Backup | Third copy | "On Every Configuration Change" (P-ACB VERIFIED option); long encryption password; device key saved; both go to the secret manager only | OWNER |
| F8 | Wrapper script, root-owned, mode not writable by others, in a location that survives upgrades (**OPEN**, Q3) | Validate, encrypt, sign | No arguments; ignores `SSH_ORIGINAL_COMMAND`; fails closed | LEAD supplies, OWNER installs after inspection |
| F9 | Recipient pin file (public key or certificate) | R1-02 | Root-owned, readable by the wrapper, not writable by `backup-ro`; fingerprint recorded offline | OWNER |
| F10 | Receipt signing key pair; private half on the firewall only | R1-03 | Root-only, mode 0600; public half to the monitor and the owner's offline record; regenerated after any rebuild | OWNER generates on the firewall, public half copied out |
| F11 | State directory: sequence, epoch, previous-receipt hash, pending receipts, lock file | Monotonic receipts, single writer, atomic reserve (2.2) | Root-owned, outside `config.xml`, written only by rename of a new file; epoch set by the owner | OWNER |
| F12 | Stateless self-test script `<selftest-path>` | R2-06 | Root-owned; no lock, no state writes, no signing; not reachable through the key | LEAD supplies, OWNER installs after inspection |
| F13 | Change-marker key | R2-07 | Root-only, firewall only, never copied out; regenerated with the signing key after a rebuild | OWNER |
| F14 | Memory-backed root-only scratch directory for the snapshot and ciphertext buffer | R2-03 | Mode 0700, root; availability **OPEN** (Q16); cleaned by trap | OWNER, after the check |

### 7.2 NAS (nas.example.internal)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| N1 | Shared folder `pfsense-backup` | Home for receipts and ciphertext | No guest access; not shared with anything else | OWNER |
| N2 | Account `svc-pfpull` | Runs the scheduled pull and S3 upload | Create-only on that folder (capability **OPEN**, Q11); no admin rights; no inbound SMB login; no prune; holds the SSH private key (ed25519, mode 0600, no passphrase so it can run unattended; usable only from the NAS address and only to run the wrapper); cannot write `known_hosts` | OWNER |
| N3 | Account `svc-pfmon-ro` (optional) | Liveness only | Read-only on the folder; SMB only. The monitor's alerts do not depend on it | OWNER |
| N4 | Task Scheduler entry, daily | Runs the pull (INFERRED that DSM Task Scheduler can run a script as a chosen user) | Runs as `svc-pfpull`, not root | OWNER |
| N5 | No encryption tool on the NAS | R1-01 | The NAS needs only `ssh`, a hash tool and the S3 client; it holds no key of any kind except the pull key and the S3 writer key | n/a |
| N6 | (Optional) manual prune identity | Retention by hand | Separate from N2; used by the owner only, never scheduled | OWNER |
| N7 | `known_hosts` for the firewall host key | R1-07 | Root-owned, not writable by `svc-pfpull`; fingerprint from command 12 | OWNER |
| N8 | Immutable snapshots of the share | R1-11 | Snapshot only; capability **OPEN**, Q11; if unavailable, D-R3 | OWNER |

### 7.3 S3 (bucket `fw-config-backup-example`; provider **OPEN**, policy shown in AWS terms)

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| S1 | Bucket | Offsite copy | Block all public access; versioning on; Object Lock with the mode and default retention of 5.2 (AWS and B2 allow enabling it on an existing bucket, VERIFIED, 5.2; Wasabi only at creation); TLS-only policy; default encryption on | OWNER |
| S2 | Writer credential `pfbackup-put` | The NAS uploads receipts and ciphertext | Put on the one prefix; list on the prefix; no delete, no version delete, no retention change, no bypass, no bucket policy, no lifecycle | OWNER creates |
| S3 | Reader credential `pfbackup-read` | Restore drill | Get, get-version, list on the prefix; used from the owner's workstation, never on the NAS or the monitor | OWNER |
| S4 | Lifecycle rule | Expire non-current versions after 365 days, which is after the retention end (5.2) | Bucket setting, no credential | OWNER |
| S5 | Monitor credential `pfbackup-monitor` (R1-06) | Independent S3 state for the monitor | Get, get-version, list and read of retention on the prefix only; no write of any kind; held only on `mon.example.internal` | OWNER creates |
| S6 | Break-glass admin (only if Governance-equivalent is chosen) | Bypass for emergencies | Not stored on any host; use pages the phone | OWNER |

### 7.4 Secret manager (R1-09)

**DECIDED** (owner, 2026-11-27): the backup secrets go first in a dev config
of Doppler project `homelab`, never in prd, until the owner says in his own
words that the backup is live in production; promotion to prd is its own step.
Round 1 found two problems with that, which this note records instead of
overriding: anyone who can read that dev config gains the restore key and the
S3 identities, and the owner's Doppler layout standard is one project per
product. **OWNER DECISION** D-R6, choose one (a decision, no command):

1. Dedicated project for this product with dev and prd environments, then the
   configs below. (Reviewer's recommendation; needs the owner's OK before a
   project is created.)
2. Keep the decided `homelab` dev config, but split it into the per-role
   configs below, each readable only by its own principal (config granularity
   and per-config access are **OPEN**, Q12), and record that the project is
   not the one-per-product layout.

Per-role configs, whichever project:

| # | Config and secret | Why | Readers |
|---|-------------------|-----|---------|
| D0 | A dev config per role (names placeholders: `<cfg-nas-writer>`, `<cfg-monitor>`, `<cfg-owner-restore>`) | Isolation of roles | The lead checks the real list read-only before any command is given to the owner |
| D1 | `PFSENSE_BACKUP_RESTORE_KEY` in `<cfg-owner-restore>` | The private restore key | Owner only; never on the NAS, the monitor or in CI. The offline copy remains. |
| D2 | `PFSENSE_BACKUP_S3_PUT_KEY_ID`, `PFSENSE_BACKUP_S3_PUT_SECRET` in `<cfg-nas-writer>` | The NAS upload | The identity that installs it on the NAS task (owner) |
| D3 | `PFSENSE_BACKUP_S3_READ_KEY_ID`, `PFSENSE_BACKUP_S3_READ_SECRET` in `<cfg-owner-restore>` | Restore drill | Owner only |
| D4 | `PFSENSE_BACKUP_S3_MON_KEY_ID`, `PFSENSE_BACKUP_S3_MON_SECRET` in `<cfg-monitor>` | The monitor's S3 state read | The monitoring host's secret reader only |
| D5 | (Optional) `PFSENSE_ACB_DEVICE_KEY`, `PFSENSE_ACB_ENCRYPTION_PASSWORD` in `<cfg-owner-restore>` | Third copy recovery; P-ACB (VERIFIED) says a lost encryption password makes backups unrecoverable | Owner only |
| D6 | (Optional) `PFSENSE_BACKUP_MON_SMB_PASSWORD` in `<cfg-monitor>` | Only if the liveness mount (N3) is used | The monitoring host's secret reader |

Not stored in the secret manager: the NAS-to-firewall SSH private key
(rebuildable) and the firewall signing private key (it must exist only on the
firewall). Not secrets: the recipient fingerprint, the verification public
key and the host key fingerprint; they are recorded offline and on the monitor.

Setting a secret: `doppler secrets set NAME` can echo the value, so every
command given to the owner ends `> /dev/null`, and the value is entered at a
prompt, never put on the command line (the prompt behavior is INFERRED; the
exact command will be given in full with each request).

### 7.5 Metric and Grafana side

| # | Item | Why | Least privilege | Who |
|---|------|-----|-----------------|-----|
| M1 | Telegraf exec input on the monitoring host | Emits the metrics | Runs the checker script; reads S3 through D4; holds the verification key, the expected fingerprint and its own state file root-owned; writes InfluxDB with the existing Telegraf credential (INFERRED that one exists) | LEAD writes script and test, OWNER deploys |
| M2 | Grafana alert rules file (paused) | Alerts in section 4.5 | Repo file only; existing `influxdb-pfsense` datasource and `n8n-grafana-router` contact point | LEAD (PR) |
| M3 | Unpause after data arrives | Avoid false alerts | One click or one line | OWNER or LEAD with OK |

### 7.6 Read-only verification the owner runs on the firewall first

The firewall shell is csh, so each line is wrapped in `sh -c` with single
quotes and contains no `!` or `$`. None changes state. None is intended to
print a secret: they print counts, names, sizes, dates, versions, public
fingerprints. Command 1 changed after round 1: it no longer prints raw log
lines, because log lines were not shown to be free of identifiers; it prints
a count and the first 15 characters (the timestamp) of the last line. Run
each at the firewall shell and send the output. They are twelve commands plus
one GUI screenshot request; item 6 is three lines.

1. Is Auto Config Backup logging? (P-ACB status page VERIFIED: success and
   failure lines are in the System log, General tab, and mention
   `acbupload.php` and `services_acb_backup.php`.) Count, then the timestamp
   of the last such line only:
   ```
   sh -c 'grep -c -i acb /var/log/system.log'
   ```
   ```
   sh -c 'grep -i acb /var/log/system.log | tail -n 1 | cut -c1-15'
   ```
2. How big is the log, did it rotate?
   ```
   sh -c 'ls -l /var/log/system.log*'
   ```
3. Which Auto Config Backup elements exist in the config (names only)?
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
7. Owner, group and mode of the config and of its directories (this is **not**
   proof that `backup-ro` can read it; effective access is tested as that user
   in 8.1 once the user exists):
   ```
   sh -c 'ls -l /cf/conf/config.xml'
   ```
   ```
   sh -c 'ls -ld /cf /cf/conf'
   ```
8. SSH daemon settings relevant to the pull (names and values, no keys):
   ```
   sh -c 'grep -E "^(PermitRootLogin|PasswordAuthentication|AuthenticationMethods|PubkeyAuthentication|AuthorizedKeysFile|AllowUsers|ForceCommand|PermitUserEnvironment)" /etc/ssh/sshd_config'
   ```
9. In the GUI, the Restore tab of Services, Auto Config Backup lists backups on
   the server and notes staged entries (P-ACB status page VERIFIED). A
   screenshot of that tab is enough.
10. Which tools exist on the firewall, and the platform version (settles the
    2.2 decision table; `which` prints a path or a "not found" line):
    ```
    sh -c 'which openssl age gpg gpg2 minisign signify xmllint sudo'
    ```
    ```
    sh -c 'freebsd-version; uname -sr'
    ```
11. Versions of the tools that exist (a missing tool just prints an error):
    ```
    sh -c 'openssl version'
    ```
    ```
    sh -c 'age --version'
    ```
    ```
    sh -c 'gpg --version | head -n 1'
    ```
12. The firewall's SSH host key fingerprints (public information, to pin on
    the NAS; the path is INFERRED and the command is read-only):
    ```
    sh -c 'ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub'
    ```

**Lab test list** (required before implementation; read-only first, on a lab
firewall or the real one; each is csh-safe and prints no secret):

L-a. Mode and owner of the config (settles F6; weak forum evidence says
world-readable on an old release, S-FORUM):
```
sh -c 'ls -l /cf/conf/config.xml'
```
Expected: one line with owner, group, mode and size. Send it.

L-b. OpenSSL version (primary tool, 2.2):
```
sh -c 'openssl version'
```
Expected: one line naming OpenSSL and a version. Plus 25.11 is documented as
3.5.3 (S-NG-REL); a CE box may differ.

L-c. The CMS subcommand exists and takes the options we rely on (it prints
usage text only; nothing is encrypted):
```
sh -c 'openssl cms -help 2>&1 | grep -c -i -e aes256 -e recip -e encrypt'
```
Expected: a number above 0. A 0 or an error means row 1 of the 2.2 table fails.

L-d. The shell the pull user gets, after F1 exists (the password field is not
printed; only name and shell):
```
sh -c 'grep backup-ro /etc/passwd | cut -d: -f1,7'
```
Expected: `backup-ro:` and a shell path. Not documented (Q5), so it is read here.

L-e. The key-option persistence test (after F1 and F2 exist, with the key line
saved through the User Manager field): read the saved option text for the
key without printing the key body, then reboot the lab firewall and read it
again.
```
sh -c 'grep -c "restrict,command=" /home/backup-ro/.ssh/authorized_keys'
```
Expected: 1 before and 1 after the reboot. 0 means the GUI strips or rewrites
the options and the mechanism must change before anything is built (2.4). The
home directory path is INFERRED; if the file is not there, the owner reports
where it is, and then T1 to T7 from the NAS are the real proof either way.

**The old `ssh ... | wc -c` proof command is removed (R2-06):** it ran the
real, stateful wrapper, advanced its sequence and chain, and threw the output
away, leaving a gap, and it skipped the pinned `known_hosts` and strict
options. Replaced by two things:

1. A stateless self-test on the firewall console, a separate root-owned script
   `<selftest-path>` that shares the wrapper's validation and encryption code
   but never takes the lock, never reads or writes the sequence, chain or
   pending state and never signs a receipt. It is not reachable through the
   key (the forced command is the wrapper only, and the wrapper takes no
   mode argument). It prints counts and versions only:
   ```
   sh -c '<selftest-path>'
   ```
   Expected: the L1 and L2 results as numbers, the cipher name, the recipient
   fingerprint, and the words `state untouched`. Test X1 proves the state
   files are byte-identical before and after.
2. The proof of the whole path is the first real pull, run as the production
   ingest on the NAS (the same script the Task Scheduler runs, as
   `svc-pfpull`, with the pinned `known_hosts` and strict options), followed by
   the monitor verifying the resulting receipt, the locked S3 object and its
   retention:
   ```
   sh -c '<nas-ingest-script>'
   ```
   Expected: exit 0, then the monitor reports `receipt_verify_ok` 1 and
   `s3_state_ok` 1 for the new `seq`. A failed first pull leaves a visible
   `pending` or no receipt, never a silent gap.

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

## 8. Required negative tests (R1: tests that bite)

None is optional. Each test names the finding it proves, runs first on a test
firewall or the isolated VM, then once on the live pair after provisioning,
and is committed with the implementation. Each fix needs the revert proof:
the test fails when the control is removed and passes when restored.

### 8.1 SSH key abuse (R1-07, R1-08)

| # | Test | Expected |
|---|------|----------|
| T1 | `ssh -tt` (request a PTY) with the pull key | No PTY; output is still only the stream |
| T2 | Run another command (`ssh host id`) with the pull key | The wrapper runs; `id` does not; `SSH_ORIGINAL_COMMAND` is ignored |
| T3 | Local, remote and dynamic forwarding attempts | All refused |
| T4 | Agent and X11 forwarding requests | Refused |
| T5 | Connect from an address other than the one in `from=` | Key rejected |
| T6 | sftp and scp subsystem requests | Refused or return only the wrapper stream (command applies to subsystems, S-SSHD VERIFIED) |
| T7 | Arguments and shell metacharacters in the client command | Ignored; no side effect |
| T8 | As `backup-ro` on the firewall: write the wrapper, the recipient file, the signing key, the counter | All denied |
| T9 | `sudo -l` as `backup-ro`, then run the wrapper with an argument, and an alternate path | One entry only; argument and alternate path denied |
| T10 | Effective read of `config.xml` as `backup-ro` without the wrapper | Denied (or, if allowed, recorded and F6 not needed) |
| T11 | The observed source address recorded for the real path (LAN, NAT or VPN) | Equals the NAS address; if not, `from=` is widened only to the recorded egress with the owner's OK |
| T12 | Wrong or changed firewall host key presented to the NAS job | Job fails closed, no state advanced, critical alert from the missing receipt |
| V1, V2 | Binary stream through the channel, both the receipt and the ciphertext | Byte-exact, hashes match (clean 8-bit channel) |

### 8.2 Wrong recipient (R1-02)

| # | Test | Expected |
|---|------|----------|
| W1 | Wrapper with a different recipient file (test firewall only) | Receipt carries the different fingerprint; the monitor raises critical |
| W2 | Restore drill step 2 against a ciphertext made for a different recipient | Rejected before any decrypt attempt |
| W3 | NAS-side swap: replace the ciphertext in S3 or on the NAS with one made to an attacker key, same name | Hash differs from the signed receipt; critical |
| W4 | Decrypt with the wrong private key | Fails; no partial output |
| W5 | Recipient file edited on the firewall by `backup-ro` | Impossible (T8) |
| W6 | Inspect the produced ciphertext with the decrypt tool's structure listing, and run the wrapper with the cipher option removed (revert proof) | The cipher is AES-256; without the explicit option the test fails because the default is triple DES (S-OSSL-CMS VERIFIED) |

### 8.3 Forged monitor input (R1-03, R1-05, R1-06, R1-10)

| # | Test | Expected |
|---|------|----------|
| M1 | `touch` the NAS status file and keep stale content | No effect on the freshness alert (it uses the signed receipt) |
| M2 | Replay an old valid receipt | Age grows; stale alerts fire |
| M3 | Receipt with a bad signature, a changed field, or signed by another key | `receipt_verify_ok` 0, critical |
| M4 | Roll the NAS back to an older receipt set | Head behind the monitor's state; critical |
| M5 | Empty, truncated or zero-size ciphertext with a fresh-looking name | Size and hash mismatch; critical |
| M6 | An S3 object missing, or present without a valid lock | `s3_state_ok` 0; critical when lock-related |
| M7 | Sequence gap or repeated sequence with a different hash | Warning, then critical per 4.5 |
| M8 | Any NAS-supplied "S3 count" value | Ignored; the monitor never reads one |
| M9 | A minimal valid-XML config or a large shrink (L2 and change rate) | Wrapper refuses a below-floor file; a legitimate shrink raises the warning |
| M10 | Monitor with no data, and with a failing exec | Alerting state, per existing rules |

### 8.4 Object Lock bypass (R1-04)

Run on a throwaway bucket with the shortest allowed retention, never on the
production bucket.

| # | Test | Expected |
|---|------|----------|
| L1 | Delete a locked version with the writer credential | Denied |
| L2 | Delete the same version with the owner's highest-privilege identity, including the account root where the provider has one | Denied (Compliance-equivalent). Under a Governance-equivalent mode the test instead proves the bypass permission is denied to every day-to-day identity |
| L3 | Shorten the retention or change the mode | Denied |
| L4 | Overwrite the same key | A new version appears; the old one remains |
| L5 | Lifecycle expiry configured before the retention end | Cannot remove the locked version before its date |
| L6 | The same attempts after the retention end on the throwaway bucket | Succeed, proving the test would have detected a missing lock |
| L7 | A delete marker placed by the writer or an admin on the throwaway bucket | The locked version is still readable and listed; the monitor flags the marker (markers are not protected, S-AWS-OL VERIFIED) |

### 8.5 Round 2 additions (R2-01 to R2-07)

Same rules as above: each runs on a test firewall first, each needs a revert
proof (the test fails with the control removed).

| # | Test | Expected |
|---|------|----------|
| C1 | Two concurrent pulls | One gets the stream; the other exits non-zero at once; no duplicate `seq`; no fork in the chain |
| C2 | Client disconnects mid-stream (kill the NAS side after the header) | `pending` stays set; the next run carries the pending receipt over; the monitor shows a warning, not a break |
| C3 | Kill the wrapper (hard) while it holds the lock, then pull again | Lock is released by the OS; the next run works; state is either the old or the new atomic file, never half-written |
| U1 | Pull twice with an unchanged configuration | Two receipts, two ciphertext objects in S3, both verify (check 5 passes); `change_marker` equal |
| U2 | Unchanged day with the upload withheld on the NAS | Check 5 fails for that receipt; `s3_state_ok` 0 (no exception exists to mask it) |
| P1 | Replace or modify `config.xml` between the wrapper's read and its encryption | Snapshot used throughout; the post-encrypt re-read differs, one retry, then fail closed; no receipt describes mixed revisions |
| P2 | Kill the wrapper at each step; list persistent disk and scratch directory | No plaintext on persistent disk; scratch empty after the trap (or after the next run's start cleanup) |
| P3 | Run with no memory-backed scratch available | Stops, exit non-zero, no disk fallback |
| P4 | Ciphertext buffer cleanup after an emission error | Buffer removed; no ciphertext emitted before the receipt was signed |
| G1 | Receipt with fields reordered | Rejected |
| G2 | Receipt with a duplicated field, an unknown field, or a missing field | Rejected |
| G3 | Receipt with extra whitespace, a different line ending, or trailing bytes | Rejected (signature or strict parse) |
| G4 | Valid signature record that names a different algorithm | Rejected: the algorithm comes only from the monitor's config |
| G5 | Signature made over different bytes than those presented | Rejected |
| G6 | Wrong `receipt_version` | Rejected |
| G7 | Verification run with the exact commands recorded when Q7 closed, on a known-good and a known-bad receipt | Good verifies, bad fails |
| K1 | Receipt whose `fw_time` is far in the future | `receipt_verify_ok` 0, critical; the freshness age is not reset by it |
| K2 | Firewall clock jumps forward, then returns, with real pulls continuing | Alerts fire for the future receipts; freshness never looks newer than the monitor saw |
| K3 | Old receipt uploaded late (withheld then released) | Age uses the earlier of `fw_time` and first-seen time, so it still reads old |
| K4 | `fw_time` goes backwards while `seq` rises | Warning |
| X1 | Run `<selftest-path>`, compare state directory before and after | Byte-identical; no receipt signed; no lock taken |
| X2 | List the credentials and administrators of the monitor host and the NAS | No shared administrator, credential or session path |
| Y1 | Review the receipt of a real pull for clear fields | Only the clear fields in 4.2; no exact count, revision, plaintext hash or version string |

## 9. INFERRED claims in this note (check before relying on them)

1. `/conf` is a link to `/cf/conf`. P-XML says `/conf/config.xml`, P-RESTORE and P-REMOTE say `/cf/conf/config.xml`.
2. `config.xml` contains VPN keys, certificate private keys, pre-shared keys and tokens, and password hashes for local users.
3. The on-box config history directory is `/cf/conf/backup`.
4. The every-minute cron line exists even when ACB is disabled.
5. The firewall's log file is plain text at `/var/log/system.log`.
6. The Authorized Keys field accepts option prefixes and the installed sshd enforces them, including `restrict`; the GUI preserves them and writes them to the file sshd reads (S-SSHD proves the upstream behavior only).
7. `backup-ro` can or cannot read `/cf/conf/config.xml`; unknown until tested as that user.
8. ACB stores its device key and encryption password inside `config.xml`; the server side offers no custom freshness hook.
9. DSM offers create-only ACLs for one account, Task Scheduler with a user script, immutable snapshots on this model, and can run `ssh`, a hash tool and an S3 client.
10. The OpenSSL version on the owner's firewall supports `cms -encrypt -aes256` as documented for 3.0 and later (FreeBSD base and Plus 25.11 are VERIFIED; the owner's CE or Plus version is not stated); `openssl x509 -fingerprint -sha256` prints the certificate fingerprint; the fingerprint is compared over a second channel; the signing flags exist in the installed version.
11. Encrypting the same plaintext twice gives different ciphertext (randomized encryption), so every pull uploads its own ciphertext and change detection uses the keyed `change_marker`.
12. A wrapper, key and state files placed outside `config.xml` survive a firmware upgrade in the chosen location.
13. The firewall host key file is `/etc/ssh/ssh_host_ed25519_key.pub`.
14. The chosen provider behaves as AWS S3 does for Object Lock (VERIFIED for AWS and, from a tool extract, for B2; not cross-checked for Wasabi, whose creation-time-only rule conflicts); no AWS price was found; S3 cost is cents per month for a few hundred kilobytes; the B2 and Wasabi prices carry no effective date.
15. The firewall config file is a few hundred kilobytes at most.
16. `doppler secrets set NAME` prompts for the value when none is given; per-config reader control exists in the plan the owner has.
17. A Telegraf write credential already exists for the monitoring host's InfluxDB; the monitoring secret-reader pattern can read D4.
18. pfBlockerNG and other package data are re-fetched after restore; the update-metric script and Telegraf snippet live outside `config.xml`.
19. The Pi UniFi backup design was not available; its alerting shape is taken only from the owner's stated 8-day and 15-day rule.
20. The Sudo package can express an exact full-path, no-argument rule with a reset environment and no setenv (the package and its full-path and mandatory-argument behavior are VERIFIED, S-NG-SUDO; the environment handling is not).
21. A 90-day Compliance retention is long enough to notice damage and costs only cents; the ssh option names for strict host key checking and a private `known_hosts` file are as in the ssh_config manual.
22. The FreeBSD sshd on pfSense matches the upstream sshd(8) page for `command=`, `from=`, `restrict` and `no-pty`.
23. The GUI-written Authorized Keys file keeps option prefixes (nothing documented; forum posts suggest keys are written from `config.xml`); the pull user's shell is not documented.
24. `age` runs on pfSense as a static binary or port package; it has no fingerprint feature (pin the full recipient string); GPG pins by full fingerprint.
25. The mode and owner of `/cf/conf/config.xml` (a forum post reports world-readable on 2.4.2).
26. The lock tool used by the wrapper releases its lock when the process dies, and a write error is visible to the wrapper when the client disconnects (tests C2, C3).
27. A memory-backed filesystem exists on the firewall for a root-only scratch directory.
28. The installed OpenSSL supports Ed25519 signing (else ECDSA P-256, else RSA 3072 or more).
29. Daily upload of every ciphertext stays under a gigabyte a year and costs cents.
30. A keyed hash of the plaintext cannot be used by a bucket thief to confirm a guessed configuration, and bands are coarse enough to hide exact counts.

## 10. OPEN questions and their status after research (2026-11-27)

Status per question, from the researcher's pages (CLOSED means a source is
cited; STILL OPEN means the owner's firewall, DSM, the provider or a manual
must answer; the table below it keeps the exact question):

| Q | Status |
|---|--------|
| Q1 | CLOSED for `openssl` with `cms`, `smime`, `pkeyutl`, `enc` in the FreeBSD base (VERIFIED, S-FBSD-OSSL) and OpenSSL 3.5.3 in Plus 25.11 (S-NG-REL); Netgate lists Sudo and no age, gnupg or openssl package (S-NG-PKGLIST). STILL OPEN: the version on the owner's firewall (command 11); `xmllint`, `minisign`, `signify` (command 10). |
| Q2 | STILL OPEN, a required lab test (L-e, T1 to T7). Documented: nothing about options surviving a save or reboot (VERIFIED absence). |
| Q3 | STILL OPEN. S-NG-SSHREC: do not manage keys from the shell. Sudo rules set through the package live in `config.xml`; `sudoers.d` files are not backed up (S-NG-SUDO). |
| Q4 | STILL OPEN (command 7, L-a). Forum post only (S-FORUM). |
| Q5 | Sudo CLOSED (S-NG-SUDO). The pull user's shell STILL OPEN (L-d). |
| Q6 | CLOSED for age: `age1...` recipients, identity file to decrypt, no fingerprint feature (S-AGE README; pinning by comparing the full string is INFERRED). GPG pinning by full fingerprint INFERRED. |
| Q7 | Encrypt side CLOSED (S-OSSL-CMS, OpenSSL 3.0 page). Signing flags STILL OPEN. |
| Q8 | CLOSED for AWS, B2, Wasabi and R2 as in 5.2. STILL OPEN: AWS price, the effective dates of the B2 and Wasabi prices, the Wasabi conflict. |
| Q16 | STILL OPEN: which lock tool and which memory-backed scratch filesystem exist on the firewall and how they behave on process death (R2-01, R2-03). Lab read-only check: `sh -c 'which lockf flock'` and `sh -c 'mount | grep -c tmpfs'` (a count only). |
| Q9 to Q15 | STILL OPEN (monitor permission names, ssh_config option names, DSM, Doppler, the observed source address, the revision field name, ACB log content). |

The exact questions:

The design above holds for each answer through the decision tables. None of
these is answered from memory.

| Q | Exact question | Source to read | Affects |
|---|----------------|----------------|---------|
| Q1 | Which of `openssl`, `age`, `gpg`, `minisign`, `signify`, `xmllint`, `sudo` ship in the pfSense CE and Plus base system, and in which versions? Owner commands 10 and 11 check the real box. | Netgate docs, FreeBSD base docs, the box | 2.2 table, 3 |
| Q2 | Does the pfSense GUI preserve option prefixes (`from=`, `restrict`, `command=`) in the Authorized Keys field? | Netgate P-ADMIN and related pages, a test user | 2.4, T1 to T7 |
| Q3 | Where does pfSense write a user's authorized keys, and where can a root-owned wrapper, recipient file, key and state live so a firmware upgrade keeps them? | Netgate docs on file persistence | F8 to F11 |
| Q4 | Default owner, group and mode of `/cf/conf/config.xml` and `/cf/conf`. | Netgate docs, command 7 | F6 |
| Q5 | Which shell does a Shell-account user get, how is `command=` run by it (csh `-c`?), the sudo package name and exact rule syntax for one command without arguments? | Netgate docs, sudo manual | 2.4, F6 |
| Q6 | age: recipient format, whether the ciphertext reveals the recipient, whether it can sign. GPG: pinning by full fingerprint, signing subkey use. | The age README and spec, the GnuPG manual | 2.2 table |
| Q7 | OpenSSL: the exact CMS or S/MIME encrypt and sign subcommands and flags for a recipient certificate and a detached signature. | The OpenSSL manual for the installed version | 2.2 table |
| Q8 | For each candidate S3 provider: Compliance-equivalent mode, Governance bypass permission and how to deny it, default and per-object retention, minimum retention, creation-time requirement, lifecycle interplay, action names for retention and bypass, early-delete billing and price. Also the recommendation of a provider. | The provider's own Object Lock and pricing pages | 5.2, S1, D-R4, D-R5 |
| Q9 | Permission names for a monitor identity that can list, get versions and read retention but nothing else. | Provider IAM docs | S5 |
| Q10 | The ssh client option names for strict host key checking and for using only a given `known_hosts` file; `ssh-keygen` fingerprint listing. | ssh_config(5), ssh-keygen(1) | 2.3, command 12 |
| Q11 | DSM: create-only ACL for one account, immutable snapshots on this model, Task Scheduler run-as user. | Synology DSM docs | N2, N8, D-R3 |
| Q12 | Doppler: per-config access control and service account scope inside one project. | Doppler docs | 7.4, D-R6 |
| Q13 | The source address sshd sees from the NAS across the real path (LAN, NAT or VPN). | The box (test T11) | F2 |
| Q14 | The name of the configuration revision field in `config.xml` and of the top-level sections, structure only. | P-XML and the box (names only) | 3, 4.2 |
| Q15 | Do ACB log lines ever carry identifiers or values (the reason command 1 changed)? | P-ACB, a redacted sample | 7.6 |

## 11. OWNER DECISION items (only the owner may accept these)

| Id | Decision | Choices | Reviewer-style recommendation |
|----|----------|---------|-------------------------------|
| D-R1 | Accept that a compromised firewall can encrypt, sign and so poison new backups, bounded by locked older versions, L2 and change-rate alerts and the drill | Accept, or require a second signer (not designed) | Accept; the firewall is the data source |
| D-R2 | Only if the lab test shows `openssl cms` unusable: install `age` or `gpg` on the firewall (unsupported by Netgate, S-NG-FBPKG VERIFIED) after inspect-before-install analysis, or fall back to option B only | Install after inspection, or option B only | Install after inspection. The default path needs no decision: `openssl cms -encrypt -aes256` (lead decision) |
| D-R3 | If the NAS cannot make immutable snapshots or create-only ACLs: accept that NAS history is deletable and S3 is authoritative | Accept, or pick another NAS target | Accept, S3 is the authority |
| D-R4 | S3 provider and its cost gate (cents per month; a Compliance lock is a commitment; Wasabi has a 90-day minimum) | AWS S3, Backblaze B2, Wasabi (new bucket needed), R2 is out (no Object Lock) | AWS S3 or Backblaze B2: both allow the lock on an existing bucket |
| D-R5 | Mode and duration: Compliance, 90 days default retention, 365 days lifecycle (irreversible for the retention length) | Compliance 90 days, longer, or Governance with the bypass permission denied | Compliance 90 days. Governance is weaker: a key holding the bypass capability can delete locked versions (S-AWS-OL, S-B2-OL VERIFIED), so a stolen admin key defeats it |
| D-R6 | Secret manager layout | Dedicated project, or per-role configs in the decided `homelab` dev config | Dedicated project; the decided dev-first rule still holds either way |
| D-R8 | Accept the receipt metadata that stays visible to a disk or bucket thief (pull timing, ciphertext size, coarse bands, epoch and sequence, change or no change) | Accept, or coarsen further (weaker monitor rules) | Accept; the configuration itself stays ciphertext |
| D-R7 | Whether the restore private key also lives in the secret manager or only offline plus the owner's workstation | Both (current text), or offline only | Both, in an owner-only config |

## 12. Build order and who does what

| Step | Who | Depends on |
|------|-----|------------|
| 1. Run the 7.6 commands, send output | OWNER | none |
| 2. Fill the OPEN answers (section 10) into this note; round 2 review | LEAD | 1 |
| 3. Approve this note, thresholds, the access list and D-R1 to D-R7 in one answer | OWNER | 2 |
| 4. Draft wrapper, NAS script, receipt verifier, checker script, Grafana rules and the section 8 tests (repo PRs, tools in `homelab-backup-tools`) | LEAD via implementer | 3 |
| 5. Create F1 to F11, N1 to N8, S1 to S6, D0 to D6 | OWNER (LEAD supplies each full command or exact text) | 3 |
| 6. Run section 8 tests on a test pair, then the live pair; throwaway bucket for L1 to L7; stateless self-test on the firewall (7.6); first real pull as the production ingest, verified by the monitor; first drill | OWNER runs on live hosts, LEAD verifies the output | 4, 5 |
| 7. Unpause the rules once metrics arrive | LEAD with OK | 6 |
| 8. Optional: ACB as a third copy | OWNER | 1 |
