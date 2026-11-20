# Owner runbook: bring the alerting platform fully online

One ordered list of every LIVE step the owner does to finish the alerting
platform (epic #62). Nothing in this repository does these steps for you. Each
step names the doc it comes from, what must be true first, the exact commands,
what to watch, and how to undo it.

Written 2026-11-19 against `origin/master` at commit `a503203`. Steps 0 to 6.3
were audited again on 2026-11-20 against `origin/master` at commit `a4cdb72`
(issue #174); `tests/python/test_owner_runbook.py` keeps the machine-checkable
parts true. Every fact is marked:

- VERIFIED: stated in a repo doc or file, and the doc is cited. VERIFIED means
  "a repo doc says so", not "seen on the live system". Most live behavior is
  still unconfirmed; the source docs say which parts (see their "unverified"
  sections).
- INFERRED: a reasonable reading that no cited doc states. Check it before
  relying on it.
- OPEN QUESTION: a doc is unclear or a name is unknown. Nothing is guessed;
  the owner decides or looks it up.

## Placeholders and conventions

| Placeholder | Meaning |
|-------------|---------|
| `LOGGING_BOX` | The SIEM host that runs the stack |
| `KEY_FILE` | Path to the SSH private key for LOGGING_BOX |
| `REPO_DIR` | Absolute path of a copy of this repository's `scripts`, `n8n`, `docs` and alerting files on LOGGING_BOX, made by step 0a (for example `/home/YOU/siem-docker-stack`). It is NOT `/opt/siem`: that is the deployed stack and has no `n8n` folder and no `live-deploy` scripts |
| `SIEM_DIR` | Live stack directory, default `/opt/siem` (`docs/live-deploy-runbook.md`, variable table) |
| `dev_network`, `DEV_CONFIG` | The Doppler branch config under the `dev` environment of project `homelab` that holds every new alerting value (created in step 0b). `DEV_CONFIG` is the placeholder name the live deploy runbook uses for the same config; its value is `dev_network` |
| `ROUTER_ID` | The n8n id (16 hex characters) of the LIVE router workflow "Grafana SOAR - Alert Router (authenticated)". The router import does NOT print it: read it with `docker exec n8n n8n list:workflow` or from the workflow's address in the n8n interface (the id is in the URL). Passing it makes the import overwrite that workflow; leaving it out makes a second copy with a new id |
| `HANDLER_ID` | The n8n id of the live error handler workflow "Alert Router Error Handler". Printed as `error workflow id:` by the handler import (`docs/live-deploy-runbook.md`, section 3); on a live box read it the same way as `ROUTER_ID` |
| `OLD_ROUTER_ID` | The n8n id of the old router that step 9 deactivates (Q5); read it the same way |
| `SERVICE_ACCOUNT` | The dedicated non-login account of step 0c (suggested name `siem-ops`) |
| `N8N_COMPOSE_FILE`, `N8N_COMPOSE_DIR` | The compose file that runs n8n and its folder. The live values are `/opt/n8n/docker-compose.yml` and `/opt/n8n` (VERIFIED by the lead 2026-11-20). INFERRED root owned, because the step 6.2 run used `sudo` for every touch of it; so copies, edits and `docker compose` runs against it below use `sudo` too |
| `HOST_PORT`, `CONTAINER_PORT` | The loopback port you publish for n8n on the host and the port n8n listens on inside its container (section 6.0) |
| `SIEM_NETWORK` | The real name of the Docker network the stack's containers share, from `docker network ls` (usually the compose project name plus `_siem-net`) |
| `PRIVATE_WEBHOOK_PATH` | The Grafana router's private path, the content of the `router-path` file in the helper's config directory. An address, not a credential, but keep it out of git and chat |
| `EXPIRY_WATCH_PRIVATE_PATH` | The expiry watch's private path, the content of the `expiry-path` file in the same directory |
| `ARCHIVE_FILE` | The `.tar.gz.age` archive a backup run wrote (step 2d) |
| `OBSERVER_HOSTNAME` | The host name inside the heartbeat observer's ping URL (step 7) |
| `VARIABLE_NAME` | A variable name from the table in 6b |

Rules every step follows:

- SSH always names the key and refuses other identities:
  `ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX '...'`. Blocks marked
  "in a session" are pasted after opening one with
  `ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX`.
- `doppler secrets set` echoes the value by default, so every such command
  carries `--silent` and ends with `> /dev/null` (VERIFIED: `--silent` per
  Doppler's setting-secrets page, read 2026-11-19; `> /dev/null` per
  `docs/update-alerting.md`, webhook authentication, step 1). Secret values go
  in on stdin, never on a command line.
- New secrets go in project `homelab`, config `dev_network`, never `prd_network`
  or any prd config, until the owner says the stack is live in production.
- No secret value, host name, real domain or personal detail is written in this
  file. Addresses use `example.com`; the documentation range 192.0.2.x stands
  for real ones.
- Do one step at a time. Verify each before the next.

## Open questions (the repo cannot answer these)

| # | Question | Where it bites |
|---|----------|----------------|
| Q1 | RESOLVED (2026-11-20). `docs/live-deploy-runbook.md` points here for `DEV_CONFIG`: it is the Doppler config `dev_network` (step 0b). | Steps 4g, 5 |
| Q4 | The names `FAILTEST` (workflow and credential) appear in no repo doc. The closest text is the failure-path test copy in `docs/live-deploy-runbook.md`, section 4, items 1 to 6 ("the copy", "a wrong credential in the copy"). Read the exact names in the n8n UI and the ids with `docker exec n8n n8n list:workflow` (INFERRED command; check `n8n list:workflow --help`). | Step 3 |
| Q5 | What is the live name of the old router workflow? The repo workflow is named "Grafana SOAR - Alert Router" and the runbook calls the new one "Grafana SOAR - Alert Router (authenticated)". Which one is live and old is not in a doc; tell them apart by id (`ROUTER_ID` versus `OLD_ROUTER_ID`), not by name. | Step 9 |
| Q7 | RESOLVED by the deploy script change (PR #126, issue #125, merged: commit `862b687`). `scripts/live-deploy/grafana-deploy.py` deploys the notification failure rule and, only when you name them with `--include-example`, the P1 email contact point and policy examples. It does NOT deploy `notification-failure-contact-point.yml.example` (`discord-direct`): that one is always copied by hand (4c). It defaults to a dry run, needs `--apply`, and backs up every file it replaces. It never starts docker and never reads the compose file, so the compose line and the restart stay manual (step 4b and 4d, and 4g below). | Steps 4, 5 |
| Q8 | The Grafana group id for `grafana_uid`/`grafana_gid` in the backup config is not stated. The compose file sets `user: "472"` (VERIFIED) and the example says `grafana_gid = 0`. Read it with `docker exec grafana id`. | Step 2 |
| Q9a | How does the dedicated service account get Docker access for `docker cp` and `docker exec`? Docker group membership is root-equivalent; the safer option is a root-owned wrapper allowed by one exact `sudoers` rule. This doc does not choose. | Steps 0c, 2 |
| Q10 | How is a P1 produced on demand to test the email route end to end? No doc says. | Step 5 |
| Q12 | ANSWERED (owner decision 2026-11-20, issue #157). The limits live in the watch (it refuses a body over 16 KB, waits 2 s between posts, posts at most 15 per run) and in the router's `Check Expiry Secret` node (it denies a body over 16 KB, a call under 1 s after the last accepted one, and more than 30 accepted calls in 10 minutes). See `docs/expiry-watch.md`, "Request limits". | Step 6 |

## Order and why

The order puts read-only checks first, the safety net second, cleanup third,
and every Grafana restart before anything that depends on it. The request's
item numbers are in the last column.

| Step | What | Risk | Depends on | Request item |
|------|------|------|-----------|--------------|
| 0 | Preflight, 0a: put the repo on the box, 0b: one dev config for every new Grafana value, 0c: the service account | low | nothing | |
| 1 | Read the heartbeat ping log | none, read only | heartbeat deployed | 1 |
| 2 | First live backup and restore rehearsal | low | step 0 | 4 |
| 3 | Delete the FAILTEST workflow and credential | low, irreversible | step 2 (a backup exists) | 2 |
| 4 | Notification failure alert rule | medium, restarts Grafana | steps 1, 2 | 3 |
| 5 | P1 email contact point | medium, restarts Grafana | step 4 (one restart at a time) | 6 |
| 6 | Expiry watch, dry run then schedule | low until it posts | steps 1, 5 | 5 |
| 7 | Game-day scenarios, dry run only | none | steps 1, 4 | 7 |
| 8 | Enable Pushover; mute before and unmute after the live tests | medium, pages a real phone | step 5 (so test pages do not collide) | 9 |
| 9 | Deactivate the old router after a day of traffic | medium | steps 1 and 24 hours of normal traffic | 8 |
| 10 | Game-day live runs | high, breaks things on purpose | steps 2, 4, 8, 9 | 7 |

Why this order:

- The backup (step 2) comes before any change to n8n or Grafana, so every later
  rollback has an archive to fall back to. It also holds the n8n credential
  store that step 3 deletes from.
- Steps 4 and 5 each restart Grafana. Do them one after the other with a check
  in between, so a bad file is traced to one change.
- Game-day live runs (step 10) wait for the old router to be gone (step 9),
  because breaking the alert path during the "normal traffic" day would spoil
  that evidence, and the `router-inactive` scenario needs the real router id.
- Pushover (step 8) is enabled before game-day runs, which send real phone
  messages, and after the email test in step 5, whose test P1 would otherwise
  also page the phone.

## Step 0. Preflight (LIVE, read only)

Source: `docs/live-deploy-runbook.md`, sections 1 and 2.

Prerequisites: the stack is running; `siem-run` and its token file exist
(runbook section 2); a copy of this repo exists at `REPO_DIR` on LOGGING_BOX
(step 0a, which you do first; every command below that says `cd REPO_DIR` fails
without it).

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker ps --format "{{.Names}}" | sort'
```

Expected: the n8n, grafana and influxdb containers are listed (VERIFIED:
runbook section 1 check).

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-setup-alert-router.py --check; echo "exit code: $?"'
```

Expected: three lines `... : present` and `exit code: 0` (VERIFIED: runbook
section 2). `siem-run: token file missing or unreadable` means section 2 of that
runbook is incomplete.

Then do step 0b before steps 4 and 5.

Rollback: nothing changed.

## Step 0a. Put the repo on the box (LIVE, do this first)

Why: `/opt/siem` on LOGGING_BOX is the deployed stack. It has no `n8n` folder and
no `scripts/live-deploy` folder, so the router import, the test script, the
backup, the expiry watch and the example files named below do not exist there.
`REPO_DIR` must be created. `scripts/live-deploy/*.py` import
`scripts/container_engine.py` from the folder above them, so copying only
`live-deploy` breaks them: copy the whole `scripts` folder.

Pick `REPO_DIR`. The suggestion is `/opt/siem-repo`: root owned and readable by
everyone, so the jobs of step 0c (which run as `SERVICE_ACCOUNT`) can read it and
cannot change the code they run. A path under a home directory fails for that
account when the home directory is mode 700. It holds no state and no secret.

On your workstation, in a clone of this repository (the fetch makes sure
`origin/master` is current; the last command prints the commit the archive was
made from, so you can record it):

```
git fetch origin && git rev-parse --short origin/master
git archive --format=tar.gz --prefix=siem-docker-stack/ -o "$HOME/siem-repo.tar.gz" origin/master scripts n8n docs docker/grafana/provisioning/alerting
gzip -dc "$HOME/siem-repo.tar.gz" | git get-tar-commit-id
scp -i KEY_FILE -o IdentitiesOnly=yes "$HOME/siem-repo.tar.gz" LOGGING_BOX:siem-repo.tar.gz
rm -f "$HOME/siem-repo.tar.gz"
```

Then unpack it on LOGGING_BOX. `--strip-components=1` drops the
`siem-docker-stack/` prefix, so the folders land directly in `REPO_DIR`:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo mkdir -p /opt/siem-repo && sudo tar -xzf "$HOME/siem-repo.tar.gz" -C /opt/siem-repo --strip-components=1 --no-same-owner && rm -f "$HOME/siem-repo.tar.gz" && ls /opt/siem-repo/scripts/live-deploy /opt/siem-repo/n8n && ls -ld /opt/siem-repo'
```

Expected: the `live-deploy` scripts (including `siem-run`), `grafana-alert-router.json`
in the `n8n` listing, and `drwxr-xr-x ... root root` for the folder. Here
`REPO_DIR` is `/opt/siem-repo`; substitute it in every command below. To update
later, repeat both blocks (files removed from the repo stay behind; to reset
first, `sudo rm -rf /opt/siem-repo`, since it holds nothing else).

Rollback: `sudo rm -rf /opt/siem-repo`. Nothing else changed. The archive holds
only repository files, no secret value and no live address.

## Step 0b. One dev config for every new Grafana value (LIVE)

Owner decision: all values the Grafana restart needs live in ONE dev config of
the `homelab` Doppler project, and the restart reads only that config. That
config holds the new SMTP values (step 5), the failure webhook URL (step 4) and a
copy of `GRAFANA_WEBHOOK_SECRET`. The copy is needed because Compose refuses to
start Grafana without that variable (VERIFIED: `docker/docker-compose.yml`
requires it non-empty). `prd_network` is not changed by anything in this step or
in steps 4 and 5: it is only read, once, to make the copy.

The config is named `dev_network` (owner decision), a branch config under the
`dev` environment of project `homelab`. It does not exist yet; item 1 creates
it. The configs in `homelab` before this step are `dev`, `dev_personal`, `prd`,
`prd_network` and `stg` (read with `doppler configs --project homelab` on
2026-11-19). Do not use any prd config.

Prerequisites: Doppler CLI logged in on the machine where you run these
commands, with access to project `homelab`.

1. Create `dev_network` and confirm it exists. Flags VERIFIED from
   `doppler configs create --help`, run 2026-11-19: `--environment/-e`,
   `--project/-p`, and the name as a positional argument or `--name`. INFERRED:
   the naming rule for branch configs (the name starts with the environment
   name, here `dev`); if Doppler refuses the name, stop and report the message.

```
doppler configs create dev_network --project homelab --environment dev
doppler configs --project homelab
```

   The second command lists the configs; `dev_network` must appear next to the
   five existing ones, and nothing existing changes. It holds no secrets yet.

   Rollback for this item: delete it only while it is empty. First confirm it is
   empty (`--only-names` is VERIFIED from `doppler secrets --help`, 2026-11-20):

```
doppler secrets --only-names --project homelab --config dev_network
```

   Then delete it. Flags VERIFIED from `doppler configs delete --help`, run
   2026-11-19: the config as a positional argument or `--config/-c`,
   `--project/-p`, and `--yes/-y` to skip the confirmation (leave `--yes` off to
   be asked):

```
doppler configs delete dev_network --project homelab
```

   Once later steps have put secrets in it, deleting it destroys them; use the
   per-step rollbacks instead.

2. Copy the webhook secret value from `prd_network` into the dev config without
   ever printing it. Doppler's own output goes straight into the second command
   on stdin. `doppler secrets set` echoes the value by default, so the second
   command carries `--silent` and also ends in `> /dev/null` (both, on purpose):

```
doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config prd_network | doppler secrets set GRAFANA_WEBHOOK_SECRET --project homelab --config dev_network --silent > /dev/null
```

   Method status, from Doppler's documentation read 2026-11-19
   (docs.doppler.com: accessing-secrets, setting-secrets, secrets-setup-guide,
   and the CLI pages):

   - VERIFIED: `doppler secrets get NAME --plain` prints the value alone
     (accessing-secrets, "Getting Values").
   - VERIFIED: `doppler secrets set NAME` accepts the value on piped stdin
     (setting-secrets: "interactive mode, key-value pairs, or stdin", with the
     example `cat file | doppler secrets set TLS_CERT`). The stdin form with
     `> /dev/null` is also used in `docs/update-alerting.md` (webhook
     authentication, step 1).
   - VERIFIED: `set` echoes the value by default and `--silent` suppresses it
     (setting-secrets). Every `doppler secrets set` in this runbook carries
     `--silent` and ends in `> /dev/null`. The CLI's own help describes
     `--silent` only as "disable output of info messages" (read from
     `doppler secrets set --help` 2026-11-20), so the `> /dev/null` is the part
     you rely on; keep both.
   - VERIFIED (CLI help, run 2026-11-20): `doppler secrets get` and `doppler
     secrets set` both take `--project/-p` and `--config/-c`; `get` has
     `--plain`; `doppler secrets` has `--only-names`; `doppler configs create`
     and `delete` take the flags used in item 1. Confirm again with `--help` if
     your CLI version differs.
   - NOT DOCUMENTED: whether `--plain` prints a trailing newline, and how `set`
     treats a trailing newline on stdin. That is why the check in item 3 is
     required, not optional.

   If the second command errors, stop and report; do not fall back to typing the
   value.

3. Required check of the copy, printing only `same` or `differs`, never a value
   (flags are VERIFIED per item 2):

```
test "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config prd_network | sha256sum | cut -d' ' -f1)" = "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config dev_network | sha256sum | cut -d' ' -f1)" && echo same || echo differs
```

Expected: `same`. If it prints `differs`, the likely cause is a trailing newline
added or kept by one of the two commands. Stop and report it. Do not use the
copy, do not start the Grafana restart in steps 4 and 5 with it, and do not
try to fix it by typing or printing the value. Delete the dev copy (see
Rollback below) until it is resolved.

4. Find out which other variables the Grafana restart needs, BEFORE steps 4 and
   5 restart it from this one config. `docker compose up -d grafana` reads the
   whole compose file, and `docker/docker-compose.yml` requires, with no default,
   `GRAFANA_ADMIN_PASS`, `WAZUH_GRAFANA_RO_PASSWORD`, `OPENSEARCH_READONLY_PASSWORD`,
   `GRAFANA_INFLUX_PASSWORD`, `PROMETHEUS_GRAFANA_PASSWORD`,
   `PROMETHEUS_OTLP_GRAFANA_PASSWORD`, `INFLUXDB_ADMIN_PASSWORD` and more (list them
   all with the first command below, which prints names only). Variables that have a
   default, such as `SIEM_HOST` (it sets `GF_SERVER_ROOT_URL`), `GRAFANA_ADMIN_USER`
   and `BIND_ADDR`, silently fall back to the default when they are missing: a
   restart that lacks `SIEM_HOST` changes Grafana's root URL. Where these values come
   from today (an `.env` file in `/opt/siem` that Compose reads on its own, or the
   shell) is not in a repo doc (OPEN QUESTION). Compose reads `/opt/siem/.env` in
   addition to the shell, and a `doppler run` value wins over `.env`, so an `.env`
   that already holds them is enough (INFERRED from Compose's precedence rules).
   Read-only checks, names and a file listing only, never a value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'grep -oE "[$][{][A-Za-z0-9_]+" /opt/siem/docker-compose.yml | sort -u; ls -l /opt/siem/.env'
doppler secrets --only-names --project homelab --config dev_network
```

   Every name from the first list that is neither in `/opt/siem/.env` nor in the
   second list must be added to `dev_network` (copy it from `prd_network` the way
   item 2 does, one at a time, with the item 3 check) before any Grafana restart.
   If the restart fails with a `set NAME` message, the container is unchanged:
   add that name and retry.

Watch: the output of item 2 is empty, and no secret value appears anywhere in
the terminal or scrollback.

Note that the copy now holds a shared secret in two configs. `docs/update-alerting.md`
says the secret must be unique to the router contact point and never reused for
other services; this is the same contact point, and the owner chose it. Rotate
both together (VERIFIED: "Rotate by changing the Doppler value and the n8n
credential together"; add the dev copy to that list).

Rollback: delete `GRAFANA_WEBHOOK_SECRET` from the dev config in Doppler. Nothing
in `prd_network` was changed, and the live Grafana is unaffected until step 4d.

## Step 0c. The dedicated service account for scheduled jobs (LIVE)

Owner decision: a dedicated, non-login system account, placeholder
`SERVICE_ACCOUNT` (suggested name `siem-ops`), runs both scheduled jobs: the state
backup (step 2) and the expiry watch (step 6). Neither runs as a person or as
root by default. Do this before step 2.

Source for the shape: `docs/examples/siem-state-backup.service` (a dedicated
user, `UMask=0077`, and the warning that docker group membership is
root-equivalent) and `docs/expiry-watch.md` ("Scheduling": the job user owns the
config, env file and state file, mode 0600).

### 0c.1 Create the account and its state directory

The flags below were checked against the local `useradd --help` on 2026-11-19
(`--system`, `--no-create-home`, `--shell`, `--home-dir` all exist). That this
combination suits your distribution is INFERRED. In a session on LOGGING_BOX:

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/SERVICE_ACCOUNT SERVICE_ACCOUNT
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /var/lib/SERVICE_ACCOUNT
id SERVICE_ACCOUNT
ls -ld /var/lib/SERVICE_ACCOUNT
```

Expect a `uid=` line with no extra groups, and `drwx------` owned by the
account. The nologin shell path may differ on your system (INFERRED; check
`getent passwd` for what other system accounts use).

### 0c.2 Where files live and who can read them

| What | Where (examples, owner may change) | Who may read | Source |
|------|------------------------------------|--------------|--------|
| Backup archives and their `.manifest.json` | `destination_dir`, for example `/var/lib/SERVICE_ACCOUNT/backups` | root and `SERVICE_ACCOUNT` only (mode 700 directory, files written with `UMask=0077`) | example service unit; `docs/backup-restore.md` (directory must be owned by you and not group or world writable, VERIFIED) |
| Backup config with the age PUBLIC recipients | `/etc/siem-state-backup.toml`, mode 0640 per the example, group `SERVICE_ACCOUNT` so only root and the account read it | root and `SERVICE_ACCOUNT` | example config |
| Expiry watch config, registry and state file | `/etc/expiry-watch`, owned by `SERVICE_ACCOUNT`, mode 700 | `SERVICE_ACCOUNT` (and root) | `docs/expiry-watch.md` |
| Doppler read-only token file | `/var/lib/SERVICE_ACCOUNT/doppler-token`, mode 600 | `SERVICE_ACCOUNT` only | this step |
| The age PRIVATE keys | NOT on LOGGING_BOX | the owner, offline | `docs/backup-restore.md` secret material warning |

The private age key is never on the box and the job never touches it: the backup
uses public recipients only and cannot decrypt (VERIFIED: `docs/backup-restore.md`).
Create the backup directory and set the group on the config:

```
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /var/lib/SERVICE_ACCOUNT/backups
sudo chgrp SERVICE_ACCOUNT /etc/siem-state-backup.toml
sudo chmod 0640 /etc/siem-state-backup.toml
```

(Run the `chgrp` after step 2b creates the config, and set `destination_dir` to
`/var/lib/SERVICE_ACCOUNT/backups` for the SCHEDULED run; both are INFERRED layout
choices.) The backup refuses a `destination_dir` that is not owned by the user
running it (VERIFIED: `scripts/state_backup_lib.py`, "destination_dir is not owned
by the user running the backup"), so the by-hand `sudo` run of step 2c, which runs
as root, cannot use this directory; step 2c says what to do.
`ProtectSystem=strict` in the example unit also needs `ReadWritePaths` to name the
archive directory; edit the unit in step 2e.

### 0c.3 How the account gets its secrets

The owner creates a read-only Doppler service token scoped to the `dev_network`
config only (project `homelab`), in the Doppler dashboard. This doc does not
describe that screen (no repo doc verifies it; send a screenshot if unsure).
Never type the token on a command line, never print it. Store it, read from a
prompt, in a file only the account can read:

```
read -rs -p "Doppler service token: " TOK; echo
printf '%s' "$TOK" | sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /dev/stdin /var/lib/SERVICE_ACCOUNT/doppler-token
unset TOK
sudo ls -l /var/lib/SERVICE_ACCOUNT/doppler-token
```

Expect `-rw-------` owned by the account, and no token in the terminal
(INFERRED: `install` from `/dev/stdin`; this mirrors the token-file pattern in
`docs/live-deploy-runbook.md` section 2, which is VERIFIED for `siem-run`). A
scheduled job then reads it through the Doppler CLI's token variable, for example
`DOPPLER_TOKEN` set from that file inside the unit or wrapper, never written into
the unit text (INFERRED: whether your CLI version takes the token that way;
confirm with `doppler run --help`). A read-only token cannot be used to change
secrets. Rotate it by creating a new token and replacing the file, then revoking
the old one in the dashboard.

### 0c.4 The timers run as this account

The backup unit's `User=` is `SERVICE_ACCOUNT` (the example uses a placeholder
user, VERIFIED). The expiry watch unit or cron entry runs as the same account, so
the config folder in 6a is owned by it. Use whichever of systemd timers or cron
you prefer; a cron entry goes in that account's crontab (`sudo crontab -u
SERVICE_ACCOUNT -e`; INFERRED, a nologin account can still own a crontab).

### 0c.5 Docker access: the owner decides (OPEN QUESTION Q9a)

The backup uses `docker cp` and `docker exec` (VERIFIED: `docs/backup-restore.md`),
so the account needs access to the Docker socket. Plainly: membership of the
`docker` group is root-equivalent, since anyone who can start containers can
mount the host's filesystem (VERIFIED: warning in
`docs/examples/siem-state-backup.service`). Giving a service account that access
means a flaw in the job or a leak of its files becomes a root-level problem.

Two options. This doc does not choose:

- Option 1: add `SERVICE_ACCOUNT` to the `docker` group. Simple, and the
  root-equivalent risk above applies in full. The expiry watch does not need
  Docker and can run without it only if it runs under a different account, which
  contradicts the one-account decision.
- Option 2: keep the account out of the `docker` group and let it run only the
  exact backup command as root through a small root-owned wrapper script and a
  `sudoers` entry that allows that one command and nothing else. Safer. Cost: the
  wrapper and sudoers rule must be written, reviewed and tested (a code and
  config change outside this doc), and the `restore` side is a separate
  decision. The archives would then be written by root unless the wrapper
  drops privileges, which is a design question for that change.

Until the owner answers Q9a, do 0c.1 to 0c.4, and run step 2c by hand with `sudo`
as written; do not schedule the backup (2e) and do not start the expiry watch
timer under a docker-capable account.

Rollback: `sudo userdel SERVICE_ACCOUNT` (INFERRED command name), then remove
`/var/lib/SERVICE_ACCOUNT` once nothing needs the archives, and revoke the
Doppler token in the dashboard. Archives you still need must be copied out first.

## Step 1. Read the Healthchecks ping log (LIVE, read only)

Request item 1. Source: `docs/heartbeat.md` (sections "The three observers",
"Enable it", "Failure behavior").

Prerequisites (all VERIFIED as the enable list in `docs/heartbeat.md`; whether
they are done on the live box is INFERRED until you check):

- Grafana rule "Alert path heartbeat" is deployed and Grafana was restarted.
- The `heartbeat` route is merged into the notification policy tree.
- The updated router workflow is imported and active.
- `HEARTBEAT_PING_URL` and `HEARTBEAT_KIND` are set on the n8n container, with
  `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`.
- The check at the observer has a simple 5 minute period and a grace time of at least 15 minutes
  (it goes down after about 20 minutes of silence, period plus grace; see [heartbeat.md](heartbeat.md) if it shows down while the path is up).

Check the n8n container has the variable, printing presence only, never the
value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$HEARTBEAT_PING_URL\" ]; then echo HEARTBEAT_PING_URL set; else echo HEARTBEAT_PING_URL unset; fi; echo HEARTBEAT_KIND=\${HEARTBEAT_KIND:-healthchecks}"'
```

Then open the check's ping log in the observer's web interface. The docs do not
describe that screen, so this doc does not either (INFERRED: Healthchecks lists
each ping with a timestamp; send a screenshot if it looks different).

Watch:

- Pings arrive every 5 to 6 minutes (VERIFIED: `docs/heartbeat.md`, "How it
  works"; Grafana repeats only at a `group_interval` tick). Over 30 minutes
  expect 5 to 6 pings. A failed ping is now retried up to 3 times, so one ping
  can arrive up to 19 seconds late (VERIFIED: `docs/heartbeat.md`, "Failure
  behavior"); that is not a fault.
- A gap over about 6.5 minutes or two pings closer than 5 minutes is not
  expected; note the times. The observer goes down only after about 20 minutes
  of silence (period 5 plus grace 15), which tolerates about three missed pings.
- No `/fail` pings: those mean a heartbeat with a wrong `phone` label (VERIFIED:
  "Contract failure sends /fail").

If no pings: the doc's list of causes is Grafana down or the rule broken, the
contact point or its header credential wrong, n8n down or the workflow inactive,
the route to the observer broken, or the variable unset (VERIFIED: "What stops
the pings"). Fix by the "Enable it" list, then re-read the log.

Rollback: none needed, this step changes nothing.

## Step 2. First live backup and a restore rehearsal (LIVE)

Request item 4. Source: `docs/backup-restore.md`, section "n8n and Grafana state
backup (issue #83)"; `docs/examples/siem-state-backup.example.toml`; the
`.service` and `.timer` examples next to it.

What this is: an age-encrypted archive of n8n (workflows, credentials still
encrypted by n8n, its encryption key) and the Grafana database (VERIFIED: "What
is and is not covered"). OpenSearch snapshots are a separate job in the first
half of the same doc and are not part of this step.

Prerequisites:

- A machine you trust that is NOT LOGGING_BOX, to hold the age private key
  (VERIFIED: "Keep the age identity off the host that runs the backup, ideally
  offline").
- A place for the archives on LOGGING_BOX (`destination_dir`, default in the
  example `/var/backups/siem-state`).
- Step 0c done, and Q8 answered.
- The documented caveat: no live run of any of this has happened yet, including
  real `age`, `rclone` and the `docker exec` and `docker cp` calls (VERIFIED:
  "Not verified (no live run yet)"). Treat the first run as a test.

### 2a. Make the age keys (on the trusted machine, not LOGGING_BOX)

Make two key pairs so one lost key does not lose the backups (VERIFIED: example
config, "List two or more"). Store the private files offline.

```
age-keygen -o "$HOME/siem-backup-identity-1.txt"
age-keygen -o "$HOME/siem-backup-identity-2.txt"
```

Each command prints `Public key: age1...`. Only the public key goes into the
config. The `.txt` files are the identities (private keys): never copy them to
LOGGING_BOX or into this repo (VERIFIED: config comments; `backup-restore.md`
secret material warning). Copying them onto an offline store is the owner's
choice; the doc says only "offline".

### 2b. Install age and write the config (on LOGGING_BOX)

In a session:

```
sudo apt install age
age --version
sudo cp REPO_DIR/docs/examples/siem-state-backup.example.toml /etc/siem-state-backup.toml
sudo chmod 0640 /etc/siem-state-backup.toml
sudo "${EDITOR:-nano}" /etc/siem-state-backup.toml
```

(The doc says to verify the version after install, INFERRED: any current `age`
works; check the package source.) In the editor set:

- `age_recipients`: the two public keys, one string each. Public keys only; the
  tool rejects secret keys (VERIFIED).
- `destination_dir`: your archive directory.
- `grafana_data_host_dir`: `/data/warm/grafana` (VERIFIED: the compose file
  mounts `/data/warm/grafana` at `/var/lib/grafana`), and `grafana_db_method =
  "auto"` then resolves to `host-sqlite`, the recommended method.
- Restore keys, needed only for a restore but set them now: `helper_image`,
  `grafana_uid = 472` (VERIFIED: compose `user: "472"`), `grafana_gid` (Q8),
  `n8n_uid` and `n8n_gid` (the example shows 1000; INFERRED, check with
  `docker exec n8n id`).
- `rclone_remote` stays commented out until the off-host copy is chosen. An
  off-host copy is recommended by the doc but its tooling is unverified live.

### 2c. First run, by hand

`sudo` runs the backup as root because it needs the container runtime, and the
backup refuses a `destination_dir` that is not owned by the user running it
(VERIFIED: `scripts/state_backup_lib.py`). So for this by-hand run `destination_dir`
must be a root-owned folder, not the `SERVICE_ACCOUNT` folder of step 0c. Create
it and set `destination_dir = "/var/backups/siem-state"` (the example's default)
in the config first:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo install -d -m 700 -o root -g root /var/backups/siem-state && ls -ld /var/backups/siem-state'
```

OWNER DECISION (with Q9a): the scheduled runs as `SERVICE_ACCOUNT` need
`destination_dir` owned by that account (`/var/lib/SERVICE_ACCOUNT/backups`,
step 0c), so the config's `destination_dir` changes again when step 2e is done.
Until Q9a is answered, only the by-hand root run exists.

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && sudo python3 scripts/backup-state.py --config /etc/siem-state-backup.toml; echo "exit code: $?"'
```

(The scheduled runs use the dedicated account from step 0c; its Docker access is
Q9a. INFERRED.) Then look at the output directory:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo ls -l /var/backups/siem-state'
```

Watch:

- Exit code 0 and two new files: `siem-state-<UTC timestamp>.tar.gz.age` and
  `<name>.manifest.json` (VERIFIED: "Files written").
- The archive size is more than a few kilobytes (Grafana database plus n8n
  export).
- Any `RECOVERY NEEDED` or Python error text: stop, do not schedule, read
  `docs/backup-restore.md`, "Not verified".
- The `.manifest.json` is advisory only (VERIFIED). Authenticity comes from age.

### 2d. Restore rehearsal (never on production)

Follow the six-step drill in `docs/backup-restore.md` ("Restore drill") on a
scratch machine or a throwaway compose project with a second n8n and Grafana.
Copy the archive and one identity there over a path you trust.

Dry run, which changes nothing (VERIFIED: the doc's command, with your paths):

```
python3 scripts/restore-state.py --config /etc/siem-state-backup.toml --identity "$HOME/siem-backup-identity-1.txt" ARCHIVE_FILE
```

Expect both components listed and checksums ok. Then flip one byte in a copy of
the archive and confirm the dry run aborts. Only on the scratch containers:
`--apply --restore-n8n-key`, then publish workflows, restart n8n, start Grafana
and confirm a credential decrypts and the dashboards and contact point exist
(the doc's drill, steps 4 and 5). Use the second identity for one dry run to
prove it also decrypts. Record the date and result in your ops notes
(VERIFIED: step 6).

### 2e. Schedule it

Only after 2c and 2d pass, and after the Docker access answer in 0c.5 (do not
enable the timer before it). The example unit carries placeholder paths and a
placeholder user. Copy both files, then edit the unit with `sudoedit`: set
`User=` to `SERVICE_ACCOUNT`, `ExecStart=` to
`/usr/bin/python3 REPO_DIR/scripts/backup-state.py --config /etc/siem-state-backup.toml`
(the example's `/opt/siem/scripts/backup-state.py` does not exist on the box),
and `ReadWritePaths=` to the archive directory; set `destination_dir` in the
config to `/var/lib/SERVICE_ACCOUNT/backups`. Then enable the timer:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp REPO_DIR/docs/examples/siem-state-backup.service REPO_DIR/docs/examples/siem-state-backup.timer /etc/systemd/system/ && sudoedit /etc/systemd/system/siem-state-backup.service'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo systemctl daemon-reload && sudo systemctl enable --now siem-state-backup.timer && systemctl list-timers siem-state-backup.timer'
```

Expect the timer listed with a next run near 02:30 (VERIFIED: the example timer).
After its first scheduled run, check
`journalctl -u siem-state-backup.service --since today` and the directory.

Rollback: `sudo systemctl disable --now siem-state-backup.timer`; archives are
only files and can be deleted. The config file can be removed. Nothing else on
the stack changed. Keep the identities.

## Step 3. Delete the FAILTEST workflow and its credential (LIVE, irreversible)

Request item 2. Source: `docs/live-deploy-runbook.md`, section 4 (the
failure-path test in a copy, item 6 "Delete the copy") and section 3 (what lives
inside n8n). The name `FAILTEST` itself is in no doc (Q4); use the names you see
in the n8n UI.

Prerequisites:

- Step 2 done: a backup archive exists.
- You can tell the test copy from the real router. The real router is the
  workflow named in `docs/live-deploy-runbook.md` section 3
  ("Grafana SOAR - Alert Router (authenticated)", INFERRED to be the live one;
  Q5) with the credential `grafana-webhook-auth`. The error handler is a
  different workflow with an Error Trigger. Neither may be deleted.
- The test copy has its own webhook path and is not the one Grafana's contact
  point posts to (VERIFIED: the runbook gives the copy "its own webhook path").

Steps, in the n8n web interface (the docs name no menu paths; use the workflow
list and the credentials list as you find them, and send a screenshot if
unsure):

1. List the workflows with their ids (INFERRED command, check
   `n8n list:workflow --help`) and write down the id of the test copy, of the
   live router (`ROUTER_ID`) and of the error handler (`HANDLER_ID`). Tell them
   apart by id, not by name: a duplicate of the router has a similar name.
   Open the test copy in the interface by its id. Confirm it is inactive and that
   its webhook path differs from the live one.

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n list:workflow'
```

2. Delete the workflow (the copy only).
3. Open the credentials list and find the credential made for the failing test
   (for example the deliberately wrong Discord or Pushover credential from the
   test, runbook items 2 and 5). Confirm no other workflow uses it, then delete
   it.
4. Do not touch `grafana-webhook-auth`, `pushover-api`, the Discord webhook
   credential, the router, or the error handler (VERIFIED: runbook section 3).

Read back: run the same `list:workflow` command again. The copy is gone and
`ROUTER_ID` and `HANDLER_ID` are still listed.

Watch: the next heartbeat ping still arrives within 6 minutes (step 1), and no
new error appears in `docker logs --since 10m n8n`.

Rollback: there is no undo in n8n. The test copy has no value; to recreate a
test copy later, duplicate the router and follow runbook section 4. If you
deleted the wrong thing, restore from the step 2 archive on the scratch setup and
re-import the item, or recreate the credentials with
`n8n-setup-alert-router.py --credentials` (VERIFIED: runbook section 3).

## Step 4. Deploy the notification failure alert rule, issue #81 (LIVE)

Request item 3. Source: `docs/notification-failure-alerts.md`; files
`docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml`,
`notification-failure-contact-point.yml.example`,
`notification-failure-notification-policy.yml.example`.

What it does: the rule fires when Grafana's own failed-delivery counter rises,
and routes to a Discord contact point that does not go through n8n (VERIFIED:
"Routing: a different path on purpose").

Prerequisites:

- Step 2 done (backup) and step 1 healthy (so a Grafana restart can be judged).
- A Discord webhook for this purpose, different from the one n8n posts to if
  you can (VERIFIED: contact point example). Created in Discord by you.
- A datasource with uid `prometheus` exists in the live Grafana (VERIFIED in
  `docker/grafana/provisioning/datasources/datasources.yml`; INFERRED for the
  live stack, check the datasource list).
- Step 0b done, and Q7 settled.

### 4a. Store the webhook URL in Doppler dev

In a terminal where the Doppler CLI is logged in. The value is read without
echo and sent on stdin; the command ends in `> /dev/null` because the CLI
echoes values:

```
read -rs -p "Discord failure webhook URL: " VAL; echo
printf '%s' "$VAL" | doppler secrets set DISCORD_FAILURE_WEBHOOK_URL --project homelab --config dev_network --silent > /dev/null
unset VAL
doppler secrets --project homelab --config dev_network --only-names | grep -c DISCORD_FAILURE_WEBHOOK_URL
```

The last line prints `1` when the name exists (the `--only-names` flag is
VERIFIED; the check prints a count, never the value). The `read -rs` plus stdin
approach follows the documented `openssl ... | doppler secrets set ... >
/dev/null` form (VERIFIED: `docs/update-alerting.md`); reading from a prompt is
INFERRED.

### 4b. Pass the variable to Grafana (compose, on LOGGING_BOX)

The compose file does not carry it today (VERIFIED: no `DISCORD_FAILURE` in
`docker/docker-compose.yml`; the example file says it "needs the variable passed
to the grafana service"). In a session, back up and add one line after the
`GRAFANA_WEBHOOK_SECRET` line:

```
cd /opt/siem
( umask 077 && cp --no-clobber docker-compose.yml "docker-compose.yml.bak-$(date -u +%Y%m%dT%H%M%SZ)" )
ls -l docker-compose.yml.bak-*
grep -c 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml
sed -i '/- GRAFANA_WEBHOOK_SECRET=/a\      - DISCORD_FAILURE_WEBHOOK_URL=${DISCORD_FAILURE_WEBHOOK_URL:-}' docker-compose.yml
grep -n -B1 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml
```

The first `grep -c` must print `0` before the `sed` (else the line already
exists; skip the `sed`). The last command shows the new line directly under
`GRAFANA_WEBHOOK_SECRET`. The path `/opt/siem` is the documented default
(`SIEM_DIR`). The backup is mode 600 and never replaces an earlier one (the same
form as `docs/live-deploy-runbook.md`, section 5, step 4); its `ls` line must start
with `-rw-------`. If the last `grep` prints nothing, the live file spells the
line without `=` (the form `      - GRAFANA_WEBHOOK_SECRET` that the live deploy
runbook gives): the `sed` anchor found nothing, so add the line by hand under that
one instead. If the `cp` or the `sed` says permission denied, `/opt/siem` is not
yours to write (INFERRED; step 4c needs `sudo` for the folder below it): repeat
with `sudo`, and keep the backup mode 600.

### 4c. Copy the rule and the contact point

Copy them as their own files so a later `grafana-deploy.py` run, which rewrites
`contact-points.yml`, cannot overwrite them (INFERRED from the script's file
list, Q7):

```
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml /opt/siem/grafana/provisioning/alerting/notification-failure-alert-rule.yml
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/notification-failure-contact-point.yml.example /opt/siem/grafana/provisioning/alerting/notification-failure-contact-point.yml
ls -l /opt/siem/grafana/provisioning/alerting/
```

(`/opt/siem/grafana/provisioning/alerting/` is the folder the deploy script
writes: VERIFIED in `scripts/live-deploy/grafana-deploy.py` and runbook
section 5.)

### 4d. Restart Grafana and check

Grafana reads provisioning files only at startup (VERIFIED: runbook section 5).
The restart reads only the one dev config from step 0b (owner decision). The
`doppler run --project ... --config ... --` form is VERIFIED in
`docs/update-alerting.md`, step 4 of its webhook authentication list, there with
`prd_network`:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && doppler run --project homelab --config dev_network -- docker compose up -d grafana; echo "exit code: $?"'
```

(That the Doppler CLI on LOGGING_BOX is logged in to project `homelab` with
access to the dev config is INFERRED; the runbook's token file serves `siem-run`
only, and that token is, per the repo's examples, scoped to `prd_network`, not to `dev_network`.
OWNER DECISION: how the box reads `dev_network` for a Grafana or n8n restart, either
a login of your own user on the box, or a read-only service token scoped to
`dev_network` kept in a mode 600 file and used the way `siem-run` uses its token.
The `SERVICE_ACCOUNT` token of step 0c is for that account's jobs only.) Compose refusing to start with `GRAFANA_WEBHOOK_SECRET must be set and
non-empty` means the copy in step 0b is missing; the container stays on its old
definition until it is fixed. Any other variable Grafana needs from the old
`prd_network` setup, such as the Pushover or datasource values, must also be in
this config (INFERRED: compare `docker/docker-compose.yml` with the config before
you restart).

Check:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker logs --since 5m grafana 2>&1 | tail -40'
```

Look for provisioning errors naming the two new files. In the Grafana web
interface (Alerting), the folder "Alert Path" holds the rule "Grafana
notification delivery failing" (VERIFIED: rule file), state Normal, and the
contact point `discord-direct` exists. An Error state means the datasource uid
or the metric query is wrong; see 4f.

### 4e. Merge the policy route (manual, the tree is one per organization)

Do not load the `.example` policy file: it replaces the whole tree (VERIFIED:
its header). In Alerting, Notification policies, add one child route with these
values from the example file (VERIFIED): matcher `delivery_failure = true`,
contact point `discord-direct`, group by `alertname` and `integration`, group
wait 30s, group interval 5m, repeat interval 4h. Place it before any route that
matches everything. Do not change the other routes.

### 4f. Prove it can fire (the metric name is UNVERIFIED)

The counter name `grafana_alerting_notifications_failed_total` is unverified,
and it did not exist on the live Grafana on 2026-11-19 because Grafana creates
it after its first failure (VERIFIED: `docs/notification-failure-alerts.md`,
"Unverified: the metric name"). Until you force one failure, the rule is not
proven. The doc's procedure:

1. In Grafana create a temporary contact point of type webhook with URL
   `http://localhost:9/` and use its Test button. Leave the real policy tree
   alone. (That the Test button increments the counter is itself unverified;
   if it does not, point a temporary policy route at it and fire a test alert,
   then remove the route.)
2. Read the counter:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec grafana wget -q -O- http://localhost:3000/metrics | grep notifications_failed'
```

(The doc uses `curl http://grafana:3000/metrics` from a host that can reach it;
the `docker exec wget` form is INFERRED, and the metrics endpoint may need
authentication on your setup.)

3. If the name differs, change the one metric name in query A of the rule file,
   copy it again (4c), restart Grafana (4d).
4. Delete the temporary contact point (and temporary route if used).
5. Then press Test on `discord-direct` and confirm a Discord message arrives.

Watch: after a real or forced failure, the rule goes Pending for 5 minutes then
Firing, and a Discord message arrives in the failure channel (VERIFIED: rule
`for: 5m`).

Rollback (VERIFIED approach, same as `docs/live-deploy-runbook.md` section 5):
delete the policy route; delete the two files from the live alerting folder;
restore `docker-compose.yml.bak-<UTC timestamp>` over the compose file; run the restart
in 4d. n8n and the heartbeat are untouched by this change.

### 4g. Optional: copy the rule file with the deploy script instead of the first line of 4c

PR #126 is merged (commit `862b687`), so the script is in the repo; it reaches
LOGGING_BOX through step 0a. It replaces only the FIRST line of 4c (the rule file):
the `discord-direct` contact point file in the second line of 4c is not on the
script's allowlist and is always copied by hand. The script copies files and
nothing else: it never starts docker and never reads the compose file. It needs
write access to `/opt/siem/grafana/provisioning` as the user who runs it; 4c uses
`sudo` for that folder, so check `ls -ld /opt/siem/grafana/provisioning` first
(INFERRED: if it is root owned, this route does not work as your user, and 4c is
the way). It also needs the `router-path` file of step 6.1 in the helper's config
directory, because it writes the private path into `contact-points.yml`.

Stage the repo files into `SIEM_STAGE_DIR` (default `$HOME/bin/alerting`; the folder
must not be writable by group or others and the files must be mode 644), look at
the plan, then apply:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'mkdir -p "$HOME/bin/alerting" && cd REPO_DIR/docker/grafana/provisioning/alerting && install -m 644 contact-points.yml update-alert-rules-unifi.yml update-alert-rules-pfsense.yml heartbeat-alert-rule.yml notification-failure-alert-rule.yml "$HOME/bin/alerting/"'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/grafana-deploy.py'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/grafana-deploy.py --apply'
```

The second command is a dry run (the default) and changes nothing. `--apply`
backs up each file it replaces as `NAME.bak-<UTC timestamp>`, replaces the files
one at a time and prints a `manifest:` line for each. It is not atomic: if it
stops on an error it lists the files already replaced and the backup for each
(`cp -p BACKUP FILE` restores one). Details: `docs/live-deploy-runbook.md`,
section 5.

The compose lines stay manual and go to the grafana service only: the
`DISCORD_FAILURE_WEBHOOK_URL` line of 4b is still needed. If your
compose file does not already list `GRAFANA_WEBHOOK_SECRET` in the grafana service
environment, follow `docs/live-deploy-runbook.md`, section 5, step 4: it makes the
compose backup mode 600 and no-clobber (`umask 077`, `cp --no-clobber`), shows the
item `      - GRAFANA_WEBHOOK_SECRET` to add by hand after the `GF_SERVER_ROOT_URL`
line, and gives an `awk` check that only `grafana:` mentions the variable (the
value stays in Doppler; never run `docker compose config` for the check, it
prints resolved values). Then restart, as in 4d:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && doppler run --project homelab --config DEV_CONFIG -- docker compose up -d grafana; echo "exit code: $?"'
```

Check: `docker compose ls` lists the project as running, the grafana container shows
`Up` (and `healthy` if it defines a healthcheck), and the checks of 4d pass.
Rollback: restore the compose backup `docker-compose.yml.bak-<UTC timestamp>`
and each replaced file from its `.bak-` copy, then run the restart above.

## Step 5. P1 email contact point (LIVE)

Request item 6. Source: `docs/channel-redundancy.md` (sections "Enable it",
"Provider-neutral checklist", "Example: Mailgun", "Rollback"); files
`email-contact-point.yml.example`, `email-notification-policy.yml.example`,
`.env.example`.

What it does: a P1 (`severity=critical` and `phone=true`) is also emailed by
Grafana itself, without n8n, Discord or Pushover. It is a double page by design
(VERIFIED).

Prerequisites (VERIFIED: the provider-neutral checklist):

- An SMTP provider account (Mailgun is the planned one) with a sending domain
  verified through the provider's DNS records, separate from any primary
  domain.
- An SMTP login for that domain, a From address on the verified domain, and the
  recipient address or addresses for `P1_EMAIL_TO`.
- Step 4 is finished and checked (one Grafana restart at a time).
- Step 0b done.

Mailgun values (VERIFIED against the page cited in `docs/channel-redundancy.md`,
read 2026-11-19 by that doc): host `smtp.mailgun.org`, port 587, STARTTLS.
INFERRED and to be checked at the provider for your account: the SMTP username
format, and a different host if the account is in another region. Use a
verified domain, not the sandbox (sandbox sends only to authorized recipients).

### 5a. Store the seven values in Doppler dev

In a terminal where Doppler is logged in. The non-secret values:

```
printf '%s' 'true' | doppler secrets set GF_SMTP_ENABLED --project homelab --config dev_network --silent > /dev/null
printf '%s' 'smtp.mailgun.org:587' | doppler secrets set GF_SMTP_HOST --project homelab --config dev_network --silent > /dev/null
printf '%s' 'MandatoryStartTLS' | doppler secrets set GF_SMTP_STARTTLS_POLICY --project homelab --config dev_network --silent > /dev/null
printf '%s' 'alerts@example.com' | doppler secrets set GF_SMTP_FROM_ADDRESS --project homelab --config dev_network --silent > /dev/null
printf '%s' 'oncall@example.com' | doppler secrets set P1_EMAIL_TO --project homelab --config dev_network --silent > /dev/null
```

Replace `alerts@example.com` and `oncall@example.com` with your own addresses (the
sender must be on the verified domain). The login and password, read without
echo:

```
read -rs -p "SMTP user: " VAL; echo
printf '%s' "$VAL" | doppler secrets set GF_SMTP_USER --project homelab --config dev_network --silent > /dev/null
read -rs -p "SMTP password: " VAL; echo
printf '%s' "$VAL" | doppler secrets set GF_SMTP_PASSWORD --project homelab --config dev_network --silent > /dev/null
unset VAL
```

Every command ends in `> /dev/null`. Variable names are VERIFIED
(`docs/channel-redundancy.md`, Settings); the `GF_SMTP_*` names themselves are
INFERRED from Grafana's `GF_<SECTION>_<KEY>` rule (stated in that doc's
"Verified" section).

### 5b. Pass the seven variables to Grafana (compose)

Same pattern as 4b, seven lines. The compose file does not carry them (VERIFIED:
the doc says "the repo does not do this for you"). In a session:

```
cd /opt/siem
( umask 077 && cp --no-clobber docker-compose.yml "docker-compose.yml.bak-$(date -u +%Y%m%dT%H%M%SZ)-email" )
ls -l docker-compose.yml.bak-*
grep -c 'GF_SMTP_' docker-compose.yml
for V in GF_SMTP_ENABLED GF_SMTP_HOST GF_SMTP_USER GF_SMTP_PASSWORD GF_SMTP_FROM_ADDRESS GF_SMTP_STARTTLS_POLICY P1_EMAIL_TO; do
  sed -i "/- GRAFANA_WEBHOOK_SECRET=/a\\      - ${V}=\${${V}:-}" docker-compose.yml
done
grep -n -E 'GF_SMTP_|P1_EMAIL_TO' docker-compose.yml
```

The first `grep -c` must print `0`. The last command lists seven lines. Empty
defaults (`:-`) keep Compose from refusing to start when a value is unset.

### 5c. Copy the contact point

```
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/email-contact-point.yml.example /opt/siem/grafana/provisioning/alerting/email-contact-point.yml
```

### 5d. Restart Grafana and check

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && doppler run --project homelab --config dev_network -- docker compose up -d grafana; echo "exit code: $?"'
```

Check `docker logs --since 5m grafana 2>&1 | tail -40` for SMTP or provisioning
errors, and that the contact point `email-p1` appears in Alerting.

### 5e. Merge the `email-p1` route as the FIRST route

In Alerting, Notification policies (the tree is one per organization; do not
load the `.example` file, VERIFIED). Add a child route as the first one, with
(VERIFIED from the example file): contact point `email-p1`, matchers
`severity = critical` and `phone = true`, group by `alertname`, group wait 30s,
group interval 5m, repeat interval 1h, and Continue matching subsequent sibling
nodes turned on (`continue: true`), so the n8n path still receives the P1.

### 5f. Test

1. Use the test action of the `email-p1` contact point in Grafana and confirm the
   mail arrives (the "test button" is INFERRED to exist in your version; the doc
   lists it as unverified).
2. End to end: a P1 that goes through the policy. The docs do not say how to
   produce one on demand (OPEN QUESTION, Q10). INFERRED approach: a temporary
   Grafana alert rule that always fires, labeled `severity=critical` and
   `phone=true`, deleted afterwards. Do this before step 8 enables Pushover,
   because such a label would also page the phone through n8n once Pushover is
   on. Confirm: the email arrives, Discord receives the router's message, and
   the heartbeat keeps arriving (it carries `phone=false`, so it never matches
   the email route; VERIFIED).

Rollback (VERIFIED: `docs/channel-redundancy.md`): remove the `email-p1` route,
remove `email-contact-point.yml` from the live folder, restore the compose
backup, restart Grafana. To stop mail without touching provisioning, set
`GF_SMTP_ENABLED` to `false` in Doppler dev and restart Grafana.

## Step 6. Expiry watch: config, secrets, dry run, schedule (LIVE)

Request item 5. Source: `docs/expiry-watch.md` ("Quick start", "Config
reference", "Channels and routing", "Scheduling") and
`docs/expiry-watch.example.toml`.

What it does: reads items that expire (a registry file, TLS certificates,
Grafana service account tokens, secret manager service tokens) and posts notices
to the n8n router, and directly to Matrix and email if routed there. It is
read-only toward the things it watches (VERIFIED).

Prerequisites:

- Python 3.11 or newer on LOGGING_BOX (VERIFIED: "You need Python 3.11 or
  newer").
- The router is live and healthy (step 1). Owner decision: the watch runs ON
  LOGGING_BOX and posts to n8n through a localhost port, because the watch
  requires an https router URL and allows plain http only for localhost
  (VERIFIED: `docs/expiry-watch.md`, config reference), so no plaintext path
  crosses the network. Section 6.0 sets that up.
- For email delivery from the watch itself: SMTP login values (step 5 provider).
- For the two token providers: throwaway read-only tokens to test with. The
  secret manager list permission is undocumented by the vendor; test with a
  throwaway token before relying on it (VERIFIED: "doppler_tokens"). The Grafana
  token needs `serviceaccounts:read` on scope `serviceaccounts:id:*` (VERIFIED).
  Start with only the registry and TLS providers; add the token providers in a
  second pass.
- The router side is done in section 6.1: the watch has its own endpoint and its
  own secret on the router, separate from Grafana's (VERIFIED: `docs/expiry-watch.md`,
  "The router credential"). It needs the merged router workflow imported live
  first, which 6.1 does.

### 6.0 A localhost URL for n8n (on LOGGING_BOX)

n8n is on the siem network and a macvlan network, and the docs reach it by the
name `n8n` from other containers (VERIFIED: `docs/live-deploy-runbook.md`,
section 4; `docs/examples/n8n-compose.example.yml`). A macvlan container cannot
be reached from its own host (VERIFIED: same section), so the watch needs a
port published on the host's loopback address.

Check first whether one is already published (read only):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker port n8n'
```

Expected if one exists: a line such as `PORT/tcp -> 127.0.0.1:HOST_PORT`. Empty
output means no port is published. A mapping to `0.0.0.0` is not acceptable
here, because it would expose the router webhook on every host address; handle it
as "not published on 127.0.0.1 only" and fix it in the same edit below.

If none is published on 127.0.0.1, publish one. n8n is deployed from its own
compose file, separate from this repo's `docker/docker-compose.yml` (VERIFIED:
header of `docs/examples/n8n-compose.example.yml`). Do not guess the internal
port: read it from that compose file (its `N8N_PORT` setting, or the port the
docs use). The docs reach n8n at `http://n8n/webhook/...`, which is port 80
(VERIFIED: runbook section 4 and `scripts/n8n_address.py`, default 80), not
n8n's own upstream default, so do not assume 5678. Find and note it:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo grep -n -i -E "N8N_PORT|ports:|container_name: n8n" N8N_COMPOSE_FILE'
```

`N8N_COMPOSE_FILE` is the compose file that defines n8n (`/opt/n8n/docker-compose.yml`
live, root owned, so `sudo` is used for every touch of it, as step 6.2 did). Back it
up first (`cp -p` keeps its mode, and the file may hold values), then edit it with
`sudoedit` to add this under the `n8n` service, with
`CONTAINER_PORT` the value you read and `HOST_PORT` any free port above 1024
that you choose (INFERRED: the `127.0.0.1:HOST:CONTAINER` form is standard
Compose syntax, not in a repo doc, and publishing on a container attached to
a bridge network is assumed to work alongside the macvlan one):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p N8N_COMPOSE_FILE "N8N_COMPOSE_FILE.bak-$(date -u +%Y%m%dT%H%M%SZ)" && ls -l N8N_COMPOSE_FILE.bak-*'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudoedit N8N_COMPOSE_FILE'
```

```
    ports:
      - "127.0.0.1:HOST_PORT:CONTAINER_PORT"
```

Apply it by recreating only n8n, then immediately re-check the siem network,
because a recreate can drop it (VERIFIED: runbook, "Keep n8n on the siem
network"):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd N8N_COMPOSE_DIR && sudo docker compose up -d n8n && docker port n8n && docker network inspect SIEM_NETWORK --format "{{range .Containers}}{{.Name}} {{end}}"'
```

`N8N_COMPOSE_DIR` is the folder of that file and `SIEM_NETWORK` the real network
name from `docker network ls` (VERIFIED: runbook). Expect the new
`127.0.0.1:HOST_PORT` line and `n8n` in the container list. A recreate can also
blank variables that the compose file takes from the environment (the heartbeat
URL, and later the expiry secret) if the command runs without them (INFERRED; see
the OWNER DECISION in 6.1, item 2). So read them back at once with the presence
check of step 1 (`HEARTBEAT_PING_URL set` must still print), then send the
baseline test alert and confirm the next heartbeat ping arrives within 6 minutes
(step 1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py; echo "exit code: $?"'
```

Expected: six lines ending `PASS` and `failed cases: 0` (VERIFIED: runbook section
4); it posts three visible test messages to Discord. A recreate restarts n8n,
so do this in a quiet moment; the heartbeat and any firing alert wait for the
restart.

Prove the loopback port reaches the Grafana router without sending an alert, with a
request that carries no secret and expects a 401 or 403 (VERIFIED: runbook section
4, cases 1 to 3). The private path is read on the box, so it never lands in your
terminal or in the command text. This URL is for the probe only; the expiry watch
uses its own path (6.1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'P=$(cat "$HOME/.config/doppler-siem/router-path") && curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:HOST_PORT/webhook/$P"'
```

A `401` or `403` means the localhost URL reaches the authenticated router. A
`404` means the path or port is wrong; `Connection refused` means no port is
published. (`PRIVATE_WEBHOOK_PATH` in the placeholder table is the content of
that `router-path` file.)

Rollback: restore `N8N_COMPOSE_FILE.bak-<UTC timestamp>` over the compose file with
`sudo cp -p`, run the
same recreate command, and re-check the siem network and the heartbeat. Nothing
else changes; the siem network name `n8n` still serves Grafana.

### 6.1 The router's own endpoint and secret (on LOGGING_BOX)

Source: `docs/expiry-watch.md`, "The router credential" and its owner steps;
`docs/update-alerting.md` (the expiry watch paragraph); `docs/live-deploy-runbook.md`
sections 3 and 4; `docs/heartbeat.md` (settings); the merged PR #128 text. Nothing
runs from the repo; each step here is a live change.

What exists (VERIFIED: `docs/expiry-watch.md`): the router has a second entry,
the `Expiry Watch Webhook` node, with its own private path. A `Check Expiry
Secret` node compares the `Authorization` header with `Bearer ` plus the n8n
container variable `EXPIRY_WATCH_ROUTER_SECRET`. Grafana's webhook and its
credential are untouched, and the Grafana secret is never used for the watch.
Rotating or revoking one never touches the other. The watch's side of the same
value is `EXPIRY_WATCH_ROUTER_TOKEN`.

Cost to know before you start (VERIFIED: `docs/expiry-watch.md`): the router
accepts only item names of letters, digits, space, dot, colon and hyphen,
starting with a letter or digit, up to 100 characters. An item name with an
underscore, slash, `@`, backtick, angle bracket, asterisk or any non-ASCII
character gets a uniform 403 and the watch fails loudly. Rename such items in the
registry or at their provider. Also, the notice text the router sends to Discord
and the phone is built by the router from `item`, `kind` and `stage`; owner,
dates and runbook links stay in the watch's own output and its Matrix and email
channels.

Prerequisites: step 0b (the `dev_network` config exists), section 6.0 (the
localhost port), the Doppler CLI logged in where you run these commands, and the
heartbeat healthy (step 1) so you can tell if the re-import disturbs the router.

**1. Generate the new secret and store it (watch side).** A new random value, not
the Grafana secret. It goes in on stdin, with `--silent` and `> /dev/null`, and is
never printed. The `openssl rand -base64 32` form (44 characters) is the one the
docs use (VERIFIED: `docs/update-alerting.md`, `docs/expiry-watch.md`). It prints a
trailing newline. The watch refuses a token that holds anything but printable
characters (VERIFIED: `scripts/expiry_watch.py`, the `_TOKEN` pattern allows 0x21 to
0x7e), and the router compares the value byte for byte, so a stored newline would
make every real run exit 2. Strip it, then read back only the length:

```
openssl rand -base64 32 | tr -d '\n' | doppler secrets set EXPIRY_WATCH_ROUTER_TOKEN --project homelab --config dev_network --silent > /dev/null
doppler secrets get EXPIRY_WATCH_ROUTER_TOKEN --plain --project homelab --config dev_network | wc -c
```

The second command prints a count, never the value. Expect `44`, or `45` if
`--plain` adds its own newline (NOT DOCUMENTED, see step 0b item 2). Any other
number: delete the secret in Doppler and redo this item. Do not also run the "Value
for EXPIRY_WATCH_ROUTER_TOKEN" prompt in 6b: this command is that step. The value
is now only in Doppler.

**2. Give the n8n container the same value as `EXPIRY_WATCH_ROUTER_SECRET`.** The
repo docs say: an environment entry in the n8n compose file with an empty
default, and `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` set there (VERIFIED:
`docs/expiry-watch.md` owner step 1; the heartbeat doc shows the same shape,
`- HEARTBEAT_PING_URL=${HEARTBEAT_PING_URL:-}`, and says the blocking setting is
needed). That setting is already required for the heartbeat (VERIFIED:
`docs/heartbeat.md`), so it should already be present; confirm it. Back up the
n8n compose file first (N8N_COMPOSE_FILE and N8N_COMPOSE_DIR as in 6.0), then add
this entry under the `n8n` service `environment:` list with `sudoedit`. The value
comes from the watch-side name; mapping `_TOKEN` to `_SECRET` in the entry is an
INFERRED choice that avoids storing the secret twice in Doppler (a second Doppler
key with the `_SECRET` name is the alternative):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p N8N_COMPOSE_FILE "N8N_COMPOSE_FILE.bak-$(date -u +%Y%m%dT%H%M%SZ)-expiry" && ls -l N8N_COMPOSE_FILE.bak-*'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudoedit N8N_COMPOSE_FILE'
```

```
      - EXPIRY_WATCH_ROUTER_SECRET=${EXPIRY_WATCH_ROUTER_TOKEN:-}
      - N8N_BLOCK_ENV_ACCESS_IN_NODE=false
```

(Only add the second line if the file does not already carry it. Step 6.2 below
adds `N8N_PAYLOAD_SIZE_MAX=1` after that line, so do 6.2 in this same edit and one
recreate if you have not applied it yet: its `sed` needs the
`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` line to exist.) Recreate n8n with the
dev_network values in the environment of the compose command, and re-check the siem
network as in 6.0.

OWNER DECISION: how n8n's variables reach `docker compose` on EVERY recreate. The
entries above take their values from the environment of the compose command. A
recreate run without them (the plain `sudo docker compose up -d n8n` of 6.0 and
6.2) writes empty values: `HEARTBEAT_PING_URL` and `HEARTBEAT_KIND` go blank (the
heartbeat turns off, the observer reports down after about 20 minutes) and
`EXPIRY_WATCH_ROUTER_SECRET` goes blank (the watch gets 403). INFERRED, because no
repo doc says how the heartbeat variables reach the compose run today. Choose one:
(a) always run n8n's compose through `doppler run` as below, and keep the heartbeat
values in `dev_network` too; (b) an env file next to the compose file, root owned,
mode 600, which writes secrets to disk and so conflicts with the Doppler-only rule.
Recommended: (a). The form below is INFERRED (`sudo --preserve-env=LIST` needs the
sudoers rule to allow it, and refuses with a clear message if not):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd N8N_COMPOSE_DIR && doppler run --project homelab --config dev_network -- sudo --preserve-env=EXPIRY_WATCH_ROUTER_TOKEN,HEARTBEAT_PING_URL,HEARTBEAT_KIND docker compose up -d n8n; echo "exit code: $?"'
```

Check presence only, never the value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$EXPIRY_WATCH_ROUTER_SECRET\" ]; then echo EXPIRY_WATCH_ROUTER_SECRET set; else echo EXPIRY_WATCH_ROUTER_SECRET unset; fi; echo N8N_BLOCK_ENV_ACCESS_IN_NODE=\${N8N_BLOCK_ENV_ACCESS_IN_NODE:-unset}"'
```

Expect `set` and `false`. While env access is blocked or the variable is empty,
the watch gets 403 and exits 1 (VERIFIED: `docs/expiry-watch.md`); Grafana is
unaffected.

**3. Re-import the router with the live import helper.** Use the existing router
and handler ids, so the import overwrites the router in place (VERIFIED:
`docs/live-deploy-runbook.md` section 3), and run it with the Doppler token the
helper already uses. Order, from the helper's own docstring: the error handler is
imported FIRST and its id passed to the router import, so the router's
`errorWorkflow` setting points at a real workflow. The live handler already exists
(`HANDLER_ID`), so only the router is re-imported here, with `--error-workflow-id
HANDLER_ID`. On a fresh box, import the handler first (`docs/live-deploy-runbook.md`,
section 3). Do not leave `--error-workflow-id` out: the router would then lose its
error workflow setting.

The import is an in-place overwrite of the live, active router, and the helper
always writes the workflow INACTIVE (`active` is set to false in the script, and the
live deploy runbook says "Both workflows import inactive"). So from the moment the
import finishes until the publish and the n8n restart below have finished, the
router receives nothing. That is the alert gap: Grafana's webhook calls fail (404
or a refused connection), the heartbeat pings stop, and a real alert that fires
inside the gap is delayed until Grafana retries or repeats it (INFERRED; the repeat
interval is up to 4 hours for warnings). The gap is the restart time, about a minute.
Keep it short: run import, publish and restart as ONE command in a quiet moment,
right after a heartbeat ping arrived (step 1), and not while any game-day or test
scenario runs. The observer tolerates about 20 minutes of silence, so one or two
missed pings do not alert.

Before the import, read three things (all read only):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'ls -l "$HOME/.config/doppler-siem/router-path" && cut -c1-15 "$HOME/.config/doppler-siem/router-path"; echo'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n --help | grep -E "publish|update:workflow"'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'umask 077 && docker exec n8n n8n export:workflow --id=ROUTER_ID --output=/tmp/router-before.json && docker cp n8n:/tmp/router-before.json "$HOME/router-before.json" && docker exec n8n rm -f /tmp/router-before.json && ls -l "$HOME/router-before.json"'
```

- The first must list the file as `-rw-------` and print `grafana-alerts-`: that file
  is the live Grafana path. If it is missing, the import makes a NEW Grafana path and
  Grafana's contact point (still on the old one) gets 404 on every alert: stop and
  find the file (the helper reads it from `SIEM_CONFIG_DIR`, default
  `$HOME/.config/doppler-siem`; the user running the import must be the user who owns
  it) before going on.
- The second must show `publish:workflow`. On an older n8n only `update:workflow`
  exists: use `update:workflow --id=ROUTER_ID --active=true` in the command below
  (VERIFIED: `docs/game-day.md` says the name differs between versions).
- The third saves a copy of the live router before it is overwritten (the
  `export:workflow` flags are INFERRED; check `n8n export:workflow --help`). The file
  holds the private webhook path, so it is mode 600 and stays on the box; delete it
  after step 4 passes. The step 2 archive is the older fallback.

Now the import, publish and restart, stopping at the first failure:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-setup-alert-router.py --workflow n8n/grafana-alert-router.json ROUTER_ID --error-workflow-id HANDLER_ID && docker exec n8n n8n publish:workflow --id=ROUTER_ID && docker restart n8n; echo "exit code: $?"'
```

Expected output lines (VERIFIED: the script and runbook section 3):
`workflow import exit code: 0`, `new webhook path saved (mode 600): ...`,
`expiry watch webhook path saved (mode 600): ...` and `error workflow set: True`,
then the publish output, the container name from `docker restart`, and
`exit code: 0`. The helper reuses the saved
Grafana path (`router-path`) when it looks right and makes the expiry path
(`expiry-watch-alerts-` plus 24 URL-safe characters) the first time, writing it mode
600 to `expiry-path` in the same config directory (VERIFIED: script). The
committed `Expiry Watch Webhook` node ships disabled with a placeholder path
(`PLACEHOLDER-set-by-the-import-helper`); only the helper enables it, with the
private path. Read back that there is still exactly one router (no duplicate made
by a wrong id) and the heartbeat resumes (step 1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n list:workflow'
```

Rollback of this item: import the saved copy back
(`docker cp "$HOME/router-before.json" n8n:/tmp/router-before.json`, then
`docker exec n8n n8n import:workflow --input=/tmp/router-before.json`, then publish
and restart as above). The saved file is a workflow array or one object depending
on the n8n version; if the import rejects it, restore from the step 2 archive.

**4. Post-import checks.** First the placeholder path must serve nothing (the
point is that the committed node is disabled). That n8n registers no webhook for
a disabled trigger node is UNVERIFIED against a live n8n (VERIFIED: stated as
unverified in `docs/expiry-watch.md`); this check is how you find out:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" http://127.0.0.1:HOST_PORT/webhook/PLACEHOLDER-set-by-the-import-helper'
```

Expect `404`. Anything else: stop, deactivate the workflow and report; do not use
the endpoint. Then confirm the real path rejects a call with no secret. The private
path is an address, not a credential, but keep it out of git and chat (VERIFIED:
`docs/expiry-watch.md`), so it is read on the box and never printed:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'P=$(cat "$HOME/.config/doppler-siem/expiry-path") && curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:HOST_PORT/webhook/$P"'
```

(`$HOME/.config/doppler-siem` is the helper's default config directory, VERIFIED:
runbook variable table; use yours if you changed it.) Expect `403` (VERIFIED: a
denied call is answered 403 with a fixed body). A real accepted call comes only
from the real run in 6d and the limit test in 6.3, which use the real secret. The
dry run in 6c never posts and never reads the secret.

**5. Point the watch at it.** In `/etc/expiry-watch/expiry-watch.toml` set
`[router].url` to `http://127.0.0.1:HOST_PORT/webhook/EXPIRY_WATCH_PRIVATE_PATH`
(the path from `expiry-path`; plain http is allowed for localhost, VERIFIED) and
keep `[router].token_env = "EXPIRY_WATCH_ROUTER_TOKEN"`. Never commit the path.
The config file is created in 6a, so this edit happens there, after the files exist.
The file `expiry-path` belongs to the user who ran the helper while the config
belongs to SERVICE_ACCOUNT; copy the one line by hand (read it with `cat` in a session
and paste it into the `sudoedit` of 6a; it stays out of command lines you save).

**6. Ingress limits (Q12, ANSWERED 2026-11-20, issue #157).** The watch posts
to the loopback port in 6.0, which does not pass a reverse proxy, so a proxy
cannot enforce limits on this path. They live in the watch and in the router
instead (VERIFIED: `docs/expiry-watch.md`, "Request limits"): the watch refuses a
body over 16 KB, waits 2 seconds between posts and posts at most 15 times per
run; the router's `Check Expiry Secret` node denies a body over 16 KB, a call
under 1 second after the last accepted one and more than 30 accepted calls in 10
minutes. No owner step is needed for these once the router is re-imported. After
the first import, check the items that doc marks UNVERIFIED (that the Code node
can read the workflow static data in a production execution, which the check
needs or it denies every call, that two overlapping executions do not both read
the old counter, that the counter persists across executions, and that the
`content-length` header reaches it).
A denied call still starts one workflow execution, and anyone who can reach n8n's
webhook address on the siem network or LAN can still cause that. n8n's own body
limit is `N8N_PAYLOAD_SIZE_MAX`, default 16 (MiB per the n8n docs, read
2026-11-20). Section 6.2 below sets it; the router's Code node cannot see the raw
body, so that setting is the real body cap.

**Rotate.** Generate a new value, store it with the command in item 1 (it
replaces the old one), then restart the n8n container so it reads the new
environment (VERIFIED: `docs/expiry-watch.md` owner step 5): recreate n8n with the
same `doppler run` command as item 2. Both sides change together; between the
n8n restart and the next watch run the watch must already hold the new value. The
dry run in 6c does NOT confirm that: it never reads the secret (VERIFIED:
`scripts/expiry_watch.py` reads the token only when it posts). The first real run
or the 6.3 test does.

**Revoke the watch alone.** Empty the router's variable (VERIFIED: `docs/expiry-watch.md`
owner step 5): set the n8n entry to an empty value, or delete
`EXPIRY_WATCH_ROUTER_TOKEN` from the dev config so the substitution is empty, and
recreate n8n. The endpoint then denies every call with 403. Grafana alerts are
unaffected (VERIFIED). A full rollback of this section: restore the backed-up
n8n compose file, recreate n8n, and re-import the previous workflow from the step
2 backup archive or deactivate the `Expiry Watch Webhook` node in the n8n
interface.

### 6.2 Cap request bodies at n8n: N8N_PAYLOAD_SIZE_MAX (LIVE, restarts n8n)

Target: the n8n container on LOGGING_BOX, compose file
`/opt/n8n/docker-compose.yml` (VERIFIED by the lead 2026-11-20: n8n runs from
that file and its environment list has no `N8N_PAYLOAD_SIZE_MAX`, so n8n uses
its default of 16 MiB).

Change: add `N8N_PAYLOAD_SIZE_MAX=1` (MiB) after the
`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` line and recreate the container. The n8n
docs (https://docs.n8n.io/hosting/configuration/environment-variables/endpoints/,
read 2026-11-20) give the unit as MiB, default 16, and say a restart is
required. They say nothing about fractional values or which request types the
setting limits (UNVERIFIED both). This is the real cap on the raw request,
because the router's Code node runs after n8n has parsed the body and cannot see
the raw bytes. The owner applied this value live on 2026-11-20 with the command
below; the section is the record and the command to repeat it on another host.

Run it from a real terminal. `sudo` needs a tty, so do not run it with a `!`
prefix or over a no-tty ssh. One line, as the whole command:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p /opt/n8n/docker-compose.yml /opt/n8n/docker-compose.yml.bak-payload && sudo sed -i "/- N8N_BLOCK_ENV_ACCESS_IN_NODE=false/a\      - N8N_PAYLOAD_SIZE_MAX=1" /opt/n8n/docker-compose.yml && cd /opt/n8n && sudo docker compose config -q && sudo docker compose up -d n8n && sleep 15 && docker inspect n8n --format "{{range .Config.Env}}{{println .}}{{end}}" | grep N8N_PAYLOAD; docker ps --filter name=n8n --format "{{.Status}}"'
```

Evidence (VERIFIED by the lead 2026-11-20 after the owner ran it): the read-back
printed `N8N_PAYLOAD_SIZE_MAX=1` and `docker ps` showed a healthy container. On
a new run, expect the same two lines; no `N8N_PAYLOAD_SIZE_MAX` line means the
`sed` found no anchor line, so restore the backup (below) and edit by hand. The
backup name `.bak-payload` is fixed: if that file already exists, a second run
overwrites the pre-change copy, so check with `ls` first and pick another name.

That run recreated n8n WITHOUT `doppler run`, and its read-back did not check the
two things a recreate can drop. Read them back now, and after any repeat of this
section (INFERRED hazard, see the OWNER DECISION in 6.1 item 2). The heartbeat and
(once 6.1 is done) expiry variables must still say `set`, and `n8n` must still be
on the siem network:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$HEARTBEAT_PING_URL\" ]; then echo HEARTBEAT_PING_URL set; else echo HEARTBEAT_PING_URL unset; fi; echo HEARTBEAT_KIND=\${HEARTBEAT_KIND:-healthchecks}"'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker network inspect SIEM_NETWORK --format "{{range .Containers}}{{.Name}} {{end}}"'
```

`HEARTBEAT_PING_URL unset` means the heartbeat is off: the observer reports down
after about 20 minutes. Recreate n8n through the form chosen in the 6.1 OWNER
DECISION and check again. `n8n` missing from the second list means Grafana cannot
reach it: reattach it as in `docs/live-deploy-runbook.md`, "Keep n8n on the siem
network". Also confirm the next heartbeat ping arrives (step 1).

Blast radius: recreating n8n interrupts every webhook receiver for about 15
seconds (Grafana, Wazuh and CrowdSec notices that arrive in that window are not
received). The limit is instance-wide, so a Wazuh or CrowdSec payload over 1 MiB
would be refused. How large real payloads get is UNVERIFIED; if a sender starts
failing with 413 after this change, raise the value.

Rollback: copy the backup over the file and recreate:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p /opt/n8n/docker-compose.yml.bak-payload /opt/n8n/docker-compose.yml && cd /opt/n8n && sudo docker compose up -d n8n'
```

### 6.3 Test the router limits after the import (LIVE, UNVERIFIED)

Run this after the router is imported and active (6.1). Nothing here is
confirmed against a live n8n: the live rate-limit counter (the workflow static
data read in the `Check Expiry Secret` node) has not been exercised, and a
denied call is answered 403 by design (VERIFIED: `docs/expiry-watch.md`).

Target: the `Expiry Watch Webhook` endpoint on LOGGING_BOX. Change: none to the
system, it sends test notices. Blast radius: each call starts one workflow
execution, and every ACCEPTED call posts one message to Discord (no phone: the
body below has no `phone` label). The window test in item 3 therefore posts about
30 messages; the dry run of the watch does not post and cannot stand in for this
test (it never calls the router).

OWNER DECISION: run item 3 (about 30 Discord messages in a minute), or accept
items 1 and 2 as the evidence for the 1 second rule and defer the 30-in-10-minutes
rule to real use.

The secret never goes on a command line: the commands below pass the header on
standard input (`curl -H @-`, VERIFIED to read headers from stdin with curl 8.21,
run 2026-11-20) from the `printf` built-in, inside `doppler run`, so the value is only
in the environment of that one child process. Run them as yourself, in a session on
LOGGING_BOX where the Doppler CLI is logged in with access to `dev_network` (the
`SERVICE_ACCOUNT` files are not needed here). The body is exactly the shape the
watch builds (VERIFIED: `tests/python/test_router_expiry_secret.py`, `_expiry_body`):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX
```

In that session:

```
umask 077
printf '%s' '{"receiver":"expiry-watch","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Expiry watch: limit-test","severity":"info","expiry_watch":"true","item":"limit-test","kind":"test","stage":"30"},"annotations":{"summary":"limit test","description":"limit test"},"fingerprint":"0123456789abcdef0123456789abcdef"}]}' > "$HOME/notice.json"
```

1. One authenticated, valid notice. Expect `200` and one message in Discord:

```
doppler run --project homelab --config dev_network -- sh -c 'printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")"'
```

2. A fast burst: three calls started at the same moment. The router accepts one
   call and denies a call under 1 second after it, so expect one `200` and two
   `403` (a second `200` means two overlapping executions read the old counter, a
   finding):

```
doppler run --project homelab --config dev_network -- sh -c 'for i in 1 2 3; do printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")" & done; wait'
```

3. The window (only if you chose to run it): 32 calls, 2 seconds apart, then the
   count per status. Calls accepted in items 1 and 2 count toward the 30, so
   `200` appears 30 minus those times and the rest are `403`:

```
doppler run --project homelab --config dev_network -- sh -c 'for i in $(seq 1 32); do printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")"; sleep 2; done | sort | uniq -c'
```

4. Evidence to record: the status code for every call and the number of messages
   that reached Discord (it must equal the number of `200` results). n8n lists NO
   execution for these calls: the router stores neither successful nor failed
   executions by design (`saveDataSuccessExecution` and `saveDataErrorExecution`
   are `none`; VERIFIED: `docs/update-alerting.md`), so there is nothing to read in
   the executions list. If every call is `403`, the Code node cannot read the static
   data or the secret does not match (compare with the presence check in 6.1 item
   2, and see the UNVERIFIED list in 6.1, item 6); if the fast burst has more than
   one `200`, the counter is not safe under overlap.

Clean up the body file when you are done:

```
rm -f "$HOME/notice.json"
```

Rollback: nothing to undo; wait 10 minutes for the counter window to clear.

### 6a. Private config folder and copies (on LOGGING_BOX)

The folder must be writable only by the job user (VERIFIED: "Paths and symbolic
links"). Keep it outside the repo, since the router URL contains the private
webhook path.

```
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /etc/expiry-watch
sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT REPO_DIR/docs/expiry-watch.example.toml /etc/expiry-watch/expiry-watch.toml
sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT REPO_DIR/docs/expiry-watch-registry.example.toml /etc/expiry-watch/expiry-watch-registry.toml
sudoedit /etc/expiry-watch/expiry-watch.toml
```

Edit (the example values are placeholders and several will fail until replaced):

- `[router].url`: the localhost URL from section 6.0 plus the expiry watch's
  private path from section 6.1,
  `http://127.0.0.1:HOST_PORT/webhook/EXPIRY_WATCH_PRIVATE_PATH` (the path is in
  the `expiry-path` file in the helper's config directory, not the Grafana
  `router-path`).
- `path` of the registry provider: `expiry-watch-registry.toml`. List your real
  items in the registry file (`name`, `kind`, `expires` as `YYYY-MM-DD`,
  `owner`, `runbook`).
- Replace the example `tls` provider host with real hosts, or delete the block.
  Delete the `grafana_sa_tokens` and `doppler_tokens` blocks, the `[matrix]` and
  `[email]` tables and any route that names them, until you are ready for them.
- `[routes]`: keep `pushover` out of every route until step 8 is finished; the
  router only pages the phone when Pushover is enabled (VERIFIED: "Channels and
  routing"), so a premature `pushover` is harmless but misleading. A notice
  routed only to `matrix` or `email` does not touch the router and so does not
  go to Discord (VERIFIED).

### 6b. Secrets by variable name

The config only ever names variables, never values (VERIFIED). The names:

| Variable | Used for | Source doc |
|----------|----------|-----------|
| `EXPIRY_WATCH_ROUTER_TOKEN` | Router bearer secret | `expiry-watch.md`, quick start step 2 |
| `EXPIRY_WATCH_GRAFANA_TOKEN` | `grafana_sa_tokens` provider | example config |
| `EXPIRY_WATCH_DOPPLER_TOKEN` | `doppler_tokens` provider | example config |
| `EXPIRY_WATCH_MATRIX_TOKEN` | `[matrix]` | example config |
| `EXPIRY_WATCH_SMTP_USER`, `EXPIRY_WATCH_SMTP_PASSWORD` | `[email]` login | example config |

Set only the ones the config uses, to the dev_network config, each with
`--silent` and ending in `> /dev/null`.

`EXPIRY_WATCH_ROUTER_TOKEN` is already set by section 6.1, item 1 (a generated
value, never typed and never the Grafana secret); do not set it again here. For
any other variable you use, such as `EXPIRY_WATCH_MATRIX_TOKEN`:

```
read -rs -p "Value for VARIABLE_NAME: " VAL; echo
printf '%s' "$VAL" | doppler secrets set VARIABLE_NAME --project homelab --config dev_network --silent > /dev/null
unset VAL
```

### 6c. Dry run first (changes nothing, posts nothing, saves nothing)

The config folder is mode 700 and owned by `SERVICE_ACCOUNT` (6a), so your own
user cannot read it: run the watch as that account with `sudo -u`. The account's
read-only Doppler token (0c.3) goes into the environment of the one `doppler run`
child process from its file, never onto a command line (the `cat` argument is only
the file path). `REPO_DIR` must be readable by the account (step 0a makes it so):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo -u SERVICE_ACCOUNT sh -c "cd REPO_DIR && DOPPLER_TOKEN=\$(cat /var/lib/SERVICE_ACCOUNT/doppler-token) doppler run --no-check-version --config-dir /var/lib/SERVICE_ACCOUNT/.doppler -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml --dry-run; echo \"exit code: \$?\""'
```

(`doppler run` form VERIFIED in `docs/update-alerting.md`; `--config-dir` and
`--no-check-version` are VERIFIED in `scripts/live-deploy/siem-run`; the token
variable and the use with this script are INFERRED, see 0c.3. The token is scoped to
`dev_network`, so no `--project` or `--config` is needed.)

The dry run never reads the router secret (VERIFIED: `scripts/expiry_watch.py` looks
the token up only when it posts), so a clean dry run does not prove the secret or
the router URL. Section 6.3 and the first real run in 6d do.

Watch:

- Exit code `0` ok, `1` a provider or delivery failed (details on stderr), `2` a
  config problem; a missing or malformed secret gives `2` only on a real run
  (VERIFIED).
- The output lists the notices that are due and the JSON it would post. Check the
  item names, dates and owner lines are the real ones.
- A TLS provider error is a real finding, not a date (VERIFIED: "tls").
- Expect a first run to show many notices at once for items already inside a
  threshold; only the lowest crossed threshold per item fires (VERIFIED).

### 6d. First real run, then schedule

Only when the dry run is clean and the route is the one you want. A real run
posts real messages to Discord, and an unwanted message cannot be recalled:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo -u SERVICE_ACCOUNT sh -c "cd REPO_DIR && DOPPLER_TOKEN=\$(cat /var/lib/SERVICE_ACCOUNT/doppler-token) doppler run --no-check-version --config-dir /var/lib/SERVICE_ACCOUNT/.doppler -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml; echo \"exit code: \$?\""'
```

An exit code `2` with `config error: set the environment variable
EXPIRY_WATCH_ROUTER_TOKEN` means the token did not reach the process (check 6.1 item
1 and the account's token file); a `403` from the router in the stderr text means the
router's `EXPIRY_WATCH_ROUTER_SECRET` and the token differ or env access is blocked
(6.1 item 2).

Confirm the messages arrive and the state file `/etc/expiry-watch/expiry-watch-state.json`
exists with mode 0600 (VERIFIED). Then schedule it on LOGGING_BOX with either a
systemd service and timer or a cron entry; both are given in
`docs/expiry-watch.md`, "Scheduling", and the choice is yours. Whichever you
pick, the job runs on the box, as the same user that owns the config folder, and
reads its secrets only from the single dev config by wrapping the command in
`doppler run` with the account's `dev_network` token, as in 6c (the secrets are
named by variable only; no value goes in the unit, the cron line or the config). That
doc's examples instead read the router secret from an `EnvironmentFile` (mode
0600, owned by the job user); using `doppler run` in place of it is INFERRED, and
needs the Doppler CLI logged in for that user (non-interactive login for a
scheduled job is not covered by any repo doc). The doc also warns that nothing alerts you if the schedule stops;
use job monitoring (VERIFIED).

Rollback: disable the timer or remove the cron line. Deleting the state file
makes the next run re-send everything due (VERIFIED: state semantics). Messages
already sent stay sent.

## Step 7. Game-day scenarios, dry run only (LIVE read-only on the box)

Request item 7, first half. Source: `docs/game-day.md` ("Safety model",
"Configuration", "Scenarios"). Dry run is the default and changes nothing
(VERIFIED).

Prerequisites: steps 1 and 4 (so the failure alert and heartbeat exist to
observe). The config file lives outside the repo.

Make the config (a file kept outside the repository; `router_path` is the private
webhook path, so mode 0600):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'umask 077 && mkdir -p "$HOME/.config/gameday" && cat > "$HOME/.config/gameday/gameday.toml" <<EOF
n8n_container = "n8n"
grafana_container = "grafana"
heartbeat_host = "OBSERVER_HOSTNAME"
router_workflow_id = "ROUTER_ID"
router_path = "PRIVATE_WEBHOOK_PATH"
EOF'
```

Replace `OBSERVER_HOSTNAME` (the host of the observer's ping URL),
`ROUTER_ID` (the n8n id of the router) and `PRIVATE_WEBHOOK_PATH` (the contents
of the `router-path` file) before running, with an editor if you prefer. All
three are required by their scenarios (VERIFIED: configuration table).

List and preview each scenario, in this order from least to most disruptive
(the order is INFERRED from the scenario descriptions):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && python3 scripts/gameday.py list'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && for S in wrong-header discord-unreachable phone-unreachable heartbeat-silent router-inactive n8n-down grafana-down; do echo "=== $S"; python3 scripts/gameday.py $S --config "$HOME/.config/gameday/gameday.toml"; done'
```

Read each plan: what it would do, what you should observe, how to revert. Check
the revert command for each. The `router-inactive` plan uses the `n8n
update:workflow` CLI whose name differs between n8n versions (VERIFIED:
`docs/game-day.md`, "Not verified"); run `docker exec n8n n8n --help` and confirm
the subcommand before step 10.

Watch: every plan exits 0 and prints a plan, no step runs. `--apply` alone is
refused with exit 2 (VERIFIED), which is the safe failure.

Rollback: nothing changed.

## Step 8. Pushover and the phone (LIVE, pages a real phone)

Request item 9. Source: `docs/update-alerting.md` ("Pushover (phone push)",
"Pushover credential", "Enable it", "Manual pre-deploy checklist") and
`docs/live-deploy-runbook.md` section 4 (optional phone test).

What the docs say: Pushover is off by default; one constant,
`PUSHOVER_ENABLED`, in the `Build Pushover Payload` Code node turns it on; only
alerts with `phone=true` reach it; priority 1 bypasses quiet hours; priority 2
(emergency) repeats until acknowledged (VERIFIED).

Owner decision: the phone is muted only while the live game-day
and failure tests run, so test pages wake no one, and it is unmuted afterward.
Real paging stays fully on at all other times. The mute and unmute procedure is
8b and 8c below. This doc does not describe Pushover's or the phone's own
screens, because no repo doc verifies them; use whatever mute control you
normally use and send a screenshot if you want it written down.

Prerequisites for enabling: the credential `pushover-api` exists
in n8n and the Doppler values `PUSHOVER_API_KEY` and `PUSHOVER_USER_KEY` exist
(VERIFIED: `docs/update-alerting.md`, which says they already exist in
`prd_network`; the live check is `siem-run ... --check` in step 0).

### 8a. Enable Pushover in the router

In the n8n web interface open the router workflow, open the
`Build Pushover Payload` Code node, change `const PUSHOVER_ENABLED = false;` to
`true` (VERIFIED: "Enable it", item 4), save and keep the workflow active. An
alternative is re-running the import with `--pushover-on` and the existing
ids, `--workflow n8n/grafana-alert-router.json ROUTER_ID --error-workflow-id
HANDLER_ID`, then publish and `docker restart n8n` (VERIFIED: runbook section
3), but whether a re-import keeps the private path and the active state is
INFERRED, so prefer the UI edit.

Test, using the documented script (VERIFIED: runbook section 4). The phone is
unmuted for this one, so you hear the first real pages:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone; echo "exit code: $?"'
```

It sends a priority 1 and a priority 2 message. Confirm both arrive, then cancel
the repeats:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone-resolve; echo "exit code: $?"'
```

Watch: no successful execution is listed in n8n afterward (VERIFIED: checklist
item 6), and the heartbeat still pings and never reaches the phone.

### 8b. Mute before the live tests (before step 10, and before any forced failure test)

Mute the phone's alert sound for Pushover just before you inject the first live
scenario in step 10, or before any step that sends test pages to the phone.
Tell anyone else who receives the pages. Muting changes nothing in the stack; it
only stops the phone from sounding.

WARNING: while the phone is muted, P1 pages are NOT delivered audibly. A real
emergency (priority 2, which repeats until acknowledged) will not wake you. Keep
the muted window as short as the tests, and never leave the phone muted: do 8c
the moment the last scenario is reverted and recovery is checked.

### 8c. Unmute after the tests and prove it rings

1. Unmute the phone.
2. Send one real test page and confirm it rings once:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone; echo "exit code: $?"'
```

3. Confirm the message arrived and the phone sounded once (this sends a priority
   1 and a priority 2 message; the doc script's behavior is VERIFIED in runbook
   section 4, so expect the emergency one to repeat), then cancel the repeats:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone-resolve; echo "exit code: $?"'
```

If it did not ring, the phone is still muted or Pushover is off: fix that before
you call the platform online.

Rollback: set `PUSHOVER_ENABLED` back to `false` in the same node (VERIFIED: it
is the shipped default). Emergency repeats already started stop with
`--phone-resolve` or by acknowledging in the app. Unmute the phone if you muted
it.

## Step 9. Deactivate the old router workflow after a day of normal traffic (LIVE)

Request item 8. Source: `docs/live-deploy-runbook.md` section 3 ("The old
router (if any) is untouched because a fresh import gets a new id") and the
deactivation commands in `docs/game-day.md` ("Rollback", deactivated router).

Prerequisites:

- Grafana's contact point `n8n-grafana-router` posts to the new router's private
  path (VERIFIED: runbook section 5 writes that path into the contact point).
- At least 24 hours of normal traffic on the new router with the heartbeat
  pinging steadily (step 1). Do not run any game-day live scenario in that
  window.
- The old router's live name and id are known (Q5). The new router must not be
  mistaken for it: the new one has the credential `grafana-webhook-auth` on its
  webhook node (VERIFIED).

Check the old router handled nothing in the last day in the n8n executions list
(INFERRED: it is only meaningful if the old workflow saved executions). Then
deactivate it. In the n8n interface, switch the old workflow to inactive, or use
the CLI with the old id (the subcommand name varies by n8n version, VERIFIED:
`docs/game-day.md`; check `docker exec n8n n8n --help` first):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n update:workflow --id=OLD_ROUTER_ID --active=false && docker restart n8n'
```

The restart is needed for the change to take effect (VERIFIED: game-day
`router-inactive` plan restarts n8n).

Watch: the next two heartbeat pings arrive (step 1); send one test alert with
`n8n-test-router.py` (no flags) and confirm Discord receives it; Grafana shows
no failed notification and the step 4 alert stays Normal.

Rollback: activate the old workflow again (n8n interface, or the same command
with `--active=true`) and `docker restart n8n`. Do not delete the old workflow
until you are sure, then delete it by hand in n8n.

## Step 10. Game-day live runs (LIVE, breaks things on purpose)

Request item 7, second half. Source: `docs/game-day.md` ("Safety model",
"Checklist", "Recording results", "Rollback").

Prerequisites:

- Steps 2, 4, 7, 8 and 9 done. The backup exists and was rehearsed.
- A maintenance window agreed, recipients told, a second person or channel
  watching (VERIFIED: checklist item 1).
- `router_workflow_id` in the config is the NEW router, and the CLI name for
  `router-inactive` was confirmed in step 7.
- The phone is muted per step 8b, just before the first live scenario. Unmute it
  per step 8c as soon as the last scenario is reverted and recovery is checked.
  A muted phone means P1 pages are NOT delivered audibly; never leave it muted.

Changes need both flags: `--apply --confirm-live` (VERIFIED). Run one scenario
at a time, from the checklist in the doc. Start with `wrong-header`, which sends
one webhook call with a made-up header (VERIFIED: no real secret is sent):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && python3 scripts/gameday.py wrong-header --config "$HOME/.config/gameday/gameday.toml" --apply --confirm-live --log "$HOME/.config/gameday/results.jsonl"; echo "exit code: $?"'
```

Expected: 401 or 403; anything else is a defect (VERIFIED). For each other
scenario use the same shape, with the baseline and recovery steps from the doc:

1. Baseline: `n8n-test-router.py` and confirm arrival, note the time.
2. Inject: `gameday.py SCENARIO --config ... --apply --confirm-live --log ...`.
3. Watch every OBSERVE line from the plan (Discord, phone, the observer's
   alert after period plus grace, the Grafana failure alert from step 4).
4. Revert: `gameday.py SCENARIO --revert --run-id ID --apply --confirm-live`.
   The three hosts scenarios (`discord-unreachable`, `phone-unreachable`,
   `heartbeat-silent`) print a run id at injection; keep it (VERIFIED).
5. Recovery check: a test alert arrives, the heartbeat resumes, and the
   observer shows up.

Expected outcomes (VERIFIED: the scenario table): `discord-unreachable` gives a
502 and one Pushover message from the error handler; `phone-unreachable` gives a
Discord alert plus a "phone delivery failed" notice; `heartbeat-silent` shows
the observer alerting after period plus grace; `n8n-down` shows the step 4
alert and the observer alert; `grafana-down` stops the heartbeat; and
`router-inactive` makes Grafana log a failed notification and stops the
heartbeat. Whether the stopped-container scenarios produce those alerts is "to
be confirmed on the first game day" (VERIFIED: "Not verified"). A scenario with
no alert is a finding: file an issue (VERIFIED).

Rollback, in order of preference (VERIFIED: `docs/game-day.md`, "Rollback"):

1. `gameday.py SCENARIO --revert --run-id ID --apply --confirm-live`.
2. By hand: `docker start n8n` or `docker start grafana` for a stopped
   container; activate the router again for `router-inactive` and restart n8n;
   remove the `# gameday-84-<id>` line from the n8n container's `/etc/hosts`
   (`docker exec n8n grep gameday-84 /etc/hosts` shows it).
3. Last resort for the hosts line: recreate n8n with
   `docker compose up -d --force-recreate n8n`, after checking that n8n stays on
   the siem network (VERIFIED: `docs/live-deploy-runbook.md`, "Keep n8n on the
   siem network").

After any rollback, send a baseline test alert and wait one heartbeat interval
for the observer to show up. When all scenarios are done, do step 8c (unmute and
confirm one test page rings).

## Not covered

- Matrix as a third P1 path: a later task, not part of this change (VERIFIED:
  `docs/channel-redundancy.md`).
- The OpenSearch snapshot job and the Wazuh indexer (separate backup, first
  half of `docs/backup-restore.md`).
- Production (prd) promotion of any new secret: its own step with its own
  approval, after you say the stack is live.
- The roadmap (`docs/roadmap.md`) carries no owner steps for this epic; none was
  cited. Check the epic's issue #62 for any step not listed here.
