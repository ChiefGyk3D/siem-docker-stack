# Owner runbook: bring the alerting platform fully online

One ordered list of every LIVE step the owner does to finish the alerting
platform (epic #62). Nothing in this repository does these steps for you. Each
step names the doc it comes from, what must be true first, the exact commands,
what to watch, and how to undo it.

Written 2026-11-19 against `origin/master` at commit `a503203`. Every fact is
marked:

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
| `REPO_DIR` | Where this repository is checked out on LOGGING_BOX |
| `SIEM_DIR` | Live stack directory, default `/opt/siem` (`docs/live-deploy-runbook.md`, variable table) |
| `dev_network` | The Doppler branch config under the `dev` environment of project `homelab` that holds every new alerting value (created in step 0b) |
| `ROUTER_ID`, `HANDLER_ID` | The n8n workflow ids printed by the router import (`docs/live-deploy-runbook.md`, section 3) |

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
| Q4 | The names `FAILTEST` (workflow and credential) appear in no repo doc. The closest text is the failure-path test copy in `docs/live-deploy-runbook.md`, section 4, items 1 to 6 ("the copy", "a wrong credential in the copy"). Read the exact names in the n8n UI. | Step 3 |
| Q5 | What is the live name of the old router workflow? The repo workflow is named "Grafana SOAR - Alert Router" and the runbook calls the new one "Grafana SOAR - Alert Router (authenticated)". Which one is live and old is not in a doc. | Step 9 |
| Q7 | `scripts/live-deploy/grafana-deploy.py` copies only four alert files (`contact-points.yml`, the two update rule files, `heartbeat-alert-rule.yml`; VERIFIED: the `FILES` tuple). It does not copy the notification failure rule or the example contact points, and it rewrites `contact-points.yml` on every run. Steps 4 and 5 therefore copy files by hand into their own files. Should the deploy script take over that job (a code change, not part of this doc)? Issue #126 (an open PR, not merged) is the deploy script change that will later replace the manual file copies in steps 4 and 5; until it merges, copy by hand as written. | Steps 4, 5 |
| Q8 | The Grafana group id for `grafana_uid`/`grafana_gid` in the backup config is not stated. The compose file sets `user: "472"` (VERIFIED) and the example says `grafana_gid = 0`. Read it with `docker exec grafana id`. | Step 2 |
| Q9 | Which account runs the scheduled backup? The example unit uses a dedicated user and warns that docker group membership is root-equivalent (VERIFIED: `docs/examples/siem-state-backup.service`). The account and its container access are the owner's decision. | Step 2 |
| Q10 | How is a P1 produced on demand to test the email route end to end? No doc says. | Step 5 |
| Q11 | Should the expiry watch reuse the router secret from `prd_network` (copied to dev) or get its own router credential? | Step 6 |

## Order and why

The order puts read-only checks first, the safety net second, cleanup third,
and every Grafana restart before anything that depends on it. The request's
item numbers are in the last column.

| Step | What | Risk | Depends on | Request item |
|------|------|------|-----------|--------------|
| 0 | Preflight, then 0b: one dev config for every new Grafana value | low | nothing | |
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
(runbook section 2); this repo is checked out at `REPO_DIR` on LOGGING_BOX.

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
   empty (INFERRED flag; check `doppler secrets --help`):

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
     `--silent` and ends in `> /dev/null`.
   - INFERRED: `--project`/`-p` and `--config`/`-c` are documented as general
     flags but the docs show them only on `doppler run`; their use on
     `secrets get` and `secrets set` is not shown. The docs site has no
     per-command reference page for these, so the authority is the CLI itself:
     confirm with `doppler secrets get --help` and `doppler secrets set --help`
     before running the commands.
   - NOT DOCUMENTED: whether `--plain` prints a trailing newline, and how `set`
     treats a trailing newline on stdin. That is why the check in item 3 is
     required, not optional.

   If the second command errors, stop and report; do not fall back to typing the
   value.

3. Required check of the copy, printing only `same` or `differs`, never a value
   (flags are INFERRED per item 2, so confirm with `--help` first):

```
test "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config prd_network | sha256sum | cut -d' ' -f1)" = "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config dev_network | sha256sum | cut -d' ' -f1)" && echo same || echo differs
```

Expected: `same`. If it prints `differs`, the likely cause is a trailing newline
added or kept by one of the two commands. Stop and report it. Do not use the
copy, do not start the Grafana restart in steps 4 and 5 with it, and do not
try to fix it by typing or printing the value. Delete the dev copy (see
Rollback below) until it is resolved.

Watch: the output of step 2 is empty, and no secret value appears anywhere in
the terminal or scrollback.

Note that the copy now holds a shared secret in two configs. `docs/update-alerting.md`
says the secret must be unique to the router contact point and never reused for
other services; this is the same contact point, and the owner chose it. Rotate
both together (VERIFIED: "Rotate by changing the Doppler value and the n8n
credential together"; add the dev copy to that list).

Rollback: delete `GRAFANA_WEBHOOK_SECRET` from the dev config in Doppler. Nothing
in `prd_network` was changed, and the live Grafana is unaffected until step 4d.

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
- The check at the observer has a 5 minute period and a 10 minute grace time.

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
  expect 5 to 6 pings.
- A gap over 6 minutes or two pings closer than 5 minutes is not expected; note
  the times.
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
- Q8 and Q9 answered.
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

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && sudo python3 scripts/backup-state.py --config /etc/siem-state-backup.toml; echo "exit code: $?"'
```

(`sudo` because the run needs the container runtime; whether a non-root account
should do this is Q9. INFERRED.) Then look at the output directory:

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

Only after 2c and 2d pass. Install the example unit and timer (they carry
placeholder paths and a placeholder user; edit them first, Q9):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp REPO_DIR/docs/examples/siem-state-backup.service REPO_DIR/docs/examples/siem-state-backup.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now siem-state-backup.timer && systemctl list-timers siem-state-backup.timer'
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

1. Open the workflow list and find the test copy by its name. Confirm it is
   inactive and that its webhook path differs from the live one.
2. Delete the workflow.
3. Open the credentials list and find the credential made for the failing test
   (for example the deliberately wrong Discord or Pushover credential from the
   test, runbook items 2 and 5). Confirm no other workflow uses it, then delete
   it.
4. Do not touch `grafana-webhook-auth`, `pushover-api`, the Discord webhook
   credential, the router, or the error handler (VERIFIED: runbook section 3).

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

The last line prints `1` when the name exists (INFERRED: the `--only-names`
flag; the check prints a count, never the value). The `read -rs` plus stdin
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
cp docker-compose.yml "docker-compose.yml.bak-$(date +%Y%m%d)"
grep -c 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml
sed -i '/- GRAFANA_WEBHOOK_SECRET=/a\      - DISCORD_FAILURE_WEBHOOK_URL=${DISCORD_FAILURE_WEBHOOK_URL:-}' docker-compose.yml
grep -n -B1 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml
```

The first `grep -c` must print `0` before the `sed` (else the line already
exists; skip the `sed`). The last command shows the new line directly under
`GRAFANA_WEBHOOK_SECRET`. The path `/opt/siem` is the documented default
(`SIEM_DIR`).

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
only.) Compose refusing to start with `GRAFANA_WEBHOOK_SECRET must be set and
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
restore `docker-compose.yml.bak-<date>` over the compose file; run the restart
in 4d. n8n and the heartbeat are untouched by this change.

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
cp docker-compose.yml "docker-compose.yml.bak-$(date +%Y%m%d)-email"
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
- The decision about the router token: the router secret is the same value as
  `GRAFANA_WEBHOOK_SECRET`, without the word `Bearer` (VERIFIED: step 2 of the
  quick start). That value lives in `prd_network` today. Copying it to dev
  reuses a shared secret; the alternative is a second header credential for the
  watch (a router change). OPEN QUESTION, Q11, the owner decides.

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
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'grep -n -i -E "N8N_PORT|ports:|container_name: n8n" N8N_COMPOSE_FILE'
```

Replace `N8N_COMPOSE_FILE` with the path of the compose file that defines n8n.
Back it up first, then edit it to add this under the `n8n` service, with
`CONTAINER_PORT` the value you read and `HOST_PORT` any free port above 1024
that you choose (INFERRED: the `127.0.0.1:HOST:CONTAINER` form is standard
Compose syntax, not in a repo doc, and publishing on a container attached to
a bridge network is assumed to work alongside the macvlan one):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cp N8N_COMPOSE_FILE "N8N_COMPOSE_FILE.bak-$(date +%Y%m%d)"'
```

```
    ports:
      - "127.0.0.1:HOST_PORT:CONTAINER_PORT"
```

Apply it by recreating only n8n, then immediately re-check the siem network,
because a recreate can drop it (VERIFIED: runbook, "Keep n8n on the siem
network"):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd N8N_COMPOSE_DIR && docker compose up -d n8n && docker port n8n && docker network inspect SIEM_NETWORK --format "{{range .Containers}}{{.Name}} {{end}}"'
```

`N8N_COMPOSE_DIR` is the folder of that file and `SIEM_NETWORK` the real network
name from `docker network ls` (VERIFIED: runbook). Expect the new
`127.0.0.1:HOST_PORT` line and `n8n` in the container list. Then send the
baseline test alert (`n8n-test-router.py`, runbook section 4) and confirm the
next heartbeat ping arrives within 6 minutes (step 1). A recreate restarts
n8n, so do this in a quiet moment; the heartbeat and any firing alert wait for
the restart.

The URL for the watch config is then
`http://127.0.0.1:HOST_PORT/webhook/PRIVATE_WEBHOOK_PATH` (plain http is allowed
for localhost; VERIFIED: `docs/expiry-watch.md`). Prove it reaches the router
without sending an alert, with a request that carries no secret and expects a
401 or 403 (VERIFIED: runbook section 4, cases 1 to 3):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" http://127.0.0.1:HOST_PORT/webhook/PRIVATE_WEBHOOK_PATH'
```

A `401` or `403` means the localhost URL reaches the authenticated router. A
`404` means the path or port is wrong; `Connection refused` means no port is
published.

Rollback: restore `N8N_COMPOSE_FILE.bak-<date>` over the compose file, run the
same recreate command, and re-check the siem network and the heartbeat. Nothing
else changes; the siem network name `n8n` still serves Grafana.

### 6a. Private config folder and copies (on LOGGING_BOX)

The folder must be writable only by the job user (VERIFIED: "Paths and symbolic
links"). Keep it outside the repo, since the router URL contains the private
webhook path.

```
sudo install -d -m 700 -o "$USER" /etc/expiry-watch
cp REPO_DIR/docs/expiry-watch.example.toml /etc/expiry-watch/expiry-watch.toml
cp REPO_DIR/docs/expiry-watch-registry.example.toml /etc/expiry-watch/expiry-watch-registry.toml
"${EDITOR:-nano}" /etc/expiry-watch/expiry-watch.toml
```

Edit (the example values are placeholders and several will fail until replaced):

- `[router].url`: the localhost URL from section 6.0,
  `http://127.0.0.1:HOST_PORT/webhook/PRIVATE_WEBHOOK_PATH` (the private path is
  in the `router-path` file in the secrets config directory, runbook section 7).
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

Set only the ones the config uses. Same pattern as step 5a, to dev, each ending
in `> /dev/null`:

```
read -rs -p "Value for EXPIRY_WATCH_ROUTER_TOKEN: " VAL; echo
printf '%s' "$VAL" | doppler secrets set EXPIRY_WATCH_ROUTER_TOKEN --project homelab --config dev_network --silent > /dev/null
unset VAL
```

(If Q11 is answered "copy": the value is the existing router secret, entered
from your own source; do not read it back out of the secret manager into a
terminal.)

### 6c. Dry run first (changes nothing, posts nothing, saves nothing)

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && doppler run --project homelab --config dev_network -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml --dry-run; echo "exit code: $?"'
```

(`doppler run` form VERIFIED in `docs/update-alerting.md`; its use with this
script is INFERRED.)

Watch:

- Exit code `0` ok, `1` a provider or delivery failed (details on stderr), `2` a
  config or secret problem (VERIFIED).
- The output lists the notices that are due and the JSON it would post. Check the
  item names, dates and owner lines are the real ones.
- A TLS provider error is a real finding, not a date (VERIFIED: "tls").
- Expect a first run to show many notices at once for items already inside a
  threshold; only the lowest crossed threshold per item fires (VERIFIED).

### 6d. First real run, then schedule

Only when the dry run is clean and the route is the one you want. A real run
posts real messages to Discord, and an unwanted message cannot be recalled:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && doppler run --project homelab --config dev_network -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml; echo "exit code: $?"'
```

Confirm the messages arrive and the state file `/etc/expiry-watch/expiry-watch-state.json`
exists with mode 0600 (VERIFIED). Then schedule it on LOGGING_BOX with either a
systemd service and timer or a cron entry; both are given in
`docs/expiry-watch.md`, "Scheduling", and the choice is yours. Whichever you
pick, the job runs on the box, as the same user that owns the config folder, and
reads its secrets only from the single dev config by wrapping the command in
`doppler run --project homelab --config dev_network --` (the secrets are named by
variable only; no value goes in the unit, the cron line or the config). That
doc's examples instead read the router secret from an `EnvironmentFile` (mode
0600, owned by the job user); using `doppler run` in place of it is INFERRED, and
needs the Doppler CLI logged in for that user (non-interactive login for a
scheduled job is not covered by any repo doc). Decide Q11 on the router secret
separately. The doc also warns that nothing alerts you if the schedule stops;
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
