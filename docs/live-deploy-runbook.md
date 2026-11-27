# Live deploy runbook: rebuild the alert setup on an empty box

For an operator under stress. It rebuilds the update-alerting deploy
(`docs/update-alerting.md`) on a SIEM host that has the stack but none of the
alert setup. Every step has a check with the expected output and a rollback.

The tooling lives in `scripts/live-deploy/`. Nothing here contains a secret
value, a real address or a real webhook path; those are placeholders in angle
brackets. Documentation addresses (192.0.2.x) stand for real ones.

| File | Role |
|------|------|
| `scripts/live-deploy/siem-run` | Runs a command with the alert values injected from the secret manager |
| `scripts/siem-net-run` | The same idea for the Doppler config `dev_network` (project `homelab`): reads a read-only service token from `$SIEM_NET_CONFIG_DIR/token` (default `$HOME/.config/doppler-siem-net`), refuses a missing, symlinked, non-private or foreign-owned file, and runs a command with the token only in that process. It needs `--require NAMES` and/or `--optional NAMES` then `--` (only those secrets are injected, only names in its fixed table are accepted, and a required one that is missing stops the command) and reads no cached copy. It restarts Grafana and recreates n8n for the owner runbook (`docs/owner-runbook.md`, step 0b.5) |
| `scripts/live-deploy/n8n-setup-alert-router.py` | Creates the two n8n credentials and imports the router workflow |
| `scripts/live-deploy/n8n-test-router.py` | Pre-deploy checks against the router (401/403 cases, test alerts, phone test) |
| `scripts/live-deploy/grafana-deploy.py` | Grafana file deploy (dry run by default): allowlisted alert files with backups, one datasource file; never starts docker |
| `scripts/live-deploy/pfb-fix-feeds.php` | One-time firewall feed fix, kept as a change note (see the last section) |

Every script documents its environment variables at the top. The defaults are
the values of the original deploy; override them for your host:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SIEM_DIR` | `/opt/siem` | Live stack directory with `docker-compose.yml` |
| `SIEM_STAGE_DIR` | `$HOME/bin/alerting` | Staged copy of `docker/grafana/provisioning/alerting/` |
| `SIEM_CONFIG_DIR` | `$HOME/.config/doppler-siem` | Private config directory: token file, router path file |
| `N8N_CONTAINER`, `GRAFANA_CONTAINER` | `n8n`, `grafana` | Container names |
| `N8N_BASE` | looked up at run time | Full n8n URL for the checks. Unset: found from the container's address on the siem network (`scripts/n8n_address.py`; see `N8N_CONTAINER`, `SIEM_NETWORK`, `N8N_PORT`) |
| `INFLUX_URL` | `http://influxdb:8086` | URL of the two added datasources |
| `DOPPLER_PROJECT`, `DOPPLER_CONFIG` | unset | Only if your token is not already scoped; examples `homelab` and `prd_network` |

## 1. Prerequisites

- The SIEM stack is running (Grafana, InfluxDB, n8n containers) and you have
  shell access with permission to run `docker`.
- The secret-manager CLI is installed on the host.
- The secret manager already holds three values: the webhook secret, the
  Pushover application token and the Pushover user key. Which names they have
  there is in `docs/update-alerting.md`. If the webhook secret is missing,
  create it the way that document says (random, at least 32 characters).
- This repository is checked out on the host (or copy `scripts/live-deploy/` and
  `docker/grafana/provisioning/alerting/` and `n8n/grafana-alert-router.json`).

Check: `docker ps --format '{{.Names}}'` lists the three containers.

## 2. The read-only token file

The scripts read one read-only service token from a mode-600 file. Use your own
private directory: the CLI's default folder may be root-owned.

1. In the secret manager, create a read-only service token for the project and
   config that hold the three values (examples `homelab` and `prd_network`).
   Do this in the web UI or with the CLI, and copy the token once.
2. On the host:

```
mkdir -p "$HOME/.config/doppler-siem"
chmod 700 "$HOME/.config/doppler-siem"
# paste the token, then press Ctrl-D (it is not echoed or kept in shell history)
cat > "$HOME/.config/doppler-siem/token"
chmod 600 "$HOME/.config/doppler-siem/token"
```

3. Install the wrapper: `install -m 755 scripts/live-deploy/siem-run "$HOME/bin/siem-run"`.

Check (prints only presence, never values):

```
"$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-setup-alert-router.py --check
```

Expected: three lines `GRAFANA_WEBHOOK_SECRET: present`, `PUSHOVER_API_KEY: present`,
`PUSHOVER_USER_KEY: present`, exit code 0. `siem-run: token file missing or
unreadable` means step 2 is incomplete.

Rollback: `rm -r "$HOME/.config/doppler-siem"` and revoke the token in the
secret manager.

## 3. What lives only inside n8n's data volume

n8n keeps these in its own data volume, encrypted with its own key. A rebuild of
the n8n container without that volume loses all of them:

| Item | Type | Recreated by |
|------|------|--------------|
| Credential `grafana-webhook-auth` | Header Auth (`Authorization: Bearer <webhook secret>`) | `n8n-setup-alert-router.py --credentials` |
| Credential `pushover-api` | Custom Auth with a JSON body holding the app token and user key | `n8n-setup-alert-router.py --credentials` |
| The imported workflow (with the router code and constants) | Workflow | `n8n-setup-alert-router.py --workflow` |
| The imported error handler workflow | Workflow (Error Trigger) | `n8n-setup-alert-router.py --error-workflow` |
| The private webhook path | Value in the workflow and in the Grafana contact point | A new one is generated on first import and saved to `router-path` in the config directory |
| Credential `matrix-bot-auth` (optional, for the weekly digest) | Custom Auth with an `Authorization: Bearer <token>` header | `MATRIX_BOT_TOKEN=... n8n-setup-alert-router.py --credentials --with-matrix` |
| The imported weekly update digest workflow (optional) | Workflow, imported inactive | `n8n-setup-alert-router.py --digest-workflow n8n/weekly-update-digest.json` |
| The Discord webhook credential | Existing credential, used by the router's Discord nodes | Not recreated here: it is part of the original n8n setup |

Details that were learned live:

- Credentials import takes plain data and n8n encrypts it. The script sends it
  over stdin to `n8n import:credentials` inside the container, so no file with
  a value stays on the host.
- Workflow import needs an `id`. The script makes a fresh 16-hex id, or reuses
  the one you pass as the second argument so a re-run overwrites the earlier
  import (import overwrites by id).
- To keep the short URL `/webhook/<path>`, the webhook node needs a
  `webhookId`; the script sets one. With none, n8n serves the webhook under
  `/webhook/<workflowId>/<node name>/<path>`.
- Publishing a workflow through the CLI needs an n8n restart before the
  webhook is registered: `docker restart n8n`.
- The imported workflow is inactive (`active: false`). Activate it in n8n after
  you check it, or publish through the CLI, then restart.
- The Matrix credential is created only with `--with-matrix` (together with
  `--credentials`; `--check --with-matrix` also reports `MATRIX_BOT_TOKEN`). The
  token comes from the secret manager through `siem-run` as the environment value
  `MATRIX_BOT_TOKEN`, goes to n8n over stdin like the other secrets, and is never
  on argv and never printed. Add `MATRIX_BOT_TOKEN` to the names `siem-run` injects.
- `--digest-workflow n8n/weekly-update-digest.json [ID] [--error-workflow-id HANDLER_ID]`
  imports the weekly digest inactive and maps its Discord and `matrix-bot-auth`
  credential ids. Import the error handler first and pass its id, as for the
  router. Without the id the placeholder `errorWorkflow` setting is removed. It
  stays inactive until you activate it in n8n.
- `MATRIX_HOMESERVER` and `MATRIX_ROOM_ID` are not secrets. The digest reads them
  as `$env` values, so they are pass-through lines (names only) in the `n8n:`
  service `environment:` list of the compose file, like the other n8n variables;
  the values live in the secret manager or the compose environment, never in git.
  Recreate the n8n container after adding them.
- Pass `--pushover-on` to switch the `PUSHOVER_ENABLED` constant on. Leave it
  off until the checks below pass.

Import order: credentials, then the **error handler**, then the router. The
router's `errorWorkflow` setting must point at the handler's real id, so the
handler is imported first and its id is passed to the router import.

Steps:

```
siem-run python3 -I scripts/live-deploy/n8n-setup-alert-router.py --credentials
siem-run python3 -I scripts/live-deploy/n8n-setup-alert-router.py --error-workflow n8n/alert-router-error-handler.json
siem-run python3 -I scripts/live-deploy/n8n-setup-alert-router.py --workflow n8n/grafana-alert-router.json --error-workflow-id <handler id>
```

The second command prints `error workflow id: <16 hex characters>`; use that
value in the third. To re-run later, pass the earlier ids (`--error-workflow
FILE <handler id>` and `--workflow FILE <router id> --error-workflow-id
<handler id>`) so the imports overwrite by id instead of adding copies.

Check: the first prints `credentials import exit code: 0`; the second prints
`error workflow import exit code: 0` and the id; the third prints
`workflow import exit code: 0`, `new webhook path saved (mode 600): ...`,
`dashboard origin constant set: True` (False if Grafana's root URL is not a
plain http or https origin) and `error workflow set: True`. In n8n, the
workflow `Grafana SOAR - Alert Router (authenticated)` exists, its webhook node
has credential `grafana-webhook-auth`, and its settings name the handler as the
error workflow. Both workflows import inactive.

Publish both (the handler too: an inactive handler never runs), then restart
n8n once: `docker restart n8n`. Publishing through the CLI needs the restart
before the webhook and the error trigger are registered.

Failed runs are not stored, by design: a stored failed run would keep the
request headers, which carry the webhook credential. The only trace of a failure
is the n8n container log and the notice the handler sends.

Rollback: delete the two imported workflows and the two credentials in n8n, and
remove the `router-path` file. The old router (if any) is untouched because a
fresh import gets a new id.

## 4. Test through the Docker bridge address

A macvlan container is not reachable from its own host, so the checks go
through the siem network. The test script finds the n8n container's address on
that network at run time (the address changes after a recreate, so none is
written down here):

```
siem-run python3 -I scripts/live-deploy/n8n-test-router.py
```

It stops with a clear message if n8n is not on the siem network. To skip the
lookup, set `N8N_BASE=http://<n8n-bridge-address>:80` for the one command.

Expected: six lines ending `PASS`, then `failed cases: 0`. Cases 1 to 3 (no
header, wrong value, wrong scheme) must be 401 or 403. Cases 4 to 6 must be
200 and put visible test messages in Discord (a malformed-alert notice, a
firing test and a resolved test). No phone message is sent while the Pushover
constant is off.

Optional phone test after you enable Pushover (`--pushover-on` on the import and
a restart): `n8n-test-router.py --phone` sends a priority 1 and a priority 2
message, `--phone-resolve` cancels the repeats. Remember the `phone` label gate:
the test uses real update alert names; see the label taxonomy in
`docs/update-alerting.md`.

The 200 now comes only after the channel steps finish: the webhook answers
through a Respond to Webhook node at the end of the run, so a failing Discord
step makes the checks (and Grafana) see an error status instead of a premature
"received".

Prove the failure path on purpose, in a copy, never on the live router:

1. In n8n, duplicate the router workflow and give the copy its own webhook path.
   Set the copy's error workflow to the handler.
2. In the copy, break the `Discord - Firing` node (for example, point its
   credential at a Discord webhook that does not exist), and publish the copy.
3. Post one firing test alert to the copy's path (the same call
   `n8n-test-router.py` uses for case 5).
4. Expect: the call returns an error status (not 200); within a minute the
   failure notice arrives on the phone (handler channel: Pushover, priority 1)
   naming the workflow, the failed node, a short error and the execution id,
   and no alert content. Nothing is stored in n8n's execution list (by design).
5. Break the Pushover step instead (a wrong credential in the copy): the call
   still returns 200, Discord still gets the alert, and Discord shows one short
   "phone delivery failed" notice.
6. Delete the copy.

Rollback: nothing changed on the live router; the checks only send test alerts
and the copy is deleted.

### Keep n8n on the siem network

Warning: recreating the n8n container (`docker compose up -d` after an image or
config change) from a compose file that does not list the siem network drops it
off that network. Grafana then cannot resolve the name `n8n`, and alert delivery
fails silently until it is reattached. The reference service definition
(siem network as `external: true` plus the macvlan network) is in
`docs/examples/n8n-compose.example.yml`; make your live compose file match it.

For a container that was already recreated, reattach it. The real network name
is usually the compose project name plus `_siem-net` (for example
`siem_siem-net`); `docker network ls` shows it.

```
docker network connect <network-name> n8n
```

Verify Grafana reaches n8n by name. Expected: an HTTP status line (a 404 or 405
from the webhook path is fine, it proves the name resolves and n8n answers);
`Could not resolve host` means the container is still off the network:

```
docker exec grafana wget -S -q -O /dev/null --post-data '{}' http://n8n/webhook/probe 2>&1 | head -3
```

Then run the checks of this section; they fail with the same hint if the
container is off the network.

## 5. Additive Grafana deploy

The script `scripts/live-deploy/grafana-deploy.py` copies the provisioning files
only. It never starts docker and never reads the compose file. The one compose
line and the Grafana restart are manual steps (steps 4 and 5 below).

1. Stage the files: copy these files from `docker/grafana/provisioning/alerting/`
   to `SIEM_STAGE_DIR`: `contact-points.yml`, `update-alert-rules-unifi.yml`,
   `update-alert-rules-pfsense.yml`, `heartbeat-alert-rule.yml` and
   `notification-failure-alert-rule.yml`. Also copy `update-alert-rules-twingate.yml`
   when the Twingate rules exist in the repo: it is in the script's `OPTIONAL_FILES`
   list, deployed when staged and skipped when absent (`infra-alerts.yml`, issue #224, is in that list too; see `docs/infrastructure-alerts.md` before staging it) (a new rule file the live box
   needs is a one-line add to that list). For the P1 email channel also copy
   `email-contact-point.yml.example` and `email-notification-policy.yml.example`;
   they are only deployed when you name them (below).
2. Dry run. This is the default, so no flag is needed. It changes nothing:

```
siem-run python3 -I scripts/live-deploy/grafana-deploy.py
```

Expected: `staged files ok; router path length <n>`, then `dry run: nothing is
changed` and one line per file: `create`, `unchanged` or `overwrite`. For every
file that would be overwritten it prints only the number of lines added and
removed, never file content and never a hash (live files can hold credentials,
and a hash of a guessable file is a guessing aid); variable names are listed for
example files. `--stage` is the shorter check and prints the first line and the
`INFLUX_URL` lines.

Every run (`--stage`, dry run, `--apply`) prints `INFLUX_URL in effect: <url>` and
whether it came from the environment or is the default. The datasource file is
rewritten from fixed text, so the deploy keeps a live `influxdb-twingate`
datasource (its block is carried over unchanged) and never invents one. If
`INFLUX_URL` is unset but the live datasource file gives the pfSense or UniFi
datasource another URL than the default, the stage and dry run print a `WARNING`
and the script refuses --apply (fail closed, nothing is changed): set `INFLUX_URL` to the
live URL to keep it, or to the default on purpose. The check is a read-only
compare of the live file with the default; the script never guesses a URL.

It refuses, with a plain message and a nonzero exit code, if a staged file or the
`router-path` file is owned by someone else or writable by group or others (use
`chmod 644`), the stage, config, alerting or datasource folder is writable by group
or others (a sticky folder such as `/tmp` is accepted only as a parent, never as
those folders themselves), the router path
file looks wrong (it must be `grafana-alerts-` plus 8 to 128 letters, digits, `_`
or `-`), a staged file is missing, a file or directory is a symlink or not a
regular file (every directory in the path is opened without following symlinks,
and each must be owned by root or you and not writable by group or others; a
sticky world-writable directory such as `/tmp` is accepted), a file is over 1
MiB, the contact point URL is not found, or `N8N_WEBHOOK_BASE` or `INFLUX_URL` is
not a plain `http(s)` URL (they are written into YAML as is).

3. Apply, only when the dry run looks right:

```
siem-run python3 -I scripts/live-deploy/grafana-deploy.py --apply
```

To deploy an example file as well, name it exactly (repeat the option for both):

```
siem-run python3 -I scripts/live-deploy/grafana-deploy.py --apply --include-example email-contact-point.yml.example
```

Only `email-contact-point.yml.example` and `email-notification-policy.yml.example`
can be named; any other name is refused. A deployed example loses the `.example`
suffix in the alerting folder. Without the option the examples stay inactive.
The email contact point needs `P1_EMAIL_TO` and the `GF_SMTP_*` variables in the
Grafana container environment ([channel-redundancy.md](channel-redundancy.md));
the plan lists the variable names it sees, never values. The policy example
replaces the whole notification policy tree (Grafana loads one tree per
organization), so deploy it only when that tree is meant to be exactly that
file; otherwise merge the route by hand as in step 6.

What the script does, and only this:

- Writes the alerting folder `grafana/provisioning/alerting/` (the contact
  point gets the private webhook path; the pfSense rules stay paused; the
  heartbeat and notification failure rule files are copied as is, mode 644, and
  files in the folder that are not on the allowlist are left alone).
- Writes one datasource file with two extra InfluxDB datasources, ids
  `influxdb-pfsense` and `influxdb-unifi` (names `InfluxDB-pfSense-alerts` and
  `InfluxDB-UniFi-alerts`). Existing datasources are not changed, because
  changing a datasource id breaks dashboards that reference it.
- Before it replaces anything, it re-reads every existing target and saves the
  old content as `<name>.bak-<UTC timestamp>` (mode 600) in the same folder (a
  file that changed since the dry run stops the run before any replacement). The
  backup is written under a temp name and linked into place only after a full
  fsync, so a backup that exists is complete. Grafana ignores the `.bak-` files.
- Then it replaces the files one at a time (temp file, fsync, rename), comparing
  each one with the planned content right before its rename, and prints one
  `manifest:` line per file as it goes (`replaced <name> (backup <name>)` or
  `created <name>`). At the end it lists the files replaced and points here.
- It is not atomic across files and not crash safe. If it stops on an error, or
  is killed, the set can be partial: some files new, some old. Nothing is rolled
  back for you. On an error it prints which files it had already replaced and the
  backup that restores each one.
- Concurrent edits are not supported. A process of the same user, or root, can
  still change a file in the window of a few microseconds between the final
  comparison and the rename; that edit would be replaced and is not in the backup.
- Output: file names, line counts, backup names, variable names and the router
  path length. No file content, no hashes, no environment values, and error
  messages do not echo the path components or arguments you supplied.

4. Manual: add the pass-through line that gives the webhook secret to the Grafana
   container, and only to the grafana service (only if the compose file does not
   already list it). `GRAFANA_WEBHOOK_SECRET` is the variable name; its value stays
   in the secret manager. The backup of the compose file is made with `umask 077`
   so it is mode 600, and `--no-clobber` so an existing backup is never replaced.
   The compose file only references variable names, so the backup holds no secret
   values unless someone wrote literal values into the compose file; treat it as
   sensitive anyway. On the SIEM host, in `SIEM_DIR` (default `/opt/siem`):

```
cd /opt/siem
( umask 077 && cp --no-clobber docker-compose.yml "docker-compose.yml.bak-$(date -u +%Y%m%dT%H%M%SZ)" )
ls -l docker-compose.yml.bak-*
awk '/^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {svc=$1} /GRAFANA_WEBHOOK_SECRET/ {print svc, NR}' docker-compose.yml
```

The `ls` line of the new backup must start with `-rw-------`. The `awk` line prints
the service name and line number of every line that mentions the variable. Before
the edit it must print nothing for the grafana service (if it prints
`grafana:` the line is already there, skip the edit). It assumes the usual layout
with service names indented by two spaces; check the result by eye if your file
is laid out differently.

Edit the file in an editor (no scripted edit is given, because a blind
insert would also hit any other service that has the same neighbor line). In the
`grafana:` service, inside its `environment:` list, add exactly this item at the
same indentation as its neighbors, directly after the `GF_SERVER_ROOT_URL` line:

```
      - GRAFANA_WEBHOOK_SECRET
```

Then run the `awk` line again. It must print exactly one line, and the service name
on it must be `grafana:`. If any other service name appears, remove the line from
any other service and run it again until only `grafana:` is listed: the secret
must not reach any other service. Do not run `docker compose config` to check the
result: it prints resolved values, including secrets, to your terminal.

5. Manual: recreate only Grafana. Grafana loads provisioning files only at
   startup, and `docker compose up -d grafana` may not re-read them: it does
   nothing when the service definition is unchanged. When only the provisioning
   files changed (no compose or environment change), restart the container; the
   script prints this exact step on every run and never runs it:

```
docker restart grafana
```

   When the compose file or its environment changed too (step 4), the
   recreate below is needed. Either way this restart is what makes Grafana read the new files. The values the
   compose file needs come from the one Doppler dev config (`DEV_CONFIG` is the
   config name; see `docs/owner-runbook.md`, Q1):

```
cd /opt/siem && doppler run --project homelab --config DEV_CONFIG -- docker compose up -d grafana
```

Check:

- The command exits 0. `docker compose ls` lists the project as running, and
  `docker ps --filter name=grafana --format '{{.Names}} {{.Status}}'` shows
  `Up` (and `healthy` when the service defines a healthcheck).
- In Grafana, Alerting shows the rules in the folder `Update Alerts` and the
  contact point `n8n-grafana-router`; the datasources list shows the two new
  ones. The UniFi rule states are Normal, not Error.
- Verify the data the UniFi rules read: `SHOW FIELD KEYS ON unpoller FROM usw`
  lists the boolean field `upgradeable`.

Rollback, by hand (there is no automatic rollback): take the `manifest:` lines of
the run, or the list in its error message. For each `replaced` file, copy its
backup over it in the same folder, for example
`cp -p contact-points.yml.bak-<UTC timestamp> contact-points.yml`. Delete each
file marked `created`, and delete the datasource file `alerting-influx.yml` if it
is not wanted. If you edited the compose file, restore it with
`cp -p docker-compose.yml.bak-<UTC timestamp> docker-compose.yml`. Then recreate
Grafana with the command of step 5. After a kill with no report, look for
`*.bak-*` backups and leftover `.*.new-*` temp files in the alerting folder and
the datasources folder; the backups of the files that were replaced are the
newest `.bak-` of each name.

### Datasource name collision (seen live)

Another stack's service named `influxdb` on the same Docker network made the
name `influxdb` ambiguous: Grafana's added datasources reached the wrong
database. The stopgap is to point the two added datasources at the real
InfluxDB container's own address by setting `INFLUX_URL` for the deploy:

```
INFLUX_URL=http://<influxdb-container-address>:8086 siem-run python3 -I scripts/live-deploy/grafana-deploy.py --apply
```

This is a stopgap: the address can change when the container is recreated. The
proper fix (unique service names or separate networks) is tracked in a netpulse
issue and in siem-docker-stack#61. Symptom to look for: datasource test fails or
returns another stack's measurements.

### Folder and file modes the deploy script accepts (seen live)

The deploy script refuses to run if any folder on the path to the stage,
config, alerting or datasource folders is writable by group (a sticky folder
such as `/tmp` is accepted only as a parent), and it refuses staged files that
are not mode 644 (or that are writable by group or others). A typical cause is a
umask of 002, which creates group-writable folders and files. Fix it on the host,
using your own paths:

```
# every folder on the path, from the stage folder up to (not including) /
chmod g-w <stage-folder> <config-folder> <alerting-folder> <datasource-folder>
# check each parent too: namei -m <stage-folder> shows the mode of every component
# every staged file
chmod 644 <stage-folder>/*
```

Then re-run the dry run. Folders must also be owned by root or by the user running
the script.

## 6. The manual Grafana notification policy route

Grafana provisions the notification policy as one tree for the whole
organization, so the repository ships it only as
`update-notification-policy.yml.example`; it is not applied by the deploy.
Add the route by hand in Alerting, Notification policies: a child route that
matches `update_alert = true`, with contact point `n8n-grafana-router`, and two
sub-routes: `severity = warning` with repeat interval 84h and
`severity = critical` with repeat interval 24h.

Check: Alerting, Notification policies shows the route. Fire a test alert (or
wait for one) and see the message in Discord.

Rollback: delete the route in the same screen.

## 7. What is not in git, and why

| Item | Why it is not in git |
|------|----------------------|
| The three secret values (webhook secret, Pushover app token, user key) | They are secrets; they live in the secret manager |
| The service token file in the private config directory | A credential; recreate it in step 2 |
| The `router-path` file (private webhook path) | The path is an access control by design; the import makes a new one, and Grafana's contact point is rewritten from it. If you lose it, redo steps 3 and 5 |
| n8n's data volume, with the encrypted credentials and workflow state | Instance state; recreated by step 3 |
| The compose backups `docker-compose.yml.bak-<UTC timestamp>` | Host-local copies of the live file |
| The Discord webhook credential in n8n | Part of the original n8n setup, outside this tooling |

## 8. One-time firewall feed fix (change note)

Two pfBlockerNG DNSBL feeds were failing (investigation in
pfsense-siem-stack#66, tracked in #67). One dead feed was set to Disabled
(its source site is down), and one feed whose keyless URL now returns 410 Gone
was moved to a keyless mirror of the same data. Both were changed in the
firewall's configuration by hand with a short PHP snippet; the snippet is kept
for reference as `scripts/live-deploy/pfb-fix-feeds.php`. This runbook does not
automate it and the deploy never runs it. If the same two feeds break again,
read the snippet and make the change in the firewall's own interface or run
the snippet there deliberately; it writes nothing if the rows are not in the
expected state.

## 9. InfluxDB authentication: one write-only user per writer

InfluxDB runs with authentication on (`INFLUXDB_HTTP_AUTH_ENABLED=true` in
`docker/docker-compose.yml`). Every writer needs its own user that can only write
to its own database: unifi-poller, Telegraf and each collector. Do not reuse the
admin account in a writer. Grafana's datasources read; give them a separate
read-only user.

Create the unifi-poller user. The password is read without being shown, goes to
the secret manager through stdin with the output discarded, and is never put on a
command line (`printf` is a shell builtin, so the value never reaches a process
argument list; the container's own admin login from its environment is used):

```
# 1. Read a new password without echo
read -rs UP_PW
# 2. Store it in the secret manager (value from stdin, output discarded)
printf '%s' "$UP_PW" | doppler secrets set UNPOLLER_INFLUX_PASSWORD --project <project> --config <config> > /dev/null
# 3. Create the user in InfluxDB (statement from stdin, output discarded)
printf "CREATE USER unpoller_wo WITH PASSWORD '%s'\n" "$UP_PW" | docker exec -i influxdb influx > /dev/null
unset UP_PW
# 4. Grant write on the one database only (no password in this statement)
docker exec influxdb influx -execute 'GRANT WRITE ON unpoller TO unpoller_wo'
# 5. Check: the grant shows WRITE on unpoller and nothing else
docker exec influxdb influx -execute 'SHOW GRANTS FOR unpoller_wo'
```

Then point unifi-poller at it with two lines in the `unifi-poller` service
environment of `docker/docker-compose.yml` (the shipped compose file already
carries them):

```
- UP_INFLUXDB_USER=${UNPOLLER_INFLUX_USER:-unpoller_wo}
- UP_INFLUXDB_PASS=${UNPOLLER_INFLUX_PASSWORD:?set UNPOLLER_INFLUX_PASSWORD in .env}
```

The password reaches compose from the secret manager (or the private `.env`
described in the README upgrade notes), never from a value typed into the compose
file. Recreate the container with `docker compose up -d unifi-poller` and confirm
new points arrive:
`docker exec influxdb influx -execute 'SELECT count(*) FROM usw' -database unpoller`.
If the writer logs show an authentication error (401), the user or password does
not match. Rollback: `DROP USER unpoller_wo`.

Repeat the same steps for each other writer, with its own user name and database.

## 10. Twingate collector (hourly metrics into InfluxDB)

Issue #222. This feeds the paused Twingate rules
(`update-alert-rules-twingate.yml`). It does not unpause them: that is a later,
separate step after the landing check below passes.

| File | Role |
|------|------|
| `scripts/live-deploy/twingate-fetch-secrets.py` | Broker step: runs under `siem-run`, receives only the Twingate secret names and writes one generation (a directory named by a random run id: one private credential file per stage plus a manifest with the id and file digests); prints counts only |
| `scripts/live-deploy/twingate-generation.py` | Root-side helper, run only by `+` unit commands with fixed arguments: validates and publishes the broker's generation, records which one the writer consumes, removes exactly that one afterwards and purges leftovers |
| `scripts/live-deploy/twingate-stage.py` | Stage wrapper: checks the generation (manifest, digest, run id), loads the stage's own credential file, checks the names against an allowlist, builds a clean environment and replaces itself with the collector or the writer |
| `scripts/live-deploy/twingate-collect` | Manual single-process runner for a bench test (not a security boundary, see "Why a broker" below): re-executes itself under `env -i`, runs the collector and pipes its output to the writer, each under `siem-run`; exits non-zero if either stage fails or nothing is written |
| `scripts/live-deploy/twingate-influx-write.py` | Stdlib writer: one POST to `/write?db=telegraf&precision=s`, Basic auth, 5 s timeout, no redirects, no retry; prints only counts and the HTTP status |
| `docs/systemd/twingate-collect.service`, `twingate-collect-metric.service`, `twingate-collect-write.service`, `.timer`, `twingate-collect-failure.service` | Hourly chain of three sandboxed oneshots (broker, check, write) and a journal notice when any step fails |

Owner steps (placeholders in angle brackets; the InfluxDB admin credentials are
read inside the container from its own environment, so they are never typed):

1. Create the secrets. The password is generated, piped straight into the
   secret manager and never shown. The secret manager config `prd_network` is the
   one `siem-run` reads; its service token must be able to read the two names
   (that the CLI takes the value from stdin is not verified here: if it asks for
   a prompt, type nothing into the terminal history and paste the value instead):

```
openssl rand -base64 36 | tr -d '\n=+/' | doppler secrets set TWINGATE_INFLUX_PASSWORD --project homelab --config prd_network > /dev/null
printf '%s' 'twingate_wo' | doppler secrets set TWINGATE_INFLUX_USER --project homelab --config prd_network > /dev/null
```

   The collector also REQUIRES the expected Connector inventory. The owner
   supplies the real names; they are not kept in this repository. Put the JSON
   array in the same secret manager config as `TWINGATE_EXPECTED_CONNECTORS`
   (for example `["connector-a","connector-b"]` with your own names), or keep a
   root-owned file and read it into the secret. Names use letters, digits, `.`,
   `_` and `-` only (1 to 64 characters), with no duplicates (case does not
   count). Without a valid list the check fails closed.

2. Create the write-only InfluxDB account, `twingate_wo`, with write on the
   `telegraf` database only (the same pattern as `unpoller_wo`). The SQL is read
   from stdin and its output is discarded. The `influx` client reads the login
   from its `INFLUX_USERNAME` and `INFLUX_PASSWORD` environment variables (set as a
   prefix inside the container's shell, so no password is in any process argument;
   that the deployed InfluxDB 1.x client honors them is not verified here: if it
   answers with an authorization error, stop and report it, and do not fall back
   to a `-password` argument or a password in a command line):

```
siem-run bash -c 'docker exec -i influxdb sh -c '\''INFLUX_USERNAME="$INFLUXDB_ADMIN_USER" INFLUX_PASSWORD="$INFLUXDB_ADMIN_PASSWORD" influx'\'' > /dev/null <<EOSQL
CREATE USER "$TWINGATE_INFLUX_USER" WITH PASSWORD '\''$TWINGATE_INFLUX_PASSWORD'\''
GRANT WRITE ON "telegraf" TO "$TWINGATE_INFLUX_USER"
EOSQL'
docker exec influxdb sh -c 'INFLUX_USERNAME="$INFLUXDB_ADMIN_USER" INFLUX_PASSWORD="$INFLUXDB_ADMIN_PASSWORD" influx -execute "SHOW GRANTS FOR twingate_wo"'
```

   Check: the last command lists `telegraf WRITE` and no other database.

3. Preflight. Nothing is changed. The units need systemd 249 or newer: `OnSuccess=` needs 249,
   `StandardOutput=truncate:` needs 248, `ProtectProc=` and `ProcSubset=` need 247. Three
   commands run as root (`ExecStartPre=+`, `ExecStartPost=+`, `ExecStopPost=+`) and execute
   scripts from the checkout, so the checkout must be owned by root and not writable by
   anyone else. Stop here if any line fails:

```
systemctl --version | head -n 1
test "$(systemctl --version | awk 'NR==1 {print $2}')" -ge 249; echo "systemd>=249 exit=$?"
sudo find /opt/siem/scripts/live-deploy /opt/siem/scripts/twingate-update-metric.py ! -user root -o -perm /022 | head -n 5
sudo systemd-analyze verify docs/systemd/twingate-collect.service docs/systemd/twingate-collect-metric.service docs/systemd/twingate-collect-write.service
```

   Expected: a version of 249 or higher, `exit=0`, no path listed by `find`, and no
   `systemd-analyze` complaint about an unknown directive (an unknown directive means the
   systemd is too old). Replace `/opt/siem` with the checkout path in the three service
   files before the install step; `docs/systemd/` is read here, so run the commands from
   the repository root.

4. Put the secret manager's read-only service token where only root can read it and install
   the units. No account is created: the broker is a dynamic user. The token must be a
   read-only service token scoped to the one config, `prd_network`. The token is typed at
   the prompt of `read -rs`, so it is in no history and no argument. If you used the old
   per-user token file or a `siem-broker` account, delete them after this step:

```
sudo install -d -m 700 -o root -g root /etc/siem
read -rs -p 'service token: ' T; echo; printf '%s' "$T" | sudo sh -c 'umask 277; cat > /etc/siem/doppler-token'; unset T
sudo install -m 644 docs/systemd/twingate-collect.service docs/systemd/twingate-collect-metric.service docs/systemd/twingate-collect-write.service docs/systemd/twingate-collect-failure.service docs/systemd/twingate-collect.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/twingate-collect.service /etc/systemd/system/twingate-collect-metric.service /etc/systemd/system/twingate-collect-write.service
sudo systemctl daemon-reload
```

   The chain uses `OnSuccess=`, which needs systemd 249 or newer (`systemctl --version`).

5. First run of the whole chain (broker, then check, then write), then the landing check:

```
sudo systemctl start twingate-collect.service
journalctl -u twingate-collect.service -u twingate-collect-metric.service -u twingate-collect-write.service --since '-5min' --no-pager
```

   Expected: `twingate-fetch: files=3 secrets=<n>`, the collector's lines
   (`twingate_connector_behind` and `twingate_connector_up` per Connector,
   `twingate_unexpected_connector value=0i`, `twingate_update_check_success value=1i`),
   `twingate-influx-write: lines=<n> status=204`, and no generation left afterwards
   (`sudo ls /run/twingate-collect` lists no 32-character directory and no `current`;
   `/run/twingate-broker` does not exist). A 401 from the writer means the account or
   password is wrong. Read the point back through the Grafana read account (never the write
   account):

```
docker exec influxdb sh -c 'INFLUX_USERNAME="$GRAFANA_INFLUX_USER" INFLUX_PASSWORD="$GRAFANA_INFLUX_PASSWORD" influx -database telegraf -execute "SELECT last(value) FROM twingate_update_check_success"'
```

   Expected: one row with value 1 and a recent time. Then, in Grafana, open the
   datasource `influxdb-twingate` and press Save and test. The repo's
   `datasources.yml` gives it the read account `grafana_ro`, but `grafana-deploy.py`
   keeps the live block as it is and writes no credentials into the pfSense or UniFi
   datasources, so confirm on the live box that the test passes (InfluxDB has auth
   on) before anyone unpauses the rules.

6. Prove the boundary on the live host. The sandboxed dynamic user cannot open the token:

```
sudo systemd-run --wait --pipe -p DynamicUser=yes -p InaccessiblePaths=/etc/siem /usr/bin/test ! -r /etc/siem/doppler-token; echo "exit=$?"
```

   Expected: `exit=0` (the token is not readable by a dynamic user inside the sandbox; the
   broker only has it through `LoadCredential=`). The live verification list further down
   covers what this repository cannot prove.

7. Enable the timer:

```
sudo systemctl enable --now twingate-collect.timer
systemctl list-timers twingate-collect.timer
```

   Check after the next hour: `systemctl status twingate-collect.service` shows
   `status=0/SUCCESS` and `journalctl -u twingate-collect.service` shows only the
   counts line.

Rollback: `sudo systemctl disable --now twingate-collect.timer`, delete the five
unit files from `/etc/systemd/system/`, run `sudo systemctl daemon-reload`, then remove
`/etc/siem/doppler-token` and `/run/twingate-collect` (`sudo rm -r /run/twingate-collect`,
a tmpfs path that also vanishes at reboot). To remove the InfluxDB account, run `DROP USER "twingate_wo"` as the InfluxDB admin and delete
the two names from the secret manager. Points already written are harmless and can
stay.

How a cleanly stopped Connector appears: the Twingate Admin API still lists it with
a state other than `ALIVE`, so the collector writes `twingate_connector_up` value 0
(the series does not go missing) while `twingate_update_check_success` stays 1. The
rule "Twingate Connector not ALIVE" fires after 15 minutes once it is unpaused. A Connector that is deleted in Twingate disappears from the data instead, which is
why the expected inventory (`TWINGATE_EXPECTED_CONNECTORS`) is required, not optional.
The collector fails closed, writing only `twingate_update_check_success value=0i`,
when the setting is unset, empty, `[]`, not a JSON array of valid strings, or has
duplicates, and when any listed name is missing from the API answer. In that last
case it also writes `twingate_connector_up value=0i` for each missing name (with its
`managed_by` tag), so the existing rule "Twingate Connector not ALIVE" fires for it.
A Connector that the API returns but you did not list is not an error: it is counted in
`twingate_unexpected_connector` and still gets its normal metrics. The rule "Twingate
unexpected Connector" (warning, `phone=false`, paused with the others) fires when the metric
is above 0 in EVERY sample of the last 3 hours and there are at least two samples (the rule takes the
minimum over the window). So a Connector that stays unexpected is noticed only after the last
zero-valued sample ages out of the window, which takes up to about 3 hours after it first appears,
even if two runs have already counted it. An unexpected Connector that disappears again before
that (or that any run in the window does not count) is not alerted; the metric still records it.
Update the list when you add or retire a Connector on purpose. The check
also fails on a duplicate Connector name or id, a repeated page cursor, a page that
adds nothing while more pages are promised, an API answer without a valid `pageInfo`,
or a Docker Hub release list that is still paging after the page cap.

Why a broker (issue #222, review rounds 3 to 5): clearing environment variables does not
stop a process that runs as the same user from opening that user's files, so a collector
that shared a user with the token file could read the secret manager's service token. The
design options were (a) a separate broker identity that fetches the secrets and hands each
stage its own credential file, (b) sandboxing the stages while the token stays in the same
user's home, and (c) documenting the residual risk. This runbook uses (a), with the sandbox
of (b) as a second layer. The token is a root-owned file (`/etc/siem/doppler-token`, mode
400) that systemd passes only to `twingate-collect.service` as a credential (`LoadCredential=`).

Round 5 choices and their reasons:

- The broker is a `DynamicUser` (no reusable account). A static `siem-broker` account would let any
  other process that ever ran under that name read the token's credential copy, the fetched secrets
  and the `/proc` environment of the fetch. A dynamic user has no login, no other workload and no
  lingering identity, and `ProtectProc=invisible` with `ProcSubset=pid` hides the broker's processes
  from other services. Trade-off: the broker's files belong to a user that is gone after the run, so
  a root-run step publishes them (next point) instead of leaving them in place.
- One generation per run. The broker writes a directory named by a random run id (128 bits) in its
  own runtime directory (`/run/twingate-broker`, removed by systemd whenever the unit stops, whether
  it succeeded, failed, timed out or was killed). It holds `collector.json` and `writer.json`, each
  repeating the run id, and `manifest.json` (written last) with the run id and the SHA-256 of both
  files. The broker's `ExecStartPost=+` (root, fixed arguments) validates it (exactly one
  generation, no symlink followed for the files inside it, digests and ids agree, the id exactly 32
  lowercase hex characters), copies it to the root-owned
  `/run/twingate-collect/<run id>/` and points the symlink `/run/twingate-collect/current` at it. A run id that already exists there is refused and the existing
  generation is left untouched.
  Only root can write there. Each stage receives the manifest and its own file as credentials and
  refuses to start when the manifest is missing, the file does not match its digest, or the ids
  differ, so a stale file can never be replayed even if a stage is started by hand.
- The check prints the header line `# twingate-run <run id>` first; the writer accepts the check's
  output only with the same id (and strips the line), so a metrics file from an earlier run is
  refused.
- Cleanup does not depend on the last step alone. The broker removes everything unclaimed before it
  starts (`ExecStartPre=+ purge`) and again when it fails (`ExecStopPost=+ purge --if-failed`). The
  writer records the generation it will consume (`claim`) and afterwards removes exactly that one
  (`cleanup`); a late cleanup therefore cannot delete a newer run's generation, and a new publish
  never removes a generation that is claimed. Every change to the destination holds an exclusive
  lock on it (bounded wait, then an error), so two invocations never interleave. A generation is also left behind if the check unit
  cannot be started at all (systemd start limit, for example): it stays root-only in a mode 700
  tmpfs directory until the next run purges it or the host reboots.
- No overlap. `twingate-collect.service` is ordered `After=` the check and the writer, and each of
  those after the one before it, so the hourly timer's next run waits for an unfinished chain (the
  longest chain is 120 + 120 + 60 seconds of start timeouts, far below an hour). The run id checks
  above make an overlap that slips through fail closed instead of mixing runs.
- The check's output goes to a file in the check unit's own runtime directory
  (`/run/twingate-collect-metric/metrics.lp`, owned by that unit's dynamic user, kept after the unit
  ends because systemd's manager hands it to the writer as a credential). It is opened with
  `StandardOutput=truncate:`, not `file:`: `file:` does not truncate, so a short failure result
  would leave the tail of an older, longer result behind. The file holds no secret.

The check and the writer are separate units, each a dynamic user with `InaccessiblePaths=/etc/siem
/run/twingate-collect /run/twingate-broker`, `ProtectHome=yes` and no capabilities. The collector
therefore never holds the InfluxDB login, the writer never holds the Twingate key, and neither can
open the token. If the check fails it still prints its `success=0` lines, and `OnFailure=` starts
the writer anyway. Residual risk: root, or a compromise of the broker unit or of
`siem-run`/the CLI during its run, still reaches the token. Reduce that blast radius by using a
read-only service token scoped to the single config `prd_network`, and rotate it if the host is
suspected. `twingate-collect` (the script) remains for bench runs from a terminal and is not a
boundary: it runs both stages as the calling user.

What this repository cannot prove (only a real systemd host can; the tests check the unit text
and run the helper scripts against temporary directories). Systemd behaviors this design relies on from
its documentation and that nobody has observed here: (1) that `LoadCredential=` copies from a root-owned path under
`/run/twingate-collect/current/` through the symlink; (2) that credentials are read when each
command starts, so `ExecStartPre=+ claim` and the writer's `ExecStart` see the same generation;
(3) that `InaccessiblePaths=` does not stop PID 1 from loading a credential from the listed path;
(4) that the preserved runtime directory of the check unit is handed to the next start of the same
dynamic user with the right owner, and that the writer's credential read of
`/run/twingate-collect-metric/metrics.lp` works after the check unit has ended; (5) that
`ExecStopPost=+` runs after a timeout or kill; (6) that `OnSuccess=`/`OnFailure=` start the next step
in the expected order and that `After=` holds a new broker back while the chain is running; (7) that
`ProcSubset=pid` does not break `siem-run` or the secret manager CLI; (8) systemd version
compatibility of every directive on the target host.

Live verification list (run on the target host with the units installed; every command is
copy-paste, none carries a secret or a real value):

```
# 1. systemd is new enough, and the units parse without unknown directives
systemctl --version | head -n 1
sudo systemd-analyze verify /etc/systemd/system/twingate-collect.service /etc/systemd/system/twingate-collect-metric.service /etc/systemd/system/twingate-collect-write.service

# 2. one full chain: the check unit can create its output (no EACCES) and every step succeeds
sudo systemctl start twingate-collect.service
systemctl show -p Result,ExecMainStatus twingate-collect.service twingate-collect-metric.service twingate-collect-write.service
sudo ls -ld /run/twingate-collect-metric /run/twingate-collect-metric/metrics.lp
sudo head -n 1 /run/twingate-collect-metric/metrics.lp

# 3. cleanup after a normal run: no generation, no claim, no broker directory
sudo ls -A /run/twingate-collect
sudo ls -d /run/twingate-broker

# 4. the broker is a dynamic user and other services cannot see it (expect no process line from the second command)
systemctl show -p DynamicUser twingate-collect.service
sudo systemd-run --wait --pipe -p DynamicUser=yes -p ProtectProc=invisible /usr/bin/ps -eo pid,user,comm

# 5. a failed broker leaves nothing (stop the secret manager token read by making the file unreadable for one run, then restore it)
sudo chmod 000 /etc/siem/doppler-token
sudo systemctl start twingate-collect.service; echo "exit=$?"
sudo chmod 400 /etc/siem/doppler-token
sudo ls -A /run/twingate-collect /run/twingate-broker

# 6. a stale replay is refused: start the writer alone with nothing published
sudo systemctl start twingate-collect-write.service; echo "exit=$?"
journalctl -u twingate-collect-write.service --since '-2min' --no-pager

# 7. a short result replaces a long one: run twice, the metrics file keeps only the second result
sudo systemctl start twingate-collect.service
sudo wc -c /run/twingate-collect-metric/metrics.lp
```

Expected: step 2 shows `Result=success` for all three and the metrics file owned by a dynamic
user (a numeric UID) with mode 600 or 700 on its directory, starting with `# twingate-run `;
step 3 lists nothing; step 4 shows `DynamicUser=yes` and the `ps` output lists only the
`systemd-run` command; step 5 exits non-zero and leaves both directories empty (or absent); step 6
exits non-zero with `twingate-generation` or `twingate-stage` complaining, and the writer never
reaches InfluxDB. If any step differs, stop and report it; do not unpause the rules.

Starting clean: the broker's `ExecStart` runs through `/usr/bin/env -i` with a short list of
names, so unit defaults and caller variables never reach `siem-run`. The stage wrapper
builds the stage's environment from scratch (fixed `PATH` and `LC_ALL`, the credential's
allowlisted names, and for the writer `INFLUX_URL`, `TWINGATE_INFLUX_DB` and the CA
variables) and refuses any credential that holds another name. Commands use absolute
paths, and core dumps are off (`LimitCORE=0`). The failure notice runs as a transient
unprivileged user.

A dead collector does not look green: the check rule "Twingate update check failing
or stale" has `noDataState: Alerting`, reads a 6 hour window and fires on a 0 or on
no point at all. When the Twingate or Docker Hub call fails, the collector writes
`twingate_update_check_success value=0i` (the run still exits non-zero), and the
unit's `OnFailure` leaves a journal notice.
