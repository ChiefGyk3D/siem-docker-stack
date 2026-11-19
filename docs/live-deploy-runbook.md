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
| `scripts/live-deploy/n8n-setup-alert-router.py` | Creates the two n8n credentials and imports the router workflow |
| `scripts/live-deploy/n8n-test-router.py` | Pre-deploy checks against the router (401/403 cases, test alerts, phone test) |
| `scripts/live-deploy/grafana-deploy.py` | Additive Grafana deploy: alert files, two datasources, one compose line |
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

1. Stage the files: copy `docker/grafana/provisioning/alerting/contact-points.yml`,
   `update-alert-rules-unifi.yml`, `update-alert-rules-pfsense.yml` and
   `heartbeat-alert-rule.yml` to `SIEM_STAGE_DIR`.
2. Plan (changes nothing):

```
siem-run python3 -I scripts/live-deploy/grafana-deploy.py --stage
```

Expected: `staged files ok; router path length <n>; compose: insert after line <k>`
(or `compose: already present` on a re-run). It refuses with a plain message if
the router path file looks wrong, a staged file is missing, the contact point
URL is not found, or the `GF_SERVER_ROOT_URL` anchor line is missing or appears
more than once.

3. Apply:

```
siem-run python3 -I scripts/live-deploy/grafana-deploy.py --apply
```

What it does, and only this:

- Writes the alerting folder `grafana/provisioning/alerting/` (the contact
  point gets the private webhook path; the pfSense rules stay paused; the
  heartbeat rule file is copied as is, same mode, and files in the folder
  that are not on this list are left alone).
- Writes one new datasource file with two extra InfluxDB datasources, ids
  `influxdb-pfsense` and `influxdb-unifi` (names `InfluxDB-pfSense-alerts` and
  `InfluxDB-UniFi-alerts`). Existing datasources are not changed, because
  changing a datasource id breaks dashboards that reference it.
- Adds one pass-through line (`- GRAFANA_WEBHOOK_SECRET`) after the
  `GF_SERVER_ROOT_URL` line in the Grafana service of the live compose file,
  after saving a backup `docker-compose.yml.bak-<date>`. A second run finds the
  line and does not add it again.
- Recreates only the Grafana container (`docker compose up -d grafana`). That
  restart is what makes Grafana load a new rule file such as
  `heartbeat-alert-rule.yml`; file provisioning reads the folder at startup.

Check:

- Output ends with `compose up exit code: 0`.
- In Grafana, Alerting shows the rules in the folder `Update Alerts` and the
  contact point `n8n-grafana-router`; the datasources list shows the two new
  ones. The UniFi rule states are Normal, not Error.
- Verify the data the UniFi rules read: `SHOW FIELD KEYS ON unpoller FROM usw`
  lists the boolean field `upgradeable`.

Rollback: restore `docker-compose.yml.bak-<date>` over the compose file, delete
`grafana/provisioning/alerting/` and the datasource file `alerting-influx.yml`,
then `docker compose up -d grafana`.

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

## 6. The manual Grafana notification policy route

Grafana provisions the notification policy as one tree for the whole
organization, so the repository ships it only as
`update-notification-policy.yml.example`; it is not applied by the deploy.
Add the route by hand in Alerting, Notification policies: a child route that
matches `update_alert = true`, with contact point `n8n-grafana-router`, and two
sub-routes: `severity = warning` with repeat interval 4h and
`severity = critical` with repeat interval 1h.

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
| The compose backups `docker-compose.yml.bak-<date>` | Host-local copies of the live file |
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
