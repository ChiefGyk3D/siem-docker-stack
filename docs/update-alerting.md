# Update alerting (pfSense, UniFi and Twingate)

Grafana alerts that keep nagging while a pfSense, UniFi or Twingate Connector update is pending.
Nothing here applies an update or changes a device. The alerts read data that
is already collected, and they clear only when the data shows the update is
gone.

Tracked in issue #53 (epic #52). To rebuild the live setup on an empty box, see [docs/live-deploy-runbook.md](live-deploy-runbook.md).

## Flow

```
UniFi poller -> InfluxDB (unpoller) --\
                                       >-- Grafana alert rules
pfSense Telegraf exec -> InfluxDB ----/        |
 (pfsense_update_pending)                      v
                                  contact point n8n-grafana-router
                                    (webhook, header auth)
                                               |
                                  n8n "Grafana SOAR - Alert Router"
                                       |                 |
                                    Discord         Pushover (optional)
```

Discord delivery is unchanged. Pushover is added next to it and is off until
you turn it on.

## What ships

| File | Purpose |
|------|---------|
| `docker/grafana/provisioning/alerting/update-alert-rules-unifi.yml` | UniFi rules: warning from 24h to 7 days pending, critical after 7 days |
| `docker/grafana/provisioning/alerting/update-alert-rules-pfsense.yml` | pfSense rules and a collector health rule, shipped paused |
| `docker/grafana/provisioning/alerting/contact-points.yml` | Webhook contact point pointing at the n8n router |
| `docker/grafana/provisioning/alerting/update-notification-policy.yml.example` | Repeat intervals: 84h warning (twice a week), 24h critical |
| `n8n/grafana-alert-router.json` | Router with header auth and the added Pushover nodes |
| `docs/heartbeat.md` | The alert path heartbeat (dead-man's switch), its own rule, policy route and settings |
| `scripts/pfsense-update-metric.sh` | Read-only metric source for the firewall (deployed 2026-11-26) |
| `docker/grafana/provisioning/alerting/update-alert-rules-twingate.yml` | Twingate Connector rules and a collector health rule, shipped paused |
| `scripts/twingate-update-metric.py` | Read-only metric source for Twingate Connectors (not deployed) |
| `tests/python/test_update_alerting.py` | Tests for all of the above (Node is required) |

### Rules

- Every rule carries `severity` (warning or critical), `update_alert=true` and
  `alert_group=updates`. The pfSense security rule also carries
  `update_security=true`.
- The two UniFi pending rules use `noDataState: OK` (no data legitimately
  means no pending update) and `execErrState: Alerting`: a failing query must
  alert. These rules once sat in an evaluation error state for about seven
  hours with nothing alerting, which is why the error state is not OK.
- The rule "UniFi poller data stale" (warning, `phone=false`) fires when the
  poller wrote no point to `usw` for 15 minutes (`for: 5m`, no data and
  errors both alert). It is the watchdog for the data the UniFi rules read.
  A heartbeat that proves the whole path (rule, router and delivery) end to
  end is not part of this change; it ships separately, see
  [docs/heartbeat.md](heartbeat.md).
- pfSense rules are security detectors, so `noDataState` and `execErrState`
  are `Alerting`: a silent or broken check raises an alert instead of hiding.
  A separate rule, "pfSense update check failing or stale", fires when
  `pfsense_update_check_success` is 0 or no result has arrived for 36 hours.
- A rule clears only when its query stops returning a pending update (the
  UniFi `upgradeable` flag goes false, or `pfsense_update_pending` returns to
  0). There is no manual override in the rules.
- UniFi escalation is exclusive and has no `for` clock (both rules use
  `for: 0s`), because a `for` clock restarts whenever the data has a gap and
  would silence an unpatched device for a day. Both rules count the hourly
  buckets in the last 7 days that held a pending point, and require that the
  device is pending now. The warning needs 24 to 159 buckets and the critical
  needs 160 or more. The 160 is the same number in both rules, so they cannot
  overlap and cannot leave a gap (Grafana-managed alerting has no inhibit
  rule). The tolerance is about 8 hours of missing data per week (168 buckets
  minus 160), so a short outage does not drop a critical back to a warning.
  pfSense rules keep the separate `for` durations.

### Query errors

Failure mode (found on a live stack): the UniFi rules once sat in an
evaluation error state for about seven hours because every query failed, and
nothing alerted. Grafana keeps two separate settings per rule: `noDataState`
(the query worked and returned nothing) and `execErrState` (the query failed
or timed out). Provisioning accepts `Error`, `Alerting` and `OK` for
`execErrState` (Grafana file-provisioning docs, read 2026-11-19). With
`OK` the failed evaluation reads as healthy, so a broken datasource looks the
same as no pending update.

Every update rule, in both files, sets `execErrState: Alerting`, so a failing
query fires that rule's own alert with its own severity and routing. It is set
explicitly even though Alerting is Grafana's default, so no edit can lean on
a default. A test fails if any update rule has an `OK` or `Error` error state.
The alternative, `Error`, was not used: it leaves the rule to raise a
separate `DatasourceError` alert, which carries no `update_alert` or `phone`
label and so would not use the update routes. Alerting directly instead of the
default separate-alert behavior keeps one rule, one route and one place to look.
The "UniFi poller data stale" rule remains the watchdog for a poller that is
up but not writing.

`noDataState` is unchanged: `OK` on the two UniFi pending rules (no data means
no pending update) and `Alerting` everywhere else.

A pending-rule alert caused by a query error shows the device label as empty,
because no series came back. Check the rule's state history for the error text
before assuming a device is behind on updates.

The datasource address: the live UniFi datasource currently uses the InfluxDB
container's own address instead of its service name, because another container
advertises the same service name on the shared network. Replacing that with a
stable alias is blocked on fixing the collision on the live box and is tracked
in issue #61, not changed in this repository.

### UniFi data

The UniFi poller (unpoller) writes InfluxDB database `unpoller`, one
measurement per device type (`uap`, `usw`, `ugw`, `udm`, `uxg`), with a
boolean field `upgradeable` (spelled with an "e") and the device `name` as a
tag. This was verified on 2026-11-18 against a live unpoller database: the
measurements `uap` and `usw` exist with that field and tag, and devices are
written about every 30 seconds. Other device types (`ugw`, `udm`, `uxg`) are
in the rules for stacks that have them. Re-check it on your stack:

```
docker exec influxdb influx -execute 'SHOW FIELD KEYS ON unpoller FROM usw'
```

The UniFi Network application itself is not reported by the poller, so a
pending Network application update does not raise an alert.

### pfSense data

The pfSense rules ship active (`isPaused: false`). The Telegraf exec input
below was added on the firewall on 2026-11-26 and the script was verified on
the live firewall in the healthy case. The pending-update parser fix is PR
#217 (not yet merged when this was written). Pause a rule (`isPaused: true`)
if the metrics stop arriving.

Metric `pfsense_update_pending`: gauge, `value` 0 or 1, tags `kind`
(`core`, `kernel`, `package`) and `security` (`true`, `false`). Metric
`pfsense_update_check_success`: 1 when both checks ran, 0 when one failed.
On success the script prints all six update series plus the health metric. On
any failure (a missing or failing `pfSense-upgrade -c` or
`pkg-static version -qRl '<'`, or an unexpected package line) it prints only
`pfsense_update_check_success value=0i` and exits non-zero, never zero-valued
update metrics. Telegraf may drop the output of a command that exits
non-zero; that is why the health rule also alerts on missing data. The
`security` tag is a best-effort match on the word "security" in the
`pfSense-upgrade -c` text.

`pfSense-upgrade -c` exits 2 when an update is pending. Real output seen on a
live firewall (2026-11-26) was two lines, `>>> Updating repositories
metadata...done.` and `26.07.2 version of pfSense is available`, with exit 2.
The script reads that as core pending (`core=1`, health 1). `>>> ...done.`
progress lines are ignored. Everything else still fails closed: exit 2 without
a recognized "version of pfSense is available" line, exit codes other than 0
and 2, any other unknown line, error or warning wording, empty output, and
healthy text mixed with update text.

Telegraf exec input for the firewall:

```toml
[[inputs.exec]]
  commands = ["/usr/local/bin/pfsense-update-metric.sh"]
  interval = "6h"
  timeout = "120s"
  data_format = "influx"
```

Copy `scripts/pfsense-update-metric.sh` to that path by hand when you are
ready. The script runs only those two read-only commands.

### Twingate data (not deployed)

The Twingate rules ship paused (`update-alert-rules-twingate.yml`). Enable
them (set `isPaused: false`) once the collector below runs and the metrics
arrive in the InfluxDB database `telegraf` (datasource `influxdb-twingate`).

The Twingate Admin API is GraphQL and has no "update available" field. The
Connector type has `version`, `state`, `lastHeartbeatAt` and `name`, so the
collector compares each Connector version with the newest released version.
`scripts/twingate-update-metric.py` (Python standard library only, read-only)
sends one GraphQL query for the Connectors and one GET to the Docker Hub tags
API for `twingate/connector`. Docker Hub was chosen over the Twingate
Connector changelog page: it returns small, structured JSON with one version
per tag, while the changelog is a 1 MB HTML page that would need scraping and
breaks when the layout changes. A source that returns nothing is a failure.

Metrics (integers, so the field type never changes):

- `twingate_connector_behind`, tags `connector` and `managed_by`: how many
  released versions are newer than the Connector (0 when current).
- `twingate_connector_up`, tags `connector` and `managed_by`: 1 when the
  state is `ALIVE`, otherwise 0.
- `twingate_update_check_success`: 1 when the whole check ran, 0 when it
  failed. On any failure (API error, GraphQL errors, no Connectors returned,
  an unparsable version, a bad management config or an unreachable
  latest-version source) the script prints only
  `twingate_update_check_success value=0i` and exits non-zero. Telegraf may
  drop the output of a command that exits non-zero, so the health rule also
  alerts on missing data.

Credentials come from the environment only, never from an argument or a file
in this repo, and the script never prints them:

| Variable | Meaning |
|----------|---------|
| `TWINGATE_API_KEY` | Admin API key (read-only is enough), from the secret manager (Doppler) |
| `TWINGATE_NETWORK_URL` | `https://<network>.twingate.com`; any other host is refused so the key cannot be sent elsewhere |
| `TWINGATE_CONNECTOR_MANAGED_BY_FILE` | optional path to the management mapping (below) |
| `TWINGATE_CONNECTOR_MANAGED_BY` | optional inline JSON mapping, used only when no file is set |

Telegraf exec input (the values are injected into Telegraf's environment from
the secret manager; nothing is written into the file):

```toml
[[inputs.exec]]
  commands = ["/usr/local/bin/twingate-update-metric.py"]
  interval = "1h"
  timeout = "60s"
  data_format = "influx"
```

Copy `scripts/twingate-update-metric.py` to that path by hand when you are
ready. The rules assume one run per hour.

To act on a "behind" alert, follow
[twingate-connector-update.md](twingate-connector-update.md).

#### How each Connector is managed (`managed_by`)

Connectors are not all updated the same way, and the mix will change. The
collector reads a small JSON object that maps a Connector name to one of
three modes and writes it as the `managed_by` tag:

| Mode | Meaning | Alerting |
|------|---------|----------|
| `docker` | a container updated by hand (default) | pages: warning after 7 days behind, critical after 14, `phone=true` |
| `systemd` | a package or service updated by hand | same as `docker` |
| `operator` | run by the Kubernetes Operator, which updates it by itself | never pages |

A Connector name that the mapping does not list (an unlisted name) is
`docker`, so a new Connector pages until you say otherwise. The mapping
lives outside the repo, in the file named by
`TWINGATE_CONNECTOR_MANAGED_BY_FILE` or in `TWINGATE_CONNECTOR_MANAGED_BY`;
the shape is `{"<connector name>": "operator", "<other name>": "systemd"}`.
A bad mapping (not JSON, a repeated name, an unknown mode, too large) fails
the check closed.

Connectors under the Kubernetes Operator auto-update, so a page for them would
be noise. Their rule, "Twingate Connector (operator) behind over 14 days",
is `severity=warning`, `phone=false`: it reaches Discord and Matrix and not
the phone, and because the weekly digest lists every alert that fired, they
show up there. Behind for 14 days means the Operator itself is stuck. The
manual rules read only `managed_by` other than `operator`, so the two sets
never overlap. The rules "Twingate Connector not ALIVE" and "Twingate update
check failing or stale" apply to every mode.

### Label taxonomy

| Label | What it controls |
|-------|------------------|
| `update_alert` | `true` marks an update-alerting rule: it matches the notification policy route with the 84h and 24h repeats, and its title belongs in `ALLOWED_ALERTNAMES` |
| `severity` | `warning` or `critical`: the repeat interval, and the Pushover priority (1, or 2 for an allowlisted name with an urgent label) |
| `phone` | `true` is the only way an alert reaches Pushover; any other value or no label keeps it off the phone (Discord is unaffected). The exact value per rule is in the table under "Update rule matrix" below; four rules are `phone=false`: the UniFi 24h warning, the pfSense 24h warning, the Twingate operator-managed rule and the UniFi poller-stale watchdog |
| `alert_group` | Grouping and display (`updates` for these rules); no routing effect |
| `update_security` | `true` marks a security release: emergency priority for allowlisted names |

SIEM alerts stay off the phone until they carry `phone=true`; only the update
rules do today. The malformed-alert notice from the router is the one
exception: it is a fault in the alerting pipeline itself, so it pushes at
priority 1 whenever Pushover is enabled.

### Notification policy

Grafana provisions the notification policy as one tree for the whole
organization, so the file ships as `.example` and Grafana ignores it. Merge its
`update_alert` route into your existing tree (Alerting, Notification
policies), or copy it to `update-notification-policy.yml` if you have no
tree yet. Repeat intervals: 84h for warning, 24h for critical (owner decision, issue #53: a fresh critical page daily, not hourly). Owner decision (issue
#199): update alerts for critical infrastructure reach the phone and repeat at
least twice a week until the update is applied, so no repeat interval may be
longer than 84h. This supersedes the earlier P2 and `phone=false` ruling (#152). Refinement (owner, 2026-11-26, "wait 7 days first"): a UniFi pending update does not page the phone until it has been pending 7 days, so auto-patching devices usually finish first. The UniFi 24h warning is `phone=false`; the UniFi 7-day critical rule stays `phone=true`. The pfSense 24h warning is also `phone=false` (P2, owner decision 2026-11-20, #152); the other pfSense rules are `phone=true`. Twingate (owner, 2026-11-26): critical infrastructure pages at least twice a week until updated, so the 7-day warning is `phone=true` (84h repeats), the 14-day critical pages daily, and only the operator-managed rule is `phone=false`.

### Update rule matrix

Every update rule as shipped in `docker/grafana/provisioning/alerting/update-alert-rules-*.yml`. The repeat interval comes from the notification policy by severity (84h for `warning`, 24h for `critical`), not from the rule. `tests/python/test_update_alerting.py` pins the `phone` column.

| Rule uid | Severity | `for` | `phone` | Repeat |
|----------|----------|-------|---------|--------|
| `update-pfsense-pending-24h` | warning | 24h | false | 84h |
| `update-pfsense-pending-7d` | critical | 168h | true | 24h |
| `update-pfsense-security-pending` | critical | 10m | true | 24h |
| `update-pfsense-check-failing` | critical | 10m | true | 24h |
| `update-unifi-pending-24h` | warning | 0s (age in the query) | false | 84h |
| `update-unifi-pending-7d` | critical | 0s (age in the query) | true | 24h |
| `update-unifi-poller-stale` | warning | 5m | false | 84h |
| `update-twingate-pending-7d` | warning | 0s (age in the query) | true | 84h |
| `update-twingate-pending-14d` | critical | 0s (age in the query) | true | 24h |
| `update-twingate-operator-behind` | warning | 0s (age in the query) | false | 84h |
| `update-twingate-check-failing` | critical | 10m | true | 24h |
| `update-twingate-connector-down` | critical | 15m | true | 24h |

## Webhook authentication

The router's `Grafana Webhook` node uses n8n Header Auth, so a call without
the right secret is rejected before the Discord and Pushover branches run.
Without this, anyone who can reach the webhook could post alerts and page the
phone.

1. Generate the secret: `openssl rand -base64 32` (44 characters).
   `scripts/check-env.sh` rejects a value that is empty, only whitespace, a
   placeholder or under 32 characters; do not use a human-chosen value. The
   secret must be unique to this contact point and never reused for any
   other webhook, credential or service. Store it in Doppler, project
   `homelab`, config `prd_network`, as `GRAFANA_WEBHOOK_SECRET` (the owner can
   move it later). Send the value on stdin and the output to `/dev/null`, so
   it is never typed on a command line or echoed:
   `openssl rand -base64 32 | doppler secrets set GRAFANA_WEBHOOK_SECRET --project homelab --config prd_network > /dev/null`.
   Never write it into the repo or `.env`.
2. In n8n, create a credential of type **Header Auth** named
   `grafana-webhook-auth`. Header name `Authorization`, header value
   `Bearer <the same secret>`. The value must be a non-empty secret after
   `Bearer `. Select the credential on the `Grafana Webhook` node after you
   import the workflow (the JSON carries only the credential name).
3. Defense in depth: change the webhook node path from `grafana-alerts` to
   `grafana-alerts-<opaque>`, where `<opaque>` comes from `openssl rand -hex
   16`, and use the same URL in `contact-points.yml`. Keep that value out of
   public places.
4. Run Grafana with the variable in its environment, for example
   `doppler run --project homelab --config prd_network -- docker compose up -d`.
   The compose file requires a
   non-empty `GRAFANA_WEBHOOK_SECRET` and refuses to start without it.
   `contact-points.yml` sends it as `authorization_credentials` with
   `authorization_scheme: Bearer`, written as `$GRAFANA_WEBHOOK_SECRET`, which
   Grafana provisioning replaces from the environment (Grafana documentation,
   "Use configuration files to provision alerting resources", read
   2026-11-17).
5. Rotate by changing the Doppler value and the n8n credential together.

The expiry watch does not use this credential. It posts to its own endpoint,
the `Expiry Watch Webhook` node (its own private path, file `expiry-path`), where the
`Check Expiry Secret` Code node compares the header with the environment
variable `EXPIRY_WATCH_ROUTER_SECRET` of the n8n container and denies with 403
when it is unset, empty or different. The `Grafana Webhook` node and its
credential are unchanged. See
[expiry-watch.md](expiry-watch.md#the-router-credential).

Two checks apply. Compose refuses to start Grafana when the value is unset or
empty. `scripts/check-env.sh` (run it before `docker compose up`) also rejects
whitespace-only, placeholder and short values. It measures the value the way
Compose reads it from `.env`: an unquoted value ends at whitespace followed by
`#` (so `x # long comment` is the one character `x`), matching quotes are
removed, and a duplicate assignment, unmatched quote, backslash or unquoted
`$` is rejected. Only the plain `NAME=value` line form is measured: a line
with an `export` prefix, indentation, whitespace before the equals sign or a
carriage return (a CRLF file; convert it to LF) is rejected, so is an
assignment inside another variable's multi-line quoted value, and a duplicate
counts in any of those forms. The value itself may use only letters, digits
and `+ / = _ . , : @ % ^ -` (what `openssl rand -base64 32` produces), with no
space after the `=`; any shell character (backtick, `$`, `<`, `>`, `;`, `&`,
`|`, parentheses, quotes inside the value) is rejected. A file with a control
byte (NUL, carriage return, escape), or with a multi-line or backslash-escaped
quoted value anywhere, is rejected for this check, because parsers disagree on
where the line is. The check refuses a symlinked `.env`, opens the file once and
validates that one in-memory copy, so every check sees the same bytes. Trailing whitespace after an unquoted or quoted
value is ignored, and a commented-out line is not an assignment. Neither check can see what you typed into n8n: an n8n credential whose value is just `Bearer`
would accept an empty-secret call, so follow step 2 exactly and run the
checklist below.

## Pushover (phone push)

Off by default. All Pushover behavior is set by constants at the top of the
`Build Pushover Payload` Code node, so no environment access is needed in n8n
at all (reading environment values from n8n expressions needs a setting that
widens what workflow authors can read, so this repo avoids it):

| Constant | Default | Meaning |
|----------|---------|---------|
| `PUSHOVER_ENABLED` | `false` | Set to `true` to send to Pushover |
| `PUSHOVER_RETRY` | 300 | Seconds between repeats for priority 2 (minimum 30) |
| `PUSHOVER_EXPIRE` | 10800 | Seconds before repeats stop (maximum 10800) |
| `ALLOWED_DASHBOARD_ORIGIN` | empty | Only an https link on exactly this origin is forwarded; empty drops every link |
| `ALLOWED_ALERTNAMES` | the provisioned update alert titles | Only these names can page at emergency priority or cancel repeats |

Keep `ALLOWED_ALERTNAMES` equal to the rule titles in
`update-alert-rules-*.yml`; a test enforces this.

Priority mapping:

| Alert | Pushover priority |
|-------|-------------------|
| allowlisted name, severity `critical` or `update_security=true` | 2 (emergency, repeats until acknowledged) |
| any other critical or `update_security=true`, or severity `warning` | 1 (high, bypasses quiet hours) |
| resolved | 0 (normal, no repeat) |
| malformed body | 1, generic "malformed alert" message |

Messages are cut to the Pushover limits (title 250, message 1024 characters).

### Pushover credential

The Pushover application token and user key never appear in the Code node,
its output, or the workflow JSON. Both HTTP Request nodes use an n8n
**Custom Auth** credential named `pushover-api` whose JSON supplies them as
body fields:

```
{ "body": { "token": "<application token>", "user": "<user key>" } }
```

Doppler (project `homelab`, config `prd_network`) is the source of truth. The
application token is the Doppler secret `PUSHOVER_API_KEY` and the user key is
`PUSHOVER_USER_KEY`. You copy the two values from Doppler into the n8n
credential by hand; the JSON here carries only the credential name and a
placeholder id. To rotate, change the Doppler values, then paste the new ones
into the n8n credential.

The workflow settings do not save successful executions, manual executions or
execution progress, so alert content is not kept in n8n history. Failed
executions are deliberately not stored either (`saveDataErrorExecution` is
`none`): a failed execution keeps the first node's output, which includes the
request headers, and the `Authorization` header carries the webhook
credential. So failures show only in the n8n log. If an earlier import of
this workflow stored executions, delete those executions and rotate the
webhook credential (the Doppler value and the n8n credential together).

### Delivery and failure reporting

A failed delivery is never silent. The router's webhook uses the response mode
that waits for the run (`responseMode: responseNode` on the webhook node) and
answers through one `Respond to Webhook` node (`respondWith: json`, a static
body `{"status": "delivered"}`, response code 200) at the very end. So the
caller (Grafana) gets its answer only after the channel steps finish, and a
failed run answers with an error status, which Grafana logs and retries.

How the channel steps are wired (n8n node settings used: `onError:
continueRegularOutput` on the Discord steps and the notice nodes, `onError:
continueErrorOutput` on the Pushover steps, a `Stop and Error` node, and an
`If` node):

- Verified live: the Discord node (`n8n-nodes-base.discord` v2, webhook
  authentication, `sendLegacy`) does not use an error output. With its
  credentials removed it ended the run as a success and emitted ONE item on its
  NORMAL output whose json had a single key `error` (a string). So a Discord
  failure is detected from that item, not from an error output. For each of the
  three Discord steps (firing, resolved, malformed notice) the check is: the
  first output item has a non-empty `error` (a string, or an object with a
  `message`). The check is guarded, so a node that did not run counts as not
  failed.
- The Pushover steps still run after a Discord step either way (a Discord
  outage must not silence the phone). Then `Discord Failed?` looks at all three
  Discord nodes. If any failed, `Respond Error` answers first (a Respond to
  Webhook node, HTTP 502, static body `{"status": "delivery failed"}`), and then
  `Fail Run` (a `Stop and Error` node) fails the run with a message of the node
  name and the trimmed error text only (120 characters, any `Bearer` value
  removed, never the alert), so the error workflow fires. Otherwise `Respond OK`
  answers 200 with `{"status": "delivered"}`.
- Why `Respond Error` exists. Verified live: with `responseNode` mode, a run
  that stops with an error before any Respond to Webhook node ran answers HTTP
  200 with an empty body, so `Stop and Error` alone would make Grafana treat a
  failed delivery as delivered. The first Respond node reached decides the
  answer, so `Respond Error` runs before `Fail Run`, and the run still ends in
  error. `Fail Run` reads the Discord nodes by reference, not from the item
  that passes through the Respond node.
- A failed Pushover step (send or cancel) never blocks Discord and never fails
  the run. Its error output goes to a short Discord notice: "phone delivery
  failed: Pushover Notify <short error>". The notice has no payload and no
  headers; the error text is trimmed to 120 characters and any `Bearer` value
  is removed. A failed notice does not fail the run either.
- The payload builder reads the alert by node reference (`$('Normalize
  Alert')`), because the Discord step's own output replaces the item.

The error workflow `n8n/alert-router-error-handler.json` starts at an Error
Trigger. For any failed run of the router it sends one message with the
workflow name, the failed node name, the error message (trimmed to 300
characters) and the execution id, through a channel independent of Discord:
Pushover at priority 1 (credential `pushover-api`). A second channel, Discord,
sits behind the constant `NOTIFY_DISCORD` (off by default, since Discord may be
the failing channel); `NOTIFY_PUSHOVER` (on by default) controls the first. It
reads only the `execution` and `workflow` parts of the error data and never
the alert, its labels or annotations, or any header. The router setting
`errorWorkflow` ships as the placeholder `ERROR_WORKFLOW_ID`; the import script
fills it with the handler's real id (see `docs/live-deploy-runbook.md`) and
drops it when no id is given.

Failed runs stay unsaved by design (`saveDataErrorExecution: none`, also on the
handler): a stored failed run keeps the first node's output, which includes the
request headers and so the webhook credential. The traces of a failure are the
n8n container log and the handler's notice.

Unverified against a live n8n (the graph tests model these, they are not n8n):
the 502 itself (that `Respond Error` is the answer Grafana receives, and that
the run still ends in error after it); that the error workflow fires for a run
stopped by `Stop and Error` in a webhook-triggered production run;
the `lastNodeExecuted`, `error.message` and `id` fields the handler reads; the
`continueErrorOutput` setting on the Pushover HTTP Request nodes and what their
error item holds (the notices read `$json.error.message`); and `isExecuted` on
a node reference in the expressions. Verified live: the Discord failure shape
(an item with an `error` key on the normal output), the run ending in `error`
at `Fail Run`, and that `Stop and Error` alone answers 200 with an empty body.

### Enable it

1. Create a Pushover application and note its token and your user key.
2. Store them in Doppler (project `homelab`, config `prd_network`) as
   `PUSHOVER_API_KEY` and `PUSHOVER_USER_KEY`; they already exist there.
3. Create the `pushover-api` Custom Auth credential in n8n as above.
4. Import `n8n/grafana-alert-router.json`, select the `grafana-webhook-auth`
   and `pushover-api` credentials on the nodes, set `PUSHOVER_ENABLED` to
   `true` (and `ALLOWED_DASHBOARD_ORIGIN` if you want links), and activate it.

### Tags and cancelling repeats

An emergency message carries a tag: `upd-` plus the first 32 hex characters
of SHA-256 over `alertname|fingerprint`, computed in pure JavaScript (n8n's
Code sandbox does not allow built-in modules by default). When the alert
resolves, the router sends a normal message and asks Pushover to cancel
repeats for that tag. The cancel call runs only for tags with the `upd-`
prefix and only for names in `ALLOWED_ALERTNAMES`.

Acknowledging in the Pushover app stops that one message only. While the
update is still pending, Grafana re-alerts at the policy repeat interval (84h
warning, 24h critical) and a new emergency message starts. The alert itself
ends only when the update is applied.

A critical update pages at emergency priority (Pushover priority 2), which
itself repeats about every 5 minutes (`PUSHOVER_RETRY`, 300 seconds) for up to
3 hours (`PUSHOVER_EXPIRE`, 10800 seconds) until you acknowledge it. Priority 1
and 2 both bypass Pushover quiet hours. So the 24h policy repeat starts a fresh
page each day, and each page keeps ringing until acknowledged or the 3 hours end.

### Residual risk (accepted)

This is an accepted residual risk, and the owner's call, not something the
workflow fixes. The webhook secret is a shared secret. Anyone who holds it,
and can reach the webhook, can send an alert with any allowlisted title, pick
emergency priority, and cancel the repeats for a tag they can compute from a
title and fingerprint. The allowlist (`ALLOWED_ALERTNAMES`) only limits
which names get emergency priority; it does not prove which Grafana rule
sent the call, and it is not provenance. The cancel call and the emergency
page are only reachable by an authenticated Grafana caller (one that
presents the secret), because the webhook rejects everything else. This repo
does not keep a store of previously paged fingerprints.

Limit the exposure:

- The secret must be unique to this contact point and never reused for other
  webhooks.
- Make the n8n webhook reachable only from the Grafana host. Examples:
  - Docker: put n8n and Grafana on a Docker network of their own, and do not
    publish the n8n port to the host (no `ports:` entry for the webhook).
  - Reverse proxy: allow only the Grafana address and deny the rest, for
    example in nginx:
    `location /webhook/grafana-alerts { allow 192.0.2.10; deny all; proxy_pass http://n8n:5678; }`
    (192.0.2.10 is a documentation address; use your Grafana host's address).
- Rotate the secret if anyone who held it leaves or a copy may have leaked.

### Request normalization

The `Normalize Alert` node rebuilds the first alert into a new body before
the switch. Scalar fields (labels, annotations, `valueString`, timestamps,
links, fingerprint) are coerced to length-capped strings, objects and arrays
in scalar positions become empty strings, and a timestamp that does not parse
is dropped. The Discord and Pushover expressions read only those rebuilt
fields, and a test scans every expression to keep it that way. A body that
cannot be rebuilt (bad status, no alerts) goes to the malformed notices.

## Known limitations

- The existing Discord embeds in the router forward alert text and links
  without length or Markdown limits; that pre-existing behavior is left for a
  separate hardening change.
- The Custom Auth body merge, the `URL` global in the n8n Code node and
  Telegraf's handling of a non-zero exit are expected behavior, not checked
  against a live system.

## Deploying to a stack that already exists

What a deploy onto a running stack needed (placeholders, no real values):

- **Datasource ids.** The rules refer to the datasource ids `influxdb-pfsense`
  and `influxdb-unifi`. An older stack may not have given its InfluxDB
  datasources those fixed ids. Do not change the ids of existing datasources:
  dashboards that reference them would break. Add two extra datasources with
  the ids the rules expect, same databases (`pfsense` and `unpoller`), a
  distinct name such as `InfluxDB-UniFi-alerts`, in their own provisioning
  file next to the existing one.
- **Contact point URL.** In `contact-points.yml`, use the private webhook path
  of the authenticated n8n router (the opaque path from the webhook
  authentication section), for example `http://<n8n-host>/webhook/<private-path>`,
  not the short default.
- **n8n import.** The workflow JSON needs an `id`, and, to keep the short
  webhook URL, a `webhookId` on the webhook node. With no `webhookId`, n8n
  serves the webhook under `/webhook/<workflowId>/<node name>/<path>`.
- **Publishing through the CLI** needs an n8n restart before the webhook is
  registered.
- **macvlan.** A container on a macvlan network is not reachable from its own
  host. Test the webhook through the Docker bridge address of the container
  instead (placeholder: `http://<bridge-address>/webhook/<private-path>`).

## Manual pre-deploy checklist

No unit test can prove these. Do them against a live n8n and Grafana before
you rely on the alerts.

1. n8n rejects, with 401 or 403 and no downstream node running (check the
   execution list and Discord), a POST to the webhook with: no
   `Authorization` header; an empty one; `Bearer` with no secret; the wrong
   scheme (`Basic <secret>`); a different-case scheme; the wrong secret; and
   two `Authorization` headers.
2. n8n accepts a POST with the exact `Bearer <secret>` and one test message
   reaches Discord.
3. In Grafana, the contact point test sends the secret: confirm that n8n
   accepts it, which proves `$GRAFANA_WEBHOOK_SECRET` was substituted.
4. With `PUSHOVER_ENABLED` still `false`, confirm no Pushover call is made.
   Then enable it and confirm a priority 1 test message arrives, with the
   token and user key added by the `pushover-api` credential.
5. Confirm an emergency test (a provisioned alert name, critical) repeats and
   stops after acknowledging, and that a resolved message cancels repeats.
6. Confirm no successful execution is listed in n8n after these tests.
7. Check the unpoller field names with the `SHOW FIELD KEYS` command above.

## Tests

```
python3 -m pytest tests/python/test_update_alerting.py tests/python/test_twingate_update_metric.py -q
```

The tests need Node on the path (the Code node source is executed for
real). The script tests use fake `pfSense-upgrade` and `pkg-static` programs
that record their arguments and reject any other argument, so they never
touch a firewall.
