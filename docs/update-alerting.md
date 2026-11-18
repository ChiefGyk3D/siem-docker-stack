# Update alerting (pfSense and UniFi)

Grafana alerts that keep nagging while a pfSense or UniFi update is pending.
Nothing here applies an update or changes a device. The alerts read data that
is already collected, and they clear only when the data shows the update is
gone.

Tracked in issue #53 (epic #52).

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
| `docker/grafana/provisioning/alerting/update-notification-policy.yml.example` | Repeat intervals: 4h warning, 1h critical |
| `n8n/grafana-alert-router.json` | Router with header auth and the added Pushover nodes |
| `scripts/pfsense-update-metric.sh` | Read-only metric source for the firewall (not deployed) |
| `tests/python/test_update_alerting.py` | Tests for all of the above (Node is required) |

### Rules

- Every rule carries `severity` (warning or critical), `update_alert=true` and
  `alert_group=updates`. The pfSense security rule also carries
  `update_security=true`.
- UniFi rules use `noDataState: OK`: missing poller data never pages.
- pfSense rules are security detectors, so `noDataState` and `execErrState`
  are `Alerting`: a silent or broken check raises an alert instead of hiding.
  A separate rule, "pfSense update check failing or stale", fires when
  `pfsense_update_check_success` is 0 or no result has arrived for 36 hours.
- A rule clears only when its query stops returning a pending update (the
  UniFi `upgradable` flag goes false, or `pfsense_update_pending` returns to
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

### UniFi data

The UniFi poller (unpoller) writes InfluxDB database `unpoller`, one
measurement per device type (`uap`, `usw`, `ugw`, `udm`, `uxg`), with a
boolean field `upgradable` and the device `name` as a tag. This schema is
taken from the unpoller documentation and has not been checked against a live
database. Check it before relying on the rules:

```
docker exec influxdb influx -execute 'SHOW FIELD KEYS ON unpoller FROM usw'
```

The UniFi Network application itself is not reported by the poller, so a
pending Network application update does not raise an alert.

### pfSense data (not deployed)

The pfSense rules ship paused. Enable them (set `isPaused: false`) once the
Telegraf input below is deployed and the metrics are arriving.

Metric `pfsense_update_pending`: gauge, `value` 0 or 1, tags `kind`
(`core`, `kernel`, `package`) and `security` (`true`, `false`). Metric
`pfsense_update_check_success`: 1 when both checks ran, 0 when one failed.
On success the script prints all six update series plus the health metric. On
any failure (a missing or failing `pfSense-upgrade -c` or
`pkg-static version -qRl '<'`, or an unexpected package name) it prints only
`pfsense_update_check_success value=0i` and exits non-zero, never zero-valued
update metrics. Telegraf may drop the output of a command that exits
non-zero; that is why the health rule also alerts on missing data. The
`security` tag is a best-effort match on the word "security" in the
`pfSense-upgrade -c` text.

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

### Notification policy

Grafana provisions the notification policy as one tree for the whole
organization, so the file ships as `.example` and Grafana ignores it. Merge its
`update_alert` route into your existing tree (Alerting, Notification
policies), or copy it to `update-notification-policy.yml` if you have no
tree yet. Repeat intervals: 4h for warning, 1h for critical.

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

Two checks apply. Compose refuses to start Grafana when the value is unset or
empty. `scripts/check-env.sh` (run it before `docker compose up`) also rejects
whitespace-only, placeholder and short values. It measures the value the way
Compose reads it from `.env`: an unquoted value ends at whitespace followed by
`#` (so `x # long comment` is the one character `x`), matching quotes are
removed, and a duplicate assignment, unmatched quote, backslash or unquoted
`$` is rejected. Neither check can see what you typed into n8n: an n8n credential whose value is just `Bearer`
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
update is still pending, Grafana re-alerts at the policy repeat interval (4h
warning, 1h critical) and a new emergency message starts. The alert itself
ends only when the update is applied.

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
python3 -m pytest tests/python/test_update_alerting.py -q
```

The tests need Node on the path (the Code node source is executed for
real). The script tests use fake `pfSense-upgrade` and `pkg-static` programs
that record their arguments and reject any other argument, so they never
touch a firewall.
