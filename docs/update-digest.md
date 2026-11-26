# Weekly update digest

An n8n workflow (`n8n/weekly-update-digest.json`) that posts one message every Monday at 07:00
America/New_York saying what was updated in the last week and what is still pending. Issue #202.

The UniFi, pfSense and Twingate collectors are real: they read InfluxDB through Grafana's data
source query API (see "Collectors"). The OS packages collector is still a stub that reports
`not-deployed` until the host collectors exist (issue #219). A source that is not deployed or cannot
be read is listed in the "Not checked" section instead of being shown as "0 updates".

## What it does

```
Weekly Schedule -> Window -> UniFi Query -> UniFi Collector -> OS Packages Collector
  -> Twingate Query -> Twingate Collector -> pfSense Query -> pfSense Collector
  -> Build Digest -> Discord Digest -> Matrix Digest -> Record Window
```

- Delivery is Discord and Matrix only. There is no phone path: no Pushover node, no Pushover
  credential, and no webhook trigger. The only trigger is the Schedule Trigger. A test enforces all
  of this on the workflow JSON.
- It always sends, including a quiet week ("0 applied, 0 still pending, 0 sources not checked").
  No branch can skip the send, so a missing digest means the workflow itself is broken.
- Each source reports exactly one of `ok`, `failed`, `not-deployed`. A source that failed or is not
  deployed is listed under "Not checked" and is never shown as "0 updates". Anything a collector
  returns that is not one of those three (an error item, a typo, no result) counts as `failed`.
- Message: title with the window in Eastern, a decision sentence ("N applied, M still pending, K
  sources not checked"), sections Applied, Still pending and Not checked, and a footer.
- Limits: long lists are cut with "+N more" to stay under the Discord limits (description 4096,
  6000 for the whole embed). The Not checked section and footer are never the part that is cut.
- Sanitizing: every device, package, version and reason string is coerced to a string, stripped of
  control characters, capped in length and markdown-escaped, and every `@` is broken so nothing can
  mention anyone. The built payload also carries `allowed_mentions` with an empty `parse` list; the
  n8n Discord node does not expose that field, so the escaping is what protects the Discord post.
  The Matrix message is a plain `m.notice` and pings nobody.

## Window

The window runs from the end of the last digest to now. The last end is kept in workflow static
data (`lastDigestEnd`), capped at 14 days back. With no usable last end the window is 7 days.
`Record Window` advances it only after delivery. If both Discord and Matrix fail, the run errors
(the workflow's error workflow fires) and the window is not advanced, so the next digest covers the
gap, up to the 14 day cap. If one channel fails the window advances and the run output says which.

Workflow static data persists only for an active workflow run by its schedule, not for manual test
executions.

## Setup

1. Import `n8n/weekly-update-digest.json` into n8n.
2. Discord: attach the existing `Discord Webhook Alerts` credential (Discord webhook type) to the
   `Discord Digest` node, the same credential the alert router uses.
3. Matrix credential: create an n8n Custom Auth credential named `matrix-bot-auth` and attach it to
   `Matrix Digest`. Its JSON sets the header `Authorization` to `Bearer <bot access token>`. The
   token lives only in the n8n credential store (fed from the secret manager); it is never in the
   workflow JSON or this repo.
4. Grafana Viewer credential (UniFi, pfSense and Twingate collectors). In Grafana create a service
   account with the `Viewer` role (Administration, Users and access, Service accounts) and a token
   for it. Create an n8n Custom Auth credential named `grafana-viewer-auth` and attach it to the
   three `... Query` nodes. Its JSON sets the header `Authorization` to `Bearer <viewer token>`.
   With the live-deploy tooling the token comes from the secret manager through `siem-run` as
   `GRAFANA_VIEWER_TOKEN` and the credential is created with
   `n8n-setup-alert-router.py --credentials --with-grafana-viewer` (token over stdin, never on argv,
   never printed). The token lives only in the n8n credential store and is never in the workflow
   JSON or this repo. The Viewer role reads data sources and dashboards and cannot write. InfluxDB
   has no read-only user for n8n, so n8n never holds InfluxDB credentials: Grafana does the read.
5. Environment: set these on the n8n container, values from your own deployment (never committed):

   | Name | Meaning | Placeholder |
   | --- | --- | --- |
   | `GRAFANA_BASE_URL` | Grafana base URL, no trailing slash | `https://grafana.example.org` |
   | `MATRIX_HOMESERVER` | homeserver base URL, no trailing slash | `https://matrix.example.org` |
   | `MATRIX_ROOM_ID` | target room id | `!roomid:example.org` |

   n8n must allow `$env` in nodes (`N8N_BLOCK_ENV_ACCESS_IN_NODE` not set to `true`).
6. Set the error workflow in the workflow settings (the JSON carries the placeholder
   `ERROR_WORKFLOW_ID`), then activate the workflow. It is imported inactive.

The Matrix send is `PUT {homeserver}/_matrix/client/v3/rooms/{room}/send/m.room.message/{txnId}`
with `msgtype` `m.notice`. The transaction id is derived from the window end, so a retry of the
same run does not post twice.

## Collectors

Each real collector is an HTTP Request node (`POST {GRAFANA_BASE_URL}/api/ds/query`, 7 days back,
InfluxQL, Custom Auth credential `grafana-viewer-auth`) followed by a Code node that maps the answer
to the contract. The request has a 15 second timeout, follows no redirects (so the bearer token can
never be sent to another host) and returns the status code instead of throwing. The mapping refuses
anything unexpected: a response size cap (256 KB of JSON), at most 200 series and 2000 points per
series, queries that use `SLIMIT`, and a status of `failed` for a request error, any HTTP status
other than 200 (including a redirect), a non-JSON body, a per-query error, a missing query or a
malformed frame. The reason names only the HTTP status, never text copied from Grafana. The n8n
HTTP node downloads the whole answer before the size check, so the real bound on download size is
the `SLIMIT` in each query.

| Source | Data source | Pending (current state) | Applied (state change in the window) | `ok` only when | `not-deployed` when |
| --- | --- | --- | --- | --- | --- |
| UniFi | `influxdb-unifi`, measurements `uap`, `usw`, `ugw`, `udm`, `uxg` | devices whose newest `upgradeable` is true | device now false and true at some point in 7 days | a point newer than 2 hours exists (devices with an older newest point are ignored) | no series at all |
| pfSense | `influxdb-pfsense`, `pfsense_update_pending` | kinds (core, kernel, package; security marked) whose newest value is 1 | newest 0 and 1 at some point in 7 days | `pfsense_update_check_success` newest point is 1 and under 13 hours old | no pending and no check series |
| Twingate | `influxdb-twingate`, `twingate_connector_behind` | connectors whose newest behind count is above 0 | newest 0 and above 0 at some point in 7 days | `twingate_update_check_success` newest point is 1 and under 3 hours old | no behind and no check series |
| OS packages | none yet | none | none | never: stub | always (issue #219, host collectors) |

Applied items are state changes the data proves (an upgrade or update stopped being pending), not
version numbers: none of these sources stores a version history yet, so `from` and `to` read
"update pending" and "up to date" (Twingate: "N behind" and "current"). Nothing is invented: where
no such change is in the data, applied stays empty. A stale source is `failed`, a missing check
series next to existing data is `failed` (currency cannot be proven), and `ok` is never returned
with empty lists because of an error or an empty answer. Twingate is not deployed yet, so it
reports `not-deployed` until its metrics arrive.

## Writing a collector

Replace the stub `Code` node body. Return one item:
`{ status, reason, applied: [{name, from, to}], pending: [{name, version}] }` with `status` one of
`ok`, `failed`, `not-deployed`. When the source cannot be read, return `failed` with a reason; never
return empty lists with `ok`. The node has `onError: continueRegularOutput`, so a crashed collector
is also treated as `failed`.

## Failure behavior

| Situation | Result |
| --- | --- |
| Source stub, empty series or not installed | listed under Not checked as "not deployed yet" |
| Source errors, stale data, redirect, oversized or junk answer | listed under Not checked as "check failed", counted in K |
| Grafana down or token revoked | UniFi, pfSense and Twingate all listed as "check failed" |
| Quiet week | digest still sent, "0 applied" |
| Discord down | Matrix still sent, window advances |
| Matrix down | Discord still sent, window advances |
| Both down | run errors, window kept, next digest covers the gap (max 14 days) |
| Workflow not running | no digest: silence means broken |

Tests: `tests/python/test_update_digest.py` runs the Code node source under Node and carries
mutants for each guarantee above.
