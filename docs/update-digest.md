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
data (`lastDigestEnd`), capped at 7 days back. With no usable last end the window is 7 days. The
cap equals the lookback of every collector query (7 days), so the title never claims more than the
data covers; a test compares the two. A gap longer than 7 days is reported as 7 days.
`Record Window` advances it only after delivery. If both Discord and Matrix fail, the run errors
(the workflow's error workflow fires) and the window is not advanced, so the next digest covers the
gap, up to the 7 day cap. If one channel fails the window advances and the run output says which.

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
   JSON or this repo. The Viewer role cannot write, but it is not narrow: a Viewer token can query
   every data source through the query API (Grafana documents the fixed role `fixed:datasources:reader`
   as `datasources:query` and `datasources:read`, "Read and query data sources"; that the Viewer basic
   role includes it, and so reaches every data source unless data source permissions limit it, is
   inferred, not verified). So the token is as sensitive as read access to all your metrics: keep it
   only in the n8n credential store, rotate it, and restrict the credential as described below.
   InfluxDB has no read-only user for n8n, so n8n never holds InfluxDB credentials: Grafana does the
   read.
   Restrict where the credential can be sent: in the n8n credential editor set **Allowed HTTP Request
   Domains** to specific domains and enter only the host of `GRAFANA_BASE_URL`. Verified on the n8n
   docs page "Create and edit credentials" (read 2026-11-26): the field exists on many credentials,
   limits the HTTP Request node to the listed domains, and has the options All, Specific Domains and
   None. Not verified: that the field is shown for the Custom Auth type (n8n's `HttpCustomAuth`
   credential is a generic auth type, which suggests it is) and the exact keys and values an
   `import:credentials` file would need to preset it, so this tooling does not set it and you set it
   in the editor after the import.

   **This is a required step, not an optional hardening.** Until it is done the credential is
   unrestricted: the import cannot lock it to a host, so any valid `https` value of
   `GRAFANA_BASE_URL` receives the Viewer token with the request. The setup script prints this
   reminder after a successful import (no secret in it) but cannot verify the setting, because
   reading it back is not something the n8n command line is documented to do. After the editor step
   run the post-import check in the live deploy runbook ("Grafana Viewer credential: post-import
   check"). In addition the workflow only accepts an `https` base URL (see the environment table),
   and the query nodes follow no redirects; neither limits which `https` host gets the token.
5. Environment: set these on the n8n container, values from your own deployment (never committed):

   | Name | Meaning | Placeholder |
   | --- | --- | --- |
   | `GRAFANA_BASE_URL` | Grafana base URL, no trailing slash | `https://grafana.example.org` |
   | `MATRIX_HOMESERVER` | homeserver base URL, no trailing slash | `https://matrix.example.org` |
   | `MATRIX_ROOM_ID` | target room id | `!roomid:example.org` |

   `GRAFANA_BASE_URL` must be `https`; plain `http` is accepted only for the loopback hosts
   `localhost`, `127.0.0.1` and `[::1]`. Anything else (another scheme, credentials in the URL, a
   query string, a look-alike host) turns the request URL into a value that is not a URL, so no
   token is sent and the three collectors report `failed`.

   n8n must allow `$env` in expressions. Set `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` explicitly.
   Verified (read 2026-11-26): the n8n v2.0 breaking changes page says the default became `true`
   in n8n 2.0, while the environment variable reference for security still lists `false` as the
   default and describes the variable as covering "expressions and the Code node". The two pages
   disagree, so do not rely on the default. Whether the block applies to expressions in an HTTP
   Request node (as used here) or only to the Code node is not verified; the explicit `false`
   works either way. The collectors and the Window node do not read `$env`; only the three query
   nodes and the Matrix node do.
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
anything unexpected: a response size cap (256 KB of JSON), at most 200 series (pfSense: 50) and 2000
points per series, queries that use `SLIMIT` set one above that cap (201 and 51), so a truncated
answer arrives with one series too many and reads as "too many series" instead of passing as ok,
and a status of `failed` for a request error, any HTTP status
other than 200 (including a redirect), a non-JSON body, an `error` or `message` at the top of the
body, a result list that is not exactly the queries sent (a missing or an extra query), a per-query
error (`error`, `errorSource` or a status other than exactly 200), a query whose `frames` is absent
or not a list, or a malformed frame. A source is `not-deployed` only when every query succeeded and
every one is empty; history with no current data is `failed` (history proves it was deployed). The
reason names only the HTTP status, never text copied from Grafana.

Series identity is strict. UniFi needs a `name` label, Twingate a `connector` label and pfSense a
`kind` label plus a `security` label that is exactly `true` or `false`; each must be a non-empty
string of at most 120 characters. A missing or malformed identity fails the source (nothing is
shown as `(invalid)`), and so does a second frame with the same identity in one query (split
frames, or two kinds that print the same name), so a series can never be both applied and pending.
Each source's check query returns exactly one series.

Identities are ASCII only and nothing is normalized. The raw name must match a strict allowlist: ASCII
letters `a-z` and `A-Z`, ASCII digits, space and `. _ ( ) -`; it must start with a letter or digit, have
no leading or trailing space and be at most 120 characters. Every other character fails the source with
a fixed error message that never echoes the name: every non-ASCII letter (accented Latin, Cyrillic,
Greek, Han and so on), every compatibility character (full-width or circled letters, ligatures,
superscript digits), every combining or enclosing mark, every invisible character and every symbol.
There is no slash, colon, hash, plus or at sign, so a name cannot read as a URL scheme, a Matrix room
alias or a mention. A bare host name such as `ap-1.example.com` is still accepted and a chat client may
turn it into a plain link; it can carry no scheme or path. To fix a rejected name, rename the device (or
connector) to ASCII; the digest does not transliterate or fold anything. The duplicate check and the
join of current and history data use the exact raw name and are case sensitive, so a compatibility
spelling can never join a different plain name.

Accepted residual: ASCII has same-script look-alikes, for example a lowercase `l` and a capital `I`, or
`0` and `O`, which can be hard to tell apart in some fonts. Two such names are two distinct
identities; the digest does not compare confusable skeletons. Rejecting every non-ASCII character
removes the mark, script-mixing and invisible-character problems, but this one remains, so the digest
does not claim that two different identities can never look alike.

Frame-level errors fail the source, wherever Grafana puts them: an `error`, `errorSource`, `message`,
`errors` or `notices` key on the result, the frame, its schema or its data fails the source (the only
accepted notices are the ones inside `schema.meta`, checked below). A frame whose schema meta carries a notice with any severity other
than `info` or `warning` (an `error` notice is how Grafana marks a partial result), a notice without a
severity, malformed notices or an error field on the frame make the source `failed`; the reason never
copies the notice text.

**Download size: a limit that is only partly closed.** The n8n HTTP Request node downloads and
parses the whole answer before the Code node can look at it, and the node has no option to cap the
response size (checked on the n8n HTTP Request node docs page, its Options list, read 2026-11-26:
timeout, redirects, proxy, pagination, batching and response format; the "Truncate Response" option
on that page belongs to the AI tool variant for HTML extraction, not to this node). So the size
check above runs after the download. What bounds a well-behaved Grafana is the query design: every
series query is one aggregate (`last`, `max` or `count`) with no time grouping, so each series
returns one point, and `SLIMIT` caps the number of series. That does not bound a compromised or
fake Grafana, which can ignore both and send a very large answer: n8n would use memory until it
fails, and the 15 second timeout limits duration, not size. The real mitigations are outside the
workflow: reach Grafana only over a trusted network path, restrict the credential to the Grafana
host (above, so the token never goes elsewhere), and give the n8n container a memory limit so an
oversized answer restarts n8n instead of the host. A byte limit at a reverse proxy in front of
Grafana would close it, and is not part of this change. See Accepted residuals below.

## Accepted residuals

Two weaknesses cannot be closed inside the workflow. The owner must accept both before the workflow
is activated. Nothing here is a fix; each item states what stays open.

1. **No response size limit before n8n reads the answer** (availability). The HTTP Request node has no
   response size limit, so a compromised or fake Grafana can send a very large answer and exhaust the
   n8n container's memory before the size check in the Code node runs. Consequence: n8n stops or
   restarts, and the digest (and any other workflow in that n8n) is unavailable until it is back; the
   data is not corrupted. Mitigations: reach Grafana only over a trusted network path; set a memory
   limit on the n8n container so the failure stays inside it; put a reverse proxy in front of Grafana
   that limits the response size. None is enforced by this change.
2. **The credential's host lock is not enforced or verifiable by the import** (confidentiality). The
   Allowed HTTP Request Domains setting of `grafana-viewer-auth` cannot be set from an import file and
   cannot be read back by the setup script. Consequence: until the lock is set by hand, the Grafana
   Viewer token is sent to whatever `https` host `GRAFANA_BASE_URL` names, so a later change of that
   value would send the token to the new host. The token is read-only (Viewer role). Mitigations: the
   editor step and the post-import check in docs/live-deploy-runbook.md; keep `GRAFANA_BASE_URL`
   under change control. The setup script cannot prove the lock, so after a successful viewer import
   it exits with code 40 ("imported, domain lock not verified"), never 0.

Also open: the credential file used during import is in memory (`/dev/shm`) when the container has a
memory-backed mount there, otherwise in `/tmp` (the script prints a warning). A SIGKILL or crash
while the import runs skips the cleanup trap: on `/dev/shm` the file is gone with the container's
next stop, on `/tmp` it stays in the container's writable layer until the container is recreated.
The directory is mode 700 and the file mode 600 either way.

Not found: a supported way to verify or enforce either item. The n8n docs pages for credentials, the
environment variables and the public API could not be read in this environment (2026-11-26), so
whether a setting or variable restricts the HTTP node's target hosts, or whether the public API
exposes the allowed-domains field of a credential, is unverified. If either exists, it would replace
the manual step and should be adopted.

The value of each series must be a boolean or a finite number: a null,
NaN, string or object in the newest point fails the source (a series that is already stale is only
listed). The value field of a frame is the only non-time field, or the only one named `value`,
`last`, `max` or `count`; two candidates fail as malformed. A frame needs exactly one time field.

| Source | Data source | Pending (current state) | Applied (state change in the window) | `ok` only when | `not-deployed` when |
| --- | --- | --- | --- | --- | --- |
| UniFi | `influxdb-unifi`, measurements `uap`, `usw`, `ugw`, `udm`, `uxg` | devices whose newest `upgradeable` is true or a positive number | device now false and true at some point in 7 days | at least one device has a point newer than 2 hours (older devices are listed as not checked (stale), see below) | no current and no history series (every query empty) |
| pfSense | `influxdb-pfsense`, `pfsense_update_pending` | kinds (core, kernel, package; security marked) whose newest value is true or a positive number | newest 0 and 1 at some point in 7 days | `pfsense_update_check_success` newest point is 1 (or true) and under 13 hours old, and at least one kind series is current | no pending, no history and no check series (every query empty) |
| Twingate | `influxdb-twingate`, `twingate_connector_behind` | connectors whose newest behind count is above 0 | newest 0 and above 0 at some point in 7 days | `twingate_update_check_success` newest point is 1 (or true) and under 3 hours old, and at least one connector series is current | no behind, no history and no check series (every query empty) |
| OS packages | none yet | none | none | never: stub | always (issue #219, host collectors) |

A series that is not current (its newest point is older than the source's freshness limit, in
the future by more than 5 minutes, or it has no points) is never dropped. The source stays `ok` when
the check proves current data for the others, and every skipped series is returned in a `stale`
list with its name and the age of its newest point. The digest prints each one under "Not checked" as
`Source: name (not checked, stale: last data 5 h ago)` (age in minutes, hours or days; "timestamp in
the future" or "no usable timestamp" otherwise), counts them in the decision sentence ("2 stale
series not checked") and turns the embed orange. The list is cut with "+N more" after about 1200
characters; the count stays exact. This is the "not checked (stale)" list. When every series of a
source is stale the source is `failed`, never `ok`. A fresh check with no current-state series at
all is `failed` too ("0 connectors", "0 kinds"), not a clean ok with nothing in it.

Applied items are state changes the data proves (an upgrade or update stopped being pending), not
version numbers: none of these sources stores a version history yet, so `from` and `to` read
"update pending" and "up to date" (Twingate: "N behind" and "current"). Nothing is invented: where
no such change is in the data, applied stays empty. A source with only stale data is `failed`, a missing check
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
| Source errors, only stale data, redirect, oversized, truncated or junk answer, a null or non-number value, a non-https Grafana URL | listed under Not checked as "check failed", counted in K |
| Some series of a source stale, the rest current | source `ok`; each stale series listed under Not checked with its age, counted as stale series |
| Grafana down or token revoked | UniFi, pfSense and Twingate all listed as "check failed" |
| Quiet week | digest still sent, "0 applied" |
| Discord down | Matrix still sent, window advances |
| Matrix down | Discord still sent, window advances |
| Both down | run errors, window kept, next digest covers the gap (max 7 days) |
| Workflow not running | no digest: silence means broken |

Tests: `tests/python/test_update_digest.py` runs the Code node source under Node and carries
mutants for each guarantee above.
