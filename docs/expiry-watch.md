# Credential and key expiry watch

Keys, tokens and certificates expire silently. The expiry watch reads a list of
things that expire, warns you early enough to rotate them, keeps warning daily
at the end, and says so once when they have expired. It is one standard-library
Python script, `scripts/expiry_watch.py`, driven by one config file. It posts to
the n8n alert router from [update-alerting.md](update-alerting.md), so the
messages arrive where your other alerts do, and it can also send to a Matrix
room and by email directly. It is read-only: it never changes a
key, a certificate or a registry.

Tracked in issue #76 (epic #62). Slice 1 built the engine, the registry and TLS
providers and the router delivery. Slice 2 (issue #97) added the Grafana service
account token and secret manager service token providers and the "disappeared"
notice (see [Items that disappear](#items-that-disappear)). Slice 3 (issue #98)
added direct Matrix and email delivery (see
[Matrix and email](#matrix-and-email-direct-delivery)). See
[What is not built yet](#what-is-not-built-yet) and
[What is unverified](#what-is-unverified-until-checked-against-a-live-instance).

Every notice names the item, its expiry date, the days left, who owns it and a
link to the rotation runbook.

## Quick start

You need Python 3.11 or newer (for `tomllib`). There is nothing to install.

1. Copy the examples and edit them:

   ```sh
   cp docs/expiry-watch.example.toml expiry-watch.toml
   cp docs/expiry-watch-registry.example.toml expiry-watch-registry.toml
   ```

   In `expiry-watch.toml`, point `[router].url` at the router's own endpoint
   for the watch, `/webhook/expiry-watch-alerts-<opaque>` (the private path, see
   [The router credential](#the-router-credential)), and point the registry provider at `expiry-watch-registry.toml`. List your own
   items in the registry.

2. Export the router secret. This is the value the router checks on the
   watch's own endpoint (`EXPIRY_WATCH_ROUTER_SECRET` in the n8n container; its
   value is never the Grafana webhook secret), without the word `Bearer`. The
   config only names the variable:

   ```sh
   export EXPIRY_WATCH_ROUTER_TOKEN='...'   # from your secret manager, not typed into shell history
   ```

3. Look before you post:

   ```sh
   python3 scripts/expiry_watch.py --config expiry-watch.toml --dry-run
   ```

   A dry run reads every provider, prints the notices that are due and the
   JSON it would post, and posts nothing and saves nothing.

4. Run it for real, from a schedule (see [Scheduling](#scheduling)).

Exit codes: `0` ok, `1` a provider or a delivery failed (details on stderr),
`2` a config or secret problem. A failed provider is never silent, and a
provider outage does not make the watch forget what it already told you.

## How the decisions work

For each item the watch counts days left as the item's expiry date minus today
(UTC dates). An item that expires today has 0 days left and counts as expired.

- Each threshold in `thresholds_days` fires once. If a run was missed and
  several thresholds were crossed, only the lowest crossed one fires, so you
  get one message, not a replay of the old ones.
- At or below `daily_below_days` days left you get one notice per UTC day
  (running the script more often than daily does not repeat it). The day a
  threshold fires counts as that day's notice.
- When the item expires you get one final `expired` notice. The watch does not
  repeat it. Rotate the item or remove it from its provider.
- Rotation resets the state. When an item shows a later expiry date than the
  last one the watch saw, its history starts over and the thresholds fire again
  for the new date. An item that disappears from its provider loses its state.
- The watch remembers all of this in `state_file`. A notice that was not
  delivered is not remembered, so the next run tries again. That covers a failed
  delivery to any one of its channels, and a notice with an empty channel
  list, so fixing the route later still sends it.
- The state file is trusted local data. It is written atomically with private
  permissions (mode 0600), and you should keep it where only the job user can
  write. The watch checks each entry as a whole: if any part of it makes no
  sense (a threshold you did not configure or that the item has not reached, a
  daily date the watch could not have recorded, that is one outside 1 to
  `daily_below_days` days before the expiry date or after today, so with
  `daily_below_days = 0` only "no daily date" is valid; an expired flag before
  the expiry date), none of
  that entry is used and the item counts as "nothing sent yet", so the watch
  errs toward notifying. A changed expiry date, later or earlier, also starts
  the item's history over. This catches damage and mistakes. It cannot detect a
  plausible forged entry (for example the right expiry date with `expired` set
  to true), and the state is not signed or authenticated, so protect the file
  with permissions, not with this check.

- An item that an earlier run listed and a later run no longer lists gets one
  `disappeared` notice. See [Items that disappear](#items-that-disappear).

There is no "resolved" message: each notice is a one-off. Rotating the item
simply stops the notices.

### Items that disappear

Some vendors delete a token when it expires, so a token that runs out between
two runs is never listed as expired: it just stops being listed. The watch
therefore remembers, per provider, the items it saw and tells you when one is
gone. This works for every provider, the registry file included.

- The state file keeps the last seen name, kind, expiry date, owner and runbook
  of each item, per provider, in a `seen` section (the file format is version 2;
  a slice 1 file still loads and is upgraded on the next save).
- An item missing from `disappeared_after_runs` runs in a row (default 1) is
  reported once with the stage `disappeared`, severity `warning`, and its last
  known expiry date. It is then forgotten: if it comes back and goes again, you
  get another notice. If it is back before the count is reached, the count
  starts over.
- A failed provider run changes nothing. An outage is not a vanished item.
- A notice that was not delivered stays due and is sent on the next run, like
  every other notice.
- To say a removal is expected (you rotated or retired the item), list its item
  name in `acknowledge_removed` on that provider table for one run, then remove
  the entry. An acknowledged name is dropped from the memory without a notice.
  `notify_disappeared = false` turns the notice off for one provider, or in
  `[watch]` for all of them. Retiring a registry entry is a removal too, so
  acknowledge it or you get one notice.
- A provider removed from the config is forgotten without a notice. A provider
  whose config changes its `state_key` (the same source named differently, or
  other service account ids) starts a new memory.
- The notice can tell you a token vanished, not why: the vendor may have
  deleted it as expired, or someone may have deleted it.
- Two providers that read the same source are refused as a config error.
- The memory has a size limit (1000 remembered items per provider, 4000 in all,
  200 providers, and the state file at most 1 MiB). The same checks that read
  the file back are applied before it is written. A run whose state would exceed it fails with a state error
  (exit 1) before it sends anything or writes anything, because a file the
  watch cannot read back would stop all monitoring. Watch fewer items or tokens.
- Route it with `[routes].disappeared` (default `["discord"]`).

## Config reference

The format is TOML. Unknown fields are an error, as are duplicate keys,
repeated thresholds and files over 1 MiB. See
[expiry-watch.example.toml](expiry-watch.example.toml).

| Setting | Default | Meaning |
|---------|---------|---------|
| `[watch].thresholds_days` | `[30, 14, 7]` | Days before expiry that fire once each (1 to 20 values, 1 to 3650) |
| `[watch].daily_below_days` | `7` | At or below this many days left, notify daily; `0` turns it off |
| `[watch].state_file` | `expiry-watch-state.json` | What was already notified (JSON, mode 0600, written atomically) |
| `[watch].disappeared_after_runs` | `1` | An item must be missing from this many successful runs in a row (1 to 100) to count as disappeared |
| `[watch].notify_disappeared` | `true` | `false` turns the disappeared notice off for every provider |
| `[watch].delivery_budget_seconds` | `300` | One time budget for all deliveries of a run (router, Matrix, email), above 0 and at most 3600 |
| `[[providers]].acknowledge_removed` | `[]` | Item names whose removal is expected (any provider; up to 200) |
| `[[providers]].notify_disappeared` | the `[watch]` value | Per provider override |
| `[router].url` | required | The router webhook. https only; plain http only for localhost |
| `[router].token_env` | required | The name of the environment variable that holds the bearer secret |
| `[router].timeout_seconds` | `10` | Post timeout, above 0 and at most 60 |
| `[routes]."<days>"`, `daily`, `expired`, `disappeared` | `["discord"]` | Channels for that notice. `matrix` and `email` need their table (below) |
| `[matrix]` | none | Direct Matrix delivery, see [Matrix and email](#matrix-and-email-direct-delivery) |
| `[email]` | none | Direct SMTP delivery, same section |
| `[[providers]]` | none | One table per provider; `type` selects it |

Relative paths (`state_file`, a provider's `path` or `ca_file`) are relative to
the folder the config file is in. See [Paths and symbolic links](#paths-and-symbolic-links)
for what is refused.

### Channels and routing

Routing is per notice, so you can send the early warnings to chat only and the
last week to your phone. The channel names are `pushover`, `discord`, `matrix`,
`email` and `webhook`.

| Channel | Behavior |
|---------|------------------|
| `discord` | The router posts every firing alert to Discord |
| `pushover` | Adds the label `phone=true`, which is the only way an alert reaches the router's Pushover step. Pushover must be enabled in the router (`PUSHOVER_ENABLED`, see [update-alerting.md](update-alerting.md)) |
| `webhook` | Posts to the router; its own rules decide what happens |
| `matrix` | The script sends it to a Matrix room itself, see [Matrix and email](#matrix-and-email-direct-delivery) |
| `email` | The script sends it by SMTP itself, same section |

The script posts to the router only when a notice lists `pushover`, `discord`
or `webhook`. A notice routed only to `matrix` and/or `email` never touches the
router, so it sends no Discord message. The router always sends Discord for a
firing alert, so "phone only" through the router is still not possible; route
to `email` or `matrix` for a notice that must stay off Discord.

A notice that lists several channels is delivered to each. If any one of them
fails, the run exits 1 and the whole notice stays due, so the next run tries
again. That retry may deliver the channels that already worked a second time
(Matrix should drop the duplicate by its transaction id, which is inferred
from the API description and not verified; the router and email do not). A route that lists `matrix` or `email` without the matching `[matrix]` or
`[email]` table is a config error.

### Matrix and email (direct delivery)

Both channels are built with the Python standard library only. Their secrets
come from environment variables named in the config, never from a file, and are
never printed or put in an error message. A missing or malformed secret is a
config error (exit 2) only when a notice for that channel is due and not in a
dry run.

```toml
[matrix]
homeserver = "https://matrix.example.com"
room_id = "!abcdefghijklmnop:example.com"
token_env = "EXPIRY_WATCH_MATRIX_TOKEN"
timeout_seconds = 10

[email]
host = "smtp.example.com"
port = 587
security = "starttls"
from = "expiry-watch@example.com"
to = ["ops@example.com"]
username_env = "EXPIRY_WATCH_SMTP_USER"
password_env = "EXPIRY_WATCH_SMTP_PASSWORD"
```

**Matrix.** The script sends one `m.notice` message per notice with
`PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}` and an
`Authorization: Bearer` header. Use an access token for a dedicated bot user
that has joined the room and can send messages; the script never joins a room,
never reads one and never sends anything else. `room_id` must be the internal
room id, not an alias. `homeserver` is https (plain http only for localhost),
may carry a path prefix and must not carry credentials, a query or a
fragment. The transaction id is a hash of the item, stage and expiry date (and,
for the `daily` stage only, the days left) plus a random generation, never of
the time of the attempt. A notice that was not fully delivered keeps its
generation in a `pending` section of the state file, so its retry, on a later
day too, reuses the id and the homeserver can drop the duplicate (how long a
homeserver remembers a transaction id is its own choice). Once the notice is
delivered the generation is forgotten, so the same notice recurring later (for
example an item that disappears, returns and disappears again) is a new event.
A run in which a provider fails carries every earlier `pending` entry forward
(the notice may still be due but could not be rebuilt); when every provider
answered, an entry whose notice is no longer due is dropped.
A redirect
is never followed (the token is not replayed anywhere else), and only an
`https` or loopback server receives the token. TLS uses the system trust store.

**Email.** One plain text message per notice, to up to four plain addresses
(`name@example.com`; display names, quotes and comments are refused).

| `security` | What happens |
|------------|--------------|
| `starttls` (default, port 587) | Connects, requires the server to offer STARTTLS, upgrades and verifies the certificate and host name, then logs in (if configured) and sends. A server that does not offer STARTTLS is an error and nothing is sent: there is no fallback to plaintext |
| `tls` (port 465) | Implicit TLS from the first byte, certificate and host name verified |
| `plaintext` (port 25) | Unencrypted. Refused unless `allow_plaintext = true`, and refused together with a login. Only for a relay on a trusted local network |

The `Message-ID` of a message is a hash of the notice key and the same
generation Matrix uses, not a fresh random value per attempt. If a mail server
queues a message and then loses its final reply, the retry carries the same
`Message-ID`, which gives the receiving side its best chance to recognize the
duplicate. This mitigates, but cannot eliminate, SMTP's ambiguity about whether
a message was accepted: a retry can still deliver a second copy, and a receiver
that does not deduplicate by `Message-ID` will show both.

`ca_file` trusts ONLY the CA (or CAs) in that PEM file and no public CA: a
certificate from any other CA is refused even if it is valid for the host name
(read with the same no-link rules as every other file; a file that is not PEM is
a config error). Leave it out to use the system store. The script announces itself with
`helo_name` (default `localhost`), not the machine's own name.

Hardening that applies to both: every value that came from a provider (item
name, owner, link) is cleaned before it goes into a message, so a control
character or line break in a vendor token name cannot add a mail header, a
recipient or extra Matrix content; the From and To addresses come only from the
config; each delivery, to the router too, has one absolute deadline of
`timeout_seconds` (connect, TLS, login and send together; every blocking call is
re-armed with the time left, so a peer that answers a byte at a time cannot
stretch it, and the caller returns at the deadline with no extra wait). A
delivery that passes it cannot go on to log in
or send afterwards: the worker checks the deadline before every step, and the
connection is shut down. A name lookup cannot be interrupted, so the number of
lookups that may still be pending is bounded; when they are all stuck, deliveries
are refused and their notices stay due. A channel that overran its deadline is
skipped for the rest of that run. The whole pass also has one delivery budget,
`[watch].delivery_budget_seconds` (default 300, at most 3600), shared by the
router, Matrix and email: each delivery gets the smaller of its timeout and what
is left of the budget, and once the budget is gone the remaining deliveries are
not tried, their notices stay due for the next run, and the run exits 1 with a
message that says so. A slow server therefore cannot stretch one run into hours
(for a large backlog, raise the budget or run more often); response
bodies are read up to a cap. The message carries the item name, date, days
left, owner and runbook link and nothing else.

Pushover priority is the router's decision: an alert name the router does not
know is capped at priority 1. To let expired notices page at emergency
priority, add the alert names to `ALLOWED_ALERTNAMES` in the router (they are
`Expiry watch: <item name>`). That is a deliberate step, not the default.

### The router credential

The watch has its own endpoint on the router and its own secret, so rotating or
revoking one of the two (Grafana, the watch) never touches the other. Owner
decision, runbook Q11, issue #127.

| | Grafana | Expiry watch |
|---|---|---|
| Router node | `Grafana Webhook` (unchanged) | `Expiry Watch Webhook` |
| URL path | the private `grafana-alerts-<opaque>` path | the private `expiry-watch-alerts-<opaque>` path (file `expiry-path`); the committed node is DISABLED with a placeholder path, so importing the file directly serves nothing |
| Header check | n8n Header Auth, credential `grafana-webhook-auth` | the `Check Expiry Secret` Code node |
| Secret lives in | the n8n credential and `GRAFANA_WEBHOOK_SECRET` (Grafana side) | `EXPIRY_WATCH_ROUTER_SECRET` in the n8n container's environment |
| The watch's side | | `EXPIRY_WATCH_ROUTER_TOKEN`, the same value, named in `[router].token_env` |
| A rejected call | n8n answers 403 | the router answers 403 and routes nothing |

Why the name `EXPIRY_WATCH_ROUTER_SECRET`: it matches the `EXPIRY_WATCH_*`
family the watch already uses, and `_SECRET` (not `_TOKEN`) marks the
router-side copy, the value the router compares against, apart from
`EXPIRY_WATCH_ROUTER_TOKEN`, the value the watch sends. Both hold the same
string.

Why a second endpoint and not one endpoint taking two secrets: n8n Header Auth
holds exactly one credential per webhook node, and Grafana's check is left
exactly as it was, so a bug or a missing setting in the new check cannot stop
Grafana's alerts from arriving. The two endpoints share everything after the
check (the normalizer, routing, Discord, Pushover, heartbeat), so every
downstream guard applies to both.

The check, in the `Check Expiry Secret` Code node:

- It reads the environment variable `EXPIRY_WATCH_ROUTER_SECRET` and compares
  the request's `Authorization` header with `Bearer ` plus that value, exactly
  (case and spacing included).
- It denies when the variable is unset, empty, whitespace-only, not text or
  unreadable (env access blocked), and when the header is missing or not text.
  An empty value never matches an empty or missing header.
- The comparison visits every position and ORs the differences, so its time
  does not depend on where the first difference is, and a denied call does not
  say whether the length or the content was wrong. A length difference is the
  one thing it cannot hide; use the 44 character `openssl rand -base64 32` value.
- A denied call is answered 403 with a fixed body, runs nothing else and sends
  no message. Only a new body leaves the check node, never the header.
- It reads no other variable, and Grafana's variable is not consulted.
- An `Authorization` header over 512 characters is denied before the comparison
  loop runs, and so is a configured secret over 400 characters (checked before
  the loop, so an oversized value never costs work per request: the watch then
  gets 403 on every call, which is loud). The 44 character
  `openssl rand -base64 32` value is far below both.

What the expiry secret may send (authorization, not only authentication). The
secret proves the caller is the expiry watch, so the check also limits what that
caller can express. It accepts exactly the body `scripts/expiry_watch.py` builds
and builds a NEW body from the checked fields; anything else is denied with the
same 403, not passed on:

- one alert, status `firing` (a `resolved` is denied, so the secret cannot cancel
  a repeat);
- labels exactly `alertname` (`Expiry watch: <item>`, equal to the `item` label),
  `severity` (`critical`, `warning` or `info`), `expiry_watch=true`, `item`
  (1 to 100 characters: letters, digits, space, dot, colon and hyphen only,
  starting with a letter or digit), `kind` (1 to 40 letters, digits and hyphens),
  `stage` (a day count, `daily`,
  `expired` or `disappeared`) and optionally `phone=true`; any other label
  (`heartbeat`, `update_security`, `team`, `source`) is denied;
- annotations may only be the keys `summary` and `description` (300 and 1000
  characters at most), but their text is DROPPED: the router builds the summary
  and description itself from `item`, `kind` and `stage` (for example "deploy-key
  (ssh-key): expires within 14 days", "has expired", "is no longer listed by its
  provider") and a fixed description. No free text from the caller reaches Discord
  or the phone, so a holder of this secret cannot send a misleading message, a
  link or a mention. Item names with an underscore, slash, `@`, backtick, angle
  bracket, asterisk or any non-ASCII character are denied with the 403, so the
  watch fails loudly; rename such an item in the registry or the provider. The
  dates, owner and runbook of the full notice stay in the watch's own output
  and its Matrix and email channels;
- a 32 character lowercase hex `fingerprint`, an optional UTC `startsAt`; no URLs;
- the handed-on body carries the label `source=expiry-watch`, set by the router,
  never by the caller.

Because the name prefix `Expiry watch: ` is not on the Pushover builder's alert
name allowlist (a test enforces it), an expiry notice reaches Discord, and with
`phone=true` Pushover at priority 1 at most; priority 2 (emergency repeat) and
cancel-by-tag are unreachable with this secret. An expired item (`critical`)
still pages at priority 1. If you ever add an `Expiry watch:` name to the
allowlist, that guarantee ends.

Request limits (owner decision Q12, issue #157). The watch posts to n8n over
loopback, so no reverse proxy is in this path and the limits live in the watch
and in the router, not at a proxy:

- The watch refuses to send a body over 16 KB (16384 bytes): it sends nothing,
  names the size in the error and exits 1. It also waits at least 2 seconds
  between router posts and posts at most 15 times per run (so two runs inside the router's 10 minute window total exactly its 30, when the window held no other accepted call); a notice that was
  not posted stays due for the next run.
- The router's `Check Expiry Secret` node denies (403) a body over 16 KB (the
  parsed body re-serialized, and the `content-length` header when n8n passes it
  on), a call less than 1 second after the last accepted call, and more than 30
  accepted calls in 10 minutes. Only a call that has the right secret and a valid
  notice counts, so a caller without the secret cannot use up the watch's
  allowance. The watch's limits sit inside the router's, so a normal run is never
  denied. The counter is kept in the workflow static data; if that cannot be read,
  the call is denied.
- UNVERIFIED against a live n8n, check after the first import: that a Code node
  can read `$getWorkflowStaticData('global')` in a production execution (the
  check denies every call if it cannot), that two executions that overlap do not
  both read the old counter (a burst may then slip through), and that the
  `content-length` header reaches the node. A Code node cannot see the raw body
  bytes, and it runs after n8n has read and parsed the whole body, so it does not
  stop that work, and a chunked body or one padded with JSON whitespace passes
  the size check when its parsed form is small. The check runs after the secret
  comparison and counts UTF-8 bytes of the re-serialized body. It is defense in
  depth: the real cap on the raw request is n8n's `N8N_PAYLOAD_SIZE_MAX` below.
- What these limits cannot do: a denied call still starts one workflow
  execution, and n8n's own body limit is `N8N_PAYLOAD_SIZE_MAX`, default 16 MiB
  (n8n docs, endpoints environment variables, read 2026-11-19). Lower it for the
  n8n container if your n8n allows (an expiry notice is under 8 KB; check the
  unit and minimum in the n8n docs first). Request and header timeouts and a
  concurrency limit are n8n's and the host's, not the workflow's. The endpoint has
  a private path so it cannot be found by guessing, but the path is not a
  credential: treat it as an address, and keep n8n's port off networks that
  should not reach it.

Needs `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` in the n8n container, the same
setting the [heartbeat](heartbeat.md#settings-environment-of-the-n8n-container)
needs. While env access is blocked the check cannot read the secret and denies
every call to this endpoint, so the watch gets 403 and exits 1 (a delivery
failure, not silent); Grafana is unaffected.

Owner steps (nothing here runs from the repo; each is a live change):

1. Create the secret in the secret manager, dev config first, with the value
   piped in and the output sent to /dev/null so it is never echoed (the
   watch's side, `EXPIRY_WATCH_ROUTER_TOKEN`; `openssl rand -base64 32` makes the
   value). Give the n8n container the same value as
   `EXPIRY_WATCH_ROUTER_SECRET` (an environment entry in the n8n compose file,
   with an empty default) and make sure `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`
   is set there.
2. Re-import `n8n/grafana-alert-router.json` with the live import helper
   (`scripts/live-deploy/n8n-setup-alert-router.py --workflow ...`), then restart or
   activate the workflow as the live-deploy runbook describes. The helper makes a
   private path for each webhook and saves them in `router-path` (Grafana) and
   `expiry-path` (the watch) in its config directory. The committed
   `Expiry Watch Webhook` node ships `disabled` with a placeholder path (n8n
   does not register a webhook for a disabled trigger node: UNVERIFIED against
   a live n8n, check after the first import that the placeholder path answers
   404); only the helper enables it, and only with a path of the form
   `expiry-watch-alerts-` plus 24 URL-safe characters. The helper writes
   `expiry-path` with mode 600 enforced on the opened file, reads it only if it
   is a regular file you own with no group or other permission bits (a looser
   file is refused with a message: delete it to get a new path), refuses
   symlinks, and replaces a saved path that does not have the generated shape.
3. Read the path from `expiry-path`, point `[router].url` in the watch's config at
   `<n8n base>/webhook/<contents of expiry-path>` (never commit it), and keep the
   watch's variable `EXPIRY_WATCH_ROUTER_TOKEN` equal to the router's.
4. The body and rate limits above are in the watch and the imported router and
   need no step. Optionally lower `N8N_PAYLOAD_SIZE_MAX` for the n8n container.
5. Rotate by changing both values together, then restart the n8n container so it
   reads the new environment. To revoke the watch only, unset or empty the
   router's variable: the endpoint then denies every call.

### What the router receives

One alert in the Grafana webhook shape, with these labels: `alertname`
(`Expiry watch: <item>`), `severity` (`critical` when expired, `warning` at 14
days or less, `info` above that), `expiry_watch=true`, `item`, `kind`, `stage`,
and `phone=true` only when the notice's channels include `pushover`. The
annotations carry a summary (300 characters at most) and a description with the
item, date, days left, owner and runbook link. The fingerprint is a hash of the
item name. Posting uses `Authorization: Bearer <secret>`, never follows a
redirect (so the secret is never replayed elsewhere), and a failure message
never contains the secret.

## Paths and symbolic links

The config file's folder is opened once at the start of a run and that one open
folder is used for everything that follows: the config, registry files, a TLS
`ca_file`, and reading and writing the state file. Retargeting a link that
names the folder while a run is in progress changes nothing for that run. The
state file is written by creating a temporary file inside the held folder and
renaming it there.

- The folder named on the command line is allowed to be a symbolic link (or sit
  under one, such as a home directory that is a link). It is your own choice of
  location, resolved once, then pinned. The config file itself must not be a
  link.
- Below that folder, a symbolic link in any component of `state_file`, a
  registry `path` or a `ca_file` is refused, and so is a link as the file
  itself.
- An absolute path is walked from `/` and no component of it may be a link.
- The path text is checked as written, before any normalization: an empty
  component (`a//b`, a trailing `/`), `.` and `..` are refused, so `./x`,
  `a/./x` and `../x` are all errors.
- FIFOs, devices and directories are refused, and files over 1 MiB.

What this does not do: it does not stop someone who can already write inside the
config folder from replacing files there. Keep the folder writable only by the
job user.

## Providers

A provider reads one source and returns items. All text is validated the same
way: a name up to 100 characters, a kind up to 40, an owner up to 100, a
runbook that is an http or https link up to 512 characters, no control
characters, and a real calendar date.

### registry: a plain file

For SSH keys, PGP keys, domain registrations and anything without an API.

```toml
[[providers]]
type = "registry"
path = "expiry-watch-registry.toml"
```

The file holds `[[item]]` tables with all of `name`, `kind`, `expires`
(`YYYY-MM-DD`), `owner` and `runbook`; see
[expiry-watch-registry.example.toml](expiry-watch-registry.example.toml). The
loader refuses duplicate keys, duplicate item names, unknown fields, a date and
time instead of a date, an empty file, more than 1000 items, a file over 1 MiB,
a FIFO and anything that is not a regular file. File paths follow the rules in
[Paths and symbolic links](#paths-and-symbolic-links). The error names the item.

### tls: a certificate probe

```toml
[[providers]]
type = "tls"
host = "www.example.com"
port = 443
owner = "web-team@example.com"
runbook = "https://wiki.example.com/runbooks/renew-tls"
```

It connects, completes the TLS handshake, reads the certificate the peer sent
and takes the not-after date from it. `timeout_seconds` (default 10, at most 60)
is one overall deadline for the whole probe: name resolution, connecting (at
most 4 resolved addresses) and the handshake together. Resolution cannot be
interrupted, so the probe runs in a worker thread and the watch stops waiting at
the deadline exactly (no grace period). A resolver that never answers leaves
one idle thread until the process exits, so this provider is meant for one-shot
runs (cron or a timer, as in [Scheduling](#scheduling)), not for a long-lived
process that would collect stalled threads. The probe sends no application
data.

Verification choice: by default the handshake **verifies** the chain and the
host name against the system trust store, or against `ca_file` when set (read
through the same path rules as the other files). A peer
that fails verification is an error shown to you, not a date. Set
`verify = false` only for internal or self-signed certificates, or to learn
when an already invalid certificate ended. In that mode the handshake accepts
any certificate because the only thing read is the date, which is why it is off
by default and why the result is never evidence of identity. The date is parsed
from the certificate bytes by a small reader in the script (the standard
library gives no date for an unverified peer), which refuses anything that is
not a well-formed certificate validity field.

### grafana_sa_tokens: Grafana service account tokens

```toml
[[providers]]
type = "grafana_sa_tokens"
url = "https://grafana.example.com"
service_account_ids = [2, 5]
token_env = "EXPIRY_WATCH_GRAFANA_TOKEN"
owner = "monitoring@example.com"
runbook = "https://wiki.example.com/runbooks/rotate-grafana-token"
```

Lists each service account's tokens with `GET /api/serviceaccounts/<id>/tokens`
and makes one item per token that has an expiry date, named
`grafana-sa:<id>:<token name>`. Per token it uses `expiration` and
`hasExpired`:

- `expiration` null means the token never expires: it is skipped. With
  `report_non_expiring = true` the run prints how many were skipped.
- `hasExpired` true makes the token expired even if its date looks like the
  future (a clock difference between the watch and Grafana).
- `secondsUntilExpiration` is ignored on purpose: 0 is ambiguous.
- `expiration` must be ISO 8601: a date, or a time with an explicit zone (`Z`
  or an offset). Anything else, a time without a zone included, is an error
  that names the value. The date is converted to UTC. See
  [What is unverified](#what-is-unverified-until-checked-against-a-live-instance).

Permission: the token needs `serviceaccounts:read` with scope
`serviceaccounts:id:*` (per the Grafana API documentation). Give a dedicated
service account a custom role with just that, create one token for it and put
it in the environment variable. Do not assume a built-in role such as Viewer
holds it; check with `--dry-run`. The watch only reads. A 401 or
403 is reported as "check the token and its read permission". `url` is https
(plain http only for localhost) and may include a path prefix, but no query.
`service_account_ids` holds 1 to 50 different ids; one list call per id.

### doppler_tokens: secret manager service tokens

```toml
[[providers]]
type = "doppler_tokens"
project = "example-app"
config = "prd"
token_env = "EXPIRY_WATCH_DOPPLER_TOKEN"
owner = "platform@example.com"
runbook = "https://wiki.example.com/runbooks/rotate-service-token"
```

Lists one config's service tokens with `GET /v3/configs/config/tokens?project=...&config=...`
(`api_url` defaults to `https://api.doppler.com`) and makes one item per token
with an `expires_at`, named `doppler:<project>/<config>:<token name>` (the slug
when the name is empty). `expires_at` null means no expiry: skipped. Only name,
slug and `expires_at` are read; everything else in the response, any key
material included, is ignored and never stored. One provider reads one config;
add a provider for each project and config.

An answer that says it failed (`success` is present and not `true`, or it has an
`error` or `errors` field at all, even an empty or null one) is a provider error, never an empty list, so a failure answer
cannot make known tokens look vanished.

The vendor deletes an expired token, so this provider can only see a token that
is still alive. A token that expires between two runs is reported by the
[disappeared](#items-that-disappear) notice instead, so keep that notice routed
somewhere you read.

Permission: use a token that can list the config's service tokens and nothing
more. **The permission this list call needs is not documented by the vendor.**
Do not assume a read-only service token works. Test it with a throwaway token
before relying on it: make the token, then run the watch with `--dry-run`. A 401
or 403 names the token and permission as the thing to check. Prefer the least
privileged token that passes, and never one that can read or write the secrets
themselves unless that is the only thing that works, in which case say so in your
own runbook and rotate it on a schedule.

### Common settings of the two token providers

| Setting | Default | Meaning |
|---------|---------|---------|
| `token_env` | required | The NAME of the environment variable that holds the read-only token. The value is never read from the config file and never printed |
| `owner`, `runbook` | required | Used on every notice for these tokens (the vendors do not know them) |
| `kind` | `grafana-sa-token` or `service-token` | The kind shown on notices |
| `timeout_seconds` | `10` | One overall deadline per request, at most 60 |
| `report_non_expiring` | `false` | Print how many tokens have no expiry date |

Both providers send the token only to the configured URL, never use a proxy
from the environment (`HTTP_PROXY` and the like are ignored for these calls, so
a proxy is never handed the token; the vendor must be reachable directly), end
the request at the deadline by closing the connection (a name lookup is the
exception: **DNS resolution cannot be interrupted**, so a stuck lookup keeps its
worker thread until the resolver returns; at most 4 such threads can exist, and
further requests are refused with a message saying so instead of starting more;
when the deadline passes, the call waits up to one more second for its worker to
end, so a timed out request can take up to about one second longer than
`timeout_seconds`),
never follow a
redirect (a redirect is an error), cap a response at 1 MiB and a list at 1000
tokens, refuse JSON with duplicate keys, `NaN` or absurd nesting, and refuse
two tokens with the same name in one list (rename one). A failure message
names the host and the HTTP status, never the token and never the response
body. A missing token variable is a config error (exit 2) that names only the
variable.

### Writing your own provider

A provider is any object with one method, `items()`, that returns a list of
`Item` and raises `ExpiryWatchError` when it cannot read its source. A factory
takes the provider's config table and returns the provider. Register it and
list it in the config:

```python
import expiry_watch as ew

class MyProvider:
    def __init__(self, config):
        self.config = config              # the [[providers]] table as a dict; the watch
                                          # also adds "_base_dir", the config file's folder

    def items(self):
        # read your source here; build every item through Item.build so the
        # limits above apply to your data as well
        return [ew.Item.build(name="my-token", kind="api-token", expires="2027-01-01",
                              owner="ops@example.com", runbook="https://wiki.example.com/rotate")]

ew.register_provider("mine", MyProvider)
```

```toml
[[providers]]
type = "mine"
```

The watch also adds `"_env"` (the environment, for providers that read a token
by the variable name in their config). Give the provider a `state_key` string
attribute that names its source (for example `"mine:example.com"`) so the
[disappeared](#items-that-disappear) memory stays attached to it; without one
the key is the provider type and its position in the config. Provider names are
global and cannot be registered twice. Item names must be
unique across all providers. Run your registration, then call
`expiry_watch.main(["--config", "..."])`. Loading providers from plain files by
type name is not built yet.

## Scheduling

Run the script once a day or more often. More often is harmless: each notice
fires once per threshold or once per day.

Cron (the secret comes from a file that only the job user can read; adjust the
paths):

```cron
17 7 * * *  cd /opt/siem-docker-stack && . /etc/expiry-watch.env && python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml
```

Because the env file is sourced by the shell, write it as
`export EXPIRY_WATCH_ROUTER_TOKEN=...` for cron. A systemd service and timer:

```ini
# /etc/systemd/system/expiry-watch.service
[Unit]
Description=Credential expiry watch

[Service]
Type=oneshot
User=expirywatch
EnvironmentFile=/etc/expiry-watch.env
ExecStart=/usr/bin/python3 /opt/siem-docker-stack/scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml
```

```ini
# /etc/systemd/system/expiry-watch.timer
[Unit]
Description=Run the credential expiry watch daily

[Timer]
OnCalendar=*-*-* 07:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

For systemd the env file holds one plain line,
`EXPIRY_WATCH_ROUTER_TOKEN=...`. Either way it is owned by the job user with
mode 0600. Keep the state file on storage that survives reboots, or every run
looks like a first run. A non-zero exit means look at the journal or the cron
mail. Watch the job with your usual job monitoring, because a watch that stops
running looks exactly like nothing expiring. The [heartbeat](heartbeat.md)
covers the alert path, not this job.

## Tests

`tests/python/test_expiry_watch.py` runs the engine against a fake clock (30,
14 and 7 days, daily, expired, once per threshold, rotation reset), the
registry and config parsers against hostile input, the TLS probe against a
local server with a certificate made by `openssl` at test time, and the poster
against a local HTTP server. Run it with `python3 -m pytest
tests/python/test_expiry_watch.py`.

Slice 3 adds `tests/python/test_expiry_watch_channels.py`: the Matrix and email
config rules, message cleaning, the Matrix sender against a fake homeserver on
loopback (bearer, transaction id, redirect, errors), the email sender against a
fake SMTP server (plaintext opt-in, required STARTTLS, untrusted certificate,
implicit TLS, header injection, rejections) and the runner (routing, retries,
dry run, secrets only when due).

Slice 2 adds `tests/python/test_expiry_watch_providers.py` (both token
providers against a fake vendor on loopback: list parsing, null expiry,
`hasExpired`, bad dates, HTTP errors, timeouts and a slow drip, redirects not
followed, size caps, hostile shapes, secrets never printed or sent elsewhere)
and `tests/python/test_expiry_watch_disappeared.py` (the daily date interval
check and the disappeared notice, with the registry provider and the vendor
ones).

## What is unverified until checked against a live instance

The two token providers were written from the vendors' published API
documentation (read 2026-11-18, partly through a summary) and tested against a
fake server, never against a live Grafana or a live secret manager. Until you
have run `--dry-run` against your own instance with a throwaway token, treat
these as unconfirmed:

- **The exact `expiration` string format in Grafana.** The documentation does
  not state it for a token that has one. The watch accepts ISO 8601 and fails
  with a clear error on anything else, a time without a zone included, rather
  than guessing. If your Grafana returns something else, the run reports the
  value and exits 1; please report the shape so the parser can be extended.
- **The secret manager list permission.** The vendor does not document which
  permission a token needs to list service tokens, so the least-privilege token
  is found by testing (see the provider section).
- **The secret manager `expires_at` format.** Inferred as ISO 8601 UTC with
  milliseconds from a documentation example; the same defensive parser applies.
- **Doppler and Grafana response fields** beyond the ones read here. Unknown
  fields are ignored; a missing or mistyped field that is read is an error.
- **A zero or "never" date.** A token with no expiry should be null. A date
  before the year 2000 is treated as an error, not as a date.

- **Matrix and email delivery.** Written from the Matrix client-server API
  (`m.room.message` send, v3) and Python's `smtplib`, and tested only against
  fakes on loopback. Never run against a live homeserver or a live mail server.
  Check `--dry-run` first, then one real notice to a test room and a test
  mailbox. Unconfirmed in particular: that your homeserver accepts the bot
  token for the room, that your mail server accepts the sender address, and
  that the message is not filtered as spam.
- **Matrix end-to-end encrypted rooms.** The script sends plain `m.notice`
  events and cannot encrypt. Use an unencrypted room.

## What is not built yet

- **ntfy and other generic channels** beyond `webhook` through the router.
- **Grafana alert rules** driven by an expiry state metric, and a collector
  that writes days left as a metric, so Grafana can alert without the script.
- **A weekly digest line** for the low-urgency items (the digest itself is built: [weekly-digest.md](weekly-digest.md)).
- **Per-item overrides** of thresholds or routing, and a "resolved" message.
- **Provider plug-ins loaded from a directory.** Today a plug-in is code that
  imports the module and registers itself.
- **Alerting on a failed probe.** A TLS host that cannot be reached is reported
  on stderr and in the exit code, not as an alert.
- **A sibling check for this job.** Nothing alerts you if the schedule stops;
  use your job monitoring for that.
- **Tests against a live n8n.** The payload shape is checked against the
  router's rules and its normalizer limits, not against a running router.
