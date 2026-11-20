# Channel redundancy: a second channel for P1 alerts

Today every alert to a human goes through the n8n router, and from there to
Discord and Pushover. If n8n works but both vendors fail, a P1 alert reaches no
one. This adds an email path for P1 that does not depend on n8n, Discord or
Pushover.

Tracked in issue #82 (epic #62). The decision and the options are in
[docs/design/channel-redundancy.md](design/channel-redundancy.md) (Option B plus
Option C). Related: [heartbeat.md](heartbeat.md), [update-alerting.md](update-alerting.md).

Nothing here is active. The files ship as `.example`, and Grafana ignores them
until you copy them.

## The P1 path

A P1 is an alert with `severity=critical` and `phone=true`. With the example
policy in place:

```
Grafana alert (severity=critical, phone=true)
   |
   +--> route email-p1 (continue: true) --> contact point email-p1 --> SMTP --> your inbox
   |
   +--> next matching route / root --> contact point n8n-grafana-router --> n8n (Discord, Pushover)
```

- The `email-p1` route is the first route and has `continue: true`, so Grafana
  keeps matching after it. The n8n path behaves as before.
- The heartbeat (`severity=info`, `phone=false`) and warnings never match the
  email route.
- Email fires on every P1, not only when a primary fails. This is a double page
  by design: failure detection can itself miss a drop.
- The second part of the design is the outside heartbeat observer
  ([heartbeat.md](heartbeat.md)). It lives outside the lab and carries the
  fallback when Grafana, n8n or the internet link is down. Matrix is a third
  path, described in [the Matrix section](#third-path-matrix-issue-147) below.

Files:

- `docker/grafana/provisioning/alerting/email-contact-point.yml.example`
- `docker/grafana/provisioning/alerting/email-notification-policy.yml.example`

## Settings

All are empty and commented in `.env.example`. None is written into a repo file.
Keep every value in your secret manager.

| Variable | Meaning |
|----------|---------|
| `GF_SMTP_ENABLED` | `true` turns on Grafana's SMTP client |
| `GF_SMTP_HOST` | SMTP server and port, for example `smtp.example.com:587` |
| `GF_SMTP_USER` | SMTP login |
| `GF_SMTP_PASSWORD` | SMTP password (a secret) |
| `GF_SMTP_FROM_ADDRESS` | sender address, for example `alerts@example.com` |
| `GF_SMTP_STARTTLS_POLICY` | `MandatoryStartTLS` so mail is never sent in clear text |
| `P1_EMAIL_TO` | recipient address or addresses, read by the contact point |

## Enable it (every step is a live change the owner does)

Not done by this repository. Live change, each step:

1. Create or choose a sender mailbox and an SMTP login for it. Live change.
2. Put the seven values in the Doppler dev config of your project first (for
   example the dev config next to `prd_network`; confirm the exact name), never
   prd until you say the stack is live. Live change.
3. Pass the variables to the `grafana` service in `docker/docker-compose.yml`
   (an `environment:` entry per name, as `GRAFANA_WEBHOOK_SECRET` is). The repo
   does not do this for you, so the compose file is unchanged. Live change.
4. Copy the contact point entry into `contact-points.yml`, and merge the
   `email-p1` route into your policy tree as the first route. Grafana loads one
   policy tree per organization, so the example file replaces the whole tree if
   loaded as is. Live change.
5. Restart Grafana (`docker compose up -d grafana`). Provisioning is read at
   startup. Live change.
6. Send a test P1 and confirm the mail arrives, then confirm Discord and the
   phone still receive it. Live change.

## Provider-neutral checklist

The provisioning files name no provider. Any SMTP provider works through the
`GF_SMTP_*` variables. Before you enable it (each is an owner step):

- The sending domain is verified with the provider's DNS records.
- The sending domain is separate from any primary domain, so a deliverability
  problem there never touches your main mail.
- The SMTP user and password live only in the secret manager dev config.
- STARTTLS on port 587 (`GF_SMTP_STARTTLS_POLICY=MandatoryStartTLS`).
- The From address (`GF_SMTP_FROM_ADDRESS`) is on the verified domain.
- Send a test from the email contact point's test button in Grafana, then
  confirm it arrived.

## Example: Mailgun

Mailgun is the owner's likely provider. Read from Mailgun's SMTP page
(https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/send-smtp,
read 2026-11-19) and its sandbox page
(https://documentation.mailgun.com/docs/mailgun/user-manual/domains/domains-sandbox,
read 2026-11-19):

- Host: the page's example uses `smtp.mailgun.org`. It names no other host.
- Ports: 25, 465, 587 and 2525; 587 is recommended. Port 465 requires a TLS
  connection; 25, 587 and 2525 start unencrypted and may upgrade with STARTTLS,
  which is why `MandatoryStartTLS` matters.
- Credentials are per domain, under Sending, Domain Settings, SMTP Credentials
  (or the HTTP API).
- A sandbox domain can only send to authorized recipients.

So the values are `GF_SMTP_HOST=smtp.mailgun.org:587` and
`GF_SMTP_STARTTLS_POLICY=MandatoryStartTLS`, with the user and password from the
domain's SMTP Credentials tab, stored in the secret manager.

INFERRED, not read on those pages: the SMTP username format, the EU region host
(an EU region account may need a different host; check Mailgun's current
documentation for your region), and the sandbox daily or monthly caps. Use a
real verified domain rather than the sandbox for alerts.

## Rollback

Live change, each step: remove the `email-p1` route from the policy tree, remove
the contact point entry, restart Grafana. n8n and its contact point were never
modified, so nothing else needs reverting. To stop mail without touching
provisioning, set `GF_SMTP_ENABLED` to `false` and restart Grafana.

## Verified and not verified

Verified (repository tests, `tests/python/test_channel_redundancy.py`): the
files parse; they hold no secret or real address, only `$VARIABLE` references
and `example.com`; the route is first, has `continue: true` and matches only
`severity=critical` with `phone=true`; the n8n contact point name is
`n8n-grafana-router`; the example files are not auto-loaded; `.env.example` has
the new keys, empty.

Verified against Grafana's documentation on 2026-11-19: the `[smtp]` keys
`enabled`, `host`, `user`, `password`, `from_address` and `startTLS_policy`
(values `OpportunisticStartTLS`, `MandatoryStartTLS`, `NoStartTLS`) at
https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#smtp;
the `continue` option ("continue matching sibling policies even after the alert
matched the current policy") and top-to-bottom order at
https://grafana.com/docs/grafana/latest/alerting/configure-notifications/create-notification-policy/;
the email contact point's addresses and single email options, and that OSS
needs SMTP configured first, at
https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/configure-email/.
Inferred: the `GF_SMTP_*` names (the page gives the `GF_<SECTION>_<KEY>` rule,
not these names); the provisioning keys `addresses` and `singleEmail` and the
`;` or `,` separator (the page documents UI options only); that the test button
exists in your version.

Not verified: Grafana never loaded these files; no email was sent; the
Doppler dev config name is a guess; double paging behavior and the SMTP
provider's own limits are untested; the heartbeat observer's fallback for P1 is
described in [heartbeat.md](heartbeat.md) and is not exercised by this change.

## Third path: Matrix (issue #147)

Nothing here is active either. The files ship as `.example`:

- `docker/grafana/provisioning/alerting/matrix-contact-point.yml.example`
- `docker/grafana/provisioning/alerting/matrix-notification-policy.yml.example`
  (the `matrix-p1` route, `continue: true`, directly after `email-p1`)

### Why a relay: Grafana cannot post to Matrix directly

This is a design note, and there is no relay code in this repository (no relay
code ships here). Grafana has no Matrix contact point and a webhook contact point
cannot do the job alone:

- The Matrix send call is
  `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}` with an
  `Authorization: Bearer <token>` header. The spec says the transaction id lets
  the homeserver "distinguish a new request from a retransmission". A reused
  txnId on the same device and endpoint is treated as a retransmission and
  answered with the original event id, with no new message. Clients must change
  the txnId for every new request.
- A Grafana webhook contact point has one fixed URL. Grafana's docs show template
  support for Title, Message and Custom Payload, and none for the URL. A fixed URL
  means a fixed txnId. The first alert would post and every later one would be
  dropped as a retransmission, silently, with HTTP 200 and no error in Grafana.
  (How long a homeserver remembers a txnId is implementation specific, so the
  failure could also come and go. That is the worse behavior for a P1 path.)
- The access token must travel in a header. Grafana's webhook can send a Bearer
  header, so that part works, but the txnId blocks the direct route. Sending the
  token as a query parameter is deprecated by the spec and is not used here.

So `matrix-p1` is a plain webhook to a relay you run. The relay:

1. Accepts Grafana's webhook POST, and checks the bearer `P1_MATRIX_RELAY_TOKEN`
   in constant time.
2. Builds one `m.room.message` body from the alert payload (alert names, status,
   severity, a link).
3. Calls the Matrix send endpoint with a fresh txnId per message (for example a
   random UUID, reused only for its own retries on a network error), the room id
   percent-encoded in the path, and its own `MATRIX_ACCESS_TOKEN` and room id from
   its environment.
4. Returns a non-2xx status when Matrix fails, so Grafana's own notification
   failure alert
   ([notification-failure-alert-rule.yml](../docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml))
   sees it.

The existing `scripts/expiry_watch.py` Matrix sender already does steps 2 and 3
(its `matrix_send` derives a deterministic txnId per notice and generation and
reads the token from an environment variable), so the relay can reuse that
approach rather than invent one. A maintained alternative is the
grafana-matrix-forwarder project (MIT license, password login rather than a token,
a container image on the project's registry). It is not adopted here: it has not
been inspected, and the project's rules require an inspection before anything
third party is run.

The relay is a new single point of failure on the Matrix path, which is fine for
a third path, but it should run outside the failure domain you are protecting
against (not on the same host as Grafana if you can avoid it).

### Enable it (owner steps, each a live change)

Not done by this repository. Build or choose the relay first (a separate task),
then:

1. Create a bot account on your homeserver and a room for P1 alerts, invite the
   bot, and note the room id (the `!id:server` form, not an alias). Live change.
2. Create an access token for the bot. Live change.
3. Store the secrets by variable name only in the Doppler dev config of your
   project (the `dev_network` config; confirm the exact name), never prd until you
   say the stack is live: `MATRIX_ACCESS_TOKEN` and the room id for the relay,
   `P1_MATRIX_RELAY_URL` and `P1_MATRIX_RELAY_TOKEN` for Grafana. Live change.
4. Pass `P1_MATRIX_RELAY_URL` and `P1_MATRIX_RELAY_TOKEN` to the `grafana`
   service in `docker/docker-compose.yml` (the compose file is unchanged here).
   Live change.
5. Copy the `matrix-p1` contact point into `contact-points.yml`, and merge the
   `matrix-p1` route into your policy tree directly after `email-p1`. Live change.
6. Restart Grafana (`docker compose up -d grafana`). Live change.
7. Send a test P1 twice, a few minutes apart, and confirm both messages reach
   the room (this checks the txnId handling), then confirm email, Discord and the
   phone still receive it. Live change.

### Rollback

Live change, each step: remove the `matrix-p1` route and the contact point entry,
restart Grafana, then revoke the bot's access token and remove the variables from
the secret manager. Email and n8n were never modified.

### Verified and inferred (Matrix)

VERIFIED (read 2026-11-19):

- The webhook contact point accepts `POST` or `PUT`, extra headers, a Bearer
  authentication scheme and a custom payload template; templates are documented
  for Title, Message and Custom Payload, not for the URL:
  https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/
- File provisioning of a `webhook` contact point lists `url`, `httpMethod`,
  `authorization_scheme`, `authorization_credentials`, `maxAlerts`, `tlsConfig`
  and `hmacConfig`, and interpolates environment variables with the `$variable`
  syntax (an unset variable becomes an empty string):
  https://grafana.com/docs/grafana/latest/alerting/set-up/provision-alerting-resources/file-provisioning/
- Matrix transaction identifiers: scoped to one device and one endpoint,
  idempotent, a reused id is a retransmission and returns the original response;
  the Bearer header is supported and the query parameter is deprecated:
  https://spec.matrix.org/v1.11/client-server-api/ (transaction identifiers and
  access token sections; the page was read in part, the first 100000 characters).
- No Matrix contact point appears in Grafana's contact point documentation, and a
  community guide says Grafana does not support Matrix by default and uses a
  forwarder:
  https://gyptazy.com/howto-integrate-matrix-alerts-into-grafana-with-webhooks
  (found by search; not read in full).
- The repository's own `n8n-grafana-router` contact point already uses the same
  `webhook` keys with `$GRAFANA_WEBHOOK_SECRET`.

INFERRED, not read on those pages:

- That the webhook URL cannot be templated per alert (the docs are silent; they
  show templates only for the three fields above). Even if a future version
  templated the URL, it would not produce a unique txnId.
- How long a homeserver keeps a txnId (the spec leaves it open).
- That `authorization_credentials` could be given as a secure setting; this
  example uses the same `$VARIABLE` form as the n8n contact point.
- The grafana-matrix-forwarder details above come from its README mirror and have
  not been inspected.

Not verified: Grafana never loaded these files, no relay exists, and nothing was
sent to any homeserver. The tests in `tests/python/test_channel_redundancy.py`
check only that the files parse, hold no secret, keep the route order and
`continue`, and are not auto-loaded.
