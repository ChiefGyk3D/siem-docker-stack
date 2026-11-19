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
  fallback when Grafana, n8n or the internet link is down. Matrix as a third
  path is a later task and is not part of this one.

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

Not verified: Grafana never loaded these files; no email was sent; the exact
semantics of `continue` and of the `email` contact point on the running Grafana
version were not checked against its documentation or a live instance; the
Doppler dev config name is a guess; double paging behavior and the SMTP
provider's own limits are untested; the heartbeat observer's fallback for P1 is
described in [heartbeat.md](heartbeat.md) and is not exercised by this change.
