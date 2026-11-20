# Design: private alert delivery and minimal alert detail

Status: DRAFT for the owner's review. No code or live change is part of this
document. Tracked in issue #155 (epic #62, NOC/SOC alerting platform). It builds
on `docs/design/channel-redundancy.md` (issue #82) and `docs/alert-taxonomy.md`.

Every claim is marked. **VERIFIED** means read from a page or file, with its URL
or path and the date read (2026-11-20). **INFERRED** means reasoned from those
sources or from general knowledge, and not checked against a live system.

## Owner decisions (2026-11-20)

1. Delivery is chosen per tier.
2. P1 goes to EVERY platform (Discord, Matrix, email, Pushover) AND to direct
   messages.
3. P2 and P3 go to a locked-down private channel or room.
4. Alerts carry minimal detail. The detail lives behind an authenticated link in
   a future internal ticketing system.

## Tier to channel table

| Tier | Discord | Matrix | Email | Pushover | Direct messages |
|------|---------|--------|-------|----------|-----------------|
| P1 | Private alerts channel | Private alerts room | Yes | Yes | Discord DM and Matrix DM |
| P2 | Private alerts channel | Private alerts room | No | No | No |
| P3 | Private alerts channel (digest or per alert, see decisions) | Private alerts room | No | No | No |
| none (heartbeat) | Unchanged, never to people | Unchanged | Unchanged | Unchanged | No |

Status today (VERIFIED, `docs/alert-taxonomy.md`, "Tiers"): P1 is Pushover plus
Discord, P2 is Discord only, P3 is Discord because the digest is not built.
Matrix is design-only (#147, `docs/design/channel-redundancy.md`). Discord DMs
and the private channel are new in this note.

## Minimal payload

What a person receives, on every channel and tier:

| Field | Content |
|-------|---------|
| Tier | `P1`, `P2` or `P3` |
| Short rule title | A public title, see "Rule titles" |
| Ticket id | Opaque id, see "Ticket link pattern" |
| Ticket link | `TICKET_BASE_URL/<id>`, or empty until the ticket system exists |

Excluded from every outbound message: hostnames, IP addresses, user names, file
paths, query text, label and annotation values, the rule's `values`, and every
Grafana generated link.

Reason, VERIFIED (https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/,
read 2026-11-20): the default webhook payload carries, per alert, `labels`,
`annotations`, `values`, `generatorURL`, `silenceURL`, `dashboardURL`,
`panelURL` and `imageURL`, and at top level `externalURL`, `groupLabels`,
`commonLabels` and `commonAnnotations`. Any of these can hold detail or point at
the Grafana host. The router must therefore build the outbound text from an
allowlist of fields (tier, mapped title, id) and drop the rest, instead of
forwarding the payload and removing fields.

VERIFIED (same page): the webhook has a Custom Payload option that replaces the
default payload with a template, and `Title` and `Message` are ignored when it is
used. Note: the page says this is not yet generally available in Grafana Cloud.
This stack is self-hosted, so it could shrink the payload at the source, but that
is INFERRED to work on the installed version and is not checked. The router
allowlist stays the control either way, because it also covers the Alertmanager
path.

VERIFIED (https://grafana.com/docs/grafana/latest/alerting/fundamentals/templates/,
read 2026-11-20): notification templates attach to contact points, not rules, and
the page does not say whether they shape webhook payloads. Treat templates as not
a control for this purpose.

### Rule titles

A rule name can itself leak detail (for example a name that embeds a host or a
service). Two safe options, in order of preference:

1. A `public_title` annotation on each rule, read by the router. The annotation
   is a reviewed, static string.
2. An allowlist in the router mapping rule name to public title.

Anything unmapped falls back to text only: `<tier> alert, see ticket <id>`. The
raw rule name never leaves the router for an unmapped rule. INFERRED: the router
already has an `ALLOWED_ALERTNAMES` constant for P1 (`docs/alert-taxonomy.md`,
step 3), which is the natural home for the mapping.

## Ticket link pattern

The router builds the link: `TICKET_BASE_URL/<id>`.

- Today (no ticket system): `<id>` is the Grafana alert fingerprint, or the n8n
  execution id when the fingerprint is absent. `TICKET_BASE_URL` is empty, so the
  link is omitted. VERIFIED (webhook page above): `fingerprint` is label based,
  so alerts with identical labels share it. INFERRED: a fingerprint is an opaque
  hash and does not itself reveal a host, but it is stable per label set and so
  correlates repeats. Accept for now, and replace it with a ticket id once
  tickets exist.
- Later: the ticket system creates the ticket first, returns its id, and holds
  the detail behind authentication. A person must sign in to read anything. The
  message alone is not enough to act on, by design.
- `TICKET_BASE_URL` is a setting, not a secret, and carries no query string or
  token.

## Per-platform setup (owner steps)

All of this is configuration the owner performs. Nothing here has been run.

### Discord private channel (P2, P3, and the P1 channel copy)

VERIFIED (https://docs.discord.com/developers/topics/permissions and
https://docs.discord.com/developers/resources/channel, per the researcher's read
2026-11-20, restated here):

1. Create a text channel in a server only the on-call people belong to.
2. Set the `@everyone` role override to deny View Channel.
3. Create one on-call role. Give it View Channel and Read Message History on this
   channel only.
4. Create a webhook in that channel (Channel settings, Integrations).
5. Store the webhook URL in the secret manager, dev environment first, never in
   the repository. A webhook URL is a credential: anyone holding it can post
   (https://docs.discord.com/developers/resources/webhook, read 2026-11-20).
6. Set `allowed_mentions` in every post so a title cannot ping a role or
   everyone.

Limits to accept: server administrators and the owner can still see the channel,
and Discord stores message text in clear. Both are why the payload is minimal.

### Discord direct messages (P1)

VERIFIED (https://docs.discord.com/developers/resources/webhook, read
2026-11-20): a webhook is bound to one channel and the page says nothing about
DMs. VERIFIED (https://docs.discord.com/developers/resources/user, per the
researcher): a DM needs a bot. The bot calls `POST /users/@me/channels` with
`recipient_id`, then posts to the returned channel id.

1. Create an application and bot in the Discord developer portal.
2. Invite the bot to the private server (the recipient must share a server with
   the bot).
3. Store the bot token in the secret manager, dev environment first. A bot token
   is a stronger secret than a webhook URL (it can read and act as the bot), so
   it is a separate secret with its own rotation.
4. Each recipient allows direct messages from server members, or the send fails.

Failure modes to design for (INFERRED from the API shape): 403 when the user
blocks DMs or left the server, rate limits, and token revocation. A failed DM
must not fail the P1 fan out. It is reported through the existing failure notice
(`docs/notification-failure-alerts.md`).

### Matrix private alerts room (P1, P2, P3)

VERIFIED (Matrix spec, `createRoom`, per the researcher): `preset:
private_chat` makes an invite-only room. A DM is an invite-only room created with
`is_direct: true`.

1. Create a relay account on the homeserver.
2. Create the room with `private_chat`, invite only the on-call people.
3. For P1 DMs, the relay creates one invite-only `is_direct` room per recipient.
4. Store the relay access token in the secret manager, dev environment first.

Encryption (INFERRED, not verified: the E2EE section of
https://spec.matrix.org/latest/client-server-api/ could not be read, the fetch
tool truncated the page before it, 2026-11-20): a plain relay without an
encryption stack cannot write readable messages into an encrypted room. So use an
unencrypted invite-only room and say so to the owner: homeserver administrators
can read it. The relay should refuse to send if the room has an
`m.room.encryption` state event, and report that instead of sending
unreadable text. The minimal payload is what makes an unencrypted room
acceptable.

Matrix delivery is design-only today (#147).

### Email and Pushover (P1)

No new setup. Email stays the Grafana-side path from `docs/alert-taxonomy.md`;
Pushover stays the router path. Both receive the minimal payload only. INFERRED:
the Grafana email contact point sends Grafana's own template, which includes
links and labels. Making it minimal needs a custom template or routing email
through the router; this is the largest gap, see follow-ups.

## Risks

| Risk | Effect | Mitigation |
|------|--------|------------|
| A rule title or label leaks detail | Detail in clear text on a third party | Public title allowlist, unmapped falls back to text only |
| Bot token leaks | Attacker reads and posts as the bot | Secret manager only, own rotation, least permissions, DM-only bot |
| Webhook URL leaks | Attacker posts fake alerts | Secret manager, rotate by deleting and recreating the webhook |
| Message alone is not enough to act | Slower response | Intended. Link goes to the ticket; until tickets exist the id is looked up in n8n or Grafana |
| DM fails (blocked, left server) | A P1 recipient misses the DM | Other platforms still fire, failure notice via Pushover |
| Fan out multiplies failures | One failing branch blocks the others | Each destination is independent and a failure in one does not stop the rest |
| Matrix room unencrypted | Homeserver admin can read | Minimal payload, stated openly |
| Fingerprint correlates repeats | Observer of the channel sees repeats share an id | Accepted until ticket ids exist |
| Heartbeat or ops traffic mixed into private channel | Noise, leak of ops detail | Heartbeat never sent to people (unchanged) |

## Rollback

All changes are additive and gated by settings, so rollback is a setting:

- Set the per-platform private flags off and the router falls back to today's
  behavior (P1 Pushover plus Discord, P2 and P3 Discord).
- Revoke the bot token and webhook URL in Discord and rotate the secrets.
- Delete the Matrix room and relay account.
- The minimal payload can be switched back to the current payload by a single
  setting during the cutover (remove the setting once confirmed, since the
  current payload carries the detail this note removes).

## Owner decisions list

1. Discord DM bot: approve creating a bot and holding its token. Recommended:
   yes, P1 only, minimal permissions.
2. Matrix: accept an unencrypted invite-only room. Recommended: yes with the
   minimal payload, revisit when an encryption-capable relay exists.
3. P3: one message per alert, or only the weekly digest, in the private channel.
   Recommended: the digest, since the digest is not built, per alert until then.
4. Rule titles: `public_title` annotation or router allowlist. Recommended:
   annotation, with the allowlist as fallback.
5. Interim ticket id: fingerprint, or n8n execution id. Recommended: execution
   id, which does not repeat across firings.
6. Email: route through the router for a minimal body, or keep Grafana email and
   accept its template. Recommended: through the router.
7. Server membership: who is in the private Discord server and Matrix room. The
   owner names the recipients; this note holds no personal data.

## Proposed follow-up issues (not filed)

1. Router: minimal payload builder with field allowlist, drop all Grafana links.
2. Router: `public_title` annotation read plus allowlist fallback, text-only for
   unmapped rules, with a test per rule file that every rule has a mapping.
3. Router: per-tier destination table as settings, fan out independent of
   failures.
4. Discord: private channel send with `allowed_mentions`, and the bot DM sender
   with 403 and rate-limit handling.
5. Matrix relay (extends #147): invite-only room, refuse on `m.room.encryption`,
   DM rooms for P1.
6. Email: minimal template or route via the router.
7. Ticket link: `TICKET_BASE_URL` setting, interim id, and the contract for the
   future ticket system.
8. Secrets: Doppler entries for the bot token, Matrix token and new webhook,
   dev first, with rotation notes.
9. Game-day scenario: P1 reaches all platforms and DMs, one platform down still
   delivers.

## Verified and inferred

| Claim | Status | Source |
|-------|--------|--------|
| Grafana webhook payload fields and Custom Payload option | VERIFIED | Grafana webhook notifier page, 2026-11-20 |
| Templates attach to contact points, webhook effect unstated | VERIFIED | Grafana templates page, 2026-11-20 |
| Discord webhook bound to one channel, DMs not covered | VERIFIED | Discord webhook docs, 2026-11-20 |
| DM via bot and `POST /users/@me/channels` | VERIFIED (researcher) | Discord user docs |
| Private channel permission model | VERIFIED (researcher) | Discord permissions docs |
| Matrix `private_chat` preset and `is_direct` | VERIFIED (researcher) | Matrix `create_room.yaml` |
| Matrix encryption handling by a plain relay | INFERRED | Spec section not readable in this session |
| Custom Payload works on the installed Grafana version | INFERRED | Not checked live |
| DM failure modes, fingerprint behavior, email template contents | INFERRED | General knowledge |
