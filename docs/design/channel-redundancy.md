# Design: channel redundancy for the alert path

Status: DRAFT for the owner's decision. No code or live change is part of this
document. Tracked in issue #82 (epic #62, NOC/SOC alerting platform).

Every claim is marked. **Verified** means read from a file in this repository
at the commit named in the PR (path cited). **Inferred** means reasoned from
those files or from general knowledge of the products, and not checked against
a live system or the vendors' current documentation.

## Problem

Issue #82 asks for a configurable fallback per priority (for example Discord,
then phone, then email or Matrix) so that one failing channel never drops a P1
alert. Verified (issue #82): today the router answers `received` as soon as it
accepts an alert, and failed runs are not stored, so a broken Discord step could
leave no trace. Part of that has since been fixed (see "Already covered"), but
the remaining gap is the one this design addresses: when the primary channel is
down, the only notice of that fact travels the same few channels, and a P1 alert
itself has no second delivery path.

Design goals:

1. A P1 alert reaches a human through at least two independent channels, or the
   operator learns that it could not.
2. A single failing vendor (chat, push, mail) never silences the stack.
3. Channels are settings, not code. Another deployment picks its own.
4. No new always-on dependency that is itself a single point of failure.

## Failure cases

What each failure does today, and whether anything tells the owner.

| Failure | What breaks | Who notices today |
|---------|-------------|-------------------|
| Discord down or webhook revoked | Router Discord steps fail | Router answers 502 and the error handler sends one Pushover message (verified: `docs/update-alerting.md`, "Delivery and failure reporting"). Phone still gets P1 alerts that carry `phone=true`. |
| Pushover down or credential broken | Phone push fails | Router sends a Discord notice "phone delivery failed" and keeps answering 200 (verified: same section). Discord still works. |
| Discord and Pushover both down | No human channel works | Inferred: nothing. The error handler's only default channel is Pushover (`NOTIFY_PUSHOVER = true`, `NOTIFY_DISCORD = false`; verified in `n8n/alert-router-error-handler.json`). Only the external heartbeat observer might notice, and only if the alert path itself is broken, not if just the two vendors are. |
| n8n down or router inactive | Grafana cannot deliver | Grafana rule on failed notifications (verified: `docs/notification-failure-alerts.md`) routes to a direct Discord contact point, so it needs Discord only. The heartbeat stops and the observer alerts (verified: `docs/heartbeat.md`). |
| Grafana down | No rules evaluate, no heartbeat | The observer alerts after period plus grace (verified: `docs/heartbeat.md`; the game-day scenario `grafana-down` expects it, unverified live per `docs/game-day.md`). Prometheus rules and Alertmanager do not depend on Grafana (verified: `docker/prometheus/prometheus.yml`, `alerting:` block). |
| Internet down | Every cloud channel and the observer ping fail | Inferred: nothing reaches the owner from inside the lab. The observer, being outside the lab, sees the heartbeat stop and alerts through its own channels, which is the one signal that survives. A local-only channel (a siren, a local relay) would be needed for in-lab awareness. |
| Alertmanager path | Pipeline-health alerts (Prometheus rules) | Verified: `docker/alertmanager/alertmanager.yml` has one receiver, a webhook to `http://n8n/webhook/alertmanager-siem`. No workflow in `n8n/` listens on that path (grep of `n8n/` found no `alertmanager-siem`), so this is either imported live only or not wired. Either way it shares n8n's failure. Open question 5. |

Key observation (verified from the files above): everything delivered to a human
today funnels through one n8n router, with Discord and Pushover as the only two
human channels. The independent checks are the failure rule (direct Discord) and
the heartbeat observer (outside the lab). So the weak point is "n8n works but
both vendors fail", and "internet down inside the lab".

## Already covered

| Piece | What it does | Source (verified) |
|-------|--------------|-------------------|
| Heartbeat to a hosted or self-hosted observer | A synthetic alert crosses Grafana, the contact point and the router every 5 to 6 minutes; the router pings the observer; silence makes the observer alert through its own channels. It proves the path, not Discord or Pushover. | `docs/heartbeat.md` |
| Notification failure rule | Grafana alerts when its own delivery to a contact point failed. Routed to a direct Discord contact point, not through n8n. Cannot see a router that answers 200 and then drops the alert. The counter name is UNVERIFIED against live Grafana. | `docs/notification-failure-alerts.md`, `docker/grafana/provisioning/alerting/notification-failure-*` |
| Router failure reporting | 502 answer when a Discord step fails; phone failure raises a Discord notice; the error workflow sends one Pushover message (Discord optional behind a constant). | `docs/update-alerting.md`, `n8n/alert-router-error-handler.json` |
| Game-day scenarios | `discord-unreachable`, `phone-unreachable`, `heartbeat-silent`, `n8n-down`, `grafana-down`, `router-inactive`, `wrong-header`. Dry run by default; changes need `--apply --confirm-live`. Not yet run against a live stack. | `docs/game-day.md`, `scripts/gameday.py` |
| Channel model in the expiry watch | `KNOWN_CHANNELS = pushover, discord, matrix, email, webhook`; per-stage routes are a list of channel names; matrix and email are not built on master (`BUILT_CHANNELS = pushover, discord, webhook`). | `scripts/expiry_watch.py` lines 52-54, 921-924 |
| Matrix and email adapters in the expiry watch | Open PR #105 adds direct Matrix (`m.notice` with a bearer token from an env var) and email (SMTP with required STARTTLS, secrets from env) to the script, with fakes only. Inferred: a useful reference for the adapter shape and the security rules, but it is a standalone script, not the router. | PR #105 description (not on master, so not read as a file) |

What is not covered (verified by absence): no second human channel for P1 alerts
inside the router; no weekly digest; no way to tell the owner that both Discord
and Pushover are failing at once; nothing for an in-lab "internet is down".

## Tier mapping

The owner's tiers, mapped to channels. Channel names are settings; the defaults
below are the owner's current ones.

| Tier | Meaning | Primary | Second path (this design) | Notes |
|------|---------|---------|---------------------------|-------|
| P1 | Page now | Phone push (Pushover, priority 2 for allowlisted names) plus Discord | Email and Matrix, independent of both primaries | Both primaries are sent at once today (verified: the router sends Discord for every firing alert and Pushover when `phone=true`). The second path fires on failure of either, or on a P1 always (open question 2). |
| P2 | Chat | Discord | Matrix (same message) | A failure of the one channel uses the fallback. Not a page. |
| P3 | Weekly digest | Email | none | Low urgency; a single digest is cheap to lose and rebuild. Not built (verified: `docs/expiry-watch.md`, "What is not built yet", lists the weekly digest line). |

Label mapping, verified from `docs/update-alerting.md`: `phone=true` is the only
way an alert reaches Pushover; `severity` sets repeat intervals and Pushover
priority. Inferred: P1 equals `severity=critical` plus `phone=true`, P2 equals
warning, P3 equals info. The taxonomy would gain no new label if the tier is
derived from `severity` and `phone`; a new `tier` label is an option (open
question 3).

## Options for a second path

### Option A: n8n fan-out to Matrix and email

Add Matrix and email steps to the router next to Discord and Pushover, behind
the same kind of constants (`MATRIX_ENABLED`, `EMAIL_ENABLED`). On any primary
failure, or for every P1, send through them as well.

- Pro: one place for routing and formatting; reuses the existing failure
  detection (Discord error item, Pushover error output); consistent with how
  Pushover was added (verified pattern: constants at the top of a Code node, a
  Custom Auth credential, `docs/update-alerting.md`).
- Pro: the error handler can use the same steps, so "Discord and Pushover both
  down" is reported on a third channel.
- Con: shares n8n's failure domain. n8n down or the router inactive means no
  fan-out at all (inferred; n8n is the single hub).
- Con: more nodes in an already large workflow, and every new channel is more
  code the router tests must model (verified: `tests/python/test_router_delivery.py`
  and the other router tests run the Code nodes under Node).

### Option B: a Grafana contact point directly to a second channel

Add a second contact point (Grafana ships an email contact point type and a
Matrix-capable webhook path; inferred, check current Grafana documentation) and
list both contact points in the notification policy route for P1, so Grafana
delivers to both in parallel without n8n.

- Pro: independent of n8n and of Discord and Pushover. This is the same pattern
  already shipped for the failure rule (verified: `notification-failure-contact-point.yml.example`
  is a direct Discord contact point for exactly that reason).
- Pro: repo-only to define (a provisioned file or example, secrets from the
  Grafana container environment via `$VARIABLE`, verified pattern in
  `contact-points.yml`).
- Con: shares Grafana's failure domain. Grafana down means nothing from
  Grafana-managed rules.
- Con: formatting is Grafana's templating, not the router's, so messages differ
  between channels (inferred).
- Con: Grafana provisions one notification policy tree per organization, so the
  routes ship as `.example` files and must be merged by hand (verified:
  `docs/update-alerting.md`, "Notification policy"). A second route adds to that
  manual step.
- Con: Prometheus and Alertmanager alerts are not covered, because they do not
  use Grafana contact points (verified: `alertmanager.yml`).

### Option C: an out-of-band check from outside the lab

Extend what the heartbeat observer already does. The observer (verified:
`docs/heartbeat.md`, three variants) sits outside the lab's failure domain and
alerts through its own channels when pings stop. Make it also carry the P1
fallback: a second heartbeat-style check per critical rule, or a periodic
end-to-end synthetic P1 whose absence at the phone or email is the signal.

- Pro: the only option that survives "internet down" and "the whole lab down"
  as a signal (inferred, because the observer is outside the lab).
- Pro: needs no new code in the router. The observer's channels (email, push)
  are configured in the observer.
- Con: detects a broken path, not an individual alert; it cannot carry the text
  of a real P1.
- Con: the hosted variants need a vendor account; the self-hosted ones need
  another host in another failure domain (verified as the advice in
  `docs/heartbeat.md`). This is a live-side change by the owner.

### Option D: Alertmanager as the second router

Alertmanager (verified present in `docker/docker-compose.yml` and
`docker/alertmanager/alertmanager.yml`) has native receivers for email and
webhooks. Route P1 pipeline-health alerts to an email receiver in addition to
n8n.

- Pro: independent of both Grafana and n8n for the alerts it owns. Fits the
  stated Phase F3 goal "Grafana dying must not take alerting with it"
  (verified: `docs/game-plan.md`).
- Con: covers only Prometheus rules, not Grafana-managed ones such as the update
  alerts. Would need Grafana to also send to this Alertmanager (a config choice
  I did not verify; inferred that Grafana can).
- Con: Alertmanager does not interpolate environment variables (verified: the
  header of `scripts/render-alertmanager-config.sh`), so a secret in an SMTP
  receiver needs a rendered file or a secrets-file reference; the render script
  must not write the secret into a tracked file (open question 4).

### Comparison

| | Survives n8n down | Survives Grafana down | Survives Discord and Pushover down | Survives internet down | Repo-only | Effort |
|---|---|---|---|---|---|---|
| A: n8n fan-out | no | no | yes | no | mostly | medium (router code and tests) |
| B: Grafana second contact point | yes | no | yes | no | yes (examples) | low |
| C: out-of-band observer | yes | yes | yes | yes (as a signal) | no (live account) | low, owner action |
| D: Alertmanager email | yes | yes (own rules) | yes | no | partly (rendering) | medium |

## Recommendation

Layer B and C, then add A only if the owner wants a second channel for every P2
too. Reasoning (inferred, from the table above):

1. **B first.** It is the cheapest independent path, needs no router change,
   follows a pattern the repo already ships and tests, and covers the stated
   gap (Discord and Pushover both down while n8n is up, and also n8n down while
   Grafana is up). Define a second contact point (email, and Matrix if Grafana
   supports it on the owner's version) and add it to the P1 policy route next to
   the n8n contact point.
2. **C alongside.** It is the only layer that tells the owner "the lab cannot
   reach anyone" because it lives outside the lab. It builds on the heartbeat
   that already exists. The cost is an owner action on the observer, not code.
3. **A deferred.** The router is the most complex component here; adding
   channels to it raises test and review cost and still shares n8n's failure
   domain. Use A for the error handler only (one more constant, off by default),
   which is small and reports "both primaries down" on a third channel.
4. **D optional**, only if the owner wants pipeline-health alerts independent of
   Grafana and n8n; it is blocked on the rendering question and on whether
   anything consumes `alertmanager-siem` today.

The tradeoff to accept: B and C notify through channels whose formatting is not
the router's, and a fan-out to the second channel for every P1 can double-page
(open question 2).

## Repo-only versus live changes

Repo-only (can be done in PRs without touching the lab):

- Provisioned or example files for a second Grafana contact point and policy
  route (B), following `notification-failure-contact-point.yml.example`.
- A `docs/` section for the tier mapping and the settings table.
- One more constant on the error handler for a third channel (A, minimal).
- Game-day scenarios for the new path in `scripts/gameday.py` and
  `docs/game-day.md` (for example "primary channels down, second path
  delivers").
- Tests that parse the example files and the router/handler graph, as the
  existing ones do (`tests/python/test_notification_failure_alert.py`,
  `tests/python/test_heartbeat.py`).

Needs live changes by the owner:

- Creating the email sender account or Matrix bot and room, and storing their
  credentials in the secret manager (never in the repo).
- Passing the new variables into the Grafana container environment and
  restarting it (Grafana loads provisioning at startup; verified:
  `docs/heartbeat.md`, "Enable it" step 1).
- Merging the new route into the live notification policy tree (manual, one
  tree per organization).
- Configuring the observer's channels and its period and grace (C).
- Running the game day against the live stack and recording the result.

## Configurability

Goal: other deployments choose their own channels with no code edit.

- Channel types as data, not names baked into the router. For B, the contact
  point type and its settings are Grafana provisioning, so any type Grafana
  supports works. Inferred.
- Per-tier channel lists as a documented table in `docs/`, mirroring the shape
  the expiry watch already uses: `routes.<stage> = [channel, ...]` from a fixed
  set of known names (verified: `scripts/expiry_watch.py` lines 921-924). If the
  router grows a channel list, reuse that vocabulary so the two stay aligned.
- No service names hard-coded in new files: examples use `example.com` and
  documentation addresses, as the existing docs do (verified:
  `docs/heartbeat.md`, `docs/update-alerting.md`).
- Off by default. A new channel does nothing until its variable is set, the
  same rule as `HEARTBEAT_PING_URL` and `PUSHOVER_ENABLED` (verified).
- Open source: no vendor account is required to run the stack. Every channel is
  optional and has a self-hosted option (a Matrix server, an SMTP relay,
  self-hosted Healthchecks or Uptime Kuma; verified for the observer in
  `docs/heartbeat.md`).

## Security notes

- Secrets reach the system only as environment variables or a secret manager
  reference (verified policy: `docs/update-alerting.md` uses a secret manager
  for the webhook secret and Pushover keys, and `$VARIABLE` interpolation in
  Grafana provisioning). Never write a webhook URL, token or SMTP password in a
  repo file, an example with a real value, a command line, or a log.
- A second webhook URL is a bearer secret: anyone holding it can post to the
  channel. Use a different URL from the primary so one revocation does not
  silence both (verified advice in `notification-failure-contact-point.yml.example`).
- The failure path must not carry alert content that could leak. The error
  handler is built to send only the workflow name, failed node, a trimmed error
  and the execution id (verified: `n8n/alert-router-error-handler.json`). Keep
  that rule for any third channel.
- Email: require TLS, verify the certificate, send from a fixed address to a
  fixed address from config only. Verified as the standard PR #105 sets for the
  expiry watch; reuse it as the baseline. Inferred that the Grafana email
  contact point supports equivalent settings: check before relying on it.
- Matrix: an encrypted room is not supported by a plain bot send (stated in PR
  #105); use an unencrypted alerts room and say so.
- n8n `$env` access: reading environment values in n8n nodes needs a setting
  that widens what any workflow can read (verified: `docs/heartbeat.md`). Option
  A would either need that or n8n credentials; prefer credentials.
- Rotation: any new secret follows the existing rotation note (change the
  secret manager value and the consumer together).

## Test and game-day plan

All of this is inferred as a plan; none is run. Extend `docs/game-day.md` and
`scripts/gameday.py` (verified: dry run by default, `--apply --confirm-live`
for changes, injectable runner, revert printed).

Repo tests (in CI, no live system):

1. The example contact point and policy files parse, contain no real secret, and
   read secrets only from `$VARIABLE`.
2. The P1 route lists both contact points; P2 lists one; a test fails if a P1
   rule has no second path.
3. Any router or handler change keeps the existing graph tests green and adds one
   for the new off-by-default constant.

Game-day scenarios to add, each with an expected observation:

| Scenario | Inject | Expected |
|----------|--------|----------|
| `primaries-down` | Discord and Pushover names fail to resolve inside n8n together | Second path (email or Matrix) delivers a P1 test alert; the owner is told both primaries failed |
| `n8n-down-p1` | Stop n8n, fire a P1 test | Grafana's second contact point delivers directly |
| `grafana-down` (existing) | Stop Grafana | Observer alerts; confirm the observer's channel is not Discord or Pushover |
| `internet-down` (new, manual) | Cut the lab's upstream from a safe point | Observer alerts from outside; document how long it took |
| `second-path-down` | Break only the second channel | A notice reaches a primary, so a dead fallback is not silent |

Process per scenario: the existing checklist (window agreed, dry run, baseline
test alert, inject, observe, revert, verify recovery, record). A scenario passes
only when the alert arrived through a path that does not depend on the broken
link (verified wording: `docs/game-day.md`). Record time-to-notice for each.

## Open questions for the owner

1. **Direction.** Recommended: B plus C (a Grafana second contact point and the
   outside observer), with A limited to the error handler. Or A only, if you
   prefer one router.
2. **P1 behavior.** Should the second path fire only when a primary fails, or on
   every P1 (a double page, but no dependence on failure detection)? Recommended:
   every P1, because failure detection itself can miss (the router can answer 200
   and drop an alert; verified in `docs/notification-failure-alerts.md`).
3. **Tier labels.** Derive P1/P2/P3 from `severity` and `phone`, or add a `tier`
   label? Recommended: derive, no new label.
4. **Second channel choice.** Email, Matrix, or both? Which sender account and
   which room, and who provisions them? (Needs you; secrets go to the secret
   manager.)
5. **Alertmanager.** Is anything listening on `/webhook/alertmanager-siem` in the
   live n8n? The repo has no workflow for it. If not, pipeline-health alerts
   currently have no delivery, which is a separate defect to card.
6. **Observer.** Which of the three observer variants is live, and what are its
   own alert channels? They must not be Discord or Pushover.
7. **Weekly digest (P3).** Build it in this epic or as its own issue? It is
   listed as not built in `docs/expiry-watch.md`.
8. **Internet-down awareness inside the lab.** Is the outside observer enough,
   or do you want a local channel (for example a siren or a local relay)?
9. **PR #105.** Should the router reuse that PR's Matrix and email adapters'
   rules, or stay with Grafana's built-in contact points for those channels?
