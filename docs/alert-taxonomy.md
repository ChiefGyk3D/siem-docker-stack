# Alert taxonomy: labels, tiers and routing

One label set for every Grafana alert rule, and what each tier means for
delivery. `tests/python/test_alert_taxonomy.py` enforces it against every file
under `docker/grafana/provisioning/alerting/`. Issue #71, epic #62.

Claim marks: **verified** names the file or router node that shows it;
**inferred** is reasoning from those files, not read from a live system. No live
Grafana or n8n was queried for this page.

## Tiers

The owner's tiers (verified: `docs/design/channel-redundancy.md`, "Tier mapping"):

| Tier | Meaning | Delivery today | Labels |
|------|---------|----------------|--------|
| P1 | Page now | Pushover phone push plus Discord. With the email example installed, also email | `severity=critical`, `phone=true` |
| P2 | Chat | Discord only | `severity=warning`, `phone=false` |
| P3 | Weekly digest | Weekly digest email. NOT BUILT: today a P3 alert goes to Discord like any firing alert | `severity=info`, `phone=false`, `digest=true` |
| none | Not an alert for people | Heartbeat ping only (exception, below) | `heartbeat=true` |

Delivery claims:

- Discord is sent for every firing or resolved alert that is not a heartbeat.
  Verified: `n8n/grafana-alert-router.json`, connections `Normalize Alert` ->
  `Heartbeat?` (false branch) -> `Alert Status` -> `Discord — Firing` /
  `Discord — Resolved`.
- Pushover is sent only when the label `phone` is exactly `true`, and only when
  the constant `PUSHOVER_ENABLED` is `true` (it ships `false`). Verified: node
  `Build Pushover Payload` (`phone = str(l.phone, 10) === 'true'`,
  `enabled: PUSHOVER_ENABLED === true && phone`), then `Pushover Enabled?`.
- Pushover priority: for a firing alert, 2 (emergency, repeats) when the alert
  name is in `ALLOWED_ALERTNAMES` and (`severity=critical` or
  `update_security=true`); 1 when it is urgent or `severity=warning` but not
  allowlisted; 0 otherwise. Resolved alerts are priority 0 and cancel repeats by
  tag. Verified: node `Build Pushover Payload`. Consequence (inferred): a new P1
  rule pages at priority 1, not 2, until its title is added to
  `ALLOWED_ALERTNAMES`.
- The email P1 path is Grafana-side, not n8n. A route matching `severity=critical`
  and `phone=true` sends to contact point `email-p1` with `continue: true`.
  Verified: `email-notification-policy.yml.example`. It ships as an example, so
  it is live only after the owner installs it (`docs/channel-redundancy.md`).
- The weekly digest is not built. Verified: `docs/expiry-watch.md` ("What is not
  built yet"), `docs/design/channel-redundancy.md` ("What is not covered").
  Nothing reads `digest` or `tier` today (verified: neither string appears in
  the router JSON or any policy example). They are metadata for the future
  digest and for the test; adding them cannot change routing today.

## Label set

Every rule carries these labels, all quoted strings (Grafana label values are
strings; an unquoted `true` becomes a YAML boolean and is not the string the
router compares).

| Label | Required | Allowed values | Read by |
|-------|----------|----------------|---------|
| `severity` | yes | `critical`, `warning`, `info` | Router priority (`Build Pushover Payload`); update policy repeat intervals (`update-notification-policy.yml.example`); email route |
| `tier` | yes | `P1`, `P2`, `P3`, `none` | Nothing yet (inferred: the future digest and routing by tier). Must agree with `severity` and `phone` |
| `phone` | yes | `true`, `false` | Router phone gate (`Build Pushover Payload`); heartbeat contract (`Build Heartbeat Ping`); email route |
| `alert_group` | yes | `updates`, `heartbeat`, `alert-path`, `infrastructure`, `backup` | Display only (inferred: nothing reads it). Extend the set here and in the test when a new area appears. `infrastructure` (issue #224): host down and disk full; it may carry `phone=true` only as P1 `critical`, and never an update label. `backup` (issue #228): stale or failed backup alerts; needs `source`, never an update label, and its P2 warning may page (below) |
| `source` | when `alert_group` is `updates` or `backup` | `unifi`, `pfsense`, `twingate`, `synology` (the set `SOURCES` in `tests/python/test_alert_taxonomy.py` is the authority; add a value there and here together) | Display only. This is the service owner or area; the data source or device family the rule watches |
| `digest` | P3 only | `true` | Nothing yet (future digest) |
| `update_alert` | when `alert_group=updates` | `true` | Policy route `update-notification-policy.yml.example` |
| `update_security` | optional, needs `update_alert` | `true` | Router: makes a firing alert urgent (`Build Pushover Payload`) |
| `heartbeat` | heartbeat rule only | `true` | Router: nodes `Heartbeat?` and `Build Heartbeat Ping` |
| `delivery_failure` | failure rule only | `true` | Policy route `notification-failure-notification-policy.yml.example` |

Any label outside this table is rejected by the test, since nothing reads it.
The router also receives `alertname` and `grafana_folder`, which Grafana adds;
they are not authored.

Tier rules (checked by the test):

- P1 = `severity=critical` and `phone=true`.
- P2 = `severity=warning` and `phone=false`. Two owner-decided exceptions may page: a pending-update warning (`alert_group=updates`, `update_alert=true`; issues #199, #200) and exactly one stale-backup warning, the rule uid `unifi-backup-stale-8d` (`alert_group=backup`; owner decision 2026-11-27, issue #228, "warn at 8 days": phone twice a week, repeat 84h). The set `PAGING_P2_BACKUP_UIDS` in the test is the authority: any other P2 backup rule with `phone=true` fails the test.
- P3 = `severity=info`, `phone=false` and `digest=true`.
- `tier=none` only with `heartbeat=true`, which must be `severity=info`,
  `phone=false`, no `digest`.
- `digest` only on P3. `warning` with `phone=true` and `critical` with
  `phone=false` match no tier.

## How the router maps labels to channels

All verified from `n8n/grafana-alert-router.json`, by node name:

1. `Grafana Webhook` (header auth) -> `Normalize Alert`: copies up to 50 labels
   as capped strings; unknown labels pass through untouched, so adding a label
   never breaks the router.
2. `Heartbeat?`: `labels.heartbeat === 'true'` goes to `Build Heartbeat Ping`
   (no Discord, no Pushover); anything else goes to `Alert Status`.
3. `Alert Status`: `firing` -> `Discord — Firing`, `resolved` ->
   `Discord — Resolved`, else `Discord — Malformed`. Each goes on to
   `Build Pushover Payload`.
4. `Build Pushover Payload` reads `phone`, `severity`, `update_security`,
   `alertname`, `fingerprint`. `Pushover Enabled?` gates on `phone=true` and the
   `PUSHOVER_ENABLED` constant.
5. `Build Heartbeat Ping` reads `heartbeat` and `phone`: a ping is "good" only
   with `heartbeat=true` and `phone=false`, else it sends `/fail`.

The router never reads `tier`, `digest`, `source`, `alert_group` or
`delivery_failure`.

## Rule-authoring checklist

1. Pick the tier first, then set `severity` and `phone` to match the table.
2. Add all required labels (`severity`, `tier`, `phone`, `alert_group`), every
   value a quoted string. Updates rules also need `source` and
   `update_alert: "true"`.
3. P1: add the rule title to `ALLOWED_ALERTNAMES` in the router if it should
   page at emergency priority, and keep it equal to the rule title.
4. P3: add `digest: "true"`. Remember the digest is not built; until then a P3
   alert posts to Discord when it fires.
5. Set `noDataState` and `execErrState` on purpose and write the reason in a
   comment (see the existing rules for the three patterns).
6. Never give a rule a label the router or a policy does not read, unless it is
   added to this page and to `ALLOWED_LABELS` in the test in the same change.
7. A change to `severity` or `phone` on an existing rule changes routing.
   Say so in the PR and get the owner's word.
8. Run `tests/python/test_alert_taxonomy.py`.

## Exceptions that exist today

| Exception | Where | What differs | Source |
|-----------|-------|--------------|--------|
| Heartbeat | rule `alert-path-heartbeat` | `tier=none`, `heartbeat=true`, `phone=false` is part of the contract; never reaches Discord or the phone; pings the observer | `heartbeat-alert-rule.yml`, router nodes `Heartbeat?`, `Build Heartbeat Ping` |
| Notification failure | rule `grafana-notification-failures` | Tier P2, but routed by `delivery_failure=true` to the direct Discord contact point `discord-direct` (example policy), never through n8n, so a failed n8n cannot silence it. `phone=false` so the email route never matches it | `notification-failure-alert-rule.yml`, `notification-failure-notification-policy.yml.example` |
| Expiry watch | not a Grafana rule; `scripts/expiry_watch.py` posts to the router's own `Expiry Watch Webhook` | Labels `alertname`, `severity`, `expiry_watch`, `item`, `kind`, `stage`, optional `phone=true`, plus `source=expiry-watch` added by `Check Expiry Secret`. No `tier`: severity is derived from days left (`expired` critical; `disappeared` and 14 days or fewer warning; else info), and `phone=true` is a per-item opt-in (`pushover` channel), so `info` or `warning` with `phone=true` is possible. The alert name is not on `ALLOWED_ALERTNAMES`, so these notices are Pushover priority 1 at most. The test does not cover them; a test of the script's payload is the place to guard them | `scripts/expiry_watch.py` (`build_payload`), router node `Check Expiry Secret` |
| Infrastructure P1 | rules `infra-host-down-critical`, `infra-disk-critical` | `alert_group=infrastructure`, P1 with `phone=true`. Their titles are deliberately NOT on `ALLOWED_ALERTNAMES`, so they page at Pushover priority 1, not 2 (decision for the owner; see `docs/infrastructure-alerts.md`) | `infra-alerts.yml`, router node `Build Pushover Payload` |
| UniFi backup health | rules `unifi-backup-stale-8d`, `unifi-backup-stale-15d`, `unifi-backup-sync-failed` | `alert_group=backup`, `source=unifi`, shipped paused. The 8-day rule is a P2 warning with `phone=true` (owner decision 2026-11-27); the other two are P1. Their titles are NOT on `ALLOWED_ALERTNAMES` (Pushover priority 1). The example policy `unifi-backup-notification-policy.yml.example` routes on `alert_group=backup` (84h and 24h repeats) | `unifi-backup-alert-rule.yml`, `docs/unifi-pi-backup.md` |
| Malformed alert | router fallback | Not a rule. `Build Pushover Payload` sends priority 1 when `PUSHOVER_ENABLED` is true, with no `phone` label | router node `Build Pushover Payload` (catch branch) |

## Rules that break the taxonomy today

Verified by running the test against the rule files at the time of writing.

- None. `update-unifi-pending-24h` and `update-pfsense-pending-24h` were
  `severity=warning` with `phone=true` (neither P1 nor P2). Owner decision
  2026-11-20 (issue #152): they are P2 with `phone=false`, so no phone push; they
  alert Discord, and Matrix once the inactive example route in
  `matrix-p2-notification-policy.yml.example` is enabled
  (`docs/channel-redundancy.md`). `KNOWN_VIOLATIONS` in the test is empty.

Pure label additions made with the test (cannot change routing, since no policy
or router node reads `tier` or a `phone=false` on these rules): `tier` on seven
rules, and `phone: "false"` on the notification failure rule.
