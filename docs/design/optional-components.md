# Design: optional alert router and pluggable notifiers

Status: DRAFT for the owner's decision. Docs only: no code, no configuration,
no live change. Tracked in issue #116 (epic #62), child of the deployment
variants epic #111. Companion design: [secrets-sources.md](secrets-sources.md).

Marking: **VERIFIED** means read from a file in this repository at master
c022559 (path given). **INFERRED** means reasoned from those files or from
general product knowledge and not tested or read from a vendor page. Examples
use `example.com` and placeholders only.

## 1. Problem

Issue #116: make the alert router (n8n) optional, treat notification targets
(Pushover, Discord, email, Matrix, others) as plugins with no hard dependency,
and define a minimal profile with no router and no notifier. Done when the
minimal profile starts with no router and no notifier, and each notifier can be
enabled alone.

## 2. Current state (VERIFIED)

### 2.1 Where n8n is wired in

| Fact | Source |
|---|---|
| n8n is NOT in `docker/docker-compose.yml`. It runs from its own compose file, on the stack network (external) plus a macvlan network. The repo ships only a reference example | `docs/examples/n8n-compose.example.yml`, `README.md` line 121 |
| Grafana provisions ONE contact point, a webhook to `http://n8n/webhook/grafana-alerts` with `Authorization: Bearer $GRAFANA_WEBHOOK_SECRET`. The file is always provisioned (no `.example`) | `docker/grafana/provisioning/alerting/contact-points.yml` |
| The grafana service REQUIRES `GRAFANA_WEBHOOK_SECRET`: `${GRAFANA_WEBHOOK_SECRET:?...}`, so compose refuses to start without it, router or not | `docker/docker-compose.yml` lines 228 to 232 |
| `check-env.sh` rejects an empty, placeholder or under 32 character `GRAFANA_WEBHOOK_SECRET`, and `.env.example` calls it REQUIRED | `scripts/check-env.sh`, `.env.example`, `README.md` required-secrets table |
| The `alertmanager` service is always on (no profile). Its tracked config has a default receiver `"null"` and routes critical and warning to receiver `n8n-webhook`, URL from `N8N_ALERTMANAGER_WEBHOOK_URL` rendered by a script | `docker/docker-compose.yml` line 414 on, `docker/alertmanager/alertmanager.yml(.template)`, `scripts/render-alertmanager-config.sh` |
| Prometheus always points at `alertmanager:9093` | `docker/prometheus/prometheus.yml` lines 27 to 31 |
| The only compose profiles today are `crowdsec` and `portainer` | `docker/docker-compose.yml` lines 623, 646 |
| Wazuh alerts reach n8n through a `custom-n8n` integration (webhook `/wazuh-alerts`); CrowdSec alerts through Grafana to `/crowdsec-alerts` | `docs/n8n-soar.md`, `README.md` |
| An Alertmanager comment says n8n "fans out to Discord/Matrix", but no workflow in `n8n/` contains a Matrix node and none listens on `/webhook/alertmanager-siem` | `docker/alertmanager/alertmanager.yml.template`; grep of `n8n/*.json`; the same finding is in `docs/design/channel-redundancy.md` |
| `deploy-n8n-grafana-router.py` requires `DISCORD_WEBHOOK_URL`, `N8N_API_KEY`, `N8N_PASSWORD` and exits 1 without them | `README.md` client-side table, `scripts/deploy-n8n-grafana-router.py` |

### 2.2 The notifiers today

| Notifier | How it is wired | Secret and where it lives | Enabled by |
|---|---|---|---|
| Discord (router) | n8n Discord nodes use the n8n credential "Discord Webhook Alerts" (existing credential, not recreated by the repo tooling) | n8n credential store (encrypted in the n8n volume) | always on in the router workflows (`n8n/*.json`) |
| Pushover (router) | HTTP nodes using n8n credential `pushover-api`; a `PUSHOVER_ENABLED` constant in the router Code node, default `false`; only alerts with label `phone=true` are sent | n8n credential, created by `n8n-setup-alert-router.py --credentials` from `PUSHOVER_API_KEY`, `PUSHOVER_USER_KEY` | `--pushover-on` at workflow import flips the constant |
| Discord (direct) | A Grafana `discord` contact point shipped as an example, for the notification-failure alert, so the alert about failed deliveries does not use the router | `DISCORD_FAILURE_WEBHOOK_URL` in the Grafana container environment | copy the example into provisioning (`notification-failure-contact-point.yml.example`) |
| Email (direct, P1) | Grafana SMTP contact point and policy examples, route `email-p1` with `continue: true` | `GF_SMTP_*`, `P1_EMAIL_TO` in the Grafana environment, passed through compose by hand | copy the `.example` files (`docs/channel-redundancy.md`) |
| Matrix | Delivered ONLY by `expiry_watch.py` directly (`m.notice` PUT with a bearer token); no Grafana or router path exists | `EXPIRY_WATCH_MATRIX_TOKEN` (name set in config) | the `[matrix]` table of the expiry-watch config |
| Email (expiry watch) | `expiry_watch.py` sends SMTP itself | `EXPIRY_WATCH_SMTP_USER`, `..._PASSWORD` | the `[email]` table |
| Heartbeat | n8n router branch pings an outside observer | `HEARTBEAT_PING_URL`, off when unset | environment of the n8n container |
| Router error handler | n8n workflow with constants `NOTIFY_PUSHOVER = true`, `NOTIFY_DISCORD = false` | the same credentials | constants in the workflow |

Sources for the table: `n8n/alert-router-error-handler.json`,
`n8n/grafana-alert-router.json`, `docs/update-alerting.md`,
`docs/channel-redundancy.md`, `docs/notification-failure-alerts.md`,
`docs/expiry-watch.md`, `docs/heartbeat.md`,
`scripts/live-deploy/n8n-setup-alert-router.py`.

### 2.3 What this means for "no router, no notifier"

Verified blockers to a minimal profile:

1. `GRAFANA_WEBHOOK_SECRET` is required by compose and by `check-env.sh` even
   when no router exists.
2. `contact-points.yml` is always provisioned and points at a host that does
   not exist in a minimal install, so every Grafana notification would fail
   (and the "notification failures" rule would fire for a reason that is not an
   outage).
3. `alertmanager` always runs and its non-null receiver is the router.
4. Docs and the update-alert design assume Discord is on ("Discord delivery is
   unchanged", `docs/update-alerting.md`).
5. Also outside this issue's scope but visible: `UNIFI_PASS` and the Wazuh and
   OTLP passwords are required for a UniFi-free or Wazuh-free deployment
   (`scripts/check-env.sh` REQUIRED list). Those belong to the component
   selection work under #111.

## 3. Options

### Option A: Grafana-native notifiers as plugins, router as an opt-in add-on (recommended)

Notifier = one file under `docker/grafana/provisioning/alerting/notifiers/`
shipped as `NAME.yml.example` (contact point only, secret as `$VARIABLE`) plus
its route fragment and a short doc, and an enable script that copies the file
and names the variables to put in the secret source. Notifiers: `discord`,
`pushover`, `email`, `matrix` (see below), `webhook` (generic). Each is
independent: a contact point in Grafana is a separate object, so any one can be
enabled alone. INFERRED: Grafana ships contact point types for Discord,
Pushover, email and generic webhook; this repo already uses `discord`, `webhook`
and email types (files above). Matrix has no native Grafana type that this repo
uses; Matrix would go through the generic webhook to a small bridge, or stay a
direct-send script (as `expiry_watch.py` does). Open question 3.

The router (n8n) becomes one more optional add-on, enabled by the SAME
mechanism: a `router` contact point example (today's `contact-points.yml`,
renamed to `.example`), the `docs/examples/n8n-compose.example.yml`, and the
import scripts. Compose changes:

- `GRAFANA_WEBHOOK_SECRET` becomes optional in compose (`:-` instead of `:?`)
  and `check-env.sh` requires it only when the router is enabled. Fail-closed is
  kept where it matters: the Grafana contact point and the n8n credential both
  reject an empty value (VERIFIED in `docs/update-alerting.md` and the router
  tests). The check moves from "always" to "when the router file is
  provisioned".
- `alertmanager` gets a `profiles: ["alertmanager"]` OR stays on with its
  `"null"` receiver (see recommendation below).

Minimal profile = `docker compose up` with no profile and no copied notifier
file: Grafana, Prometheus and the data services run, alert rules evaluate and
show in the Grafana UI, and no notification is sent. State this plainly in the
docs: a minimal profile is blind unless someone looks at the UI.

Trade-offs:

- Pro: no new service; each notifier is one reviewed file; native contact points
  need no n8n credential store, so the secret source design applies directly
  (`$VARIABLE` from the Grafana container environment).
- Pro: the P1 redundancy design (`docs/design/channel-redundancy.md`) already
  uses direct contact points, so this generalizes an existing pattern.
- Con: the router's value (dedup, enrichment, Wazuh triage, `phone` gating,
  emergency priority and cancel-on-resolve for Pushover) is not available to the
  plain notifiers. Pushover through a native contact point loses the router's
  emergency cancel behavior (INFERRED; the router builds it in Code node
  `pushover.tags`, VERIFIED in `n8n/grafana-alert-router.json`). Document it.
- Con: several Grafana variables must be passed through compose by hand today
  (`docs/channel-redundancy.md` step 3). An implementation should add a single
  optional include (a compose override file per notifier) so a deployer does not
  edit `docker-compose.yml`.

### Option B: everything stays behind n8n, notifiers become n8n workflows

Each notifier is an n8n sub-workflow. Rejected as the base: the minimal profile
then still needs n8n, which contradicts the issue.

### Option C: compose profiles for each notifier

A `notifier-discord` profile and so on. Rejected: compose profiles gate
SERVICES, and a Grafana contact point is configuration of a service that is
always on. INFERRED from `docker/docker-compose.yml`, where profiles only gate
`crowdsec` and `portainer`.

Recommendation: **Option A**, with these detailed choices:

- Alertmanager: put it behind `profiles: ["alertmanager"]` only if nothing in
  the minimal profile needs it. VERIFIED: Prometheus lists it as a target.
  Recommended: keep it running with the `"null"` default receiver, and make the
  `n8n-webhook` routes an include that the router add-on enables. Reason: a
  Prometheus configured for an Alertmanager that does not exist logs errors
  every evaluation (INFERRED).
- The notifier files must name no provider-specific host; defaults are
  `example.com`.
- Keep the n8n router alone-working: a deployer with n8n today changes nothing.

## 4. Security

- No secret value in a notifier file; only `$VARIABLE` names (the existing
  rule in `contact-points.yml` and the email example). Values come from the
  secret source design.
- Separate secrets per notifier and per purpose: one Discord webhook for the
  router and a different one for the direct failure path, so one revoked
  webhook does not silence both (VERIFIED advice in
  `notification-failure-contact-point.yml.example`).
- The router webhook stays authenticated (Bearer header, compared by n8n).
  Making the router optional must not weaken it: the secret is required exactly
  when the router contact point is provisioned.
- A minimal profile sends nothing out. Notifier enable scripts print variable
  NAMES only, and never echo values (rule from `lib-secrets.sh`).
- Egress: each enabled notifier adds one outbound destination (a vendor API or
  SMTP host). The docs should list it so a firewall allow-list can be built.
  INFERRED from the vendors; no vendor page was read for this design.
- The fail-closed behaviors must survive: update rules use `execErrState:
  Alerting`, and the notification-failure rule must still fire when an ENABLED
  notifier fails. With no notifier enabled it must not mask the fact that
  nothing is delivered; the docs should say so.
- SMTP: `MandatoryStartTLS` stays the documented policy (VERIFIED in
  `docs/channel-redundancy.md`).
- Public repo rule: no real hostnames, addresses or secrets in any notifier
  example.

## 5. Migration plan and owner decisions

The maintainer's live setup (n8n router, Discord, Pushover) must not change.

1. This design merges.
2. Implementation issue A: move `contact-points.yml` to an `.example` and add a
   "router" add-on include; make `GRAFANA_WEBHOOK_SECRET` conditional in compose
   and `check-env.sh`. Keep a documented one-time step for an existing install
   (copy the file back), so a live Grafana does not lose its contact point on
   the next `docker compose up`. This is the one risky step: it is a live
   change, so it needs the owner. Provisioned files are read at Grafana start
   (VERIFIED in `docs/channel-redundancy.md`, step 5).
3. Issue B: notifier files and enable script for `discord`, `pushover`, `email`,
   generic `webhook`; one doc page per notifier with least-privilege setup.
4. Issue C: Matrix path (decision below), minimal profile docs and a
   "start with nothing" quick start.
5. Issue D: Alertmanager receiver include.

Owner decisions (recommended first):

- D1. Router becomes an opt-in add-on. Recommended yes. Alternative: keep it
  default-on and only add a `minimal` variant.
- D2. Existing live install keeps its router by a one-time copy step done by
  the owner, not by a silent change. Recommended yes.
- D3. Native Pushover through Grafana is accepted as lacking emergency cancel
  behavior, which stays a router feature. Recommended yes, documented.
- D4. Matrix: direct sender script only (as today), no router node. Recommended
  yes until a user asks for more.

## 6. Open questions (recommended answer first)

1. Does a router-less install still need `GRAFANA_WEBHOOK_SECRET` in the secret
   source? Recommended: no; it is required only when the router add-on is on.
2. Should the minimal profile ship one default notifier example? Recommended:
   none; show the choice, because the "minimal" claim is "starts with nothing".
3. Matrix through Grafana: webhook to a bridge, or a native type if one exists?
   Recommended: do not design it; check Grafana's contact point list
   (`https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/`,
   not read for this design) in the implementation issue before choosing.
4. Does Wazuh keep its `custom-n8n` integration when n8n is absent?
   Recommended: the integration is disabled by default in the minimal profile and
   documented as router-only. Not verified: the Wazuh integration file was not
   inspected here.
5. Where does the Alertmanager "n8n-webhook" workflow live, given no workflow in
   `n8n/` listens on `/webhook/alertmanager-siem`? Recommended: treat it as
   not wired in the repo; the router add-on must include the workflow before the
   Alertmanager route is enabled. VERIFIED gap, same as channel-redundancy.md
   open question 5.

## 7. Test plan

1. Compose: `docker compose config` with CI env and NO `GRAFANA_WEBHOOK_SECRET`
   succeeds in the minimal profile and fails when the router add-on is enabled
   without it (fail closed kept). Extends `tests/python/test_compose_security.py`
   style checks.
2. Provisioning: parse every file in `provisioning/alerting/` with the minimal
   profile and assert there is no contact point and no policy referencing one
   (so no notification attempt exists). The existing YAML tests
   (`test_yaml_configs.py`) show the pattern.
3. Per notifier: for each of discord, pushover, email, webhook, enable ONLY that
   example and assert the provisioned set has exactly one contact point, its
   secrets are `$VARIABLE` references, and nothing else references it. Run all
   subsets, since "each notifier can be enabled alone" is the done-when.
4. Revert-proof: a test that fails when a literal URL or token appears in a
   notifier example (canary string), and when the enable script prints a value.
5. Router parity: with the router add-on enabled, the provisioned contact point
   is byte-identical to today's `contact-points.yml` (guards the live install).
6. Alertmanager: `amtool check-config` (already run in CI per
   `docs/design/podman.md`) passes for the null-only and router renderings.
7. Taxonomy and game day: `tests/python/test_alert_taxonomy.py` still passes; a
   game-day scenario is not applicable without a router, and the docs say which
   scenarios need one (`docs/game-day.md`).
8. Manual, not run here: start the minimal profile on a rehearsal host, confirm
   Grafana runs and the UI shows rules, send one test through each notifier alone.
