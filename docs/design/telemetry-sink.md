# Design: telemetry sink choice (Grafana Cloud free tier, self-hosted Grafana, or an existing Grafana)

Status: DRAFT for the owner's decision. Docs only: no code, no configuration,
no live change, no account touched. Tracked in issue #115 (epic #62), child of
the deployment variants epic #111. Companion design:
[variant-digitalocean-opentofu.md](variant-digitalocean-opentofu.md).

Marking: **VERIFIED** means read from a file in this repository at master
7c8de1b (path given) or from a vendor page (URL, read 2026-11-19).
**INFERRED** means reasoned from those and not tested. Examples use
`example.com` and placeholder names only. No hostname, address, account
identifier or secret value appears here.

## 1. Problem

Issue #115: let the deployer pick Grafana Cloud free tier, a self-hosted
Grafana stack, or an existing Grafana they already run, with one documented
switch for the data source and alerting endpoints. The free-tier limits must
be verified against the vendor page.

## 2. The finding that shapes everything: Grafana here is a viewer and a rule engine, not the store

VERIFIED from the repository:

| Fact | Source |
|---|---|
| Grafana provisions seven data sources: five OpenSearch (Suricata, syslog, pfBlockerNG, Wazuh alerts, CrowdSec), InfluxDB and Prometheus. All URLs are Docker service names on `siem-net` | `docker/grafana/provisioning/datasources/datasources.yml` |
| The data lives in OpenSearch (retention up to 365 days by the ISM policy), the Wazuh indexer, InfluxDB and Prometheus (retention default 365 days) | `docs/disk-strategy.md`, `docker/docker-compose.yml` lines 343 to 344 |
| Grafana holds the contact point to n8n (bearer secret) and the Grafana-managed alert rules (heartbeat, update, notification-failure, CrowdSec-through-Grafana) | `docker/grafana/provisioning/alerting/*`, `docs/update-alerting.md`, `docs/heartbeat.md`, `README.md` lines 127 to 141 |
| Prometheus has its own rules and sends to the local Alertmanager, which routes critical and warning to n8n | `docker/prometheus/rules/`, `docker/alertmanager/alertmanager.yml.template`, `docs/design/optional-components.md` section 2.1 |
| The grafana service requires `GRAFANA_WEBHOOK_SECRET` and the read-only passwords for the data sources | `docker/docker-compose.yml` lines 203 to 243 |
| There is no `remote_write` in the SIEM Prometheus config | grep of `docker/prometheus/prometheus.yml` (only the two scrape jobs and rule and alerting blocks) |
| A `docs/prometheus-otlp.md` receiver already exists, so metrics inbound is solved; outbound is not | `docs/prometheus-otlp.md` |

So the "telemetry sink" decision is not "where do logs go". Logs (OpenSearch,
Wazuh) cannot be moved into Grafana Cloud by Grafana itself; Grafana only
queries them. The honest scope of each option is therefore:

- **Dashboards and alert rules**: where Grafana runs.
- **Metrics**: could be copied outward with Prometheus `remote_write`.
- **Logs and security events**: stay in the stack's OpenSearch and Wazuh in
  every option, unless the owner decides otherwise (see section 9, O3).

## 3. The three options

### 3.1 Option A: self-hosted Grafana (the current behavior)

Grafana runs in the stack's compose file, queries the local data sources over
`siem-net`, evaluates Grafana-managed rules there, and calls the n8n webhook.

- Data leaving the host: nothing to a Grafana vendor. Outbound traffic is the
  notification delivery chain (n8n to the notifier), as today (VERIFIED,
  `README.md`).
- Retention and limits: bounded by local disks and the Prometheus and ISM
  settings (VERIFIED above). No vendor cap.
- Secrets: the existing `.env` list (VERIFIED). No new secret.
- Alerting: unchanged. Grafana-managed rules to the contact point to n8n;
  Prometheus rules to Alertmanager to n8n (VERIFIED).
- Cost: the host resources Grafana uses (INFERRED small); the stack already
  budgets for it.

### 3.2 Option B: Grafana Cloud free tier

Vendor limits, VERIFIED from https://grafana.com/pricing/ (read 2026-11-19):

| Signal | Free tier limit | Retention |
|---|---|---|
| Metrics | 10k active series per month | 14 days |
| Logs | 50 GB ingested per month | 14 days |
| Traces | 50 GB ingested per month | 14 days |
| Profiles | 50 GB ingested per month | 14 days |
| Grafana users (visualization) | 3 active users per month | n/a |
| IRM users | 3 active | n/a |

The pricing page content read did not list alerting limits and was truncated, so
alert rule count limits are UNVERIFIED. A second search
(`query: Grafana Cloud free tier private data source connect available alert rules limit`)
found no free-tier alert-rule cap on Grafana Cloud pages; the rule caps it found
belong to other vendors and are not applicable. The page
https://grafana.com/docs/grafana-cloud/account-management/cloud-account-limits/
returned HTTP 404 on 2026-11-19, so the account limits page was not read; its
current address is an open question for the implementer.

How data would get there, VERIFIED from
https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-prometheus/
(2026-11-19): Prometheus `remote_write` with `basic_auth`, username the
metrics instance ID and password a Cloud Access Policy token; the endpoint is
the `/api/prom/push` URL from the portal; the push-gateway protocol is not
supported. Scopes, VERIFIED from
https://grafana.com/docs/grafana-cloud/security-and-account-management/authentication-and-permissions/access-policies/
(2026-11-19): scopes such as `metrics:write` and `logs:write` exist, tokens
may expire, org admins can enforce a maximum expiry, IP range restrictions
exist, and the page gives no rotation procedure.

How Cloud Grafana would read the local data sources: Private data source
connect (PDC). VERIFIED from
https://grafana.com/docs/grafana-cloud/connect-externally-hosted/private-data-source-connect/
and `.../configure-pdc/` (2026-11-19): an agent inside the network opens an SSH
connection outward to Grafana and acts as a SOCKS proxy; the Docker agent needs
a token with the `pdc-signing:write` scope; a stack supports multiple PDC
networks; supported open-source data sources include Prometheus, Elasticsearch
and InfluxDB; only backend data source plugins are supported. NOT VERIFIED:
that PDC is free-tier eligible (the pages read do not say; a 2023 Grafana blog
result from the search says it is generally available on the free tier, so it
is a lead, not a source) and that the OpenSearch data source plugin this stack
uses (`grafana-opensearch-datasource`, VERIFIED in the compose file) is a
backend plugin supported by PDC. INFERRED: the Elasticsearch listing does not
guarantee the OpenSearch plugin.

Data leaving the host: PDC means each dashboard query result for a local data
source flows to Grafana Cloud, including security events (Wazuh alerts, IDS
events, firewall logs, IP addresses, usernames) as they are displayed or
evaluated (INFERRED from how a proxied query works). With `remote_write` the
series, labels and values leave the host and live 14 days in a third-party
service (VERIFIED retention). This is a large privacy change for a SIEM and
the reason section 8 does not recommend Cloud as the default.

Alerting in Cloud: Grafana-managed rules can query several backend data sources
at once [https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rules/alert-rule-types/,
2026-11-19; the page does not say where evaluation runs, and says nothing
specific about Grafana Cloud]. Webhook contact points support POST or PUT and
`Authorization` scheme and credentials, and the page says the URL, OAuth2 token
URL and proxy URL "can't be changed in Grafana Cloud"
(https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/,
2026-11-19). The meaning of that sentence for provisioned contact points is
UNVERIFIED and must be tested. The page on Cloud outbound IPs did not state the
sender address list, so the allow-list for an inbound webhook at n8n is
UNVERIFIED too.

INFERRED consequence for the n8n router: the router sits on the private
network. PDC carries data source queries from Cloud to the private network
(VERIFIED); nothing read says it carries notification calls. So a Cloud-hosted
Grafana cannot reach a private n8n webhook through PDC, and either n8n needs a
public, authenticated endpoint (the stack's design avoids that,
`docs/update-alerting.md` webhook authentication section) or the rules that
page a human must not run in Cloud. This is the main reason Cloud cannot be
the alert evaluator for a private stack.

### 3.3 Option C: an existing Grafana the deployer already runs

The deployer's Grafana (self-hosted or managed) is used as the viewer and
rule engine; the stack runs without its own Grafana service.

- What the stack must provide: reachable, authenticated, read-only endpoints
  for the data sources (OpenSearch with the existing read-only user, Prometheus
  with its basic-auth account, InfluxDB with the read-only account; VERIFIED
  that these accounts exist, `docker/docker-compose.yml`, README secrets table).
- How the deployer's Grafana is configured: the repo's provisioning files and
  the existing API scripts (`scripts/deploy-dashboards.py`,
  `scripts/deploy-grafana-alerts.py`, `scripts/deploy-n8n-grafana-router.py`
  exist and use `GRAFANA_PASS`; VERIFIED in the README client-side table) are
  the import path. INFERRED: they need a configurable base URL and a service
  account token rather than the admin password; confirm in the code before the
  implementation.
- Data leaving the host: queries from the deployer's Grafana to the stack's
  endpoints, so the stack must expose those endpoints beyond loopback, over TLS
  with auth, to a named source (INFERRED; contradicts the default loopback bind
  unless the deployer's Grafana is on the same overlay, `docker/docker-compose.yml`
  `BIND_ADDR`).
- Alerting: the deployer's Grafana evaluates the rules and needs a contact point
  to the router; the router stays private if the Grafana is on the same
  network (INFERRED).

## 4. What data leaves the host, per option (summary)

| Data | A self-hosted | B Grafana Cloud | C existing Grafana |
|---|---|---|---|
| Dashboard query results (security events, IPs, users) | none | to the vendor, through PDC, on every query (INFERRED) | to the deployer's Grafana, through the exposed endpoints |
| Metrics series | none | copied by `remote_write` if enabled, 14 days (VERIFIED retention) | none by the stack; the deployer chooses |
| Raw logs and Wazuh events | none | none unless an owner decision adds a log shipper | none |
| Alert text (titles, labels) | to n8n then the notifier (today) | to the vendor if rules run in Cloud, then to the notifier | to the deployer's Grafana |
| Credentials | local `.env` | plus Cloud token and PDC token | plus deployer's Grafana token |

## 5. Authentication and secret handling

New names only; values come from the secret manager (dev config first) or the
chosen host store, following [secrets-sources.md](secrets-sources.md); none is
in the repository.

| Name | Option | Purpose | Least privilege |
|---|---|---|---|
| `GRAFANA_CLOUD_REMOTE_WRITE_URL` | B | metrics push endpoint | not a secret; kept with the config |
| `GRAFANA_CLOUD_METRICS_USER` | B | metrics instance ID | identifier, kept private in the secret store |
| `GRAFANA_CLOUD_METRICS_TOKEN` | B | Access Policy token | scope `metrics:write` only, with an expiry (VERIFIED the scopes and expiry exist) |
| `GRAFANA_CLOUD_PDC_TOKEN` | B | PDC agent signing token | scope `pdc-signing:write` (VERIFIED) |
| `GRAFANA_CLOUD_PDC_CLUSTER`, `GRAFANA_CLOUD_PDC_ID` | B | PDC agent parameters | identifiers |
| `EXTERNAL_GRAFANA_URL` | C | base URL of the deployer's Grafana | not a secret |
| `EXTERNAL_GRAFANA_TOKEN` | C | service account token for the import scripts | Editor on a dedicated folder if the deployer's Grafana allows it (INFERRED) |

The PDC page's Docker example passes the token as a command-line flag
(VERIFIED); that puts it in argv and process listings, so the design requires
the token to reach the agent through the environment or a file instead
(INFERRED that the agent supports it; the pages read show only the flag form,
so verify before implementation). The owner rule is: never in argv, never in
the repository.

Each remote credential is a separate token with its own expiry. Rotation is an
a/b pair in the secret manager (owner decision O5), because the Access Policy
page gives no rotation procedure (VERIFIED absence).

## 6. Alerting, per option

| Question | A self-hosted | B Cloud | C existing |
|---|---|---|---|
| Where Prometheus rules run | local Prometheus, to local Alertmanager, to n8n (VERIFIED, unchanged) | same: local, if the stack keeps its Prometheus (INFERRED); `remote_write` is a copy, it does not move evaluation | same |
| Where Grafana-managed rules run | local Grafana | Cloud Grafana, reaching data through PDC | the deployer's Grafana |
| Does the n8n router path still work | yes, unchanged | only if the contact point can reach n8n; INFERRED not through PDC, so a public authenticated endpoint is needed, which the stack's design rejects. Alternative: keep rules local, use Cloud as a read-only view. | yes if the deployer's Grafana can reach n8n |
| Does the Alertmanager path still work | yes | yes (local) | yes (local) |
| Dead-man's switch (heartbeat) | exists locally (`docs/heartbeat.md`, VERIFIED) | a Cloud outage or a missing token silences Cloud-evaluated rules, so the heartbeat must be checked from outside the Cloud stack too (INFERRED) | the deployer's Grafana is the single point |
| Behavior when the sink is down | stack unaffected | the local alerting still pages; the Cloud copy has a gap (INFERRED) | the stack keeps running; its alerting depends on the deployer's Grafana unless Prometheus rules carry the critical ones |

Design rule: the alerts that page a human are evaluated on the host, by
Prometheus and Alertmanager, in every option; Grafana-managed rules that
exist only because Grafana was local (heartbeat, update, CrowdSec) are the ones
that depend on the option and need the test in section 8. INFERRED: moving the
critical ones to Prometheus rules is a separate effort; this design only
records the dependency.

## 7. The switch (names only)

One environment value selects the mode and the compose and provisioning
layers read it:

- `TELEMETRY_SINK` with values `self-hosted` (default), `grafana-cloud`,
  `external-grafana`.

What it controls (design, not code):

| Name | Effect |
|---|---|
| Compose profile `grafana-local` | starts the `grafana` service; on for `self-hosted` only |
| Compose profile `pdc-agent` | starts the PDC agent service; on for `grafana-cloud` only |
| Compose profile `remote-write` | adds a `remote_write` block to the SIEM Prometheus config through a rendered fragment (the repo already renders configs from templates, VERIFIED `scripts/render-alertmanager-config.sh`) |
| `TELEMETRY_SINK_RULES` | `local` or `sink`: where Grafana-managed rules are deployed; default `local` |
| `GRAFANA_BASE_URL` | the URL the deploy scripts talk to (local default); a single switch for the scripts that today assume the local Grafana |

The existing requirement that compose refuses to start without
`GRAFANA_WEBHOOK_SECRET` and `GRAFANA_ADMIN_PASS` (VERIFIED) must be relaxed per
option, the same pattern the optional-components design uses for n8n
([optional-components.md](optional-components.md)).

## 8. Test plan

| Layer | What | Needs |
|---|---|---|
| Static | `docker compose config` for each `TELEMETRY_SINK` value; each renders; the grafana service is absent for B and C | no credentials |
| Config render | The `remote_write` fragment contains no secret value, only a file reference or environment reference; the secret scan passes | no credentials |
| Option A | Existing tests plus the n8n router test (`scripts/live-deploy/n8n-test-router.py` exists) unchanged | existing |
| Option C | A throwaway Grafana container as the "existing" Grafana; import dashboards and rules with the scripts; one test alert reaches a mock webhook | local containers |
| Option B | A throwaway Grafana Cloud free account (owner provides): one series arrives, retention matches the page, PDC query works against Prometheus and against the OpenSearch plugin, a provisioned webhook contact point accepts a private target or is refused (answers the two UNVERIFIED items) | owner account, dev secret config |
| Degradation | With the sink unreachable, a local test alert still reaches the router; the heartbeat misses are detected | local |
| Cardinality | Compare `prometheus_tsdb_head_series` against 10k before enabling `remote-write` (INFERRED metric name; verify) | the live stack, read-only |

Nothing in this design is run against the maintainer's live Grafana.

## 9. Migration plan

1. Default stays `self-hosted`; nothing changes for current users.
2. Add the switch with `self-hosted` as the only behavior, merged first.
3. Option C next (no vendor account, testable locally), then option B behind a
   documented "advanced, privacy implications" warning.
4. Moving from A to C: export dashboards and rules (the scripts' import path
   in reverse is INFERRED, not verified), repoint the contact point, turn the
   local Grafana off only after one test alert has crossed.
5. Moving from A to B: enable `remote_write` for metrics only first, watch the
   active series against 10k, then decide on PDC. Rules stay local until the
   section 8 test shows a private webhook is reachable.
6. Rollback: set the switch back; the local Grafana's data directory is not
   touched by the switch (INFERRED from the compose bind mount of
   `/data/warm/grafana`, VERIFIED path).

## 10. Owner decisions (recommended answer first)

| # | Decision | Recommended | Alternatives |
|---|---|---|---|
| O1 | Default sink | `self-hosted`, unchanged | Cloud as default (not recommended: privacy, 14-day retention against 365 days, paging path cannot reach a private router) |
| O2 | Offer Cloud at all | Yes, as metrics-only `remote_write` with rules kept local, marked advanced | Also PDC for dashboards; or do not offer |
| O3 | Do logs and security events ever leave the host | No, never by default | An explicit opt-in per data source |
| O4 | Option C scope | Support it, with a service account token and a configurable base URL | Document only |
| O5 | Token policy | Separate tokens per purpose, expiry set, a/b rotation in the secret manager, dev config first | One shared token |
| O6 | Throwaway Cloud account for the test | Owner creates or names it; nothing is run until then | Skip option B testing (the two UNVERIFIED items then stay open) |
| O7 | Move the human-paging alerts from Grafana rules to Prometheus rules | Yes, tracked as its own issue, because it makes the alert path independent of any sink | Keep as is |

## 11. Sources and search record

Vendor pages read 2026-11-19 are the URLs named inline. Pages that failed or
said nothing: the Cloud account limits page (HTTP 404), the Cloud allow-list
page (no outbound IP statement), the alerting overview and the alert rule
types page (no evaluation location, no Cloud statement), the PDC pages (no
free-tier statement).
Search queries used:

- `query: Grafana Cloud free tier private data source connect available alert rules limit`
  gave the lead on PDC free-tier availability (a 2023 blog; secondary) and no
  Cloud alert-rule cap.
- `query: DigitalOcean droplet user data cloud-init size limit 64 KB` and
  `query: OpenTofu test mock_provider override_resource tofu test command`
  belong to the Digital Ocean design and are listed there.

Not found, so UNVERIFIED: Cloud free-tier alert rule limits, PDC free-tier
eligibility from a current docs page, the Cloud outbound address list, the
behavior of a provisioned webhook contact point in Cloud.
