# Infrastructure host-down and disk-full alerts

Issue #224. Rules: `docker/grafana/provisioning/alerting/infra-alerts.yml`.
Guard: `tests/python/test_infrastructure_alerts.py`.

Claim marks: **verified** was observed on the live Prometheus on 2026-11-26;
**inferred** is reasoning, not read from a live system.

## Why the old rules match nothing

Verified: live Prometheus has no job named `node`. Its jobs are `twingate-ztna`,
`unifi-controller`, `Security`, `AI`, `Cryptocurrency`, `Computers` (down, laptop
class), `grafana` and `prometheus`. The hand-made live Grafana rules "Host Down"
(`up{job="node", role!="workstation"} < 1`) and "Disk Usage Critical" select
`job="node"`, so they never fire. They live only in the Grafana database.

## Why Alertmanager-based rules do not work here

Verified: the host runs no Alertmanager container. The Prometheus-native rule
files (`docker/prometheus/rules/target-up.yml`, `siem-health.yml`) are evaluated
by Prometheus, but with no Alertmanager nothing receives the alerts. Grafana-managed
rules are the alert engine on this stack, so these rules are Grafana rules that
query Prometheus and route through the n8n router.

## Job-to-severity table

| Job | Host down | Disk over 85% |
|-----|-----------|---------------|
| `twingate-ztna`, `unifi-controller` (critical infrastructure) | `Infrastructure host down (critical)`: P1, critical, `phone=true`, 5m, no data = Alerting | `Infrastructure disk almost full (critical)`: P1, critical, `phone=true`, 5m, no data = Alerting. Ships paused |
| `Security`, `AI`, `Cryptocurrency` | `Infrastructure host down (warning)`: P2, warning, no phone, 5m, no data = Alerting | `Infrastructure disk almost full (warning)`: P2, warning, no phone, 5m, no data = OK |
| `grafana`, `prometheus` | `Infrastructure host down (warning)` (same rule) | none (they are not node exporters) |
| `Computers` | none | none |

`Computers` is the laptop job. A laptop that sleeps, travels or leaves the network
is normal, so it never pages and has no rule at all, not even a Discord warning.
A test fails if any rule selects it.

Disk rules read `node_filesystem_avail_bytes` over `node_filesystem_size_bytes`
and exclude `tmpfs`, `overlay` and `squashfs`. A vanished job gives no data and
the critical rules alert on that. Limit (inferred): if only one of two critical
jobs vanishes while the other still reports, Grafana sees the remaining series and
does not alert on the missing one; a job that is present but down still reports
`up=0` and alerts.

## Routing

Labels: `alert_group=infrastructure` (new, `docs/alert-taxonomy.md`), `severity`,
`tier`, `phone`. Only the two critical rules carry `phone=true`; the test fails
if any other rule does. The titles are not on `ALLOWED_ALERTNAMES` in the router,
so they page at Pushover priority 1, not the emergency priority 2. Adding them is
a router change and the owner's call. The rules set no `update_alert` label.

## Data source uid

The rules use the repo's Prometheus data source uid `prometheus`
(`docker/grafana/provisioning/datasources/datasources.yml`), as the notification
failure rule does. Verified on the live box: the hand-made Prometheus data source
has uid `PBFA97CFB590B2093`. Before enabling, check that a data source with uid
`prometheus` exists live (Grafana, Connections, Data sources). If the live uid is
only `PBFA97...`, change `datasourceUid` and the `uid` in query A of the four
rules to it, nothing else.

## The SIEM host itself is unmonitored

The SIEM host has no node_exporter, so no host-down or disk metric exists for it.
These rules cannot see it. The owner must deploy a node_exporter on the SIEM host
and add a scrape job, then decide its tier (it is critical infrastructure in
practice). Nothing is deployed by this change.

## Before enabling the critical disk rule

The disk rules need `node_filesystem_size_bytes{job="twingate-ztna"}` and the
same for `unifi-controller`. Check in Prometheus: `count by (job) (node_filesystem_size_bytes)`.
If the critical jobs show up, set `isPaused: false` on `infra-disk-critical`. If
they do not, those jobs are not node exporters: deploy node exporters on them
first. Unpausing without the metric would page the phone at once, because no data
means Alerting.

## Migration

1. Stage `infra-alerts.yml` with the other alerting files and run
   `grafana-deploy.py` (it is in `OPTIONAL_FILES`), then restart Grafana as in
   `docs/live-deploy-runbook.md`.
2. Confirm the two host-down rules are Normal, and that the warning rule is not
   firing for a job that is up.
3. Test the page: stop the exporter or scrape of a non-critical job to see the
   warning, and check the critical rule by a short controlled outage the owner
   approves. Confirm the phone push arrives (priority 1).
4. Run the disk check above and unpause `infra-disk-critical`.
5. Only then, the owner retires the live hand-made rules "Host Down" and "Disk
   Usage Critical" (they match nothing, so retiring them loses no coverage).

## Rollback

Remove `infra-alerts.yml` from the alerting folder (or set `isPaused: true`
on a rule) and restart Grafana. Provisioned rules disappear with the file. The
live hand-made rules are untouched until step 5, so there is nothing to restore
before then; after step 5, recreate them by hand if wanted (they matched nothing).
