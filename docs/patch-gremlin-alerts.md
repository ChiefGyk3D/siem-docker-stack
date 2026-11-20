# Patch Gremlin update alerts (draft, inactive)

Issue #65, epic #62. Alerts for hosts patched by
[Patch Gremlin](https://github.com/ChiefGyk3D/Patch-Gremlin): non-security
updates pending, reboot required on a critical system, last run stale or
failed. Security updates stay automatic and never page.

Everything here is a draft that deploys nothing. Three example files:

| File | What it is |
|------|-----------|
| `docker/prometheus/patch-gremlin-scrape.example` | scrape job snippet and notes |
| `docker/prometheus/targets/patch-gremlin.example.json` | target file template (placeholder addresses) |
| `docker/grafana/provisioning/alerting/patch-gremlin-alert-rules.example` | three Grafana alert rules |

Grafana provisions only `*.yml` and `*.yaml`, and Prometheus reads only the
files named in `prometheus.yml`, so none of these load until you copy them.
The rule file deliberately ends in plain `.example` (not `.yml.example`) so
`tests/python/test_alert_taxonomy.py` (PR #142) does not scan it before its
`source` value exists.

## What the exporter exposes

Claim marks: **VERIFIED** was read from the exporter source on 2026-11-19;
**INFERRED** is reasoning, not read from a live host or from the source.

Source: `monitoring/prometheus-exporter.sh` in `ChiefGyk3D/Patch-Gremlin`, last
changed in commit `fa2ff51f5fbb202a826aa73ec592c7ba01515128`; default branch head
read was `756610791953accc3d7b906e9cf1d935076b5f70`. State written by
`update-notifier.sh` (`write_state`) at the same head.

VERIFIED delivery: the exporter is a script for the node_exporter **textfile
collector**, run from cron or a timer every 5 minutes, writing
`/var/lib/node_exporter/patch_gremlin.prom`. It has no HTTP port of its own;
Prometheus scrapes node_exporter (:9100) on each host.

VERIFIED metrics (all gauges, no labels except `status_info`):

| Metric | Meaning |
|--------|---------|
| `patch_gremlin_health` | 1 healthy, 0 unhealthy (health-check script) |
| `patch_gremlin_last_run_timestamp_seconds` | Unix time of the last notifier run (0 when no state file) |
| `patch_gremlin_last_notification_success` | 1 if the last run delivered a notification |
| `patch_gremlin_packages_upgraded` | packages upgraded in the last run |
| `patch_gremlin_pending_updates` | packages still awaiting upgrade (total) |
| `patch_gremlin_pending_security_updates` | security packages still awaiting upgrade |
| `patch_gremlin_status_info{status="..."}` | last run status, value 1; status is one of `updated`, `updates-available`, `no-updates`, `error`, or `unknown` (default when the state file is missing) |

VERIFIED: the security count is taken from the same package listing as the
total (`grep -c -- '-security'` on the listing in `count_pending_updates`), so
security is a subset of the total.

INFERRED:

- Non-security pending = `pending_updates - pending_security_updates`. The
  subset relation is verified; the exact package-manager matching (`-security`
  in apt, a security advisory count in dnf) is not tested here.
- There is **no reboot-required metric**. Nothing in the exporter or the state
  file mentions reboot. The reboot rule uses `node_reboot_required`, a gauge you
  would have to add (below); it ships paused for that reason.
- The 48 hour staleness threshold: the notifier schedule is set per host, a daily
  timer is assumed.
- Which hosts count as critical: the rule matches `role="critical"`, the label
  of the placeholder target file. Your real critical systems may carry another
  label.
- No Patch Gremlin series has been seen in this stack's Prometheus; no live
  system was queried.

## The three rules

All carry tier P2 labels (`severity=warning`, `phone=false`, `alert_group=updates`,
`source=patch-gremlin`, `update_alert=true`), `execErrState: Alerting`, and
`for: 0s` with the clock in the query, like the UniFi and pfSense rules.

| Rule | Query idea | noDataState and why |
|------|------------|--------------------|
| non-security updates pending over 24h | minimum of (total minus security) over 24h is above 0, per host | `OK`: no series is not a pending update; a vanished exporter is the third rule's job |
| reboot required on a critical system (paused) | minimum of `node_reboot_required{role="critical"}` over 24h is above 0 | `OK`: most hosts do not emit it |
| last run stale or failed | last run older than 48h, or `status_info{status="error"}` present | `Alerting`: no data at all means every exporter stopped, which would silence the other two |

Limit: Prometheus has no series for a host that was never scraped or whose
target was removed, so one missing host is invisible to every rule. Add
`up{job="patch-gremlin"} == 0` style checks if you need per-host absence.

## Enable steps (owner steps)

Nothing below is done by this PR.

1. Roll out the exporter on each Linux host (including the Twingate connectors
   and the Docker host): install `prometheus-exporter.sh`, run it from a timer,
   and start node_exporter with
   `--collector.textfile.directory=/var/lib/node_exporter`. Follow the Patch
   Gremlin README, section Prometheus.
2. Collect it. Hosts already in a node_exporter job need nothing. Others: copy
   the job from `patch-gremlin-scrape.example` into `docker/prometheus/prometheus.yml`,
   copy `targets/patch-gremlin.example.json` to `targets/patch-gremlin.json`,
   fill in real addresses and roles, then reload Prometheus.
3. Confirm the series exist: query `patch_gremlin_pending_updates` in Prometheus
   and expect one series per host.
4. Copy the rule file to `patch-gremlin-alert-rules.yml` in the same directory,
   add `patch-gremlin` to `SOURCES` in `tests/python/test_alert_taxonomy.py` and
   to the taxonomy doc, run that test, and redeploy Grafana alert provisioning.
5. Optional reboot rule: add a textfile metric on critical hosts, for example a
   timer that writes `node_reboot_required 1` when `/var/run/reboot-required`
   exists and `0` otherwise, confirm it in Prometheus, then set `isPaused: false`
   on the rule. (This metric is not part of Patch Gremlin; consider proposing it
   upstream.)

Titles are not on the router's `ALLOWED_ALERTNAMES`; they are P2 and never use
the emergency priority, so no change there.

## Rollback

Move the copied rule file back out of the provisioning directory (or delete it)
and redeploy Grafana alert provisioning; remove the job from `prometheus.yml`
and the real `targets/patch-gremlin.json`, then reload Prometheus. The example
files in the repository stay as they are. Nothing else depends on them.
