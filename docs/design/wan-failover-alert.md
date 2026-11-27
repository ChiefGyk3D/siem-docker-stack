# WAN failover alert: design note

Issue #68, epic #62. Design only. No rule ships with this note, because the
data the rule needs is not collected yet.

## What the repo collects

Verified by searching the repo at commit 138ea4a (grep for gateway, dpinger,
Telegraf, monitor): the only pfSense Telegraf input the repo knows about is the
update exec input (`scripts/pfsense-update-metric.sh`, metrics
`pfsense_update_pending` and `pfsense_update_check_success`, see
`docs/update-alerting.md`). The repo holds no Telegraf configuration for
gateways. The pfSense side Telegraf configuration lives in the companion
repository `pfsense_siem_stack` (not read for this note, so whether it already
emits gateway metrics is unknown; check it first, see Owner steps). Nothing in
`docker/grafana/provisioning/alerting/` reads a gateway metric.

So there is no gateway status metric to alert on, and none is invented here.

## Input needed

A metric per gateway, written to the InfluxDB database `pfsense` every minute,
carrying at least: gateway name (tag), a state (online, warning, offline) or a
loss and delay pair, and which gateway is the current default if available.

Two ways to get it, both on the firewall:

1. A Telegraf `exec` input running a small read-only script that reads the
   dpinger status per gateway and prints InfluxDB line protocol. Telegraf
   documents `commands`, `timeout` and `data_format = "influx"`, and treats a
   non-zero exit as an error unless `ignore_error = true`.
2. The community gateway script for pfSense Telegraf. A forum post describes a
   Python script, installed under `/usr/local/libexec/telegraf/` and wired in
   with an `[[inputs.exec]]` block (`timeout = "5s"`, `data_format = "influx"`),
   that reads the dpinger sockets and emits a `gateways` measurement with
   delay, loss, stddev, status and defaultgw fields. It is third party code:
   inspect it before use (owner rule: inspect before install).

Gateway states are Online, Offline and Warning per the pfSense gateway status
page. The monitor addresses the issue mentions are the ones already set in
pfSense for each gateway; the metric reads them from dpinger, so nothing new
is probed. This note uses 192.0.2.1 (primary) and 192.0.2.2 (cell) as
documentation placeholders only.

## Rule once the data exists

Two rules in a new group, shipped as a `.example` file first, paused, same
pattern as `docs/patch-gremlin-alerts.md`.

- Failover (P1): primary gateway offline AND cell gateway online.
  Labels: `severity: critical`, `tier: P1`, `phone: "true"`,
  `source: pfsense`, and an `alert_group` for network. The taxonomy
  (`docs/alert-taxonomy.md`) does not list a network group today, so the first
  step is adding one to the taxonomy and `tests/python/test_alert_taxonomy.py`
  (the table says to extend the set there). `for: 3m` so one lost probe burst
  does not page; `interval: 1m`.
- Recovery notice: prefer the resolved message of the failover rule (Discord
  sends resolved alerts and Pushover cancels the repeat; verified on the
  taxonomy page). That needs no second rule. A separate info rule would be
  `severity: info`, `tier: P3`, `digest: "true"`, `phone: "false"`.
- `execErrState: Alerting`: a failing query must alert (the UniFi outage
  lesson in `docs/update-alerting.md`).
- `noDataState: Alerting` for the failover rule. If the gateway metric stops
  arriving, nobody can tell whether the uplink is up, and the router itself
  may be the thing that died. Pair it with a staleness rule like
  `update-pfsense-check-failing`.
- Each query reduces with `dropNN`, as in the pfSense update rules.
- Pushover priority is 1, not 2, until the rule title is added to
  `ALLOWED_ALERTNAMES` in the router (taxonomy page).

Caveat: if both links are down, no metric arrives at all, and only the
staleness rule can alert.

## Owner steps

Each is a change to the firewall or the live stack and needs the owner's
approval. None was done.

1. Check `pfsense_siem_stack` for an existing gateway metric.
2. If none, approve a read-only exec input on the firewall (script plus an
   `[[inputs.exec]]` block). Editing Telegraf settings in the pfSense UI
   rewrites `telegraf.conf` (forum report, unverified), so add it where it
   survives.
3. Confirm points arrive in InfluxDB database `pfsense`, then give the
   measurement and field names so the rule can be written against them.
4. Add the network `alert_group` to the taxonomy and test.
5. Install the rule file, unpause, and test with a controlled primary unplug in
   a maintenance window.

## Rollback

Remove the exec block and restart Telegraf on the firewall; delete the rule file
and restart Grafana. Nothing in this PR changes a live system.

## Verified and inferred

Verified, read 2026-11-19:

- Gateway states Online, Offline, Warning; monitor address, RTT, loss shown:
  https://docs.netgate.com/pfsense/en/latest/monitoring/status/gateways.html
- Telegraf exec options and influx data format, non-zero exit is an error unless
  `ignore_error`:
  https://github.com/influxdata/telegraf/blob/master/plugins/inputs/exec/README.md
- Repo has no gateway metric: search of this repository at the commit above.

Inferred, not checked:

- The community script, its measurement and field names, and that it reads
  dpinger sockets (from a forum post and search summary; the script source was
  not read): https://forum.netgate.com/post/707844
- Whether the pfSense Telegraf package overwrites a hand edit.
- That `pfsense_siem_stack` has no gateway metric (not read).
- The `for` duration and noDataState choice: reasoning, not tested on live data.

Searches run:

- query: pfSense gateway status telegraf dpinger metrics
- query: pfSense return_gateways_status command line script gateway status

The Netgate gateway-monitoring page URL returned 404 and was not used.
