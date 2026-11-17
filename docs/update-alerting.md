# Update alerting (pfSense and UniFi)

Grafana alerts that keep nagging while a pfSense or UniFi update is pending.
Nothing here applies an update or changes a device. The alerts read data that
is already collected, and they clear only when the data shows the update is
gone.

Tracked in issue #53 (epic #52).

## Flow

```
UniFi poller -> InfluxDB (unpoller) --\
                                       >-- Grafana alert rules
pfSense Telegraf exec -> InfluxDB ----/        |
 (pfsense_update_pending)                      v
                                  contact point n8n-grafana-router
                                               |
                                  n8n "Grafana SOAR - Alert Router"
                                       |                 |
                                    Discord         Pushover (optional)
```

Discord delivery is unchanged. Pushover is added next to it and is off until
you turn it on.

## What ships

| File | Purpose |
|------|---------|
| `docker/grafana/provisioning/alerting/update-alert-rules-unifi.yml` | UniFi rules: warning after 24h pending, critical after 7 days |
| `docker/grafana/provisioning/alerting/update-alert-rules-pfsense.yml` | pfSense rules, shipped paused (see below) |
| `docker/grafana/provisioning/alerting/contact-points.yml` | Webhook contact point pointing at the n8n router |
| `docker/grafana/provisioning/alerting/update-notification-policy.yml.example` | Repeat intervals: 4h warning, 1h critical |
| `n8n/grafana-alert-router.json` | Router with the added Pushover nodes |
| `scripts/pfsense-update-metric.sh` | Read-only metric source for the firewall (not deployed) |
| `tests/python/test_update_alerting.py` | Tests for all of the above |

### Rules

- `noDataState: OK` on every rule: missing data never pages.
- Every rule carries `severity` (warning or critical), `update_alert=true` and
  `alert_group=updates`. The pfSense security rule also carries
  `update_security=true`.
- A rule clears only when its query stops returning a pending update (the
  UniFi `upgradable` flag goes false, or `pfsense_update_pending` returns to
  0). There is no manual dismiss or silence logic in the rules.
- The 24h and 7 day thresholds use the rule `for` duration, so a device that
  is updated and later has a new update starts a fresh clock.

### UniFi data

The UniFi poller (unpoller) writes InfluxDB database `unpoller`, one
measurement per device type (`uap`, `usw`, `ugw`, `udm`, `uxg`), with a
boolean field `upgradable` and the device `name` as a tag. This schema is
taken from the unpoller documentation and has not been checked against a live
database. Check it before relying on the rules:

```
docker exec influxdb influx -execute 'SHOW FIELD KEYS ON unpoller FROM usw'
```

The UniFi Network application itself is not reported by the poller, so a
pending Network application update does not raise an alert.

### pfSense data (not deployed)

The pfSense rules ship paused. Enable them (set `isPaused: false`) once the
Telegraf input below is deployed and the metric is arriving.

Metric `pfsense_update_pending`: gauge, `value` 0 or 1, tags `kind`
(`core`, `kernel`, `package`) and `security` (`true`, `false`). The script
prints all six series every run, so a series never goes stale while an update
is pending. The `security` tag is a best-effort match on the word "security"
in the `pfSense-upgrade -c` text.

Telegraf exec input for the firewall:

```toml
[[inputs.exec]]
  commands = ["/usr/local/bin/pfsense-update-metric.sh"]
  interval = "6h"
  timeout = "120s"
  data_format = "influx"
```

Copy `scripts/pfsense-update-metric.sh` to that path by hand when you are
ready. The script only runs `pfSense-upgrade -c` and `pkg-static version`, and
always exits 0. If a check fails it prints nothing.

### Notification policy

Grafana provisions the notification policy as one tree for the whole
organization, so the file ships as `.example` and Grafana ignores it. Merge its
`update_alert` route into your existing tree (Alerting, Notification
policies), or copy it to `update-notification-policy.yml` if you have no
tree yet. Repeat intervals: 4h for warning, 1h for critical.

## Pushover (phone push)

Off by default. n8n reads these variables with expressions:

| Variable | Default | Meaning |
|----------|---------|---------|
| `PUSHOVER_ENABLED` | off | Set to `true` to send to Pushover |
| `PUSHOVER_APP_TOKEN` | none | Pushover application token (secret) |
| `PUSHOVER_USER_KEY` | none | Pushover user or group key (secret) |
| `PUSHOVER_RETRY` | 300 | Seconds between repeats for priority 2 (minimum 30) |
| `PUSHOVER_EXPIRE` | 10800 | Seconds before repeats stop (maximum 10800) |

Priority mapping:

| Alert | Pushover priority |
|-------|-------------------|
| severity `critical`, or label `update_security=true` | 2 (emergency, repeats until acknowledged) |
| severity `warning` | 1 (high, bypasses quiet hours) |
| resolved | 0 (normal, no repeat) |

Messages are cut to the Pushover limits (title 250, message 1024 characters).

### Enable it

1. Create a Pushover application and note its token and your user key.
2. Store the three secret values in Doppler, project `siem-docker-stack`,
   config `dev`. Never put values in this repo or in `.env`.
3. Run n8n with those variables in its environment, for example
   `doppler run -- docker compose up -d`. n8n is not defined in this repo's
   `docker/docker-compose.yml`, so add the variables to wherever your n8n
   container is defined. Pass the secrets through by name only, without a
   `:-` default.
4. n8n blocks `$env` in expressions by default in current releases. Set
   `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` on the n8n container, or the gate
   node cannot read `PUSHOVER_ENABLED`.
5. Set `PUSHOVER_ENABLED=true`. Import the updated
   `n8n/grafana-alert-router.json` into n8n and activate it.

### How acknowledging stops the nag

A priority 2 message repeats every `PUSHOVER_RETRY` seconds until you
acknowledge it in the Pushover app or `PUSHOVER_EXPIRE` passes. Acknowledging
stops that one message only. While the update is still pending, Grafana
re-alerts at the policy repeat interval (4h warning, 1h critical) and a new
emergency message starts. The alert itself ends only when the update is
applied. On resolve, the router sends a normal priority message and asks
Pushover to cancel any repeats still running for that alert (matched by the
alert fingerprint tag).

## Tests

```
python3 -m pytest tests/python/test_update_alerting.py -q
```

The script test uses fake `pfSense-upgrade` and `pkg-static` programs, so it
never touches a firewall.
