# Prometheus OTLP receiver

Prometheus can accept OpenTelemetry (OTLP) metrics pushed over HTTP, for
example from an OpenTelemetry Collector. This stack enables the receiver, sizes
the out-of-order window for bursty senders, and keeps the port on loopback until
you widen it on purpose.

> **Warning: the receiver must be authenticated and firewalled.** Prometheus
has no authentication of its own, so this stack turns on basic auth
(`--web.config.file`) for the whole port and also limits who can reach it with a
`DOCKER-USER` rule that names the approved senders. Do both before you widen the
bind address. Docker-published ports bypass UFW, so UFW alone is not enough.
Never expose the port to an untrusted network.

## What changes

| Where | Setting | Why |
|-------|---------|-----|
| `docker/docker-compose.yml` | `--web.enable-otlp-receiver` | Turns the receiver on at `POST /api/v1/otlp/v1/metrics` on the existing Prometheus port. It needs a container restart. |
| `docker/docker-compose.yml` | `PROMETHEUS_BIND_ADDR` (falls back to `BIND_ADDR`, then `127.0.0.1`) | Lets you widen Prometheus alone, without also exposing Grafana, OpenSearch and the other management ports that `BIND_ADDR` controls. |
| `docker/docker-compose.yml` | `--web.config.file=/etc/prometheus/web.yml` | Basic auth (user `prometheus`) on every Prometheus endpoint, the receiver included. The bcrypt hash lives in `docker/prometheus/web.yml`, rendered from `PROMETHEUS_BASIC_AUTH_PASSWORD` by `scripts/render-prometheus-web-config.sh`; neither is committed. |
| Grafana, self-scrape | `basic_auth` on the Prometheus datasource and the `prometheus` scrape job | Both keep working once auth is on. |
| `docker/prometheus/rules/siem-health.yml` | every alert selects its metrics by `job` | See [Alert rules](#alert-rules). |
| `docker/prometheus/prometheus.yml` | `storage.tsdb.out_of_order_time_window: 30m` | See below. Reloads without a restart. |
| `docker/prometheus/prometheus.yml` | `otlp.promote_resource_attributes: []` | Resource attributes stay in `target_info` instead of becoming labels on every series. `service.name` and `service.instance.id` still become `job` and `instance`. |

### Why 30 minutes

OTLP senders batch, retry and flush in bursts, so samples can arrive after newer
ones. Prometheus rejects those unless the out-of-order window covers them. The
window is measured against the newest sample in the database, not the wall
clock: a sample is accepted if its timestamp is no older than the newest sample
minus the window. 30 minutes is the value the Prometheus OTLP guide recommends.
It comfortably covers a sender batch timeout of 10 to 30 seconds with the default
60 second export interval, and short sender retries.

It does not cover a long outage. A sender that queues data across an outage
longer than 30 minutes will have the oldest points rejected as too old when it
catches up. If you need that, raise the window (more WAL and memory) and
reload; do not raise it speculatively.

### Sender requirements

- Use **cumulative** temporality. Delta metrics are dropped unless the
  experimental `otlp-deltatocumulative` feature flag is enabled, which this
  stack does not enable.
- Send to `http://<siem-host>:9090/api/v1/otlp/v1/metrics` with
  `Content-Type: application/x-protobuf` or `application/json`.
- Keep high-cardinality values (session or request ids) off metric labels.
  Scrape limits do not apply to pushed data, so control cardinality at the
  sender or collector.

### Alert rules

Every alert rule selects its metrics by scrape job (for example
`job="cadvisor"`), so a series with the same name pushed through the receiver
under another job does not satisfy or suppress them. A test fails if an alert
has no job matcher. This is a second layer: the authentication and the firewall
are the controls that keep unapproved writers out. Give senders their own
`service.name` (it becomes `job`); do not reuse a scrape job name.

### Credentials

One password, `PROMETHEUS_BASIC_AUTH_PASSWORD` in `.env`, serves senders,
Grafana and the self-scrape. Prometheus does not separate read from write
permission by user, so treat the sender credential as write access. Rotate by
changing the value, re-running the render script and recreating `prometheus`
and `grafana`. Senders send it as HTTP basic auth (for an OpenTelemetry
Collector, the `basicauth` client extension on the `otlphttp` exporter).

## Firewall

The receiver shares port 9090 with the Prometheus API, so a source-address rule
limits **everything** on that port, not only OTLP. The allowed list therefore
holds both the approved senders and any host that reads the Prometheus API or
UI from outside the Docker network. Grafana reaches Prometheus over the Docker
network and is not affected by a rule on published traffic.

Use placeholders here; fill in the real addresses at apply time. The
documentation range `192.0.2.0/24` is used below.

```bash
# Run on the SIEM host. Replace the example addresses; adjust 9090 if you set
# PROMETHEUS_PORT. Matching on DNAT'd connections leaves container-to-container
# traffic alone.
sudo iptables -N PROM-OTLP-ALLOW
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.10 -j RETURN    # approved sender 1
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.11 -j RETURN    # approved sender 2
sudo iptables -A PROM-OTLP-ALLOW -j DROP
sudo iptables -I DOCKER-USER -p tcp \
    -m conntrack --ctstate DNAT --ctorigdstport 9090 -j PROM-OTLP-ALLOW

# Check
sudo iptables -S DOCKER-USER
sudo iptables -S PROM-OTLP-ALLOW
```

These rules do not survive a reboot. Persist them the way the host already
persists firewall rules (for example `netfilter-persistent save`), or the port
becomes open to the bind address after a restart.

Defense in depth: also limit the source network at the edge firewall, and set
`SIEM_ALLOWED_CIDR` when running `scripts/02-bootstrap.sh` so ufw names a
source for 9090 (see [Network exposure](../README.md#network-exposure)).

## Apply order

Apply in this order so the port is never open without the allow-list. Nothing
here is applied by merging; run each step on the SIEM host on purpose.

1. Set `PROMETHEUS_BASIC_AUTH_PASSWORD` in `.env` (a strong unique value;
   `bash scripts/check-env.sh` rejects placeholders) and run
   `bash scripts/render-prometheus-web-config.sh /opt/siem`. Prometheus will not
   start without the rendered files, and Grafana will not start without the
   variable.
2. Add the firewall rules above, with the real sender addresses.
3. Set `PROMETHEUS_BIND_ADDR` in `.env` to the one interface address senders
   reach (not `0.0.0.0`).
4. Pull the change and recreate Prometheus and Grafana:
   `cd /opt/siem && docker compose up -d prometheus grafana`
5. Confirm the flags and config took effect, then run [Verify](#verify).

## Verify

All four checks must pass. `SENDER_USER` is `prometheus`; read the password from
your shell or a secrets file, never type it into shared history.

1. From an **approved** sender, with the password (expect `200`):

```bash
now=$(date +%s)000000000
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -u "prometheus:${PROMETHEUS_BASIC_AUTH_PASSWORD}" \
  -H 'Content-Type: application/json' \
  "http://SIEM_HOST:9090/api/v1/otlp/v1/metrics" \
  -d '{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"otlp-smoke-test"}}]},"scopeMetrics":[{"metrics":[{"name":"otlp_smoke_test","gauge":{"dataPoints":[{"timeUnixNano":"'"$now"'","asDouble":1}]}}]}]}]}'
```

2. From the same approved sender, **without** the password (expect `401`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  -d '{}' "http://SIEM_HOST:9090/api/v1/otlp/v1/metrics"
```

3. From an **unapproved** host (expect no response: the connection times out or
   is refused, even with the correct password):

```bash
curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' -X POST -u "prometheus:${PROMETHEUS_BASIC_AUTH_PASSWORD}" \
  -H 'Content-Type: application/json' -d '{}' \
  "http://SIEM_HOST:9090/api/v1/otlp/v1/metrics"
```

Any HTTP status from the unapproved host means the firewall rule is not in
effect: stop and fix it before leaving the receiver on.

4. On the SIEM host, confirm the series arrived and the settings took effect:

```bash
curl -sS -u "prometheus:${PROMETHEUS_BASIC_AUTH_PASSWORD}" 'http://127.0.0.1:9090/api/v1/query?query=otlp_smoke_test' | grep -c otlp-smoke-test
curl -sS -u "prometheus:${PROMETHEUS_BASIC_AUTH_PASSWORD}" http://127.0.0.1:9090/api/v1/status/flags | grep -o '"web.enable-otlp-receiver":"[a-z]*"'
curl -sS -u "prometheus:${PROMETHEUS_BASIC_AUTH_PASSWORD}" http://127.0.0.1:9090/api/v1/status/config | grep -o 'out_of_order_time_window: [0-9a-z]*'
```

Also confirm in Grafana that the Prometheus data source still tests green and
that the `prometheus` target is up. Watch `prometheus_tsdb_out_of_order_samples_total`:
a rate that stays above zero means senders still arrive later than the window
allows.

## Rollback

Fastest first, each reversible on its own:

1. **Close the door:** set `PROMETHEUS_BIND_ADDR=127.0.0.1` (or remove it) in
   `.env` and run `docker compose up -d prometheus`. Remote senders can no
   longer connect. The firewall rules can stay; to remove them afterward:
   `sudo iptables -D DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9090 -j PROM-OTLP-ALLOW`,
   then `sudo iptables -F PROM-OTLP-ALLOW && sudo iptables -X PROM-OTLP-ALLOW`.
2. **Turn the receiver off:** revert this change (`git revert` the merge, or
   remove `--web.enable-otlp-receiver` from the compose command) and run
   `docker compose up -d prometheus grafana`. Reverting also removes basic auth,
   the Grafana credential and the self-scrape credential together, so do it
   with the port still on loopback.
3. **Drop the window:** remove the `storage` block from `prometheus.yml` and
   `curl -X POST http://127.0.0.1:9090/-/reload`. Data already stored stays;
   only new out-of-order samples are rejected again.

Pushed series are kept in the TSDB until retention expires. To remove the smoke
test series, let retention age them out (the admin API is not enabled).
