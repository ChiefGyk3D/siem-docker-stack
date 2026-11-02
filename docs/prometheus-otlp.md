# Prometheus OTLP receiver

This stack can accept OpenTelemetry (OTLP) metrics pushed over HTTP, for example
from an OpenTelemetry Collector. The receiver is a **separate Prometheus
instance** (`prometheus-otlp`), authenticated with basic auth, firewalled to
approved senders, and given the least privilege it needs. It is on loopback
until you widen it on purpose.

> **Warning: the receiver must be authenticated and firewalled.** Prometheus has
> no authentication of its own, so this instance turns on basic auth
> (`--web.config.file`) and you limit who can reach it with a `DOCKER-USER`
> rule that names the approved senders. Do both before you widen the bind
> address. Docker-published ports bypass UFW, so UFW alone is not enough. Never
> expose the port to an untrusted network.

## Design

| Choice | Why |
|--------|-----|
| A separate instance (`prometheus-otlp`, port 9091), not the SIEM Prometheus on 9090 | Pushed series live in their own database, so they cannot mix with the series the SIEM alert rules evaluate, and a sender credential has no reach into the SIEM Prometheus. Labels such as `job` can be set by a sender, so a label cannot prove where a series came from; separating the database does. |
| No `--web.enable-lifecycle` and no admin API on the instance | A sender credential cannot reload or stop anything. Config changes take a container restart. |
| Three accounts: `sender`, `grafana`, `scrape` | Each is rotated or revoked on its own. Prometheus has no per-user permissions, so the separation limits blast radius and lets you cut one off; it is not an authorization system. |
| No scrape jobs and no rules on the instance | It only stores and serves what was pushed. |
| The SIEM Prometheus (9090) is unchanged | Same port, same lifecycle behavior as before; it only gains a scrape job for the receiver's own health. |

Files: `docker/prometheus-otlp/prometheus.yml` (window and OTLP translation),
the `prometheus-otlp` service in `docker/docker-compose.yml`, the Grafana data
source "Prometheus OTLP", and `scripts/render-prometheus-web-config.sh`.

### Why a 30 minute out-of-order window

OTLP senders batch, retry and flush in bursts, so samples can arrive after newer
ones. Prometheus rejects those unless the out-of-order window covers them. The
window is measured against the newest sample in the database, not the wall
clock: a sample is accepted if its timestamp is no older than the newest sample
minus the window. 30 minutes is the value the Prometheus OTLP guide recommends.
It comfortably covers a sender batch timeout of 10 to 30 seconds with the default
60 second export interval, and short sender retries.

It does not cover a long outage. A sender that queues data across an outage
longer than 30 minutes will have the oldest points rejected as too old when it
catches up. If you need that, raise the window in
`docker/prometheus-otlp/prometheus.yml` (more WAL and memory) and restart the
instance; do not raise it speculatively.

### Sender requirements

- Use HTTP basic auth with user `sender` and `PROMETHEUS_OTLP_SENDER_PASSWORD`
  (for an OpenTelemetry Collector, the `basicauth` client extension on the
  `otlphttp` exporter).
- Use **cumulative** temporality. Delta metrics are dropped unless the
  experimental `otlp-deltatocumulative` feature flag is enabled, which this
  stack does not enable.
- Send to `http://<siem-host>:9091/api/v1/otlp/v1/metrics` with
  `Content-Type: application/x-protobuf` or `application/json`.
- Keep high-cardinality values (session or request ids) off metric labels.
  Scrape limits do not apply to pushed data, so control cardinality at the
  sender or collector.

### Credentials and file permissions

Set `PROMETHEUS_OTLP_SENDER_PASSWORD`, `PROMETHEUS_OTLP_GRAFANA_PASSWORD` and
`PROMETHEUS_OTLP_SCRAPE_PASSWORD` in `.env` (three different strong values;
`bash scripts/check-env.sh` rejects placeholders). Then run, as root:

```bash
sudo -E bash scripts/render-prometheus-web-config.sh /opt/siem
```

The script writes bcrypt hashes to `docker/prometheus-otlp/web.yml` and the
scrape password (the one value Prometheus must hold in plain text, to
authenticate its own scrape) to `docker/prometheus-otlp/secrets/`. Files are
owned by the container user (65534), mode 0400, directory 0500, so no other
user can read them. It refuses to run unprivileged rather than leave a readable
secret. The sender and Grafana passwords are never written by the script.

Rotate an account by changing its value in `.env`, re-running the script and
restarting the affected containers.

## Firewall

Only the OTLP senders need to reach port 9091. Grafana and the SIEM Prometheus
reach the instance over the Docker network, which published-port rules do not
affect. Use placeholders here; fill in the real sender addresses at apply time.
The documentation range `192.0.2.0/24` is used below.

```bash
# Run on the SIEM host. Replace the example addresses; use your
# PROMETHEUS_OTLP_PORT if you changed it. Matching DNAT'd connections leaves
# container-to-container traffic alone.
sudo iptables -N PROM-OTLP-ALLOW
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.10 -j RETURN    # approved sender 1
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.11 -j RETURN    # approved sender 2
sudo iptables -A PROM-OTLP-ALLOW -j DROP
sudo iptables -I DOCKER-USER -p tcp \
    -m conntrack --ctstate DNAT --ctorigdstport 9091 -j PROM-OTLP-ALLOW

# Check
sudo iptables -S DOCKER-USER
sudo iptables -S PROM-OTLP-ALLOW
```

These rules do not survive a reboot. Persist them the way the host already
persists firewall rules (for example `netfilter-persistent save`), or the port
is open to the bind address after a restart.

Defense in depth: also limit the source network at the edge firewall (see
[Network exposure](../README.md#network-exposure)).

## Apply order

Apply in this order so the port is never open without the allow-list. Nothing
here is applied by merging; run each step on the SIEM host on purpose.

1. Set the three passwords in `.env` and run the render script (above).
2. Create the data directory: `sudo mkdir -p /data/hot/prometheus-otlp && sudo chown 65534:65534 /data/hot/prometheus-otlp`
   (`scripts/01-disk-setup.sh` does this on a new host).
3. Add the firewall rules above, with the real sender addresses.
4. Set `PROMETHEUS_OTLP_BIND_ADDR` in `.env` to the one interface address
   senders reach (not `0.0.0.0`).
5. Pull the change and start the receiver; restart Grafana and the SIEM
   Prometheus so they pick up the new data source and scrape job:
   `cd /opt/siem && docker compose up -d prometheus-otlp prometheus grafana`
6. Run [Verify](#verify).

## Verify

All four checks must pass. Read the passwords from your shell or a secrets file,
never type them into shared history.

1. From an **approved** sender, with the sender password (expect `200`):

```bash
now=$(date +%s)000000000
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" \
  -H 'Content-Type: application/json' \
  "http://SIEM_HOST:9091/api/v1/otlp/v1/metrics" \
  -d '{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"otlp-smoke-test"}}]},"scopeMetrics":[{"metrics":[{"name":"otlp_smoke_test","gauge":{"dataPoints":[{"timeUnixNano":"'"$now"'","asDouble":1}]}}]}]}]}'
```

2. From the same approved sender, **without** the password (expect `401`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  -d '{}' "http://SIEM_HOST:9091/api/v1/otlp/v1/metrics"
```

3. From an **unapproved** host (expect no response: the connection times out or
   is refused, even with the correct password):

```bash
curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" \
  -H 'Content-Type: application/json' -d '{}' \
  "http://SIEM_HOST:9091/api/v1/otlp/v1/metrics"
```

Any HTTP status from the unapproved host means the firewall rule is not in
effect: stop and fix it before leaving the receiver on.

4. On the SIEM host, confirm the series arrived, that the sender account cannot
   use the reload endpoint, and that the settings took effect:

```bash
curl -sS -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" 'http://127.0.0.1:9091/api/v1/query?query=otlp_smoke_test' | grep -c otlp-smoke-test
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" http://127.0.0.1:9091/-/reload   # expect 403 or 404, not 200
curl -sS -u "scrape:${PROMETHEUS_OTLP_SCRAPE_PASSWORD}" http://127.0.0.1:9091/api/v1/status/config | grep -o 'out_of_order_time_window: [0-9a-z]*'
```

Also confirm the `prometheus-otlp` target is up on the SIEM Prometheus and that
the "Prometheus OTLP" data source tests green in Grafana. Watch
`prometheus_tsdb_out_of_order_samples_total` on the receiver: a rate that stays
above zero means senders still arrive later than the window allows.

## Rollback

Fastest first, each reversible on its own:

1. **Close the door:** set `PROMETHEUS_OTLP_BIND_ADDR=127.0.0.1` (or remove it)
   in `.env` and run `docker compose up -d prometheus-otlp`. Remote senders can
   no longer connect. To remove the firewall rules afterward:
   `sudo iptables -D DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9091 -j PROM-OTLP-ALLOW`,
   then `sudo iptables -F PROM-OTLP-ALLOW && sudo iptables -X PROM-OTLP-ALLOW`.
2. **Stop the receiver:** `docker compose stop prometheus-otlp` (or
   `docker compose rm -sf prometheus-otlp`). The SIEM Prometheus, its rules and
   its data are not affected. The `prometheus-otlp` scrape target will show
   down; that job is not part of any alert.
3. **Remove the change entirely:** `git revert` the merge and run
   `docker compose up -d`. Remove `/data/hot/prometheus-otlp` and the rendered
   files in `docker/prometheus-otlp/` if you want the pushed data and secrets
   gone; otherwise they stay on disk until retention (30 days by default)
   expires.
