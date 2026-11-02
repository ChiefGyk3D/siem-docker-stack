# Prometheus OTLP receiver

This stack can accept OpenTelemetry (OTLP) metrics pushed over HTTPS, for example
from an OpenTelemetry Collector. The receiver is a **separate Prometheus
instance** (`prometheus-otlp`), authenticated with basic auth, firewalled to
approved senders, and given the least privilege it needs. It is on loopback
until you widen it on purpose.

> **Warning: the receiver must be authenticated and firewalled.** Prometheus has
> no authentication of its own, so this instance turns on basic auth
> (`--web.config.file`) and you limit who can reach it with a `DOCKER-USER`
> rule that names the approved senders, and the credentials travel over TLS. Do all three before you widen the bind
> address. Docker-published ports bypass UFW, so UFW alone is not enough. Never
> expose the port to an untrusted network.

## Design

| Choice | Why |
|--------|-----|
| A separate instance (`prometheus-otlp`, port 9091), not the SIEM Prometheus on 9090 | Pushed series live in their own database, so they cannot mix with the series the SIEM alert rules evaluate, and a sender credential has no reach into the SIEM Prometheus. Labels such as `job` can be set by a sender, so a label cannot prove where a series came from; separating the database does. |
| No `--web.enable-lifecycle` and no admin API on the instance | A sender credential cannot reload or stop anything. Config changes take a container restart. |
| Three accounts: `sender`, `grafana`, `scrape` | Each is rotated or revoked on its own. Prometheus has no per-user permissions: see [Account privileges](#account-privileges). |
| TLS on the receiver (`tls_server_config`, TLS 1.2 or later) | Basic-auth credentials would otherwise cross the network in clear text, and the allow-list does not stop capture on the path. |
| A disk bound (`--storage.tsdb.retention.size`, 5GB by default) as well as 30 days | Pushed data shares the hot tier with OpenSearch and Wazuh; scrape limits do not apply to pushed data, so a misbehaving sender must not be able to fill the disk. |
| No scrape jobs and no rules on the instance | It only stores and serves what was pushed. |
| The SIEM Prometheus (9090) now requires basic auth too (accounts `grafana` and `self`) | It keeps `--web.enable-lifecycle` (used for config reload), so it must never answer unauthenticated. A test fails if any service enables lifecycle or the admin API without a web config. |
| Alert rules select metrics by `job` | Hygiene only: a label does not prove where a series came from, because a sender can set any label. Pushed series are kept out of the rules' database altogether, which is what actually protects the alerts. |

Files: `docker/prometheus-otlp/prometheus.yml` (window and OTLP translation),
the `prometheus-otlp` service in `docker/docker-compose.yml`, the Grafana data
source "Prometheus OTLP", and `scripts/render-prometheus-web-config.sh`.

### Account privileges

Prometheus basic auth only authenticates; it does not authorize. **Every account
on an instance has identical web access**: full read and write on that
instance's HTTP API. On the SIEM Prometheus that includes the lifecycle
endpoints (`/-/reload`, `/-/quit`), for `grafana` and `self` alike, so the
Grafana data source credential can do what `self` can. On the receiver, the
`sender`, `grafana` and `scrape` accounts all have full read and write, but the
instance has no lifecycle or admin API, no rules and no scrape jobs, and holds
only pushed data in its own database.

I did not put an endpoint-aware proxy in front, because it adds a component to
secure and patch for little gain here: the receiver has nothing to protect
except pushed data, and the SIEM Prometheus is separate. The stated controls
are the firewall allow-list, TLS, separate credentials you can revoke one at a
time, and the disk bound. If you want a hard boundary on the SIEM Prometheus,
drop `--web.enable-lifecycle` (reload with `docker kill -s HUP prometheus` or a
restart) or add a proxy that only allows the paths each account needs.

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
  `otlphttp` exporter) over HTTPS, trusting the receiver's certificate
  (`tls.ca_file` on the exporter).
- Use **cumulative** temporality. Delta metrics are dropped unless the
  experimental `otlp-deltatocumulative` feature flag is enabled, which this
  stack does not enable.
- Send to `https://<siem-host>:<port>/api/v1/otlp/v1/metrics` (port 9091 unless
  you set `PROMETHEUS_OTLP_PORT`) with
  `Content-Type: application/x-protobuf` or `application/json`.
- Keep high-cardinality values (session or request ids) off metric labels.
  Scrape limits do not apply to pushed data, so control cardinality at the
  sender or collector.

### Credentials and file permissions

Set `PROMETHEUS_OTLP_SENDER_PASSWORD`, `PROMETHEUS_OTLP_GRAFANA_PASSWORD`,
`PROMETHEUS_OTLP_SCRAPE_PASSWORD`, `PROMETHEUS_GRAFANA_PASSWORD` and
`PROMETHEUS_SELF_PASSWORD` in `.env` (five different strong values of at most 72 bytes, because bcrypt ignores the
rest; avoid `$`, which Grafana and compose expand, so use letters, digits and
simple punctuation; `bash scripts/check-env.sh` rejects placeholders). Create the receiver's TLS certificate first (next section), then run,
as root, **on the deployed copy**:

```bash
sudo -E bash scripts/render-prometheus-web-config.sh /opt/siem
```

The script hashes everything first and stages the files privately, so a failure
leaves the previous set untouched. It refuses symlinked or group- or
world-writable target directories, and it refuses to run unprivileged. Do not
render in the workstation checkout: `scripts/03-deploy.sh` protects the rendered
files on the server from `rsync --delete` and stops if they are missing.

The script writes bcrypt hashes to `docker/prometheus/web.yml` and
`docker/prometheus-otlp/web.yml`, and the two scrape passwords (the only values
Prometheus must hold in plain text, to authenticate its own scrapes) to
`docker/prometheus/secrets/`. Files are
owned by the container user (65534), mode 0400, directory 0500, so no other
user can read them. It refuses to run unprivileged rather than leave a readable
secret. The sender and Grafana passwords are never written by the script.
The SIEM Prometheus now asks for a password too: use
`curl -u "self:$PROMETHEUS_SELF_PASSWORD" ...` for API queries and for
`POST /-/reload`.

Rotate an account by changing its value in `.env`, re-running the script and
restarting the affected containers.

### TLS certificate

Put a certificate and key in `docker/prometheus-otlp/tls/` on the server
(`server.crt`, `server.key`); the render script makes them readable by the
container only. For a self-signed pair (replace the names; keep the key private):

```bash
sudo mkdir -p /opt/siem/prometheus-otlp/tls
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=SIEM_HOST" \
  -addext "subjectAltName=DNS:SIEM_HOST,IP:192.0.2.1" \
  -keyout /opt/siem/prometheus-otlp/tls/server.key -out /opt/siem/prometheus-otlp/tls/server.crt
```

Copy `server.crt` to each sender as its trust anchor. Grafana and the SIEM
Prometheus reach the receiver over the Docker network on the same host and do
not verify this certificate.

## Firewall

Only the OTLP senders need to reach the receiver port (9091 unless you set
`PROMETHEUS_OTLP_PORT`). Grafana and the SIEM Prometheus
reach the instance over the Docker network, which published-port rules do not
affect. Use placeholders here; fill in the real sender addresses at apply time.
The documentation range `192.0.2.0/24` is used below.

```bash
# Run on the SIEM host. Replace the example addresses. OTLP_PORT must be the
# published port, so it follows PROMETHEUS_OTLP_PORT from .env. Matching DNAT'd
# connections leaves container-to-container traffic alone.
OTLP_PORT=${PROMETHEUS_OTLP_PORT:-9091}
sudo iptables -N PROM-OTLP-ALLOW
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.10 -j RETURN    # approved sender 1
sudo iptables -A PROM-OTLP-ALLOW -s 192.0.2.11 -j RETURN    # approved sender 2
sudo iptables -A PROM-OTLP-ALLOW -j DROP
sudo iptables -I DOCKER-USER -p tcp \
    -m conntrack --ctstate DNAT --ctorigdstport "$OTLP_PORT" -j PROM-OTLP-ALLOW

# Check
sudo iptables -S DOCKER-USER
sudo iptables -S PROM-OTLP-ALLOW
```

Scope: this is an IPv4, iptables (DOCKER-USER) rule. It assumes the receiver
is bound to a single IPv4 address, as the apply order requires. A Docker
nftables backend has no DOCKER-USER chain, and IPv6 needs its own rules; if
either applies, do not widen the bind address, and test from an unapproved
IPv6 host too.

These rules do not survive a reboot. Persist them the way the host already
persists firewall rules (for example `netfilter-persistent save`), or the port
is open to the bind address after a restart.

Defense in depth: also limit the source network at the edge firewall (see
[Network exposure](../README.md#network-exposure)).

## Apply order

Apply in this order so the port is never open without the allow-list. Nothing
here is applied by merging; run each step on the SIEM host on purpose.

1. Create the TLS certificate and set the five passwords in `.env`, then run the
   render script on the server (above).
2. Provide the TLS files and the data directory: `sudo mkdir -p /data/hot/prometheus-otlp && sudo chown 65534:65534 /data/hot/prometheus-otlp`
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
OTLP_PORT=${PROMETHEUS_OTLP_PORT:-9091}
now=$(date +%s)000000000
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" \
  -H 'Content-Type: application/json' \
  --cacert server.crt "https://SIEM_HOST:${OTLP_PORT}/api/v1/otlp/v1/metrics" \
  -d '{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"otlp-smoke-test"}}]},"scopeMetrics":[{"metrics":[{"name":"otlp_smoke_test","gauge":{"dataPoints":[{"timeUnixNano":"'"$now"'","asDouble":1}]}}]}]}]}'
```

2. From the same approved sender, **without** the password (expect `401`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  -d '{}' --cacert server.crt "https://SIEM_HOST:${OTLP_PORT}/api/v1/otlp/v1/metrics"
```

3. From an **unapproved** host (expect no response: the connection times out or
   is refused, even with the correct password):

```bash
curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" \
  -H 'Content-Type: application/json' -d '{}' \
  --cacert server.crt "https://SIEM_HOST:${OTLP_PORT}/api/v1/otlp/v1/metrics"
```

Any HTTP status from the unapproved host means the firewall rule is not in
effect: stop and fix it before leaving the receiver on.

4. On the SIEM host, confirm the series arrived, that the sender account cannot
   use the reload endpoint, and that the settings took effect:

```bash
OTLP_PORT=${PROMETHEUS_OTLP_PORT:-9091}
curl -sS -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" --cacert /opt/siem/prometheus-otlp/tls/server.crt --resolve SIEM_HOST:${OTLP_PORT}:127.0.0.1 "https://SIEM_HOST:${OTLP_PORT}/api/v1/query?query=otlp_smoke_test" | grep -c otlp-smoke-test
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -u "sender:${PROMETHEUS_OTLP_SENDER_PASSWORD}" --cacert /opt/siem/prometheus-otlp/tls/server.crt --resolve SIEM_HOST:${OTLP_PORT}:127.0.0.1 https://SIEM_HOST:${OTLP_PORT}/-/reload   # expect 403 or 404, not 200
curl -sS -u "scrape:${PROMETHEUS_OTLP_SCRAPE_PASSWORD}" --cacert /opt/siem/prometheus-otlp/tls/server.crt --resolve SIEM_HOST:${OTLP_PORT}:127.0.0.1 https://SIEM_HOST:${OTLP_PORT}/api/v1/status/config | grep -o 'out_of_order_time_window: [0-9a-z]*'
```

Also confirm the `prometheus` and `prometheus-otlp` targets are up on the SIEM
Prometheus and that both Prometheus data sources test green in Grafana. The SIEM
Prometheus without a password must answer 401:
`curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9090/-/healthy`. Watch
`prometheus_tsdb_out_of_order_samples_total` on the receiver: a rate that stays
above zero means senders still arrive later than the window allows.

## Rollback

Fastest first, each reversible on its own:

1. **Close the door:** (`OTLP_PORT` is `${PROMETHEUS_OTLP_PORT:-9091}`) set `PROMETHEUS_OTLP_BIND_ADDR=127.0.0.1` (or remove it)
   in `.env` and run `docker compose up -d prometheus-otlp`. Remote senders can
   no longer connect. To remove the firewall rules afterward:
   `sudo iptables -D DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdstport "$OTLP_PORT" -j PROM-OTLP-ALLOW`,
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
