# Optional node_exporter for the SIEM host

Issue #224. Service: `node-exporter` in `docker/docker-compose.yml` (compose
profile `node-exporter`, off unless asked for). Guard:
`tests/python/test_node_exporter_optional.py`.

Source: node_exporter README, section "Docker",
https://github.com/prometheus/node_exporter#docker (read 2026-11-26). It says the
exporter in a container needs `--path.rootfs` matching a bind mount of the host
root, shown as `-v "/:/host:ro,rslave"` and `--path.rootfs=/host`. It also shows
`--net=host --pid=host`. This service leaves both out on purpose (see below).
Image pin `v1.12.1` is a release older than seven days (published 2026-07-14).

## What it gives you

Prometheus gets a `node` job for the host that runs the stack: filesystem, CPU,
memory, load. Without it the box running Grafana and Prometheus has no host
metrics, so nothing can alert on its disk.

## Safe by default

- Not published on any host port. Prometheus reaches it on `siem-net` as
  `node-exporter:9100`. Nothing listens on the host.
- `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, no `privileged`.
- The only mount is the host root, read-only (`/:/host:ro,rslave`).
- No `pid: host` and no `network_mode: host`. Host networking would move the
  listener onto the host, out of reach of Prometheus on the bridge network
  without publishing a port. Trade: `node_network_*` shows the container's
  interfaces, not the host's. Everything the disk and host-down rules use is
  unaffected.

## Add it to a live, older compose file

Placeholders: `/opt/siem/docker` is your compose directory.

1. Back up: `cd /opt/siem/docker && cp docker-compose.yml docker-compose.yml.bak`
2. Under `services:` of the live file, paste the `node-exporter` block from this
   repo's `docker/docker-compose.yml` (from `node-exporter:` through its
   `networks:` entry). The live file must have the network `siem-net`; if it
   names it differently, use that name in the block.
3. Start only this service. Naming it activates its profile, and `--no-deps`
   leaves everything else untouched:
   `docker compose up -d --no-deps node-exporter`
4. Create the target file (it is gitignored):
   `cp prometheus/targets/node.example.json prometheus/targets/node.json`
   and set `instance_name` to the host's name. The live `prometheus.yml` needs
   the `node` job from this repo (a `file_sd_configs` job reading
   `/etc/prometheus/targets/node.json`); add it if missing. Prometheus re-reads
   target files within about 5 minutes, or reload:
   `curl -X POST http://localhost:9090/-/reload` (if lifecycle is on and auth
   needs `-u`, use your own method; never put the password on the command line).
5. Verify, in Prometheus (Status, Targets) or by query: `up{job="node"}` is 1,
   and `node_filesystem_avail_bytes{job="node"}` returns series.
6. Check the container is quiet and not exposed:
   `docker compose ps node-exporter` shows no published ports.

## Rollback

`docker compose rm -sf node-exporter`, remove the block from the compose file (or
`cp docker-compose.yml.bak docker-compose.yml`), delete `targets/node.json`.
Nothing else was changed.

## Grafana infrastructure rules do not cover this job

Checked against `docker/grafana/provisioning/alerting/infra-alerts.yml` on
master (2026-11-26): the rules select `twingate-ztna|unifi-controller` and
`Security|AI|Cryptocurrency|grafana|prometheus`. None selects `job="node"`.
This service keeps the job name `node` because `prometheus.yml` already defines
it, so the SIEM host is monitored in Prometheus but does not alert yet. Adding
`node` to a rule's job regex (for example the warning host-down and disk rules)
is a separate change and the owner's call; the rules are not edited here.
