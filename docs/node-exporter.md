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

## Grafana infrastructure rules: disk only, not host down

The `node` job is in the infra disk rule only: `Infrastructure disk almost full
(critical)` in `docker/grafana/provisioning/alerting/infra-alerts.yml`, critical
tier with `phone=true`, the same as `twingate-ztna` and `unifi-controller`. That
change ships with PR #231 (branch `feat/224-node-alerts`). Until it merges, master's
infra rules select no `job="node"`.

The `node` job is deliberately NOT in either host-down rule. A Grafana rule cannot
report its own host down while Grafana is dead: if the SIEM host dies, so does the
rule that would say so. The external heartbeat observer (`docs/heartbeat.md`)
covers that case.

The disk rules still ship paused. Nothing alerts on this host's disk until the
owner unpauses `infra-disk-critical`; see `docs/infrastructure-alerts.md`.
