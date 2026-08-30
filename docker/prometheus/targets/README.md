# Prometheus File-Based Service Discovery Targets

Host/LAN scrape targets (node_exporter, GPU exporters, etc.) live here as
JSON files loaded by `file_sd_configs` in `prometheus.yml`, one file per
scrape job. This keeps your real IPs and hostnames out of version control —
only the `*.example.json` templates are tracked; the real `*.json` files
are gitignored.

## Setup

1. Copy each example file to its real name (drop `.example`):

   ```bash
   cd docker/prometheus/targets
   for f in *.example.json; do cp "$f" "${f%.example.json}.json"; done
   ```

2. Edit each `.json` file: replace the `192.0.2.x` placeholder addresses
   with your real exporter IPs, and set `instance_name` to each host's
   actual name. Keep the `role` / `gpu_role` label values as-is unless you
   also update the dashboards and alerts that filter on them.

3. Restart or reload Prometheus:

   ```bash
   cd docker/
   docker compose restart prometheus
   # or, without a restart (--web.enable-lifecycle is on):
   curl -X POST http://localhost:9090/-/reload
   ```

   Prometheus also re-reads `file_sd` files automatically within about
   5 minutes of a change — no reload needed for target edits after that.

Only create the files for jobs you actually use. A job whose target file is
missing simply scrapes nothing (Prometheus logs a harmless read error).

| File | Job | Exporter / port |
|------|-----|-----------------|
| `node.json` | `node` | node_exporter on the SIEM host (:9100) |
| `twingate-ztna.json` | `twingate-ztna` | node_exporter on Twingate connectors (:9100) |
| `unifi-controller.json` | `unifi-controller` | node_exporter on the UniFi controller (:9100) |
| `Cryptocurrency.json` | `Cryptocurrency` | node_exporter (:9100) |
| `AI.json` | `AI` | node_exporter (:9100) |
| `Security.json` | `Security` | node_exporter (:9100) |
| `Computers.json` | `Computers` | node_exporter (:9100) |
| `nvidia-dcgm.json` | `nvidia-dcgm` | dcgm-exporter on Linux GPU hosts (:9400) |
| `nvidia-gpu-windows.json` | `nvidia-gpu-windows` | nvidia_gpu_exporter on Windows (:9835) |

To add more hosts to a job, append another `{"targets": [...], "labels":
{...}}` object to that job's JSON array (see `twingate-ztna.example.json`
for a multi-target file).

## Migration

If you were running this stack before scrape targets moved to `file_sd`
(targets used to be hard-coded in `prometheus.yml`): after pulling this
change you **must create the real target files** as described above, or the
`node`, `twingate-ztna`, `unifi-controller`, `Cryptocurrency`, `AI`,
`Security`, `Computers`, and GPU scrape jobs will have **no targets** and
their dashboards/alerts will go empty. Re-enter the IPs and
`instance_name` labels you previously had in `prometheus.yml` (they are in
your git history), then restart/reload Prometheus and confirm all targets
are UP at http://localhost:9090/targets.
