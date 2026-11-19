# Design: running the stack on Podman as an option

Issue: #120 (epic #62). Status: proposal, docs only. Docker stays the default
until the owner decides. Nothing in this document changes code, config or any
live system.

Claim labels. VERIFIED names a repo file or a vendor URL with the date read
(all vendor pages read 2026-11-19). INFERRED is reasoning that was not checked
against a source or a running Podman host; each INFERRED item needs a test on a
rehearsal host before it is relied on. Claims in the per-service and script
tables are INFERRED unless a source is shown.

Vendor sources used:

- [R] https://github.com/containers/podman/blob/main/rootless.md
- [C] https://docs.podman.io/en/latest/markdown/podman-compose.1.html
- [Q] https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html
  (read except the last ~5.7 KB)
- [N] https://docs.podman.io/en/latest/markdown/podman-network-create.1.html
- [RUN] https://docs.podman.io/en/latest/markdown/podman-run.1.html (first
  100 KB only; `--userns`, `--ulimit` and `--memory-lock` were not in the part
  read, so claims about them are INFERRED)

## 1. Summary and recommendation

1. The compose files are mostly portable. The scripts are ahead of the stack:
   `scripts/state_backup_lib.py` (`DockerRuntime`) and `scripts/gameday.py`
   (`CLI_ALLOWED = ("docker", "podman")`) already accept either CLI.
2. The hard parts are not compose syntax. They are: rootless cannot do macvlan
   and cannot bind ports below 1024; cadvisor and the Portainer profile depend
   on the Docker daemon; the Docker-specific firewall model in the bootstrap and
   `prometheus-otlp-firewall.sh`; volume ownership under user namespaces; and
   the n8n macvlan service.
3. Recommended shape: rootful Podman first (same privilege model as today, so
   macvlan, ports 514 and 443, and cadvisor keep a path), rootless later and per
   service. Move restart policy and ordering to Quadlet only after the
   compose-on-Podman step is proven.
4. Migrate one tier at a time, stateless first, OpenSearch and Wazuh last, with
   the Docker definitions kept (stopped) for rollback.

## 2. What the repo uses today (VERIFIED, master 14874a4)

| Fact | Source |
|---|---|
| One compose project, one bridge network `siem-net` (172.20.0.0/24); fixed IPs only on opensearch-hot (.10) and opensearch-warm (.11) | docker/docker-compose.yml |
| Persistent data is host bind mounts under /data/hot and /data/warm; only `portainer_data` is a named volume | docker/docker-compose.yml |
| `restart: unless-stopped` on every service; `depends_on` with `condition: service_healthy` on opensearch-hot for five services | docker/docker-compose.yml |
| Healthchecks call `curl` inside the OpenSearch images | docker/docker-compose.yml |
| `ulimits` memlock -1 and nofile 65536, plus `bootstrap.memory_lock=true`, on both OpenSearch nodes | docker/docker-compose.yml |
| `mem_limit` on prometheus-otlp | docker/docker-compose.yml |
| Explicit `user:` on grafana (472), prometheus, prometheus-otlp, alertmanager (65534) | docker/docker-compose.yml |
| Long-form bind mounts with `create_host_path: false` on prometheus and prometheus-otlp | docker/docker-compose.yml |
| `${VAR:?msg}` required variables and `${VAR:-default}` interpolation | docker/docker-compose.yml, tests/compose.ci.env |
| Profiles `crowdsec` and `portainer` | docker/docker-compose.yml |
| Host ports bind to `${BIND_ADDR}` / `${INGEST_BIND_ADDR}` (default loopback); 514 (syslog-ng, udp and tcp) and 443 (wazuh-dashboard) are below 1024 | docker/docker-compose.yml |
| cadvisor mounts `/`, `/var/run`, `/sys`, `/var/lib/docker`; the "Docker Container Restart Loop" alert reads `container_start_time_seconds{job="cadvisor", name!=""}` | docker/docker-compose.yml, docker/prometheus/rules/siem-health.yml |
| portainer mounts `/var/run/docker.sock` read-write | docker/docker-compose.yml |
| The crowdsec add-on file uses `version: "3.9"`, a path relative to the repo root, named volumes and publishes 3001; it redefines `crowdsec` without the profile | docker/crowdsec/docker-compose.crowdsec.yml |
| n8n is not in the compose file. It runs from its own compose file, on `siem-net` (external) plus a macvlan network with a LAN address | docs/examples/n8n-compose.example.yml, README.md line 121 |
| Bootstrap installs docker-ce and the compose plugin, writes /etc/docker/daemon.json (log opts, overlay2, default ulimits), adds the user to the docker group, sets ufw and notes that Docker-published ports bypass ufw | scripts/02-bootstrap.sh |
| `03-deploy.sh` checks `docker info`, then runs `docker compose pull && docker compose up -d` over SSH | scripts/03-deploy.sh |
| `07-generate-opensearch-certs.sh` chowns node keys to uid 1000 and removes directories "Docker created" at missing bind-mount paths | scripts/07-generate-opensearch-certs.sh |
| `11-wazuh-grafana-readonly.sh`, `05-verify.sh`, `prometheus-otlp-firewall.sh` call `docker exec`, `docker ps`, `docker port` | those scripts |
| CI Test job runs `docker compose config`, `docker pull`, `docker run` (promtool, amtool, logstash, htpasswd) on ubuntu-24.04 with a registry egress allow-list | .github/workflows/ci.yml |
| `n8n_address.py` shells out to `docker inspect` and reads `.NetworkSettings.Networks` | scripts/n8n_address.py |

## 3. Cross-cutting findings

### 3.1 Compose: `podman compose` is a wrapper, not an engine

- VERIFIED [C, 2026-11-19]: `podman compose` runs an external provider. The
  defaults are `docker-compose` and `podman-compose`; if both are installed,
  `docker-compose` wins. Override with `compose_providers` in containers.conf or
  `PODMAN_COMPOSE_PROVIDER`. Behavior depends on the provider.
- Features this repo uses that are most likely to differ in the Python
  `podman-compose` provider: `${VAR:?msg}` errors, `profiles`, `depends_on` with
  `condition: service_healthy`, long-form mounts with `create_host_path: false`,
  `mem_limit`, `$$` escaping in the InfluxDB command, and network name
  prefixing. INFERRED: none were tested.
- Recommendation: use the Docker `docker-compose` v2 binary against the Podman
  socket, which keeps the Compose-spec semantics CI already checks. INFERRED to
  work for every file here. [C] says only that the wrapper lets the provider
  reach "the local Podman socket"; it does not discuss the Docker socket path.
- `container_name:` is used everywhere and scripts rely on those names (`docker
  exec wazuh-indexer`, `docker port prometheus-otlp`, the n8n and grafana names
  in the backup and game-day code). INFERRED: Podman honors `container_name`.

### 3.2 Rootless limits

- VERIFIED [R, 2026-11-19]: rootless Podman cannot bind ports below 1024 unless
  `net.ipv4.ip_unprivileged_port_start` is lowered; resource limits need cgroups
  v2; a standard rootless setup gives containers 65536 UIDs and GIDs; NFS and
  parallel filesystems do not handle user namespaces, so file creation by a
  container root can be denied; with pasta, connections from a container to the
  host's own main-interface IP do not work.
- VERIFIED [N, 2026-11-19]: macvlan and ipvlan "can only be used as root";
  rootless networking needs its own network namespace, so those drivers cannot
  reach host interfaces. They do not support port forwarding.
- VERIFIED [RUN, 2026-11-19]: `--network host` shares the host network
  namespace, including abstract Unix sockets and localhost-bound sockets (a
  security risk). The part read has no rootless-specific host-mode rule. The
  compose files here use no host networking (VERIFIED, no `network_mode`), so
  nothing needs it.
- INFERRED: rootless cannot give a container unlimited memlock unless the
  user's hard limit allows it. OpenSearch with `bootstrap.memory_lock=true`
  would then fail its bootstrap check. Rootful avoids this.
- INFERRED: rootless networking costs throughput on the ingest path (syslog-ng,
  Logstash, Wazuh). Measure before moving those.

### 3.3 Privileged ports

- Host ports 514 (syslog-ng) and 443 (wazuh-dashboard) are below 1024. Rootless
  needs the sysctl above (VERIFIED [R]; host-wide, a security trade for the
  owner, Q3) or a remap. Remapping 514 breaks senders that point at it
  (INFERRED from the sender names in docker/syslog-ng/syslog-ng.conf).
- `SYSLOG_UDP_PORT`, `SYSLOG_TCP_PORT` and `WAZUH_DASHBOARD_PORT` are already
  variables (VERIFIED), so a remap needs no compose change.

### 3.4 Volume ownership and SELinux labels

- Ownership today is set by the host: uids 1000 (OpenSearch), 472 (Grafana),
  65534 (Prometheus, Alertmanager) own the bind-mounted data (VERIFIED, compose
  `user:` lines and the 07 script). Under rootful Podman the uids map 1:1, so
  existing /data directories keep working (INFERRED). Under rootless the
  container uid maps into the user's subuid range, so the same directories are
  unreadable until re-owned with `podman unshare chown` or the `:U` mount
  option, which VERIFIED [RUN, 2026-11-19] "recursively change[s] the owner and
  group of the source volume" to the container uid and gid. `:U` on a very large
  OpenSearch data directory means a slow first start and, crucially, changes the
  owner the Docker rollback expects (Q4).
- VERIFIED [RUN]: `:z` (shared) and `:Z` (private) relabel bind mounts for
  SELinux. Several files are mounted into more than one container (for example
  `./opensearch/certs/root-ca.pem`), so `:z` is right and `:Z` would break the
  second container (INFERRED). Never label `/`, `/var/log` or similar host
  trees (cadvisor, crowdsec).
- The target host OS is not stated in the repo beyond the Ubuntu apt and ufw
  bootstrap (VERIFIED scripts/02-bootstrap.sh). INFERRED: on Ubuntu the labels
  are no-ops; an SELinux distro needs them (Q2).
- The `create_host_path: false` mounts depend on the provider honoring the flag
  (INFERRED test needed). If ignored, a missing rendered file becomes a
  directory, the failure the repo already guards against (VERIFIED comments in
  docker-compose.yml, cleanup in the 07 script).

### 3.5 Restart policy: systemd or Quadlet instead of `unless-stopped`

- VERIFIED [Q, 2026-11-19]: Quadlet reads `.container`, `.network`, `.volume`,
  `.pod`, `.kube` files from /etc/containers/systemd/ (rootful) or
  ~/.config/containers/systemd/ (rootless) and generates systemd units. A
  `Network=` ending in `.network` makes the service depend on that network
  unit; `IP=` sets a static IPv4; `PublishPort=`, `HealthCmd=`,
  `AddCapability=`, `Ulimit=`, `UserNS=` exist; `[Service]` keys pass through,
  so `Restart=always` is explicit; containers default to `Type=notify`.
- VERIFIED [Q]: no `depends_on` health condition exists; ordering is
  `After=`/`Requires=` between units. INFERRED: the current "wait until
  OpenSearch is healthy" behavior (five services) needs a health-aware notify
  mode (not in the part of the page read; verify) or retry loops.
- Option 1 (smaller): keep compose on Podman and rely on a systemd restart unit
  for boot start. INFERRED; not confirmed in the pages read. Option 2: convert to
  Quadlet. Recommend Option 1 first, Quadlet as its own step (Q6).
- Quadlet loses the single-file view and `compose config` as a CI gate. A
  converter (podlet or similar) would be a new tool, so the inspect-before-install
  rule applies: record it in ai-hardening before use.

### 3.6 Networking and the n8n address (issue #90)

- VERIFIED: #90 was a bridge address that changed after a reboot; the fix is to
  resolve it at run time (`scripts/n8n_address.py`) and keep n8n attached to both
  `siem-net` and a macvlan network (docs/examples/n8n-compose.example.yml,
  docs/live-deploy-runbook.md section 4). That a macvlan container is not
  reachable from its own host is documented in docs/update-alerting.md.
- VERIFIED [N]: Podman macvlan is root-only and supports `parent`, `--subnet`,
  `--gateway`, `--ip-range` and ipam drivers `dhcp`, `host-local`, `none`. The
  page read does not document a per-container IP flag for network create; the
  Quadlet `IP=` key is VERIFIED [Q]. INFERRED that `IP=` works on macvlan.
- Consequence: the n8n macvlan service moves to Podman only as rootful. A
  rootless n8n loses its own LAN address, and every consumer of that address
  (Grafana contact point, Wazuh integration, test scripts per docs/n8n-soar.md)
  would need a published host port instead. That is a design change (Q5).
- Name resolution: INFERRED that Podman's DNS on a user-defined network resolves
  container names like Docker, so the `n8n` alias must be retested.
- `n8n_address.py` hard-codes `docker` (VERIFIED) and is the one runtime-calling
  Python script with no runtime selector. INFERRED that `podman inspect` returns
  a Docker-compatible `.NetworkSettings.Networks`; test it.
- The fixed OpenSearch addresses (172.20.0.10, .11) are used by compose only;
  certs and clients use names (VERIFIED, 07 script and compose). INFERRED safe on
  a Podman network with the same subnet.
- The Docker firewall model does not carry over. 02-bootstrap.sh documents that
  Docker-published ports bypass ufw (VERIFIED), and
  `prometheus-otlp-firewall.sh` hard-codes `iptables` chains and `docker port`
  as root (VERIFIED). INFERRED that netavark writes its own rules. That script
  guards an authenticated metrics port, so a Podman version needs a rewrite and
  an adversarial review on the Daybreak tier before any use.

## 4. Per service

| Service | What changes | What breaks | Notes |
|---|---|---|---|
| opensearch-hot, opensearch-warm | Nothing rootful. Rootless: memlock, ownership; `vm.max_map_count` is set host-wide by 02-bootstrap.sh (VERIFIED) | Rootless memlock bootstrap check; data-dir ownership (3.4) | Move late. Security index, snapshots at /mnt/snapshots, static IPs .10 and .11 |
| opensearch-dashboards | none | depends_on health condition (3.5) | Stateless |
| logstash | none | Data dir ownership at /data/hot/logstash; ports are high (fine rootless) | Queue state only |
| grafana | `user: "472"` maps into subuid range rootless | Ownership of /data/warm/grafana; plugin install at start needs egress | State is covered by the state backup |
| influxdb | inline command uses `$$` escaping | `$$` handling varies by provider (3.1) | Bootstrap logic runs on every start |
| prometheus, prometheus-otlp, alertmanager | `user: "65534"` | Ownership; `mem_limit`; `create_host_path: false` (3.4) | Metrics state only |
| elasticsearch-exporter | none | none expected | Credentials via env |
| cadvisor | Rework | `/var/lib/docker` does not exist under Podman (Podman storage is under /var/lib/containers/storage, or the user's ~/.local/share/containers/storage; INFERRED); the `name` label may be empty, so the `name!=""` alert matches nothing; a rootless cadvisor cannot see other users' cgroups | The restart-loop alert depends on it (VERIFIED siem-health.yml). Upstream may document a Podman mode (not read). Q7 |
| wazuh-manager | none rootful | Ownership across the six /var/ossec bind mounts; the image entrypoint may expect root | Agents use 1514 and 1515; keep host IP and ports |
| wazuh-indexer | like OpenSearch | Ownership of /data/hot/wazuh/indexer; cert ownership | Move manager, indexer, dashboard as one unit |
| wazuh-dashboard | host port 443 | Privileged port rootless (3.3) | Remap via `WAZUH_DASHBOARD_PORT` or sysctl |
| syslog-ng | host port 514 udp and tcp | Privileged port rootless; INFERRED that rootless UDP forwarding may rewrite the sender source address, hiding real sender IPs from logs (verify; detection depends on it) | Highest risk for rootless |
| unifi-poller | none | none | Stateless |
| crowdsec (profile) | read-only `/var/log` mount | A rootless user cannot read root:adm logs such as auth.log (INFERRED); never relabel `/var/log` | Rootful keeps working |
| crowdsec add-on file | Rewrite | Path relative to repo root; duplicate `crowdsec` service; published 3001 | Q9 |
| portainer (profile) | Cannot mount `/var/run/docker.sock` | Needs the Podman socket at another path; API compatibility not guaranteed (INFERRED) | Recommend dropping the profile on Podman (Q8) |
| n8n (outside repo) | Rootful only, for macvlan | Rootless has no macvlan | The owner's live file; not in this repo |

## 5. Scripts that call `docker`

| Script | Today | Needed |
|---|---|---|
| scripts/state_backup_lib.py, backup-state.py, restore-state.py | `DockerRuntime` accepts `docker` or `podman` via `container_runtime` (VERIFIED, lines 108, 182, 245). Uses `exec`, `cp`, `inspect -f {{.State.Running}}`, `stop`, `start`, and `run --rm --network none --cap-drop ALL --cap-add CHOWN/DAC_OVERRIDE/FOWNER --security-opt no-new-privileges --volumes-from` | Config only (`container_runtime = "podman"`), after tests of: `podman cp` returning a plain file (the code lstat-checks it, VERIFIED), `--volumes-from` of a stopped container, the cap flags, and ownership results for `n8n_uid` and `grafana_uid`. The helper container does the chown (VERIFIED comment, lines 110-112), so it should work in either runtime. Tests use fake runtimes (VERIFIED tests/python/test_state_backup*.py), so add a Podman argv case only |
| scripts/gameday.py | `docker` config key accepts `docker` or `podman` (VERIFIED, lines 50, 108); the CLI is found only in /usr/bin, /usr/local/bin, /bin, /snap/bin and must be root-owned (VERIFIED docs/game-day.md line 123) | Works if podman is installed in those paths (INFERRED, distro packages use /usr/bin). Doc strings such as `docker compose up -d --force-recreate` need runtime-neutral wording |
| scripts/n8n_address.py | Hard-codes `docker inspect` | Add a runtime selector; test the `podman inspect` JSON shape |
| scripts/11-wazuh-grafana-readonly.sh | `docker exec -i wazuh-indexer ...`, secrets on stdin | A `CONTAINER_CLI` variable; keep the stdin pattern |
| scripts/05-verify.sh | `docker ps --format`, ssh variant | Variable; `podman ps --format "{{.Names}}"` expected to match (INFERRED) |
| scripts/03-deploy.sh | `docker info` check, `docker compose pull/up` | Variable, plus the provider choice (3.1) |
| scripts/02-bootstrap.sh | Installs docker-ce, daemon.json, docker group, ufw | A parallel Podman path: install podman, netavark, aardvark-dns and a compose provider; enable the socket and restart units; carry the daemon.json log and ulimit defaults into containers.conf (INFERRED equivalent); redo the firewall model. Docker group membership is root-equivalent, so rootless Podman removes that exposure (INFERRED) |
| scripts/prometheus-otlp-firewall.sh | `docker port`, Docker-specific chains, root-owned copy | Rework and Daybreak-tier review (3.6) |
| scripts/07-generate-opensearch-certs.sh | chown 1000:1000, directory cleanup text names Docker | Rootless chown target differs (3.4); wording |
| scripts/render-*.sh, 04, 10 | Print `docker compose` hints; 10 uses /mnt/snapshots | Text, plus snapshot path ownership |
| scripts/live-deploy/grafana-deploy.py | Runs `docker compose -f ... up -d grafana` | Variable |
| Docs: README, maintenance, troubleshooting, live-deploy-runbook, game-day, backup-restore | Many `docker ...` commands | One translation table plus a `CONTAINER_CLI` convention, not a copy of every command |

docs/maintenance.md describes a systemd timer running `docker compose pull &&
up -d` (VERIFIED line 46). Under the pin-every-dependency policy that timer
deserves its own review; on Podman it would become an auto-update design
(INFERRED, not read), separate from this one.

## 6. CI changes

Today (VERIFIED .github/workflows/ci.yml): GYST `bash-ci.yml` with a
`test-command` that runs `docker compose config`, `docker pull`, and `docker
run` for promtool, amtool, logstash and htpasswd, with an egress allow-list for
Docker Hub and ghcr.

- Docker is the default, so this job stays. The Podman option adds a check; it
  does not replace one.
- Add (as a GYST input first, per the consolidation rule) a compose-parse check
  against the Podman socket, config validation only, no stack start. INFERRED:
  ubuntu-24.04 runners provide Podman; verify the runner image first.
- Later, optional: run the promtool, amtool and logstash checks with `podman
  run`. They bind-mount staged files made readable with `chmod a+rX` (VERIFIED
  ci.yml comments); under rootless Podman the container user maps differently,
  so those mounts may need `:z`, `:U` or `podman unshare` (INFERRED).
- The egress allow-list already names the registries. Short image names such as
  `httpd:2.4` resolve through registries.conf search order in Podman and may
  prompt or fail non-interactively (INFERRED); use fully qualified names in the
  Podman path.
- Python tests: add cases proving `container_runtime = "podman"` reaches
  `DockerRuntime` and `gameday.py`, and the new `n8n_address.py` selector. No
  live runtime needed (existing tests use fakes, VERIFIED).
- Pin any new tool or provider and hold new releases 7 days (owner policy).

## 7. Migration order and plan

Principle: each step is reversible by starting the Docker definition again. Never
run Docker and Podman on the same bind-mount data at the same time.

Order, lowest risk first:

1. Rehearsal host only: install Podman, run the config checks with no data.
2. Stateless or small-state: unifi-poller, elasticsearch-exporter, alertmanager,
   prometheus-otlp, prometheus (copy metrics state first).
3. Grafana, then InfluxDB (state backup first; `restore-state.py` is a dry run
   by default, VERIFIED).
4. Logstash and syslog-ng (decide the 514 handling first; measure dropped UDP
   and sender source addresses before and after).
5. OpenSearch Dashboards, then OpenSearch hot and warm (snapshot first with
   scripts/10-snapshot-setup.sh, VERIFIED to exist).
6. Wazuh manager, indexer, dashboard as a unit (same host IP and ports 1514 and
   1515 so agents reconnect).
7. cadvisor decision and alert-rule rework (can be done earlier on rehearsal).
8. crowdsec and portainer decisions.
9. n8n last, rootful on macvlan (3.6). It is the live SOAR path; the owner runs it.
10. Quadlet conversion, one service at a time, after the stack is stable.

Per-service procedure (INFERRED shape, to prove on rehearsal):

1. Back up: n8n and Grafana state (scripts/backup-state.py), an OpenSearch
   snapshot, and the `.env` and rendered configs.
2. `docker compose stop <service>`; do not run `down` on the project, which
   removes the shared network.
3. Start the same service under Podman with the same bind mounts and ports.
4. Verify through the real path: scripts/05-verify.sh, a Grafana alert test, and
   a test event through syslog and Wazuh.
5. Keep the Docker definition (stopped) until the next tier passes.

Rollback per service: stop the Podman container, start the Docker one on the same
bind mount. This holds only if file ownership was not changed by `:U` or
`podman unshare chown`; record the original owner before any change, or restore
from backup. Whole stack: stop Podman, `docker compose up -d`. Quadlet: disable
the generated units, remove the unit files, `systemctl daemon-reload`, return to
compose.

Rollback limits: host-level changes (firewall rules, the privileged-port sysctl,
subuid ranges, containers.conf) are not undone by stopping containers. Record
each with its undo as it is made.

## 8. Live changes only the owner can make (listed, not done)

1. Choose the target host and rootful or rootless.
2. Install Podman, netavark, aardvark-dns and a compose provider (an
   ai-hardening inspection record first, per policy).
3. Enable the Podman socket and a restart unit (or Quadlet units).
4. Set `net.ipv4.ip_unprivileged_port_start` if rootless must bind 514 or 443.
5. Set /etc/subuid and /etc/subgid ranges and raise the user's memlock and
   nofile limits for OpenSearch.
6. Re-own /data/hot and /data/warm for rootless (or use `:U`), after recording
   current owners.
7. Open the firewall for Podman networks; rework the OTLP firewall script and its
   root-owned installed copy.
8. Create the Podman macvlan network and move the live n8n service, keeping its
   LAN address.
9. Stop the Docker daemon, or keep it, but never both on the same data.
10. Decide on the Docker socket: remove Portainer, or provide the Podman socket.
11. Update live timers and crontabs that call `docker` (the maintenance timer,
    VERIFIED docs/maintenance.md) and set `container_runtime` and the game-day
    `docker` key to `podman` in their live configs.
12. No new secret is introduced by this design. If a registry mirror or provider
    needs one, it goes in the secret manager's dev environment first.

## 9. Open questions for the owner

Recommended answer first in each.

- Q1. Rootful or rootless? Recommend rootful first (keeps macvlan, 514 and 443,
  cadvisor, memlock); rootless per service later.
- Q2. Which OS does the target host run: Ubuntu with AppArmor, or an SELinux
  distro needing `:z` on bind mounts? Rehearse on the real target OS.
- Q3. If rootless: lower the privileged-port sysctl host-wide, or remap 514 and
  443? Recommend the sysctl only if a remap is impossible for senders.
- Q4. If rootless: is a recursive `:U` or `podman unshare chown` acceptable given
  data size and its effect on rollback?
- Q5. n8n: stay rootful on macvlan, or accept a published-port design with no own
  LAN address?
- Q6. Restart handling: compose plus a systemd restart unit first (recommended),
  or straight to Quadlet?
- Q7. cadvisor: use a Podman mode if upstream has one, move the restart-loop alert
  to another source, or drop that alert on Podman?
- Q8. Portainer on Podman: drop it (recommended) or keep it via the Podman socket?
- Q9. Fix the stale crowdsec add-on compose file now, or leave it?
- Q10. Is this a supported option in the published repo (both runtimes, Docker
  default), or a one-host migration? That decides the `CONTAINER_CLI` variable and
  whether CI tests both.
- Q11. Compose provider: `docker-compose` against the Podman socket
  (recommended) or `podman-compose`?

## 10. Verification still needed

No Podman host was used and nothing was run. Every INFERRED item is a test for a
rehearsal host: compose parse of both files with the chosen provider;
`container_name`, `depends_on` health conditions, `create_host_path: false`,
`mem_limit`, `$$` escaping and profiles; `podman inspect` network shape for
`n8n_address.py`; `podman cp`, `--volumes-from` and cap flags for the backup
helper; cadvisor labels; syslog source-IP preservation under rootless; OpenSearch
memlock; and unqualified image name resolution in CI.
