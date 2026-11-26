# Design: Docker Compose baseline, hardened, one host-specific file

Status: DRAFT for the owner's decision. Docs only: no code, no configuration, no
live change. Issue #113, child of the deployment variants epic #111, under epic
#62. Sibling design: [variant-podman-quadlet.md](variant-podman-quadlet.md).
Related: [podman.md](podman.md), [secrets-sources.md](secrets-sources.md),
[optional-components.md](optional-components.md). This document does not repeat
them.

Marking. **VERIFIED** names a repo file at origin/master 7c8de1b or a vendor URL
with the date read (vendor pages read 2026-11-19). **INFERRED** is reasoning not
checked against a source or a running host. Examples use `example.com` and
placeholders only; no setting value appears here.

Searches and reads for items not settled by one page: Compose service reference
https://docs.docker.com/reference/compose-file/services/ (read); Docker run
reference https://docs.docker.com/engine/containers/run/ (read; it covers
`--cap-drop` and `--memory` but not `--read-only`, `--pids-limit` or
`--security-opt`, so those are taken from the Compose page only).
`query: cockpit-podman manage quadlet containers rootless user session` and
`query: loginctl enable-linger rootless podman systemd user services start at boot without login`
were run for the sibling design; no Docker-specific search turned up an
authoritative page on user namespace remapping, so that item is INFERRED.

## 1. Goals and non-goals

Goals (issue #113 done-when: a fresh host needs edits to one file only, and the
docs name every value in it):

1. The Compose deployment is the baseline other people copy, so it must be safe
   by default: no secret fallbacks, loopback ports, least privilege per service.
2. Every host-specific value lives in one file, `docker/.env`, and a documented
   table names every variable in it.
3. A fresh host, a lab user and the maintainer's own host differ only in that
   file.

Non-goals:

- Not a full rewrite of `docker/docker-compose.yml`. Changes are additive: new
  keys and new variables with defaults that keep today's behavior.
- Not Docker rootless mode or Swarm. Docker's user-namespace remap is discussed
  (section 5) but not required.
- Not the secret source or optional-component mechanism; those have their own
  designs and this one only fits them (section 8).
- Not a live change. The maintainer's running stack changes only through steps
  the owner takes (section 10).

## 2. Current state (VERIFIED, docker/docker-compose.yml, 2026-11-19)

| Fact | Evidence |
|---|---|
| 18 services; two behind profiles (`crowdsec`, `portainer`) | service list from the file; `profiles:` at lines 623 and 646 |
| One bridge network `siem-net`, subnet 172.20.0.0/24; fixed addresses .10 and .11 on the two OpenSearch nodes | lines 30 to 36, 92, 143 |
| `restart: unless-stopped` on every service | per service |
| Secrets are `${VAR:?msg}`; no secret has a `:-` default | file; guarded by `tests/python/test_compose_security.py` `test_compose_has_no_secret_fallbacks` |
| Every published port binds `${BIND_ADDR}` or `${INGEST_BIND_ADDR}` with default 127.0.0.1, except the hard-coded loopback ports 9300, 9600 and 9301 | lines 88, 89, 140; test `test_every_published_port_defaults_to_loopback` |
| Portainer is opt-in and mounts the Docker socket read-write | lines 640 to 653; `test_portainer_is_opt_in` |
| No `read_only`, `cap_drop`, `cap_add`, `security_opt`, `pids_limit`, `tmpfs`, `privileged`, `network_mode` anywhere | grep of the file |
| Healthchecks only on opensearch-hot and opensearch-warm (`curl` inside the image); five services use `depends_on` with `condition: service_healthy` on opensearch-hot | lines 93 and 144, and the `depends_on` blocks |
| One memory limit: `mem_limit` on prometheus-otlp | line 369 |
| Explicit `user:` on grafana (472) and prometheus, prometheus-otlp, alertmanager (65534); other services use the image default | lines 239, 351, 404, 429 |
| Images default to `latest` for grafana, prometheus x2, syslog-ng, unifi-poller, crowdsec; influxdb is `1.8`; logstash `8.9.0`; cadvisor `v0.49.1`; portainer `lts`; others default to a version variable | image lines |
| 20 bind mounts use the hard-coded roots `/data/hot` and `/data/warm` | `grep -c` of the file |
| Compose reads variables from the `.env` next to it; `.env.example` is the template with 99 names (commented ones included, measured 2026-11-19); `scripts/check-env.sh` validates a `.env` file | `.env.example`, `scripts/check-env.sh`, compose header comment |
| CI runs `docker compose --env-file ../tests/compose.ci.env config --quiet` | `.github/workflows/ci.yml` line 42 |

## 3. File layout

Unchanged in shape; this design adds a naming and documentation rule:

```
docker/docker-compose.yml        # the stack; no host-specific literal
docker/.env                      # THE host-specific file (git-ignored, mode 600)
.env.example                     # template: every name, grouped, each with one comment line
docker/docker-compose.hardening.yml   # proposed: hardening overlay (section 6)
docker/<service>/...             # per-service config, host-agnostic or rendered
docs/                            # one table naming every .env variable (section 4)
```

Hardening overlay (decision D2). Two ways to carry the new keys: edit the base
file, or add an overlay merged with `-f`. Recommended: edit the base file. A
baseline others copy should be safe without remembering a second `-f`. An overlay
is the fallback if the maintainer wants to roll hardening out service by service
without touching the live compose file. Compose merges multiple files by
documented rules (INFERRED, merge semantics were not read here).

## 4. The single host-specific file

`docker/.env` is already the contract (VERIFIED). It does not yet meet the
done-when for three reasons found by reading the compose file:

1. Host-specific literals are NOT variables: the data roots `/data/hot` and
   `/data/warm` (20 places), the network subnet and the two fixed addresses, and
   the loopback host ports 9300, 9600, 9301, 1515 and Portainer 9443. A fresh
   host with a different disk layout must edit `docker-compose.yml`, so the
   done-when fails.
2. Coverage is good in one direction. Measured 2026-11-19 by comparing the 63
   `${NAME}` names in compose with the names in `.env.example` (including
   commented ones): every compose name is in the template (none missing). The
   template has 36 further names that compose does not use (scripts and add-ons).
   So the template is complete for compose but has no machine check; test 1
   (section 8) keeps it so.
3. `.env.example` also carries names for scripts and add-ons that are not used by
   compose (`JUMPCLOUD_*`, `GPU_*`, `MATRIX_*`, `HEARTBEAT_*`, `GF_SMTP_*`,
   `P1_*`, `DOPPLER_*`, `EXPIRY_WATCH_*`, VERIFIED names in `.env.example`). One
   file with everything is acceptable, but each group needs a header saying which
   component uses it, so a minimal deployer can skip a group.

Proposed new variables (names only; defaults keep today's behavior):

- `SIEM_DATA_HOT`, `SIEM_DATA_WARM`: replace the literal data roots. Defaults
  `/data/hot` and `/data/warm` (no change for the maintainer).
- `SIEM_NET_SUBNET` and `SIEM_NET_OPENSEARCH_HOT_IP`, `SIEM_NET_OPENSEARCH_WARM_IP`:
  for a host where 172.20.0.0/24 overlaps an existing network (INFERRED common).
  The fixed addresses are only used by compose (VERIFIED podman.md section 3.6).
- `OPENSEARCH_TRANSPORT_BIND`, `OPENSEARCH_METRICS_BIND` style names for 9300,
  9600, 9301: stay loopback by default; named so the guard test still sees a
  variable. Names are a proposal.
- Hardening knobs with safe defaults, so a deployer can loosen one service without
  editing the file: `SIEM_PIDS_LIMIT`, and per-service memory names following the
  existing `PROMETHEUS_OTLP_MEM_LIMIT` pattern.
- `COMPOSE_PROJECT_NAME`: a standard Compose variable (INFERRED, not read on the
  pages here) that avoids a clash when two stacks share a host.

Variable groups for the table in the docs (one row per name: purpose, default,
required or optional, which services read it, secret or not):

1. Placement and exposure: `BIND_ADDR`, `INGEST_BIND_ADDR`, `PORTAINER_BIND_ADDR`,
   `SIEM_ALLOWED_CIDR`, `SIEM_HOST`, `SIEM_USER`, `TZ`, plus the data-root and
   network names above.
2. Ports: every `*_PORT`.
3. Sizing: `OPENSEARCH_HOT_HEAP`, `OPENSEARCH_WARM_HEAP`, `LOGSTASH_HEAP`,
   `WAZUH_INDEXER_HEAP`, `PROMETHEUS_OTLP_MEM_LIMIT`, retention names.
4. Image versions: every `*_VERSION`, all pinned in the baseline (section 7).
5. Secrets (names only, empty in the template, required): every `*_PASSWORD`,
   `GRAFANA_WEBHOOK_SECRET` (optional once optional-components.md lands), and the
   add-on tokens.
6. Component credentials for optional parts: UniFi (`UNIFI_*`), SMTP, Matrix.

Rule for the docs: the table is generated or tested, never hand-maintained
(section 9, test 1). A fresh host's checklist is: copy the template, fill the
required group, run `scripts/check-env.sh`, run compose. That is the done-when.

What is NOT in `.env` and still host-specific (so the docs must name it):

- Rendered and copied files: `alertmanager.yml` rendered by
  `scripts/render-alertmanager-config.sh`; `internal_users.yml` rendered by
  `scripts/08b-init-opensearch-security.sh` (VERIFIED comment in compose);
  the TLS certificates under `docker/opensearch/certs` and `docker/wazuh/certs`
  (VERIFIED mount paths; the Wazuh certs directory ships only a README).
- Prometheus scrape targets under `docker/prometheus/targets/` (ten
  `*.example.json` files, VERIFIED listing), which hold the lab's addresses and
  are copied and edited per site.
- Host preparation by scripts 01 and 02 (disks, kernel `vm.max_map_count`,
  firewall). These are outside compose by nature; the docs list them as the
  pre-compose steps and state that they are one-time and per host.

So the honest statement of the done-when is: one file for values, plus named
generated files from named scripts, plus host preparation. Anything else is a defect.

## 5. Security hardening

Compose keys are VERIFIED on https://docs.docker.com/reference/compose-file/services/
(2026-11-19): `read_only` (read-only filesystem), `cap_drop` and `cap_add`,
`security_opt` (boolean options such as `no-new-privileges` can omit the value),
`pids_limit`, `mem_limit` (must match `deploy.resources.limits.memory` when both
are set), `tmpfs` (with `mode`, `uid`, `gid`), `init`, `healthcheck`,
`depends_on` conditions (`service_started`, `service_healthy`,
`service_completed_successfully`), `sysctls` (namespaced only), `ulimits`, `user`,
`userns_mode` (supported values depend on the platform). The Docker run page
(2026-11-19) confirms `--cap-drop` accepts `ALL`, and `--memory` has a 6M minimum.
Not found on any page read: whether `pids_limit` and `deploy.resources.limits` are
honored by a plain `docker compose up` (the page says the `deploy` section is
ignored where the platform does not implement it). Use `mem_limit` and
`pids_limit`, which the repo already uses (`mem_limit`, VERIFIED), rather than
`deploy`.

### 5.1 What the images allow

Today none of these controls exist (VERIFIED, section 2). What each image
tolerates is INFERRED until a rehearsal run proves it. Method per service:
add all controls, start the service, read its log, loosen the one failing control,
record the reason in a comment next to the line.

| Service | `cap_drop: [ALL]` | `no-new-privileges` | `read_only` | `pids_limit` | Notes |
|---|---|---|---|---|---|
| grafana (user 472) | yes, expected no adds | yes | yes, with `tmpfs: /tmp`; plugins and data on bind mounts | yes | Plugin install at start needs a writable plugins dir (INFERRED) |
| prometheus, prometheus-otlp, alertmanager (65534) | yes | yes | yes | yes | Data on bind mounts; config mounted `:ro` (VERIFIED) |
| elasticsearch-exporter, unifi-poller | yes | yes | yes | yes | Stateless (VERIFIED podman.md section 4) |
| opensearch-dashboards | yes | yes | yes, test | yes | Stateless |
| opensearch-hot, opensearch-warm | yes, then add only what fails | yes | no (writes in the image tree, INFERRED) | yes, generous | `ulimits` memlock and nofile already set (VERIFIED); `IPC_LOCK` may be needed for `bootstrap.memory_lock` when caps are dropped (INFERRED) |
| logstash | yes | yes | no, test | yes | Queue state on a bind mount (VERIFIED) |
| influxdb | `CHOWN`, `SETUID`, `SETGID` likely needed (entrypoint drops privileges, INFERRED) | yes | no | yes | Bootstrap command runs on every start (VERIFIED podman.md) |
| wazuh-manager, wazuh-indexer, wazuh-dashboard | add as needed (init and `su`, INFERRED) | test, may break the init | no | yes | Six bind mounts for the manager (VERIFIED) |
| syslog-ng | yes, `NET_BIND_SERVICE` only if the port is below 1024 and the runtime does not already allow it (INFERRED) | yes | no, test | yes | 514 UDP and TCP (VERIFIED) |
| crowdsec (profile) | add as needed | yes | no | yes | Reads `/var/log` read-only (VERIFIED) |
| cadvisor | cannot drop much; needs host mounts `/`, `/sys`, `/var/run`, `/var/lib/docker` (VERIFIED lines 468 to 471) | yes | yes | yes | Keep, flagged as the highest-trust container besides Portainer |
| portainer (profile) | n/a | n/a | n/a | n/a | Docker socket read-write (VERIFIED): root on the host; stays opt-in |

Docker defaults already drop many capabilities, so `cap_drop: [ALL]` plus a
minimal `cap_add` is the target. Whether the default seccomp profile is enough is
not claimed. No service needs `privileged` (VERIFIED, none uses it).

### 5.2 Cross-cutting controls

1. `security_opt: [no-new-privileges:true]` on all services. Cheapest, widest.
2. `init: true` where a service forks children (INFERRED: Wazuh, syslog-ng).
3. `restart: unless-stopped` stays; add `healthcheck` to every service (section
   5.3) so `docker ps` and the verify script can tell a running container from a
   working one.
4. Resource limits from variables: `mem_limit` and `pids_limit` per service.
   Memory must exceed the JVM heap variable plus overhead (INFERRED); the values
   are a sizing decision for the owner and are not set here.
5. User namespaces. Docker's daemon-level user-namespace remap (`userns-remap`)
   changes the host owner of every bind mount (INFERRED from the Podman findings:
   podman.md section 3.4 VERIFIED the equivalent rootless effect). It would force
   a re-own of `/data/hot` and `/data/warm` and breaks the roll-back path to a
   non-remapped daemon. Recommended: do NOT make it part of the baseline; document
   it as an optional host hardening with its ownership consequence. Decision D4.
6. Ports. The existing rule stays: bind addresses default to loopback, guarded by
   `test_every_published_port_defaults_to_loopback`. Docker-published ports bypass
   ufw, so the bind address is the control (VERIFIED compose comment and
   `scripts/02-bootstrap.sh` per podman.md). New variables for 9300, 9600, 9301
   must keep the loopback default.
7. Docker socket. Only Portainer touches it and it is opt-in (VERIFIED). cadvisor
   mounts `/var/run` read-only (VERIFIED line 469), which exposes the socket path
   inside the container as a read-only mount (INFERRED, a read-only bind of the
   directory does not prevent connecting to a socket file in it). Decision D5:
   narrow the cadvisor mount if the upstream image works without it (not tested).
8. Secrets stay `${VAR:?}` with no default (guarded by an existing test), and no
   secret goes into `docker compose config` output kept in logs or CI artifacts
   (INFERRED, interpolated values appear; same warning as secrets-sources.md).
9. Image supply chain: every image pinned by version, and a digest where the
   owner wants it (section 7).

### 5.3 Healthchecks (new, per image)

Only the two OpenSearch checks exist (VERIFIED). A check must use a program that
exists in the image. Compose healthcheck semantics are VERIFIED (same as a
Dockerfile `HEALTHCHECK`). For each service the implementation records the tool
actually present in the image (not checked here, INFERRED): Grafana and
Prometheus have an HTTP health endpoint, but `curl` or `wget` may not be in the
minimal images (Prometheus images are known to be minimal, INFERRED). Where no
tool exists the fallback is a check that uses the service's own binary, or none,
stated in a comment. Do not add `depends_on: service_healthy` edges beyond today's
five until the checks are proven (a bad check blocks start-up).

## 6. Update and rollback

Update:

1. Pin everything. Today six images default to `latest` or a floating tag
   (section 2). The baseline pins each to a version in `.env.example`. This also
   closes the gap docs/maintenance.md warns about for the unattended update timer
   (VERIFIED line 18: pin image versions before enabling the timer).
2. A new release is held seven days before the pin moves (owner rule;
   Dependabot cooldown is the enforcement per the global rule). Dependabot for
   compose image tags: INFERRED supported; check the repo's `dependabot.yml`.
3. Procedure per service: back up state (`scripts/backup-state.py`, VERIFIED),
   change the version name in `.env`, `docker compose pull <service>`, `docker
   compose up -d <service>`. Never `docker compose down` for a partial update; it
   removes the shared network (VERIFIED podman.md section 7).
4. Verify through the real path: `scripts/05-verify.sh` (VERIFIED), a Grafana
   alert test, a test event through syslog.

Rollback:

1. Restore the previous version name in `.env`; `docker compose up -d <service>`.
2. Data does not roll back with the image. A service that migrated its data on
   upgrade may refuse the old image (INFERRED for Grafana, InfluxDB, OpenSearch,
   Wazuh). Take an OpenSearch snapshot (`scripts/10-snapshot-setup.sh`, VERIFIED)
   and the state backup before any major bump, and read the vendor's upgrade note.
3. `.env` itself: keep the last known good copy mode 600, outside git. The
   baseline docs say so.
4. The unattended timer in docs/maintenance.md (VERIFIED, weekly `docker compose
   pull && up -d`) conflicts with the hold-and-pin policy. Recommended: remove it
   from the baseline docs or make it opt-in with the warning first. Decision D6.

## 7. Fit with secrets-sources and optional-components

secrets-sources.md: Compose already consumes secrets as environment variables
(VERIFIED). The baseline is the `envfile` source: `docker/.env`, mode 600, checked
by `scripts/check-env.sh` (VERIFIED). The launcher in that design wraps
`docker compose` for the `doppler` and `credstore` sources. Constraints this
variant adds:

- `.env` stays valid for Compose even with the launcher (Compose reads it as
  data, not shell), so only the scripts that `source` it change (VERIFIED in
  secrets-sources.md section 2).
- The shell environment takes precedence over `.env` in Compose (INFERRED; the
  secrets-sources test 5 settles it). The baseline docs warn against exporting a
  stale variable.
- `docker compose config` prints interpolated secrets; the test and CI guard
  never publish it (CI uses only `--quiet`, VERIFIED ci.yml line 42).

optional-components.md: Compose profiles gate SERVICES, so crowdsec and portainer
stay profiles (VERIFIED), while the router add-on and notifiers are provisioning
files, not services. The minimal profile is `docker compose up` with no profile and
no copied notifier file. With the router off, `GRAFANA_WEBHOOK_SECRET` becomes
optional (`:-` instead of `:?`), and the existing guard test must be updated so
"no secret has a default" does not fire on a variable that is allowed to be empty;
the right rule is "required only when the router file is provisioned". The new
hardening keys apply the same way to optional services when they are enabled.

## 8. CI and test plan (no host needed)

All tests are new unless stated; existing: `tests/python/test_compose_security.py`
(VERIFIED) and the CI config check (VERIFIED).

1. Variable coverage: the set of `${NAME}` in compose, minus a short allowlist of
   Compose built-ins, is a subset of the names documented in the `.env.example`
   file and the docs table, and every name in the docs table is used somewhere
   (compose, a script or an add-on file). This is the machine check of the
   done-when "the docs name every value". Revert-proof by deleting one name.
2. No host literals: a test fails when `docker-compose.yml` contains `/data/hot`,
   `/data/warm`, an IPv4 literal (other than 127.0.0.1 defaults), or a literal
   host name outside a documented allowlist. Today it would fail on 20 data paths
   and the network lines, so it lands with the variable change, not before.
3. Hardening guard: every service carries `security_opt` with `no-new-privileges`
   and `cap_drop` of `ALL`, unless it is in a short exception list in the test with
   a reason string for each (cadvisor, portainer, any service the rehearsal
   proves cannot run). A new service without these fails CI.
4. `read_only: true` where the table in section 5.1 says so, asserted per service.
5. `pids_limit` and `mem_limit` present on every service that runs a long-lived
   process (names only; values are variables with defaults).
6. Image pin check: no `image:` ends in `:latest` or lacks a tag (default value of
   the variable is a version, not `latest`).
7. Ports: existing loopback test extended to the new variable names.
8. Healthcheck presence: every service has one or is in the exception list.
9. Config parse: `docker compose config --quiet` with `tests/compose.ci.env` for
   the default stack, each profile on, and the minimal profile (extends the CI
   step VERIFIED at ci.yml line 42). A second run with the hardening values
   removed fails (revert-proof).
10. Env checker: `scripts/check-env.sh` rejects the template as shipped (empty
    secrets) and accepts the CI file (VERIFIED existing tests).

Not testable without a host (owner or rehearsal, listed not run): that each image
starts with `cap_drop: ALL`, `read_only` and `no-new-privileges`; healthchecks pass;
memory limits do not OOM the JVMs; a fresh host starts from `.env` alone; update
and rollback with data.

## 9. Fresh host walk-through (the done-when, as a test script outline)

1. Install the container engine and the compose plugin (`scripts/02-bootstrap.sh`).
2. Prepare disks and data roots (`scripts/01-disk-setup.sh`), honoring the data
   root names in `.env`.
3. Copy `.env.example` to `docker/.env`, fill the required group, `chmod 600`.
4. `bash scripts/check-env.sh docker/.env`.
5. Generate certificates and render files with the named scripts (section 4).
6. `docker compose up -d`; verify with `scripts/05-verify.sh`.

The edit surface is step 3 only; steps 1, 2 and 5 run scripts, not edits.

## 10. Live changes only the owner can make (listed, not done)

1. Adding the new variables to the live `.env` (defaults keep the old values, so
   no change is required to keep running).
2. Applying the hardening keys to the live compose file and restarting each service
   in turn, with a rollback at each step. A restart of OpenSearch or Wazuh is a
   live outage of ingestion; schedule it.
3. Pinning `latest` images to the versions currently running (read them from the
   live host first; not read here).
4. Removing or making opt-in the weekly update timer.
5. Any `userns-remap` change (D4).

## 11. Owner decisions (recommended answer first)

- D1. Make the data roots, the subnet and the fixed addresses variables with
  today's values as defaults. Recommended yes; it is what makes the done-when true.
- D2. Put the hardening keys in the base compose file, not an overlay.
  Recommended yes.
- D3. Roll hardening out one service at a time on a rehearsal copy, starting with
  the stateless ones, never the live OpenSearch first. Recommended yes.
- D4. Docker `userns-remap` is optional host hardening, not baseline. Recommended
  yes (not baseline).
- D5. Narrow cadvisor's mounts if the upstream image still works. Recommended yes
  if proven on the rehearsal host; otherwise keep and document the trust.
- D6. Remove the unattended update timer from the baseline docs or make it opt-in.
  Recommended yes.
- D7. One `.env` for everything, with group headers, or split into a core file and
  an add-ons file. Recommended one file (the done-when says one), with headers.

## 12. Open questions

- Q1. Which images tolerate `read_only` and `cap_drop: ALL`? Rehearsal run, per
  service, recorded in the compose comments.
- Q2. Do `pids_limit` and `mem_limit` behave as expected under the engine version
  in use? Test `docker inspect` output on the rehearsal host.
- Q3. Which tool exists in each image for a healthcheck?
- Q4. Does the baseline need a second file for the n8n router stack, which runs
  from its own compose file (VERIFIED docs/examples/n8n-compose.example.yml)?
  Recommended: no, keep it an example, referenced from the add-on docs.
- Q5. PR #136 (`CONTAINER_ENGINE`) is open and adds a runtime selector for the
  helper scripts; the baseline assumes Docker and does not depend on it. Whether
  both variants share one doc naming the engine setting is for the implementation.
- Q6. Should the Podman variant's compose-parity test (variant-podman-quadlet.md
  section 10, test 3) read this file's rendered config, so the two variants cannot
  drift? Recommended yes.
