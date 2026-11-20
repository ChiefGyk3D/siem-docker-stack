# Container engine setting (CONTAINER_ENGINE)

Issue #130 (epic #62). Docker is the default. The helper scripts can use Podman
instead. This page covers the setting only. It does not claim the stack runs on
Podman; that is the open work in [design/podman.md](design/podman.md).

## The setting

`CONTAINER_ENGINE` is one environment variable with exactly two allowed values:

| Value | Meaning |
|---|---|
| unset or empty | `docker` |
| `docker` | Docker |
| `podman` | Podman |

Anything else (a different case, a path, a trailing space, another engine) stops
the script with a message that names the two allowed values. The value is never
echoed back and never placed in a shell command string.

## Where it is read

Every helper reads the same variable the same way.

| Helper | How |
|---|---|
| `scripts/n8n_address.py` (and the scripts that import it) | environment |
| `scripts/gameday.py` | default for the `docker` key; `GAMEDAY_DOCKER` or the TOML key overrides it |
| `scripts/state_backup_lib.py` (backup and restore) | default for `container_runtime`; a value in the config file wins |
| `scripts/live-deploy/n8n-setup-alert-router.py` | environment |
| `scripts/deploy-n8n-soar.sh` | validated locally, then the name is sent to the SIEM host for the address lookup |
| `scripts/03-deploy.sh` | validated locally; the name is used in the commands run on the target host (`info`, `compose pull`, `compose up`) |
| `scripts/05-verify.sh`, `scripts/08b-init-opensearch-security.sh` | environment or the `.env` they already load |
| `scripts/06-generate-wazuh-certs.sh`, `scripts/11-wazuh-grafana-readonly.sh`, `scripts/prometheus-otlp-firewall.sh` | environment |

`scripts/live-deploy/grafana-deploy.py` starts no process and is unchanged.
`scripts/02-bootstrap.sh` still installs Docker only.

## Which binary runs

The setting chooses a name from the fixed list. The program is then found only in
`/usr/bin`, `/usr/local/bin`, `/bin` and `/snap/bin`, never through your `PATH`.
The file, its directory and every directory above it up to `/` must be owned by
root and not writable by group or others; links are resolved first and the
resolved file is what runs. If there is no such file the script stops and says so.

The Python helpers share `scripts/container_engine.py`. Shell scripts source
`scripts/lib-container-engine.sh` (POSIX sh; it needs GNU `stat` and `readlink`).
`tests/python/test_container_engine.py` holds the two to the same rules.

Two places run a command on another host over ssh (`03-deploy.sh`,
`05-verify.sh` when it falls back to ssh, and the lookup in
`deploy-n8n-soar.sh`). There the validated name is used and the binary is found by
that host's own shell or by the same trusted-directory rule in the streamed
Python helper.

## The root-owned firewall script

`prometheus-otlp-firewall.sh` now sources `lib-container-engine.sh` from its own
directory and checks that file the same way it checks the script (root-owned, not
group or world writable). Install both into the root-owned directory, as in
[prometheus-otlp.md](prometheus-otlp.md). The script still changes only the
`DOCKER-USER` chain; whether that chain exists under Podman is not verified.

## Not covered

- Compose files, the bootstrap script and rootless Podman behavior (see the design doc).
- Hint text printed by some scripts still says `docker compose ...`.
