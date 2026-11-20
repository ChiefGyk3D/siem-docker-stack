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
echoed back, evaluated, or used to build a program path. After validation the
scripts hold only a fixed token, exactly `docker` or `podman`. That validated
token (never the raw setting) is the one thing placed in the command strings that
`03-deploy.sh` and `05-verify.sh` send to another host over ssh.

## Where it is read, and which source wins

The variable is validated by the same rule everywhere (exactly `docker` or
`podman`). Where a value can also come from a file, the order differs per helper:

| Helper | Source order (first match wins) |
|---|---|
| `scripts/n8n_address.py` and the scripts that import it | environment |
| `scripts/gameday.py` | `GAMEDAY_DOCKER`, then the TOML `docker` key, then `CONTAINER_ENGINE`. The engine chosen is used for the whole run, including the n8n address lookup |
| `scripts/state_backup_lib.py` (backup and restore) | the config file `container_runtime`, then `CONTAINER_ENGINE` |
| `scripts/live-deploy/n8n-setup-alert-router.py` | environment |
| `scripts/deploy-n8n-soar.sh` | environment; the validated name is sent to the SIEM host for the address lookup |
| `scripts/03-deploy.sh`, `06-generate-wazuh-certs.sh`, `11-wazuh-grafana-readonly.sh`, `prometheus-otlp-firewall.sh` | environment |
| `scripts/05-verify.sh`, `scripts/08b-init-opensearch-security.sh` | the `.env` file these scripts already load takes precedence over the exported environment, because it is sourced first |

`scripts/live-deploy/grafana-deploy.py` starts no process and is unchanged.
`scripts/02-bootstrap.sh` still installs Docker only.

## Which binary runs, and with what environment

The setting chooses a name from the fixed list. The program is then found only in
`/usr/bin`, `/usr/local/bin`, `/bin` and `/snap/bin`, never through your `PATH`.
The file, its directory and every directory above it up to `/` must be owned by
root and not writable by group or others; links are resolved first and the
resolved file is what runs. If there is no such file the script stops and says so.

The engine process gets a minimal explicit environment, not yours: a fixed `PATH`
plus `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `TERM`, `TZ` and
`XDG_RUNTIME_DIR` when they are set. Everything else is dropped, notably
`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `CONTAINER_HOST`,
`CONTAINER_CONNECTION`, `XDG_CONFIG_HOME`, `LD_*`, `BASH_ENV`, `ENV` and proxy
variables. So the engine always talks to its local default endpoint. A remote
engine would need its own validated setting; there is none. The engine's own
per-user configuration under `HOME` (for example `~/.docker/config.json`) is still
read.

The Python helpers share `scripts/container_engine.py` (`engine_run`). Shell
scripts source `scripts/lib-container-engine.sh` (POSIX sh; it needs GNU `stat`
and `readlink`) and run the engine through `ce_run`.
`tests/python/test_container_engine.py` holds the two to the same rules.

Two places run a command on another host over ssh (`03-deploy.sh`, and
`05-verify.sh` when it falls back to ssh). There the engine is found by that
host's own shell and keeps that host's environment. The lookup in
`deploy-n8n-soar.sh` runs the trusted-directory rule on the host through the
streamed Python helper.

## Sourcing the helper

Each script finds its own real directory (symlinks resolved) and sources
`lib-container-engine.sh` from there, never from a directory next to a link that
launched it. It refuses a helper that is a symlink, is owned by someone other than
root or the running user, or is world writable (and group writable when running
as root).

## The root-owned firewall script

`prometheus-otlp-firewall.sh`, run as root, resolves its own real path, requires
the script, the helper and every directory above them up to `/` to be root-owned
and not group or world writable, opens the helper once, checks the open file, and
sources that same open descriptor. Install both files into the root-owned
directory, as in [prometheus-otlp.md](prometheus-otlp.md). The script still
changes only the `DOCKER-USER` chain; whether that chain exists under Podman is
not verified.

## Not covered

- Compose files, the bootstrap script and rootless Podman behavior (see the design doc).
- Hint text printed by some scripts still says `docker compose ...`.
