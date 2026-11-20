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
| `scripts/04-apply-ism-policy.sh` | the `.env` file is consulted only when `OPENSEARCH_ADMIN_PASSWORD` is empty in the environment; the exported environment wins, then the first existing `.env` |
| `scripts/05-verify.sh`, `scripts/08b-init-opensearch-security.sh` | the `.env` file these scripts already load takes precedence over the exported environment, because it is sourced first |
| `scripts/08-crowdsec-smoketest.sh`, `scripts/09-test-crowdsec-pfsense-ingest.sh` | the `.env` file takes precedence over the exported environment, because it is sourced first |
| `scripts/10-snapshot-setup.sh` | like `04-apply-ism-policy.sh`: the `.env` file is consulted only when `OPENSEARCH_ADMIN_PASSWORD` is empty in the environment |

`scripts/live-deploy/grafana-deploy.py` starts no process and is unchanged.
`scripts/02-bootstrap.sh` still installs Docker only.

## Which binary runs, and with what environment

The setting chooses a name from the fixed list. The program is then found only in
`/usr/bin`, `/usr/local/bin`, `/bin` and `/snap/bin`, never through your `PATH`.
The file, its directory and every directory above it up to `/` must be owned by
root and not writable by group or others; links are resolved first and the
resolved file is what runs. If there is no such file the script stops and says so.

The engine process gets a minimal explicit environment, not yours: a fixed `PATH`,
`USER`, `LOGNAME`, `LANG`, `LC_ALL`, `TERM` and `TZ` when they are set, and a fresh
private empty `HOME`. That home is a mode 0700 directory made for the one call and
removed after it; `DOCKER_CONFIG` and the `XDG_*` directories point inside it.
Nothing else is passed: not `DOCKER_HOST`, `DOCKER_CONTEXT`, `CONTAINER_HOST`,
`CONTAINER_CONNECTION`, your `HOME`, `XDG_RUNTIME_DIR`, `LD_*`, `BASH_ENV`, `ENV` or
proxy variables. So no per-user engine configuration is read (docker `config.json`
and contexts, CLI plugins, credential helpers, podman `containers.conf` and
connections), and the engine uses its system defaults and local system socket.
Consequences: registry credentials in your home are not used, and rootless Podman
(whose storage lives under `HOME`) is not supported by these helpers; use rootful
Podman. A remote engine would need its own validated setting; there is none.

The Python helpers share `scripts/container_engine.py` (`engine_run`). Shell
scripts source `scripts/lib-container-engine.sh` (POSIX sh; it needs GNU `stat`
and `readlink`) and run the engine through `ce_run`.
`tests/python/test_container_engine.py` holds the two to the same rules.

Two places run a command on another host over ssh (`03-deploy.sh`, and
`05-verify.sh` when it falls back to ssh). There the engine is found by that
host's own shell and keeps that host's environment. The lookup in
`deploy-n8n-soar.sh` runs the trusted-directory rule on the host through the
streamed Python helper.

## Running the scripts as root

The seven scripts above, and also `01-disk-setup.sh`, `02-bootstrap.sh` and
`render-prometheus-web-config.sh`, use the shebang `#!/bin/bash -p`. Privileged mode makes bash ignore
`BASH_ENV` and `ENV`, skip exported shell functions, and ignore `SHELLOPTS` and
`BASHOPTS`, so none of them can run as root before the first line. As root, run a
script by its path (`sudo scripts/06-generate-wazuh-certs.sh`), never as
`bash script`: an explicit interpreter bypasses the shebang, and a root run that
finds privileged mode off stops with a message saying so (it cannot undo what the
environment already ran, which is why the path form is required). Each script
then clears `set -x` state and `BASH_ENV ENV CDPATH GLOBIGNORE PS4`, fixes `PATH`
as its first command, and learns whether it is root from the kernel through the
absolute `/usr/bin/id` (or `/bin/id`), never from `EUID` or `UID`, and stops if the
answer is not a number. `render-prometheus-web-config.sh` is the one exception to
the PATH order: it learns the user number first (builtins and the absolute `id`
only) and then, as root it fixes `PATH`; a non-root run keeps the caller's `PATH`, by
design, because the tests and the owner's tools rely on it.

The root decision, the privileged-mode check and the trusted script and helper tree
are done early in each script, before it reads `SIEM_DEPLOY_DIR`, locates a
file or sources anything. `04-apply-ism-policy.sh`, `05-verify.sh`, `08-crowdsec-smoketest.sh`,
`08b-init-opensearch-security.sh`, `09-test-crowdsec-pfsense-ingest.sh` and `10-snapshot-setup.sh` load a
`.env`, which is shell code: they do it through `ce_source_env`, which as root accepts
only a regular file (not a link) that is root-owned, with every directory above it
root-owned and not group or world writable, opens it once and sources that open
descriptor. For an ordinary user the file must be owned by root or by you and not world
writable. When sourcing the complete file returns nonzero (the status of its last command,
a syntax error, or a `return 1`), the loader prints a one-line message naming the file
(never a value) and the script stops before any request. A command that fails in the
middle of the file, followed by one that succeeds, does not fail the load. While the file
runs, its output is discarded and tracing, `PS4` and `DEBUG`, `RETURN` and `ERR` traps are
switched off before the output comes back, so a `PS4` or a trap that holds a password
prints nothing.

Start these scripts by their path (`sudo scripts/05-verify.sh`), never through an
explicit `bash` interpreter: as root an explicit interpreter reads `BASH_ENV`, imported
functions, `SHELLOPTS` and `BASHOPTS` before line 1 and bypasses the privileged shebang.
The privileged-mode check inside the script is a diagnostic only and cannot repair such
a launch.

Signals (kept deliberately small): `ce_run` runs the engine in the foreground of a
subshell that has its own traps, so your script's traps are never read or changed. The
subshell sets one EXIT trap that deletes the private home before the home exists. HUP,
INT and TERM in that subshell just `exit` with 129, 130 or 143, and the EXIT trap removes
the home; a signal that arrives while the home is being made is noted and acted on right
after. No process is tracked, forwarded to or killed by the library. In Python,
`private_home` is a plain try/finally with `rmtree`: it covers a return, an exception,
KeyboardInterrupt and SystemExit, and installs no signal handler.

What is not covered, honestly:

- SIGKILL (or a power loss) leaves `engine-home.*` (shell) or `engine-home-*` (Python)
  under `/run`, `/var/tmp` or `/tmp`. The directory is empty or holds only what the
  engine wrote into its private home; delete it when no engine call is running, for
  example `sudo find /run /var/tmp /tmp -maxdepth 1 -name 'engine-home*' -mmin +60 -exec rm -rf -- {} +`.
- A signal sent to the script's PID alone (not its process group) is acted on when the
  running engine call returns, because the shell does not run a trap during a foreground
  command. A terminal Ctrl-C, a logout and a supervisor stop reach the whole group, so
  the engine stops too.
- If the engine client is killed, the container it already asked the daemon to start may
  keep running; stop it with the engine's own command.
- In Python, SIGTERM and SIGHUP with their default action end the process without
  cleanup; a program that wants cleanup installs its own handler that raises.

Each kept variable has its own pattern: `LANG` and `LC_ALL` are `C`, `POSIX`, `C.UTF-8` or
`ll_CC[.charset]`; `TERM` is terminal-name characters only; `TZ` is a zone name such as
`UTC` or `America/New_York` (no leading colon or slash, no dots).

## Sourcing the helper

Each of these scripts (not `render-prometheus-web-config.sh`, see above) sets a fixed `PATH` as its first command, calls
`stat`, `readlink`, `dirname` and `id` by absolute path while it bootstraps, and
finds its own real directory (symlinks resolved). It sources
`lib-container-engine.sh` from there, never from a directory next to a link that
launched it. It refuses a helper that is a symlink, is owned by someone other than
root or the running user, or is world writable (and group writable when running
as root). As root it also requires every directory above the helper to be
root-owned and not group or world writable. The helper is opened once, the open
file is checked, and that same open descriptor is sourced, so replacing the path
after the check changes nothing. All scripts carry the same bootstrap block; a test
keeps the copies identical.

`lib-secrets.sh` (the placeholder rule) is loaded the same way by `check-env.sh`,
`deploy-n8n-soar.sh`, `08-crowdsec-smoketest.sh` and
`render-prometheus-web-config.sh`: no script sources it by pathname. Each one opens it
once on a descriptor, checks the open file (a regular file with one link, owned by root
or by the running user, and neither group nor world writable, for root and non-root
runs alike) and every directory above it (no symlink; as root, root-owned and closed to
group and others; otherwise owned by root or by you and not world writable, except a
sticky directory such as `/tmp`), then sources that same descriptor. A group-writable
helper is refused because a group peer could edit the very inode that was opened, after
the check and before the source (the refusal says `chmod g-w,o-w <helper>`). A
group-writable ancestor directory is acceptable for a non-root run only because the
check happens after the open: replacing a directory entry cannot change the inode the
descriptor already holds. The check stays inline in
each script on purpose: a shared loader file would itself have to be sourced unchecked
first. Tests: `tests/python/test_secrets_helper_bootstrap.py`.

## The root-owned firewall script

`prometheus-otlp-firewall.sh` uses the same bootstrap and, as root, also requires
the script itself and every directory above it to be root-owned and not group or
world writable. Install both files into the root-owned directory, as in
[prometheus-otlp.md](prometheus-otlp.md). The script still changes only the
`DOCKER-USER` chain; whether that chain exists under Podman is not verified.

## Passwords and the `.env` file in `08b-init-opensearch-security.sh`

The script keeps the four OpenSearch passwords out of every argument list and out of the environment
of every child process it starts. It sends them to the container on standard input. Two things bound
that guarantee:

- The `.env` file is sourced as shell code and must be trusted. As root it must be root-owned in a
  root-owned tree (enforced). A file that can run arbitrary shell code can do anything the script can.
  A hostile `.env` is out of scope: keep it owner-only (mode 0600) and, as root, root-owned in a
  root-owned tree. The loader neutralizes tracing, `PS4`, the `DEBUG`, `RETURN` and `ERR` traps and the
  export attribute of the named variables, and nothing more. Two things it does NOT stop, because the
  file runs in the script's own shell with the script's variables (owner decision: documented, not
  changed): the file can install an `EXIT` or a signal trap, which still runs at exit and can print or
  send a password; and it can define a function with the name of a command the script later runs
  (`jq`, `tail`, `printf` and so on), which then runs in place of that command. Both are pinned by tests
  named `test_known_limit_env_exit_trap_still_fires_and_prints_the_password` and
  `test_known_limit_env_function_shadowing_a_helper_is_not_blocked`, so a future fix flips them on
  purpose.
- Within a trusted file, the script removes the export attribute from the four password variables and
  from every variable name the file newly creates. A `.env` that exports a password through a name
  that already existed before the file ran (for example `PATH`, `CE_TRUSTED_DIRS` or another variable
  of the script itself) is NOT neutralized: that child-visible copy stays. Write plain
  `NAME=value` lines only. This limit is documented and pinned by a test
  (`test_known_limit_env_file_can_export_through_a_name_that_already_existed`), so a future fix will
  flip that test on purpose.
- A password given in the launching environment stays in the environment of the script's own process
  (only the launcher can change that); put the passwords in the `.env` file instead.
- Inside the container the password is in the environment of the hash tool's one `java` process for the
  moment it runs (readable by the same container user, container root and host root), never in an
  argument list.

## Passwords in the smoke test, the ingest test and the snapshot setup

`08-crowdsec-smoketest.sh`, `09-test-crowdsec-pfsense-ingest.sh` and `10-snapshot-setup.sh` follow the
same design as `04-apply-ism-policy.sh` and `05-verify.sh`: the OpenSearch admin password (and, in the
smoke test, the Grafana password from `GRAFANA_PASS` or `GRAFANA_ADMIN_PASS`) goes to `curl` on standard
input as a config (`curl -K -`), never in an argument list (no `-u`), and the named password variables
and every variable the `.env` newly creates lose their export attribute, so no child process inherits
them. A line break in a password (or in `GRAFANA_USER`) is refused before any request, and a `.env` that
fails to load stops the script before any request. The limits listed above for
`08b-init-opensearch-security.sh` (trusted `.env`, `EXIT` and signal traps, function shadowing, names that
already existed, the launcher's own environment) apply here unchanged. Start all three by their path
(`sudo scripts/10-snapshot-setup.sh`), never through an explicit `bash` interpreter. The tests are in
`tests/python/test_crowdsec_snapshot_credentials.py`.

## Not covered

- Compose files, the bootstrap script and rootless Podman behavior (see the design doc).
- Hint text printed by some scripts still says `docker compose ...`.
