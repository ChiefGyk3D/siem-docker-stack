# Twingate Connector update script

`scripts/twingate-connector-update.sh` automates the manual procedure in
`docs/twingate-connector-update.md` (PR #221, not merged when this page was
written; this page stands alone and is meant to be merged into that one's
"script" section later). Issue #220.

Owner decision 2026-11-26: Connector updates stay a one-command action that the
owner runs on each host, one host at a time. There are no automatic updates.

## Install location (required for a real run)

The script restarts itself in a cleared environment, so it must live where only
root can change it. It makes its own path absolute (the directory is resolved
with `pwd -P`; the file itself must not be a symbolic link) and then requires
the file and every directory above it, up to `/`, to be owned by root and not
group- or world-writable. A real run refuses with a fixed message otherwise.
`--dry-run` still works, with a warning. The restart does not reopen the path:
the script text is read once, after that check, and the clean second stage runs
from that text (`sh -c`), so a file swapped between the two stages is never
executed. Install it, for example:

```bash
sudo install -o root -g root -m 0755 scripts/twingate-connector-update.sh /usr/local/sbin/twingate-connector-update
sudo /usr/local/sbin/twingate-connector-update --dry-run <connector-name>
```

Running it from a checkout that a non-root user can write to is refused.

## Use

Run it on the Connector's own host, for one Connector at a time:

```bash
scripts/twingate-connector-update.sh --dry-run <connector-name>   # read-only preview
scripts/twingate-connector-update.sh <connector-name>             # asks before changing anything
scripts/twingate-connector-update.sh --yes <connector-name>       # no prompt
scripts/twingate-connector-update.sh --yes --force <connector-name>  # also ignore pre-check warnings
```

`<connector-name>` is the container name (letters, digits, `_`, `.`, `-`; max 63).
Needs `docker` and `jq` on the host. A real run needs root and refuses as any
other user with a clear message; `--dry-run` works for everyone. `PATH` is fixed
to the system directories
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`); the inherited
`PATH`, `TMPDIR` and `XDG_RUNTIME_DIR` are never used, and there is no environment variable that changes which programs run. Only one
run can be active per host: one lock directory,
`/run/twingate-connector-update.lock.d`, is the same for every environment.
`/run` is writable by root only, so no other user can pre-create or hold it.
If that path exists and is not a real directory owned by root (or is a
symlink), the script treats it as hostile: it never reads, uses or removes it
and stops with a fixed message that quotes nothing from it (remove the path as
root after looking at it). The lock records the process id, the
process start time (field 22 of `/proc/<pid>/stat`) and an updater identity (this
script's path, which must appear in the process's command line, and a random run
token, which must appear in its environment). A holder is live only if all of
them match; a reused process id with another start time or identity is stale.
A lock left by a dead run is taken over, and the private run directory that the
lock recorded (and only that one: it must sit directly under
`/run/twingate-connector-update`, be a real directory owned by root and not a
symlink) is shredded and removed first, so a SIGKILL cannot leave the env file
behind past the next run. A live holder blocks a second run. The env file lives in a private
directory `/run/twingate-connector-update` that must be a real directory (no
symlink), owned by root, mode 700, or the run refuses.
The whole environment is cleared. At start the script re-executes itself under
`env -i` with a fixed `PATH`, `LANG=C`, `DOCKER_HOST=unix:///var/run/docker.sock`,
a `DOCKER_CONFIG` of its own (a root-only directory, emptied by the script each run,
`/run/twingate-connector-update/docker-config`) and a `HOME` of its own (an empty
root-only directory, `/run/twingate-connector-update/home`). `DOCKER_CONTEXT`,
`DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
`CURL_CA_BUNDLE`, the proxy variables, `XDG_*` and everything else the caller had
set never reach `docker`, `curl` or `jq`, so an environment-preserving `sudo`
rule cannot point the script at a different daemon. Only the documented inputs
(`TWINGATE_API_KEY`, `TWINGATE_NETWORK_URL`, `TWINGATE_UPDATE_WAIT_SECS`,
`TWINGATE_UPDATE_POLL_SECS`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_ALLOWED_HOSTS`,
`HOST_LABEL`) are read, once, and handed to the new process on a private file
descriptor, never in argv; none of them may contain a newline (the run is
refused). They live in unexported shell variables, so `docker` and `jq` never
see them; the key reaches only the single `curl` call that needs it, on stdin.
The restarted process refuses to run if its environment holds any other name.
`TWINGATE_UPDATE_WAIT_SECS` and `TWINGATE_UPDATE_POLL_SECS` must be plain
integers 1 to 60 without a sign or leading zero; anything else uses the default.

## What it does

1. Reads `docker inspect` into a shell variable (it is never written to disk)
   and refuses unless nothing would be dropped by a recreate that uses only
   `--network host`, `--env-file`, `--name`, `--restart=unless-stopped` and the
   image. This is an allowlist: it refuses on any bind or mount, user,
   entrypoint or command override, healthcheck override, labels beyond the
   image's own, added or dropped capabilities, security options, pid or userns
   mode, read-only root, memory or CPU limits, a non-default log config, DNS,
   extra hosts, tmpfs, ulimits, devices, sysctls, privileged, extra groups,
   auto-remove, a working dir override, or a network mode other than `host`.
Every other `HostConfig` field must be empty or one of Docker's own defaults
(for example `CgroupnsMode` private, `IpcMode` private or shareable, `ShmSize`
64 MiB, `Runtime` runc, the default masked and read-only paths); anything else
(`PidsLimit`, `OomScoreAdj`, `CpusetCpus`, `Init`, port bindings, ...) is
refused, as is any `Config` field that differs from the image (stop signal and
timeout, exposed ports, volumes, domain name, open stdin, any `AttachStdin`,
`AttachStdout` or `AttachStderr` other than a detached run's `false`, and any
hostname other than Docker's default. With host networking and no UTS mode
the default is the host's own hostname (Docker's daemon sets it when no
`--hostname` is given), so that value is accepted, and only because the
network mode is exactly `host` and `UTSMode` is empty; the container id prefix
is accepted too; any other hostname is refused, because the recreate command
does not pass `--hostname`).
   User, entrypoint, command, healthcheck, working dir and labels are compared
   with the old image's own config (`docker image inspect`), so values the
   image sets itself are fine. Every environment entry must contain `=` and no
   newline, CR or NUL; every `TWINGATE_*` entry that will be written must have a
   name of letters, digits and `_` (no whitespace), be at most 8192 bytes, and
   appear only once, and its value may use only `A-Z a-z 0-9 . _ ~ : / + @ , = -`.
   Quotes, backslashes, `$`, spaces, `#`, backticks and leading or trailing
   whitespace are refused, because an env file can read them differently from the
   bytes the container has now; with the allowed characters the file always gives
   back exactly the original `Config.Env` entry. Variables that are not `TWINGATE_*` must come from the image. It
   prints why and changes nothing.
2. The old image must exist locally (`docker image inspect <id>`); if it does
   not, it refuses, because a rollback would be impossible.
3. Pre-check: if `TWINGATE_API_KEY` and `TWINGATE_NETWORK_URL`
   (`<network>.twingate.com`, `https://` optional, nothing else: no path, port
   or userinfo) are both set, it pages through the Connectors (at most 10 pages
   of 100) with the read-only Admin API, finds THIS Connector by name (and keeps
   its id and remote network id), and
   warns unless another Connector in the same remote network is ALIVE. A
   warning (including a skipped or failed check) aborts under `--yes` with exit
   3 unless `--force` is given. Without the API settings it prints a reminder.
   Every `curl` starts with `-q` (no `.curlrc`), uses `--max-redirs 0`,
   `--noproxy '*'` and `--proto =https`. The Admin API answer goes to a file in
   a private directory (no pipeline, so curl's own exit status is kept): it is
   read only if curl exited 0, it is limited to 1 MiB, must be HTTP success, must
   have no GraphQL `errors` and must carry the Connector list, or the check
   counts as failed. This holds for the pre-check and the post-check; a complete
   body followed by a curl failure is not trusted.
   The GraphQL field names (`name`, `state`, `version`, `remoteNetwork { id }`)
   follow `docs/twingate-connector-update.md`; they were not checked against a
   live network.
4. `docker pull twingate/connector:1`, then compares image ids. Equal means it
   prints `already up to date` and exits 0.
5. Prints the current version (`docker exec <name> ./connectord --version`) and
   the new one (`docker run --rm --network none --entrypoint ./connectord <image>
   --version`). If either cannot be read it says so and requires `--yes`.
6. Asks you to type `yes` (unless `--yes`). Then the protected window starts:
   INT, TERM, HUP, PIPE and QUIT are ignored until the new container is verified
   or rolled back, so a signal (or `| head`) cannot leave the Connector gone.
   Inside it: the private temp dir (mode 700) and an env file with only the
   `TWINGATE_*` variables (mode 600) are created, the old image is tagged
   `twingate/connector:rollback-<pid>` so a prune cannot drop it, then
   `docker stop`, `docker rm`, `docker run -d --network host --env-file <env>
   --name <name> --restart=unless-stopped twingate/connector:1`.
7. Polls `docker ps` (name filter regex-escaped) for up to 60 s until the
   container is Up and not unhealthy and `connectord --version` answers.
8. If it does not become healthy, it recreates the container from the rollback
   tag with the same env, reports the rollback and exits 1. If the rollback
   also fails it says `ROLLBACK FAILED` loudly, says whether the old image is
   still on the host (it never claims it is when it is not), exits 2, and KEEPS
   the env file as `connector-env-<name>-<pid>.env` (mode 600) in the private
   runtime dir and prints its path. Use it to recover, then `shred -u` it.
9. If the Admin API is configured, `updated` is reported only after Twingate
   shows the SAME Connector (same id and remote network as in the pre-check;
   an exact name match only when the pre-check could not read it) ALIVE with
   exactly the new version (an optional `Connector ` prefix is ignored; `11.96.0`
   is not `1.96.0`), from a complete answer (polled for up to the same wait). Otherwise the result is `updated-unconfirmed` (exit 4) and it says
   plainly that health was not confirmed in Twingate. Without an Admin API it
   says the same in a note and exits 0 after the local check.

The temp dir and env file are shredded and removed on every exit path and on
INT, TERM, HUP, PIPE and QUIT. SIGKILL cannot be handled by any program. The
rollback tag is kept after the run (remove it with `docker rmi` when you no
longer need it); images are never pruned.

Exit codes: 0 updated or already current (or dry-run), 1 failed or rolled back,
2 refused or rollback failed, 3 aborted (prompt or pre-check warning),
4 updated but health not confirmed in Twingate.

`--dry-run` prints every step and runs only read-only commands (`docker inspect`,
`docker image inspect`, `docker info`, `docker exec ... --version`, the optional
API read). It does not pull, tag, stop, remove or start anything, takes no lock
and sends no notice.

## Notice

If `NOTIFY_WEBHOOK_URL` is set (https only; it is passed to `curl` on stdin,
never in argv, and never printed) AND `NOTIFY_WEBHOOK_ALLOWED_HOSTS` lists the
trusted webhook hosts, a short JSON notice is POSTed with a 5 s timeout.
`NOTIFY_WEBHOOK_ALLOWED_HOSTS` is a comma-separated list of exact host names (no
wildcards, no default). The URL's host must equal one entry (case-insensitive;
an optional numeric port is allowed). IP literals of any kind (IPv4 in any
spelling, IPv6, bracketed), `localhost`, `*.localhost`, host names without a dot,
and URLs with userinfo are always refused. With no allowlist the notice is
skipped with a message and the update still succeeds. This keeps the root-run
script from POSTing to services that only the host can reach.

```json
{"host-label": "...", "connector": "...", "from": "...", "to": "...", "result": "updated"}
```

`result` is one of `updated`, `up-to-date`, `rolled-back`, `rollback-failed`,
`updated-unconfirmed`, `failed-pull`, `aborted`, `aborted-precheck`. No tokens or env are included. `HOST_LABEL` overrides
the label (default: short hostname). A failed notice never fails the update.

## Tests

`tests/python/test_twingate_connector_update.py` runs the script against a fake
`docker` and `curl` that record their arguments and environments (the fakes read
their own settings from a file next to them, since the script clears its
environment; one fake `docker` also parses the env file with a conservative model
of the env-file grammar and the tests compare the result with `Config.Env`); nothing
touches a real engine. The shipped script has no test seam: the test harness
writes a test-only copy in which exactly four fixed lines (`PATH`,
`LOCK_BASE`, `RUN_BASE`, `TRUSTED_UID`) point at the fakes, at scratch directories and at the test user (the tests do not run as root), and a
test checks that the copy differs from the shipped file in those lines only. The shellcheck test fails (never skips) in CI when
shellcheck is missing and falls back to `sh -n` locally.

## Confirming the layout on a real host

Run the script with `--dry-run` against a real Connector. It reads the
container's configuration, prints whether the layout check passes (or the
reasons it does not) and changes nothing. It prints no secret values.

```
sudo ./scripts/twingate-connector-update.sh --dry-run <container-name>
```

If it reports `hostname override`, compare `docker inspect -f '{{.Config.Hostname}}' <container-name>`
with `uname -n` on the host; they should match for a Connector created without
`--hostname`.
