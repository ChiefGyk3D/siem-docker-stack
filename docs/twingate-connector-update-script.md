# Twingate Connector update script

`scripts/twingate-connector-update.sh` automates the manual procedure in
`docs/twingate-connector-update.md` (PR #221, not merged when this page was
written; this page stands alone and is meant to be merged into that one's
"script" section later). Issue #220.

Owner decision 2026-11-26: Connector updates stay a one-command action that the
owner runs on each host, one host at a time. There are no automatic updates.

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
`PATH`, `TMPDIR`, `XDG_RUNTIME_DIR` and the current directory are never used,
and there is no environment variable that changes which programs run. Only one
run can be active per host: one lock directory,
`/run/twingate-connector-update.lock.d`, is the same for every environment.
`/run` is writable by root only, so no other user can pre-create or hold it.
If that path exists and is not a real directory owned by root (or is a
symlink), the script treats it as hostile: it never reads, uses or removes it
and stops with a fixed message that quotes nothing from it (remove the path as
root after looking at it). A lock left by a dead root-run process is taken
over; a live holder blocks a second run. The env file lives in a private
directory `/run/twingate-connector-update` that must be a real directory (no
symlink), owned by root, mode 700, or the run refuses.
`TWINGATE_API_KEY` and `NOTIFY_WEBHOOK_URL` are copied into unexported shell
variables and removed from the environment at once, so `docker` and `jq` never
see them; the key reaches only the single `curl` call that needs it, on stdin.
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
timeout, exposed ports, volumes, domain name, open stdin, a hostname that is
neither the container id prefix nor the host's).
   User, entrypoint, command, healthcheck, working dir and labels are compared
   with the old image's own config (`docker image inspect`), so values the
   image sets itself are fine. Every environment entry must contain `=` and no
   newline, CR or NUL; every `TWINGATE_*` entry that will be written must have a
   name of letters, digits and `_` (no whitespace), be at most 8192 bytes, and
   appear only once, so Docker accepts the env file for the update and for the
   rollback. Variables that are not `TWINGATE_*` must come from the image. It
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
   `--noproxy '*'` and `--proto =https`, and the Admin API answer is limited to
   1 MiB, must be HTTP success, must have no GraphQL `errors` and must carry the
   Connector list, or the check counts as failed.
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

If `NOTIFY_WEBHOOK_URL` is set in the environment (https only; it is passed to
`curl` on stdin, never in argv, and never printed), a short JSON notice is POSTed
with a 5 s timeout:

```json
{"host-label": "...", "connector": "...", "from": "...", "to": "...", "result": "updated"}
```

`result` is one of `updated`, `up-to-date`, `rolled-back`, `rollback-failed`,
`updated-unconfirmed`, `failed-pull`, `aborted`, `aborted-precheck`. No tokens or env are included. `HOST_LABEL` overrides
the label (default: short hostname). A failed notice never fails the update.

## Tests

`tests/python/test_twingate_connector_update.py` runs the script against a fake
`docker` and `curl` that record their arguments and environments; nothing
touches a real engine. The shipped script has no test seam: the test harness
writes a test-only copy in which exactly four fixed lines (`PATH`,
`LOCK_BASE`, `RUN_BASE`, `TRUSTED_UID`) point at the fakes, at scratch directories and at the test user (the tests do not run as root), and a
test checks that the copy differs from the shipped file in those lines only. The shellcheck test fails (never skips) in CI when
shellcheck is missing and falls back to `sh -n` locally.
