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
```

`<connector-name>` is the container name (letters, digits, `_`, `.`, `-`; max 63).
Needs `docker` and `jq` on the host.

## What it does

1. Refuses unless the container matches the verified layout: image
   `twingate/connector:1`, host networking, no binds or mounts, restart policy
   `unless-stopped`, not privileged, no extra capabilities, devices or sysctls.
   It prints why and changes nothing.
2. Saves `docker inspect` and builds the env file (from `Config.Env`, without
   `PATH`) in a private temp dir made by `mktemp -d` (mode 700, files mode 600).
   The dir is shredded and removed on exit, on error and on SIGINT/SIGTERM. No
   env value is ever printed.
3. Pre-check: if `TWINGATE_API_KEY` and `TWINGATE_NETWORK_URL`
   (`https://<network>.twingate.com`) are both set, asks the Admin API
   (read-only) and warns when fewer than two Connectors are ALIVE. Otherwise it
   prints a reminder to check that the other Connector is ALIVE.
4. `docker pull twingate/connector:1`, then compares image ids. Equal means it
   prints `already up to date` and exits 0.
5. Prints the current version (`docker exec <name> ./connectord --version`) and
   the new one (`docker run --rm --network none --entrypoint ./connectord <image>
   --version`). If either cannot be read it says so and requires `--yes`.
6. Asks you to type `yes` (unless `--yes`), then `docker stop`, `docker rm`,
   `docker run -d --network host --env-file <env> --name <name>
   --restart=unless-stopped twingate/connector:1`.
7. Polls `docker ps` for up to 60 s until the container is Up and not
   unhealthy and `connectord --version` answers.
8. If it does not become healthy, it recreates the container from the saved old
   image id with the same env, reports the rollback and exits 1. If the rollback
   also fails it exits 2 and says so loudly. The old image is never pruned.

Exit codes: 0 updated or already current (or dry-run), 1 failed or rolled back,
2 refused or rollback failed, 3 aborted at the prompt.

`--dry-run` prints every step and runs only read-only commands (`docker inspect`,
`docker image inspect`, `docker exec ... --version`, the optional API read). It
does not pull, stop, remove or start anything and sends no notice.

## Notice

If `NOTIFY_WEBHOOK_URL` is set in the environment (https only; it is passed to
`curl` on stdin, never in argv, and never printed), a short JSON notice is POSTed
with a 5 s timeout:

```json
{"host-label": "...", "connector": "...", "from": "...", "to": "...", "result": "updated"}
```

`result` is one of `updated`, `up-to-date`, `rolled-back`, `rollback-failed`,
`failed-pull`, `aborted`. No tokens or env are included. `HOST_LABEL` overrides
the label (default: short hostname). A failed notice never fails the update.

## Tests

`tests/python/test_twingate_connector_update.py` runs the script against a fake
`docker` and `curl` that record their arguments; nothing touches a real engine.
