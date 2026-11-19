# Game-day failure tests for the alert path

Break one link of Grafana, the n8n router, Discord and the phone on purpose,
and prove that an alert about the failure still arrives through another path.
A failed alert delivery must never be silent.

Tracked in issue #84 (epic #62). Background:
[update-alerting.md](update-alerting.md#delivery-and-failure-reporting) (the 502
answer and the error handler) and [heartbeat.md](heartbeat.md) (the dead-man's
switch).

The tool is `scripts/gameday.py` (Python standard library only, one subcommand
per scenario).

## Safety model

- **Dry-run is the default.** A scenario prints what it would do, what you
  should observe and how to revert, and changes nothing.
- **Changes need two flags together:** `--apply --confirm-live`. `--apply`
  alone is refused with exit 2 and nothing runs. `--confirm-live` alone is a
  dry-run.
- Every change is a command in an injectable runner, so the tests use fakes and
  never touch a live system. A step that fails triggers the revert steps at once;
  if the revert fails too, the script says so and you run the printed revert by
  hand.
- Options are matched exactly: abbreviations such as `--app` are rejected.
- An interrupt (Ctrl-C), a timeout or any error during a live step runs the revert
  before the script exits, and the revert cannot hide the original error.
- It never reads or sends the Grafana webhook secret. `wrong-header` sends a
  made-up value.
- Pick a maintenance window and tell whoever receives the alerts. Real messages
  arrive on a real phone and a real Discord channel.

## Configuration

Environment variables `GAMEDAY_<KEY>` or a TOML file (`--config FILE`, or
`GAMEDAY_CONFIG`). The environment wins. No hostnames or secrets belong in the
repository: keep the file outside it.

| Key | Default | Used by |
|-----|---------|---------|
| `n8n_container` | `n8n` | all but grafana-down |
| `grafana_container` | `grafana` | grafana-down |
| `docker` | `docker` | the container CLI; only `docker` or `podman` is accepted |
| `discord_host` | `discord.com` | discord-unreachable |
| `pushover_host` | `api.pushover.net` | phone-unreachable |
| `heartbeat_host` | none, required | heartbeat-silent (host of the observer's ping URL) |
| `router_workflow_id` | none, required | router-inactive |
| `router_path` | none, required | wrong-header (the router's private webhook path) |
| `n8n_base` | looked up at run time | wrong-header (see `scripts/n8n_address.py`); must be `http(s)://<loopback or private IP>[:port]`, no user info or path, never link-local; redirects are not followed |

```toml
# gameday.toml, kept outside the repository
n8n_container = "n8n"
heartbeat_host = "healthchecks.example.com"
router_workflow_id = "REPLACE_ME"
```

## Scenarios

Run `python3 scripts/gameday.py list` for the names. Each one is
`python3 scripts/gameday.py SCENARIO` previews it,
`python3 scripts/gameday.py SCENARIO --apply --confirm-live` injects it (the
three hosts scenarios print a run id), and
`python3 scripts/gameday.py SCENARIO --revert --run-id ID --apply --confirm-live`
reverts it. Only the hosts scenarios need the id; the others ignore it.

| Scenario | What it breaks | Expected observation |
|----------|----------------|----------------------|
| `discord-unreachable` | Discord name does not resolve inside n8n | Router answers 502; error handler sends one Pushover message; no Discord message |
| `phone-unreachable` | Pushover name does not resolve inside n8n | Discord alert plus a "phone delivery failed" notice; router still answers 200 |
| `heartbeat-silent` | Observer name does not resolve inside n8n | Everything else works; the observer alerts after period plus grace |
| `n8n-down` | n8n container stopped | Grafana delivery-failure alert (#81); observer alerts after the heartbeat stops |
| `grafana-down` | Grafana container stopped | No heartbeat; the observer alerts after period plus grace |
| `router-inactive` | Router workflow deactivated | Grafana gets an error and logs a failed notification; heartbeat stops |
| `wrong-header` | One webhook call with a wrong header | 401 or 403; anything else is a defect |

The three name-resolution scenarios add one exact line, marked
`# gameday-84-<run id>`, to `/etc/hosts` inside the n8n container. The run id is
random, printed when you inject, and also written to the `--log` record. Revert
with `--run-id <id>`: it removes only that run's line, and every other line
(including other runs' lines) is left alone. The script uses no temp file, runs
with `set -eu`, refuses a symlinked or empty hosts file, and checks the line is
gone. A container recreate also clears the line.

How the hosts edit is made safe: the file is never held in a shell variable. The
script copies the original to a private `mktemp -d` directory (a per-run backup on
the container's filesystem), writes the new content there with `grep -vxF`, checks
it (not empty, the marker gone, line count equal to the original minus the removed
copies), then rewrites `/etc/hosts` in place (it is usually a bind mount, which
cannot be renamed over) and compares it byte for byte with `cmp`. Any write or
compare failure restores the original from the backup and exits nonzero. On success
the private directory is removed; on failure it is kept and its path is printed. Every
other byte is preserved, with one exception: a file with no final newline keeps none
unless this run's line was last. Adding a line to such a file inserts the missing newline first.

Container side, as root: the script sets its own `PATH` first
(`/usr/sbin:/usr/bin:/sbin:/bin`) and never searches the container's `PATH`, so a
writable directory in it cannot plant a `grep` or `cat`. It needs `sh`, `grep`, `cat`,
`cmp`, `mktemp`, `tail`, `od`, `tr`, `wc`, `head`, `mv`, `rm`, `kill`, `sleep` and `mkdir`
in those directories (BusyBox has all of them). The script does not check who can
write those directories inside the container; the image must keep them root-owned.
It was tested under GNU `sh` only, not BusyBox `ash`.

Locking: every add and remove takes one lock, a directory named after the hosts file
with `.gameday-lock` added, holding the owner's pid. A second run waits (30 tries, one
second apart) and then fails; a lock whose pid is gone is treated as stale and broken
(moved aside atomically, so only one waiter wins). If a run was killed in the instant
between creating the lock and writing the pid, the lock stays and the message names
it: remove it by hand once no game-day script is running. Just before the write the
live file is compared with the backup; if anything changed (another tool appended a
line) nothing is written and the run fails. A restore happens only when the file holds
the start of our own new content (our partial write); if another writer changed it, the
restore is skipped, the backup is kept and the message says so.

Residual risk, stated plainly: the symlink check runs before the copy, before the
write and before a restore, but it is a path check, not a held file descriptor, so
`sh` cannot make check and write atomic. To exploit the gap an actor must already be
root-equivalent inside the container (or able to replace `/etc/hosts` there), at which
point the container is theirs. A swap between the last check and the write would be
followed by the write; a swap earlier is caught and the run fails loudly.

The container CLI (`docker` or `podman`) is found only in `/usr/bin`,
`/usr/local/bin`, `/bin` and `/snap/bin`, never through your `PATH`, and must be a
root-owned file that nobody else can write. Links are resolved first; the resolved
file, its directory and every directory above it up to `/` must be root-owned and not
group or world writable, and that resolved path (not the link) is what runs. The child
`PATH` lists only trusted directories that pass the same test. Anything else is refused
(exit code 127 on the step). Residual: renaming a directory between the check and the
start needs root already.

`--log` files: an existing log must be a regular file you own, mode 0600 with no
group or world bits, and have a single hard link, otherwise a warning is printed and
the log is skipped (a revert is never blocked). Short writes are completed.

## Checklist

For each scenario you run:

1. [ ] Window agreed, recipients told, a second person or channel watching.
2. [ ] Dry-run first and read the plan: `gameday.py SCENARIO`.
3. [ ] Baseline: send a test alert (`scripts/live-deploy/n8n-test-router.py`)
       and confirm it arrives. Note the time.
4. [ ] Inject: `gameday.py SCENARIO --apply --confirm-live --log RESULTS.jsonl`.
5. [ ] Send a test alert if the scenario needs one (see the table) and watch
       every OBSERVE line from the plan. Note what arrived, through which path,
       and how long it took.
6. [ ] Revert: `gameday.py SCENARIO --revert --run-id ID --apply --confirm-live` (ID is the run id printed at injection).
7. [ ] Verify recovery: a test alert arrives again, the heartbeat resumes, the
       observer shows up.
8. [ ] Record the result (below).

## Recording results

`--log FILE` (created mode 0600, never through a symlink, regular files only; a
log problem prints a warning and never blocks a revert) appends one JSON line per run (time, scenario, mode, whether each
step succeeded). It holds no commands, values or output. Add what you observed
(path, delay, anything missing) to the issue or your run notes. A scenario passes
only when the failure alert arrived through a path that does not depend on the
broken link. A scenario with no alert is a finding: file an issue.

## Rollback

Every scenario prints its revert. In order of preference:

1. `gameday.py SCENARIO --revert --run-id <id> --apply --confirm-live` (the id is needed for the three hosts scenarios).
2. By hand, the same commands the plan printed:
   - hosts line: run `gameday.py SCENARIO --revert --run-id <id>` without `--apply` to print the exact
     command for your run, and paste it. Lost the id? `docker exec n8n grep gameday-84 /etc/hosts`
     shows the line; edit `/etc/hosts` in the container by hand or recreate it (next item).
   - stopped container: `docker start n8n` (or `grafana`)
   - deactivated router: activate it again in the n8n editor, or run the
     `update:workflow --active=true` command from the plan, then restart n8n.
3. Last resort for the hosts line: recreate the n8n container
   (`docker compose up -d --force-recreate n8n`); `/etc/hosts` is rebuilt.

After any rollback, confirm with a baseline test alert and wait one heartbeat
interval for the observer to show up.

## Not verified

The graph tests model the router; the scenarios have not been run against a live
stack by this change. In particular the `update:workflow` CLI name differs between
n8n versions (check `n8n --help`), and that a stopped Grafana or n8n produces the
alerts listed above is what the design says, to be confirmed on the first game day.
