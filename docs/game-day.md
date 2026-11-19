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
| `docker` | `docker` | the container CLI |
| `discord_host` | `discord.com` | discord-unreachable |
| `pushover_host` | `api.pushover.net` | phone-unreachable |
| `heartbeat_host` | none, required | heartbeat-silent (host of the observer's ping URL) |
| `router_workflow_id` | none, required | router-inactive |
| `router_path` | none, required | wrong-header (the router's private webhook path) |
| `n8n_base` | looked up at run time | wrong-header (see `scripts/n8n_address.py`) |

```toml
# gameday.toml, kept outside the repository
n8n_container = "n8n"
heartbeat_host = "healthchecks.example.com"
router_workflow_id = "REPLACE_ME"
```

## Scenarios

Run `python3 scripts/gameday.py list` for the names. Each one is
`python3 scripts/gameday.py SCENARIO [--apply --confirm-live] [--revert]`.

| Scenario | What it breaks | Expected observation |
|----------|----------------|----------------------|
| `discord-unreachable` | Discord name does not resolve inside n8n | Router answers 502; error handler sends one Pushover message; no Discord message |
| `phone-unreachable` | Pushover name does not resolve inside n8n | Discord alert plus a "phone delivery failed" notice; router still answers 200 |
| `heartbeat-silent` | Observer name does not resolve inside n8n | Everything else works; the observer alerts after period plus grace |
| `n8n-down` | n8n container stopped | Grafana delivery-failure alert (#81); observer alerts after the heartbeat stops |
| `grafana-down` | Grafana container stopped | No heartbeat; the observer alerts after period plus grace |
| `router-inactive` | Router workflow deactivated | Grafana gets an error and logs a failed notification; heartbeat stops |
| `wrong-header` | One webhook call with a wrong header | 401 or 403; anything else is a defect |

The three name-resolution scenarios add one line marked `# gameday-84` to
`/etc/hosts` inside the n8n container. A container recreate also clears it.

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
6. [ ] Revert: `gameday.py SCENARIO --revert --apply --confirm-live`.
7. [ ] Verify recovery: a test alert arrives again, the heartbeat resumes, the
       observer shows up.
8. [ ] Record the result (below).

## Recording results

`--log FILE` appends one JSON line per run (time, scenario, mode, whether each
step succeeded). It holds no commands, values or output. Add what you observed
(path, delay, anything missing) to the issue or your run notes. A scenario passes
only when the failure alert arrived through a path that does not depend on the
broken link. A scenario with no alert is a finding: file an issue.

## Rollback

Every scenario prints its revert. In order of preference:

1. `gameday.py SCENARIO --revert --apply --confirm-live`.
2. By hand, the same commands the plan printed:
   - hosts line: `docker exec -u root n8n sh -c "grep -v '# gameday-84' /etc/hosts > /tmp/.gameday-hosts; cat /tmp/.gameday-hosts > /etc/hosts; rm -f /tmp/.gameday-hosts"`
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
