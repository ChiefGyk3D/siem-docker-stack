# Weekly status digest

One plain text email a week (the P3 tier of
[design/channel-redundancy.md](design/channel-redundancy.md)). Issue #69, epic #62.
Nothing here is active until you schedule it (owner step below).

## What the email holds

| Section | Source | State |
|---------|--------|-------|
| Patched automatically | Patch Gremlin state | PLACEHOLDER. The repo documents no Patch Gremlin state format, so the section says so. Wire it up by passing a `patched` provider (a function returning a `Section`) once a format exists. |
| Needs action | Grafana alert history: alerts whose name contains a word from `needs_action_words` (default `update`, `reboot`) that are not back to Normal | Reboots have no source in this repo yet; the section says so. |
| Alerts that fired this week | Grafana alert history, one read | Optional; needs the `[grafana]` table. |
| Stale | The expiry watch state file, read-only, plus a notice if the watch has not saved its state for `stale_run_days` | Always on. |

The Grafana read is `GET /api/annotations?type=alert&from=&to=&limit=` with a bearer
token (verified against the Grafana annotations API page, 2026-11-19: the query
parameters; the `alertName`, `newState` and `time` fields are used as Grafana
documents them as alerting fields but the page shows no example, so treat the
field names as unverified until the first live run). The token is a read-only
service account token. It goes only to the configured URL; redirects are
refused, the answer is size capped, and each record is shape-checked.

## Safe by default

- Dry run is the default. It prints the rendered email to stdout and makes no network call at all, not even the Grafana read (those two sections say "Not fetched").
- `--send` reads Grafana and sends exactly one email. There is no retry loop; exit code 3 means it was not delivered.
- The sender is the expiry watch's `smtp_deliver` (imported, not copied): server certificate and name verified, STARTTLS required (no plaintext fallback), the login only after the connection is encrypted, one overall deadline. Details: [expiry-watch.md](expiry-watch.md).
- Secrets are environment variable names in the TOML file, never values.
- Every string a provider returns (titles, notes, entries) is cleaned of control characters and line breaks at render time, whatever the provider does. The subject is built from counts only.
- The body is capped (`max_body_bytes`) and each section is capped (`max_entries_per_section`, the rest is counted).
- A failing source does not stop the digest: the email still goes out with a `SOURCE FAILED` line and the exit code is 1.

Exit codes: 0 done; 1 done but a source failed; 2 config error; 3 not delivered.

## Setup

1. Copy `docs/weekly-digest.example.toml` to `weekly-digest.toml` (keep it out of git) and edit it.
2. Put `WEEKLY_DIGEST_GRAFANA_TOKEN`, `WEEKLY_DIGEST_SMTP_USER` and `WEEKLY_DIGEST_SMTP_PASSWORD` in your secret manager (dev environment first). Names only are listed in `.env.example`.
3. Dry run: `python3 scripts/weekly_digest.py --config weekly-digest.toml`.

## Schedule it (owner step)

The script never schedules itself. Run it from a systemd timer with your secret manager
injecting the three variables. Example (adjust paths, and the wrapper that exports the
variables):

```
# /etc/systemd/system/weekly-digest.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/siem-docker-stack/scripts/weekly_digest.py --config /etc/siem/weekly-digest.toml --send

# /etc/systemd/system/weekly-digest.timer
[Timer]
OnCalendar=Mon *-*-* 08:00:00
Persistent=false
[Install]
WantedBy=timers.target
```

`Persistent=false` keeps a missed run from sending two digests after a reboot. A cron
line works the same way. A non-zero exit shows in `systemctl status`; alert on it if you
want to know a digest was missed.
