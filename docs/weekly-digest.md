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
- Every string a provider returns (titles, notes, entries) is cleaned at render time, whatever the provider does: Unicode categories Cc (controls and line breaks), Cf (bidi overrides and isolates such as U+202E, zero-width characters, the byte order mark, soft hyphen) and Zl and Zp (line and paragraph separators) become spaces, so an alert name cannot visually reverse its meaning. Ordinary text in any script is kept. The subject is built from counts only.
- The body is capped (`max_body_bytes`), each section is capped (`max_entries_per_section`, the rest is counted), and the WHOLE encoded message as SMTP transmits it (headers, MIME framing, transfer encoding) is capped by `max_message_bytes` (default 100000). The body is cut further until the encoded message fits.
- A failing source does not stop the digest: the email still goes out with a `SOURCE FAILED` line and the exit code is 1.
- A Grafana record whose time is outside the requested window (plus 5 minutes of clock skew), or is not a plain integer, is skipped on its own and reported once as a `SOURCE NOTE` line. It never costs the other records.
- One digest per ISO week, and no overlapping runs: a send takes a lock file (created with O_EXCL) in a private state folder (`state_dir`, default `weekly-digest-state` next to the config file, mode 0700), and writes the ISO week into `last-sent` after the server accepted the message. A second `--send` in the same week is refused (exit 4) unless you add `--force`. A run that was killed leaves `lock` behind; the next run refuses and names it: check that no digest run is alive, then remove the file. A dry run touches none of this. SMTP cannot give exactly-once delivery: if the connection fails right at final acceptance the digest may or may not have arrived, and the marker is then not written, so a retry may send a duplicate (the message id is stable for identical content, which helps a receiver recognize it).

The sent state is recorded in two durable phases (temp file, fsync, rename, fsync of the folder). Before the message goes to the server a `pending` file is written; after the server accepted it, `last-sent` is written and only then `pending` is removed. If anything fails or is interrupted in between (a crash, Ctrl-C, a full disk), `pending` stays, and the next run refuses with exit 4 and a message naming it. Check whether the digest arrived, then remove `pending` (or use `--force`). A plain refusal by the server (nothing accepted) removes `pending` again, so a retry is allowed. The lock is removed only by the run that created it: its device and inode are remembered and the path is unlinked only if it still names that file.

`last-sent` must hold a real ISO week written exactly as `YYYY-Www` (week 53 only in a year that has one; for example 2025 has no week 53, 2026 does). Anything else is a damaged marker.

A missing `last-sent` is the only state that allows the first send. A marker that exists but is empty, garbled, unreadable, a link or not a regular file fails closed: the run is refused (exit 4) and names the file; repair or remove it, or use `--force`.

`max_message_bytes` counts exactly what the DATA command transmits: headers, MIME framing, transfer encoding, SMTP dot-stuffing and the final terminator line. Lone Unicode surrogates (category Cs) are also replaced in provider text, so a hostile record cannot stop the digest from rendering.

Exit codes: 0 done; 1 done but a source failed (or the sent marker could not be written); 2 config error; 3 not delivered; 4 not sent on purpose (lock held, already sent this week, or a damaged `last-sent` marker).

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
