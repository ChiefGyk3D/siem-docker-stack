# Credential and key expiry watch

Keys, tokens and certificates expire silently. The expiry watch reads a list of
things that expire, warns you early enough to rotate them, keeps warning daily
at the end, and says so once when they have expired. It is one standard-library
Python script, `scripts/expiry_watch.py`, driven by one config file. It posts to
the n8n alert router from [update-alerting.md](update-alerting.md), so the
messages arrive where your other alerts do. It is read-only: it never changes a
key, a certificate or a registry.

Tracked in issue #76 (epic #62). This is slice 1; see
[What is not built yet](#what-is-not-built-yet).

Every notice names the item, its expiry date, the days left, who owns it and a
link to the rotation runbook.

## Quick start

You need Python 3.11 or newer (for `tomllib`). There is nothing to install.

1. Copy the examples and edit them:

   ```sh
   cp docs/expiry-watch.example.toml expiry-watch.toml
   cp docs/expiry-watch-registry.example.toml expiry-watch-registry.toml
   ```

   In `expiry-watch.toml`, point `[router].url` at your router webhook and
   point the registry provider at `expiry-watch-registry.toml`. List your own
   items in the registry.

2. Export the router secret. This is the value of the header credential the
   router checks (`GRAFANA_WEBHOOK_SECRET` in this repo), without the word
   `Bearer`. The config only names the variable:

   ```sh
   export EXPIRY_WATCH_ROUTER_TOKEN='...'   # from your secret manager, not typed into shell history
   ```

3. Look before you post:

   ```sh
   python3 scripts/expiry_watch.py --config expiry-watch.toml --dry-run
   ```

   A dry run reads every provider, prints the notices that are due and the
   JSON it would post, and posts nothing and saves nothing.

4. Run it for real, from a schedule (see [Scheduling](#scheduling)).

Exit codes: `0` ok, `1` a provider or a delivery failed (details on stderr),
`2` a config or secret problem. A failed provider is never silent, and a
provider outage does not make the watch forget what it already told you.

## How the decisions work

For each item the watch counts days left as the item's expiry date minus today
(UTC dates). An item that expires today has 0 days left and counts as expired.

- Each threshold in `thresholds_days` fires once. If a run was missed and
  several thresholds were crossed, only the lowest crossed one fires, so you
  get one message, not a replay of the old ones.
- At or below `daily_below_days` days left you get one notice per UTC day
  (running the script more often than daily does not repeat it). The day a
  threshold fires counts as that day's notice.
- When the item expires you get one final `expired` notice. The watch does not
  repeat it. Rotate the item or remove it from its provider.
- Rotation resets the state. When an item shows a later expiry date than the
  last one the watch saw, its history starts over and the thresholds fire again
  for the new date. An item that disappears from its provider loses its state.
- The watch remembers all of this in `state_file`. A notice that could not be
  delivered is not remembered, so the next run tries again.

There is no "resolved" message: each notice is a one-off. Rotating the item
simply stops the notices.

## Config reference

The format is TOML. Unknown fields are an error, as are duplicate keys,
repeated thresholds and files over 1 MiB. See
[expiry-watch.example.toml](expiry-watch.example.toml).

| Setting | Default | Meaning |
|---------|---------|---------|
| `[watch].thresholds_days` | `[30, 14, 7]` | Days before expiry that fire once each (1 to 20 values, 1 to 3650) |
| `[watch].daily_below_days` | `7` | At or below this many days left, notify daily; `0` turns it off |
| `[watch].state_file` | `expiry-watch-state.json` | What was already notified (JSON, mode 0600, written atomically) |
| `[router].url` | required | The router webhook. https only; plain http only for localhost |
| `[router].token_env` | required | The name of the environment variable that holds the bearer secret |
| `[router].timeout_seconds` | `10` | Post timeout, above 0 and at most 60 |
| `[routes]."<days>"`, `daily`, `expired` | `["discord"]` | Channels for that notice |
| `[[providers]]` | none | One table per provider; `type` selects it |

Relative paths (`state_file`, a provider's `path` or `ca_file`) are relative to
the folder the config file is in.

### Channels and routing

Routing is per notice, so you can send the early warnings to chat only and the
last week to your phone. The channel names are `pushover`, `discord`, `matrix`,
`email` and `webhook`.

| Channel | Slice 1 behavior |
|---------|------------------|
| `discord` | The router posts every firing alert to Discord |
| `pushover` | Adds the label `phone=true`, which is the only way an alert reaches the router's Pushover step. Pushover must be enabled in the router (`PUSHOVER_ENABLED`, see [update-alerting.md](update-alerting.md)) |
| `webhook` | Posts to the router; its own rules decide what happens |
| `matrix`, `email` | Accepted in the config, **not delivered yet**. The run prints a warning on stderr naming the channel |

A notice whose channels are only `matrix` and `email` posts nothing, because
posting would send an unwanted Discord message. The router always sends
Discord for a firing alert, so there is no way to say "phone only" in this
slice.

Pushover priority is the router's decision: an alert name the router does not
know is capped at priority 1. To let expired notices page at emergency
priority, add the alert names to `ALLOWED_ALERTNAMES` in the router (they are
`Expiry watch: <item name>`). That is a deliberate step, not the default.

### What the router receives

One alert in the Grafana webhook shape, with these labels: `alertname`
(`Expiry watch: <item>`), `severity` (`critical` when expired, `warning` at 14
days or less, `info` above that), `expiry_watch=true`, `item`, `kind`, `stage`,
and `phone=true` only when the notice's channels include `pushover`. The
annotations carry a summary (300 characters at most) and a description with the
item, date, days left, owner and runbook link. The fingerprint is a hash of the
item name. Posting uses `Authorization: Bearer <secret>`, never follows a
redirect (so the secret is never replayed elsewhere), and a failure message
never contains the secret.

## Providers

A provider reads one source and returns items. All text is validated the same
way: a name up to 100 characters, a kind up to 40, an owner up to 100, a
runbook that is an http or https link up to 512 characters, no control
characters, and a real calendar date.

### registry: a plain file

For SSH keys, PGP keys, domain registrations and anything without an API.

```toml
[[providers]]
type = "registry"
path = "expiry-watch-registry.toml"
```

The file holds `[[item]]` tables with all of `name`, `kind`, `expires`
(`YYYY-MM-DD`), `owner` and `runbook`; see
[expiry-watch-registry.example.toml](expiry-watch-registry.example.toml). The
loader refuses duplicate keys, duplicate item names, unknown fields, a date and
time instead of a date, an empty file, more than 1000 items, a file over 1 MiB,
a symlink, a FIFO and anything that is not a regular file. The error names the
item.

### tls: a certificate probe

```toml
[[providers]]
type = "tls"
host = "www.example.com"
port = 443
owner = "web-team@example.com"
runbook = "https://wiki.example.com/runbooks/renew-tls"
```

It connects, completes the TLS handshake, reads the certificate the peer sent
and takes the not-after date from it. Connect and handshake share one timeout
(default 10 seconds, at most 60). It sends no application data.

Verification choice: by default the handshake **verifies** the chain and the
host name against the system trust store, or against `ca_file` when set. A peer
that fails verification is an error shown to you, not a date. Set
`verify = false` only for internal or self-signed certificates, or to learn
when an already invalid certificate ended. In that mode the handshake accepts
any certificate because the only thing read is the date, which is why it is off
by default and why the result is never evidence of identity. The date is parsed
from the certificate bytes by a small reader in the script (the standard
library gives no date for an unverified peer), which refuses anything that is
not a well-formed certificate validity field.

### Writing your own provider

A provider is any object with one method, `items()`, that returns a list of
`Item` and raises `ExpiryWatchError` when it cannot read its source. A factory
takes the provider's config table and returns the provider. Register it and
list it in the config:

```python
import expiry_watch as ew

class MyProvider:
    def __init__(self, config):
        self.config = config              # the [[providers]] table as a dict

    def items(self):
        # read your source here; build every item through Item.build so the
        # limits above apply to your data as well
        return [ew.Item.build(name="my-token", kind="api-token", expires="2027-01-01",
                              owner="ops@example.com", runbook="https://wiki.example.com/rotate")]

ew.register_provider("mine", MyProvider)
```

```toml
[[providers]]
type = "mine"
```

Provider names are global and cannot be registered twice. Item names must be
unique across all providers. Run your registration, then call
`expiry_watch.main(["--config", "..."])`. Loading providers from plain files by
type name is not built yet.

## Scheduling

Run the script once a day or more often. More often is harmless: each notice
fires once per threshold or once per day.

Cron (the secret comes from a file that only the job user can read; adjust the
paths):

```cron
17 7 * * *  cd /opt/siem-docker-stack && . /etc/expiry-watch.env && python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml
```

Because the env file is sourced by the shell, write it as
`export EXPIRY_WATCH_ROUTER_TOKEN=...` for cron. A systemd service and timer:

```ini
# /etc/systemd/system/expiry-watch.service
[Unit]
Description=Credential expiry watch

[Service]
Type=oneshot
User=expirywatch
EnvironmentFile=/etc/expiry-watch.env
ExecStart=/usr/bin/python3 /opt/siem-docker-stack/scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml
```

```ini
# /etc/systemd/system/expiry-watch.timer
[Unit]
Description=Run the credential expiry watch daily

[Timer]
OnCalendar=*-*-* 07:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

For systemd the env file holds one plain line,
`EXPIRY_WATCH_ROUTER_TOKEN=...`. Either way it is owned by the job user with
mode 0600. Keep the state file on storage that survives reboots, or every run
looks like a first run. A non-zero exit means look at the journal or the cron
mail. Watch the job with your usual job monitoring, because a watch that stops
running looks exactly like nothing expiring. The [heartbeat](heartbeat.md)
covers the alert path, not this job.

## Tests

`tests/python/test_expiry_watch.py` runs the engine against a fake clock (30,
14 and 7 days, daily, expired, once per threshold, rotation reset), the
registry and config parsers against hostile input, the TLS probe against a
local server with a certificate made by `openssl` at test time, and the poster
against a local HTTP server. Run it with `python3 -m pytest
tests/python/test_expiry_watch.py`.

## What is not built yet

- **Grafana service account token and secret manager token providers.** The
  fields those APIs expose for expiry still have to be verified against each
  API's own docs and a live response before they are built.
- **Direct Matrix and email delivery.** The names are accepted in the config
  and skipped with a warning. The next slice adds adapters (or router nodes)
  with their own credentials.
- **ntfy and other generic channels** beyond `webhook` through the router.
- **Grafana alert rules** driven by an expiry state metric, and a collector
  that writes days left as a metric, so Grafana can alert without the script.
- **A weekly digest line** for the low-urgency items.
- **Per-item overrides** of thresholds or routing, and a "resolved" message.
- **Provider plug-ins loaded from a directory.** Today a plug-in is code that
  imports the module and registers itself.
- **Alerting on a failed probe.** A TLS host that cannot be reached is reported
  on stderr and in the exit code, not as an alert.
- **A sibling check for this job.** Nothing alerts you if the schedule stops;
  use your job monitoring for that.
- **Tests against a live n8n.** The payload shape is checked against the
  router's rules and its normalizer limits, not against a running router.
