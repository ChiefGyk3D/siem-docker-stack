# Host update collector (Debian-family hosts)

`scripts/host-update-metric.sh` reports the pending OS updates of one Debian or Ubuntu host as
InfluxDB line protocol, in the same style as `scripts/pfsense-update-metric.sh`. It is read-only and
runs unprivileged. Tracked in issue #219.

Checked against hosts of the kind this is written for: Debian 13 (arm64) and Ubuntu 24.04 (aarch64),
both with unattended-upgrades active. The apt output shape was checked against a live Debian-family
apt simulation; the security archive labels are listed under "What was verified".

## What it runs

Only these, with `PATH=/usr/bin:/bin` and `LC_ALL=C`:

- `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (a simulation: no lock, no download, no change)
- a test for `/var/run/reboot-required`
- a bounded read (last 1 MiB) of `/var/log/unattended-upgrades/unattended-upgrades.log`, and the
  `.1` file when the current log has no success line yet
- `date`, `stat`, `id`, `tail`, `grep`, `timeout`, `mkdir`, `chmod`, `mv` on its own state directory

It never runs `apt update`, never opens the network and never calls `sudo`. Because it cannot refresh
the package lists, it reports what the host's own lists say; keep the host's normal `apt-daily`
refresh enabled (unattended-upgrades hosts have it). Stale lists under-count; this script does not
detect stale lists.

## Usage

```sh
HOST_LABEL=web-1 /opt/siem/scripts/host-update-metric.sh critical
/opt/siem/scripts/host-update-metric.sh standard web-2     # label as the second argument
```

`HOST_LABEL` (or the second argument) is required: 1 to 32 characters of `A-Z a-z 0-9 _ -`, starting
with a letter or digit. The real hostname is never used. The tier is `critical` or `standard`. The
only tags are `host` and `tier` (plus `kind` and `security` on the pending metric).

## What it prints

```
host_update_pending,host=web-1,tier=critical,kind=package,security=false value=3i
host_update_pending,host=web-1,tier=critical,kind=package,security=true value=1i
host_reboot_required,host=web-1,tier=critical value=0i
host_unattended_last_run_age_seconds,host=web-1,tier=critical value=41230i
host_update_oldest_pending_age_seconds,host=web-1,tier=critical value=190020i
host_update_state_ok,host=web-1,tier=critical value=1i
host_update_check_success,host=web-1,tier=critical value=1i
```

- `security=true` counts packages with a security archive among their origins; `security=false`
  counts the rest. A package available from both `-updates` and `-security` counts as security.
- `host_unattended_last_run_age_seconds` is the age of the newest log line `All upgrades installed`
  or `No packages found that can be upgraded unattended ...`. If no such line exists, the age is
  unknown, and unknown is a **failure**, never `0`.
- `host_update_oldest_pending_age_seconds` is the age of the oldest first-seen time among the
  packages pending now. It feeds a 7-day clock. A new candidate version of the same package restarts
  its clock.

### Failure

If apt output is not understood, a package name or origin has unexpected characters, the apt summary
line is missing or disagrees with the `Inst` lines, apt exits non-zero, the unattended-upgrades age
is unknown, the label or tier is invalid, or any required command is missing, the script prints only

```
host_update_check_success,host=web-1,tier=critical value=0i
```

(untagged when the label or tier is itself invalid), writes a reason to stderr and exits 1. It never
prints zero-valued update metrics after a failure. An exec runner may drop the output of a command
that exits non-zero, so alert on missing data as well as on `host_update_check_success == 0`.

## First-seen state

The state lives in a private directory: `$HOST_UPDATE_STATE_DIR` if set, otherwise
`${XDG_STATE_HOME:-$HOME/.local/state}/host-update-metric/`. Rules:

- the directory is owned by the running user, mode `700`, and not a symlink; the file `first-seen`
  is a regular file, owned by the same user, mode `600`, at most 256 KiB and 1000 entries
- the format is a header `host-update-state v1` and lines `<package> <candidate-version> <epoch>`;
  any other line, a duplicate, a future timestamp or a bad name makes the whole file unreadable
- it is written to a temporary file in the same directory and renamed into place
- if the directory does not exist the script creates it (first run): `state_ok` is `1`
- if the directory exists but the file is **missing**, the clock is lost: the script prints
  `host_update_state_ok value=0i` and **no** oldest-age metric, then re-seeds the file, so the next
  run is `state_ok=1` with a clock that restarts at that moment (the age is understated after a
  loss; the `state_ok=0` run is the signal). A pre-created directory therefore shows `state_ok=0`
  once on the very first run
- if the file is **unreadable or corrupt**, or the directory or file has the wrong owner or mode, the
  script prints `state_ok=0`, no age, and does **not** overwrite anything: an operator must look at
  it and delete the file to re-seed
- a state problem never turns the check itself into a failure

Alert rule suggestions: page on `host_update_check_success == 0` or missing data; on
`host_update_state_ok == 0`; on `host_update_oldest_pending_age_seconds > 604800` (7 days); on
`host_unattended_last_run_age_seconds > 172800` for the unattended-upgrades hosts.

## Running it unprivileged

No root, no sudo, no special group on a stock Debian or Ubuntu install: `apt-get -s` reads the
world-readable apt lists and dpkg status, and `Debug::NoLocking=1` avoids the apt lock. The
unattended-upgrades log directory and file are normally world-readable (root:root, 755/644); if a
hardened host tightened them, give the collector user read access with a group (for example add the
user to `adm` and set the log to `root:adm 640`) rather than running it as root. Create a dedicated
user, for example `siem-collector`, with a home directory or a state directory it owns.

## Install

systemd timer (`/etc/systemd/system/host-update-metric.service` and `.timer`; the delivery command
is a placeholder, see below):

```ini
[Unit]
Description=Host update metric collector

[Service]
Type=oneshot
User=siem-collector
Environment=HOST_LABEL=web-1
StateDirectory=host-update-metric
StateDirectoryMode=0700
Environment=HOST_UPDATE_STATE_DIR=/var/lib/host-update-metric
ExecStart=/bin/sh -c '/opt/siem/scripts/host-update-metric.sh critical | /opt/siem/deliver-metrics'
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
```

(Put `[Timer]` and `[Install]` in the `.timer` unit and the rest in the `.service` unit.) Pipe
failures: a shell pipeline hides the collector's exit code; deliver the failure line too, as the
collector prints it, or use `set -o pipefail` in a bash wrapper.

Cron alternative (one user crontab line, hourly):

```
7 * * * * HOST_LABEL=web-1 /opt/siem/scripts/host-update-metric.sh standard | /opt/siem/deliver-metrics
```

## Delivery is not decided

This repo does not yet pick how the lines reach InfluxDB. The output is meant to be piped to a writer
such as `scripts/live-deploy/twingate-influx-write.py` (Twingate collector, PR #227, branch
`feat/twingate-collector-222`), or read by a Telegraf `exec` input with `data_format = "influx"`.
That writer accepts only `twingate_` lines today, so reusing it needs a prefix allow-list change; the
host metrics must not be pointed at it unchanged. Whatever carries them, keep credentials in the
secret manager and never in argv.

## What was verified, and what was not

Verified: the `Inst` line shapes (including the trailing `[]` and `[pkg:arch ]` bracket forms and
origin lists with spaces) against a live Debian-family `apt-get -s dist-upgrade`; all parsing and every
fail-closed path in `tests/python/test_host_update_metric.py` with a fake apt and clean-mutant revert
proofs.

Not verified on the owner's hosts yet: that Debian 13 prints the security archive as
`Debian-Security:13/stable-security` and Ubuntu 24.04 as `Ubuntu:24.04/noble-security`. The script
treats an origin as security when its label is `Debian-Security`, `Ubuntu`, `UbuntuESM` or
`UbuntuESMApps` and its suite (after the last `/`) ends in `-security`. Run it once per host and
compare `security=true` with `apt-get -s dist-upgrade | grep -c -- '-security'` before trusting the
alert. A third-party archive whose suite is named `*-security` under another label is not counted as
security.
