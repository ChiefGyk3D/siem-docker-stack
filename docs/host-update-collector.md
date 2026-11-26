# Host update collector (Debian-family hosts)

`scripts/host-update-metric.sh` reports the pending OS updates of one Debian or Ubuntu host as
InfluxDB line protocol, in the same style as `scripts/pfsense-update-metric.sh`. It is read-only and
runs unprivileged. Tracked in issue #219.

Checked against hosts of the kind this is written for: Debian 13 (arm64) and Ubuntu 24.04 (aarch64),
both with unattended-upgrades active. The apt output shape was checked against a live Debian-family
apt simulation; the security archive labels are listed under "What was verified".

## What it runs

Only these, with `PATH=/usr/bin:/bin` and `LC_ALL=C`:

- `env -i PATH=/usr/bin:/bin LC_ALL=C APT_CONFIG=/dev/null /usr/bin/apt-get -s -o Debug::NoLocking=1
  dist-upgrade` (a simulation: no lock, no download, no change). `env -i` means no `APT_*` or
  `DPKG_*` variable from the caller can steer apt. It runs under `timeout -k 10 120`, and its output
  is cut at 4 MiB as it is read; more than that is a failure
- a test for `/var/run/reboot-required`
- a bounded read (last 1 MiB) of `/var/log/unattended-upgrades/unattended-upgrades.log`, and the
  `.1` file when the current log has no success line yet
- `stat` of `/var/lib/apt/periodic/update-success-stamp` and of the non-empty `*_Packages*`,
  `*_Release` and `*_InRelease` files in `/var/lib/apt/lists`
- `date`, `stat`, `id`, `head`, `tail`, `grep`, `timeout`, `env`, `mkdir`, `chmod`, `mv` on its own
  state directory

It never runs `apt update`, never opens the network and never calls `sudo`. It refuses to run as
uid 0 (a failure line, exit 1): use an unprivileged user.

Because it cannot refresh the package lists, it reports what the host's own lists say, so it checks
that they are fresh (see "Apt list freshness"). Every path above is fixed in the script; there are no
test hooks in the shipped file (the tests rewrite the fixed default lines in a scratch copy).

## Usage

```sh
HOST_LABEL=web-1 /opt/siem/scripts/host-update-metric.sh critical
/opt/siem/scripts/host-update-metric.sh standard web-2     # label as the second argument
/opt/siem/scripts/host-update-metric.sh --max-lists-age-days=2 standard web-2
```

`--max-lists-age-days=N` (first argument only) sets the oldest apt lists the check accepts. N is a
whole number from 1 to 30 without a leading zero; the default is 3. Anything else is a failure.

`HOST_LABEL` (or the second argument) is required: 1 to 32 characters of `A-Z a-z 0-9 _ -`, starting
with a letter or digit. The real hostname is never used. The tier is `critical` or `standard`. The
only tags are `host` and `tier` (plus `kind` and `security` on the pending metric).

## What it prints

```
host_update_pending,host=web-1,tier=critical,kind=package,security=false value=3i
host_update_pending,host=web-1,tier=critical,kind=package,security=true value=1i
host_update_held_back,host=web-1,tier=critical value=0i
host_reboot_required,host=web-1,tier=critical value=0i
host_update_lists_age_seconds,host=web-1,tier=critical value=21600i
host_unattended_last_run_age_seconds,host=web-1,tier=critical value=41230i
host_update_oldest_pending_age_seconds,host=web-1,tier=critical value=190020i
host_update_state_ok,host=web-1,tier=critical value=1i
host_update_check_success,host=web-1,tier=critical value=1i
```

- `security=true` counts packages with a security archive among their origins; `security=false`
  counts the rest. A package available from both `-updates` and `-security` counts as security.
  An origin label with characters outside letters, digits and `._:/+, -` is counted as
  non-security (it does not fail the check); package names, versions and architectures stay strict.
  A repository can label itself `security` (a third-party archive named like a security archive
  under one of the known labels would be counted); this is accepted, the label is not authenticated.
- `host_update_held_back` is the `N not upgraded` count of the apt summary: updates apt holds back
  (kept-back packages, phased updates, pins). **Held-back updates are not counted as pending**; the
  metric makes them visible so they can be alerted on separately.
- `host_update_lists_age_seconds` is the age of the newest of the apt update stamp and the list
  files, see below.
- `host_unattended_last_run_age_seconds` is the age of the newest log line `All upgrades installed`
  or `No packages found that can be upgraded unattended ...`. If no such line exists, the age is
  unknown, and unknown is a **failure**, never `0`.
- `host_update_oldest_pending_age_seconds` is the age of the oldest first-seen time among the
  packages pending now. It feeds a 7-day clock. A new candidate version of the same package restarts
  its clock.

### Apt list freshness

The script never refreshes the lists, so stale, emptied or wiped lists would report nothing pending.
`host_update_lists_age_seconds` is the age of the newest of
`/var/lib/apt/periodic/update-success-stamp` and the newest non-empty, non-symlink list file
(`*_Packages*`, `*_Release`, `*_InRelease`) in `/var/lib/apt/lists`. If neither exists, or the age is
over the maximum (default 3 days, `--max-lists-age-days`, 1 to 30), the whole check **fails**
(`host_update_check_success value=0i` only), so stale lists never give `check_success=1` with zero
pending. A clock set into the future gives age `0`. Keep the host's `apt-daily` refresh enabled.
This covers issue #233.

### Failure

If apt output is not understood, a package name or origin has unexpected characters, the apt summary
line is missing or disagrees with the `Inst` lines, apt exits non-zero or times out or prints more than
4 MiB, the apt lists are missing or too old, the unattended-upgrades age is unknown, a number in the
state or the apt summary is not canonical (`0` or `[1-9][0-9]*`), the script runs as uid 0, the label
or tier is invalid, or any required command is missing, the script prints only

```
host_update_check_success,host=web-1,tier=critical value=0i
```

(untagged when the label or tier is itself invalid), writes a reason to stderr and exits 1. An EXIT
trap prints the same line on any unexpected internal error (for example a shell arithmetic error), so
a crash never goes silent. It never prints zero-valued update metrics after a failure. An exec runner may drop the output of a command
that exits non-zero, so alert on missing data as well as on `host_update_check_success == 0`.

## First-seen state

The state lives in a private directory: the first entry of `$STATE_DIRECTORY` (set by systemd when
the unit has `StateDirectory=`), otherwise `${XDG_STATE_HOME:-$HOME/.local/state}/host-update-metric/`.
It must be an absolute path. Rules:

- the directory is owned by the running user, mode `700`, and not a symlink; the file `first-seen`
  is a regular file, owned by the same user, mode `600`, at most 256 KiB and 1000 entries
- the format is a header `host-update-state v1` and lines `<package> <candidate-version> <epoch>`;
  any other line, a duplicate, a future timestamp, a bad name or a non-canonical number (a leading
  zero) makes the whole file unreadable. A package is matched to its first-seen line by the exact
  `<package> <candidate-version>` pair at the start of a line (`foo` never matches `libfoo`)
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

systemd exports `STATE_DIRECTORY=/var/lib/host-update-metric` to the service; the script uses it
as is, so no extra variable is needed. (Put `[Timer]` and `[Install]` in the `.timer` unit and the rest in the `.service` unit.) Pipe
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
fail-closed path and every size bound in `tests/python/test_host_update_metric.py` with a fake apt
and a clean-mutant revert proof per guard.

Not verified on the owner's hosts yet: that Debian 13 prints the security archive as
`Debian-Security:13/stable-security` and Ubuntu 24.04 as `Ubuntu:24.04/noble-security`. The script
treats an origin as security when its label is `Debian-Security`, `Ubuntu`, `UbuntuESM` or
`UbuntuESMApps` and its suite (after the last `/`) ends in `-security`. Run it once per host and
compare `security=true` with `apt-get -s dist-upgrade | grep -c -- '-security'` before trusting the
alert. A third-party archive whose suite is named `*-security` under another label is not counted as
security.
