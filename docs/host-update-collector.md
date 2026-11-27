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
- `stat` of `/var/lib/apt/periodic/update-success-stamp` and of the non-empty `*_Release` and
  `*_InRelease` files in `/var/lib/apt/lists`
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
  (kept-back packages, phased updates, pins). **Held-back updates are also counted in
  `host_update_pending` as non-security (`security=false`)**, so they cannot hide. Each package named
  in apt's "kept back" list gets its own first-seen clock (state entries named `held-back:<package>`,
  a separate kind from candidate versions, so they age and feed `oldest_pending_age`); held packages
  apt does not name share one `held-back:unlisted` clock. More names than the summary count, a bad
  name, or more than 1000 pending plus held packages is a failure.
- `host_update_lists_age_seconds` is the age that governs the freshness check: the older of the apt
  update stamp and the oldest security list, see below.
- `host_unattended_last_run_age_seconds` is the age of the newest log line `All upgrades installed`
  or `No packages found that can be upgraded unattended ...`. If no such line exists, the age is
  unknown, and unknown is a **failure**, never `0`.
- `host_update_oldest_pending_age_seconds` is the age of the oldest first-seen time among the
  packages pending now. It feeds a 7-day clock. A new candidate version of the same package restarts
  its clock.

### Apt list freshness

The script never refreshes the lists, so stale, emptied or wiped lists would report nothing pending.
Both of these are required, and the check **fails** (`host_update_check_success value=0i` only) when
either is missing or too old:

1. `/var/lib/apt/periodic/update-success-stamp` (regular file, not a symlink);
2. at least one non-empty, non-symlink `*_InRelease` or `*_Release` file in `/var/lib/apt/lists`.
   Package files (`*_Packages*`, including `*_Packages.FAILED` junk) never count.

The list age is the **oldest** of the security-archive list files (a suite ending in `-security`,
read from the file name, for example `..._noble-security_InRelease`); when there is none, the oldest
of all `InRelease`/`Release` files. One fresh third-party list therefore cannot hide a stale
security list. `host_update_lists_age_seconds` is the older of that and the stamp age; over the
maximum (default 3 days, `--max-lists-age-days`, 1 to 30) the check fails. A stamp or list mtime
more than 1 day in the future fails the check; up to 1 day ahead gives age `0`. The security files
are chosen by file name because apt's configured sources cannot be read without parsing apt
configuration; a list left behind by a removed security source keeps failing until `apt-get update`
(or `apt-get clean` of the lists) removes it. Keep the host's `apt-daily` refresh enabled.
This covers issue #233.

**Hosts without the stamp.** The age check needs the stamp, so a healthy host that has periodic
updates disabled (`APT::Periodic::Update-Package-Lists "0"`) and never wrote the stamp **fails
closed**. Enable the stamp with a file such as `/etc/apt/apt.conf.d/20auto-upgrades` containing
`APT::Periodic::Update-Package-Lists "1";` (the `apt-daily.timer` then refreshes the lists and writes
the stamp after each successful `apt-get update`); a manual `apt-get update` also writes it.
Otherwise run this collector only on hosts that keep the stamp.

### Failure

If apt output is not understood, a package name or origin has unexpected characters, the apt summary
line is missing or disagrees with the `Inst` lines, apt exits non-zero or times out or prints more than
4 MiB, the apt stamp or lists are missing, too old or dated in the future, the unattended-upgrades age is unknown, a number in the
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
  any other line, a duplicate, a bad name or a non-canonical number (a leading
  zero) makes the whole file unreadable. A package is matched to its first-seen line by the exact
  `<package> <candidate-version>` pair at the start of a line (`foo` never matches `libfoo`)
- it is written to a temporary file in the same directory and renamed into place
- if the directory does not exist the script creates it (first run): `state_ok` is `1`
- if the directory exists but the file is **missing**, the clock is lost: the script prints
  `host_update_state_ok value=0i` and **no** oldest-age metric, then re-seeds the file, so the next
  run is `state_ok=1` with a clock that restarts at that moment (the age is understated after a
  loss; the `state_ok=0` run is the signal). A pre-created directory therefore shows `state_ok=0`
  once on the very first run
- if any first-seen time (a package or a held-back entry) is more than 60 seconds **in the future**
  (a clock set back, or a planted file), the whole file is distrusted: the script prints
  `state_ok=0` and no age, discards every stored time and re-seeds the file from the current
  time, so the next run is `state_ok=1`. A future time is never turned into an age of `0`. Up to
  60 seconds ahead is accepted as clock jitter and gives age `0`
- if the file is **unreadable or corrupt**, or the directory or file has the wrong owner or mode, the
  script prints `state_ok=0`, no age, and does **not** overwrite anything: an operator must look at
  it and delete the file to re-seed
- a state problem never turns the check itself into a failure

The metrics are built in full and written in one step, only after every value is known; if building them fails, nothing is printed and the script exits non-zero. If that write fails (a
full disk, a closed pipe), the script exits non-zero and does not exit 0 with a partial set; gate
every health conclusion on a fresh `host_update_check_success == 1`, because a killed process or a
closed output can still leave no data at all. Termination signals (HUP, INT, TERM) are ignored
once the write begins, so a signal can never append a failure line after a complete payload.

What is guaranteed, and what is not. A single terminal status line is printed in these cases only:
normal completion (the metrics, with `host_update_check_success value=1i`), a signal before the
write (HUP, INT or TERM; the failure line), and a failure of the write itself when the output can still
take the failure line. These cases may leave no status line at all: a forced kill (KILL cannot be
trapped), a stopped process, a signal the script does not trap (PIPE, ALRM, USR1, QUIT), a closed
output, and a sink that fails after accepting part of the payload. Alert on missing data.

**Blocked-write interval.** If the reader of the output never drains it (a stuck writer or a full
pipe), the write blocks, and because TERM is ignored there, a normal stop does not end the process.
That interval is bounded only by the runtime limit you configure, so the Install section sets one:
a systemd `TimeoutStartSec=` (with `TimeoutStopSec=` and the default `KillMode=control-group`, so
the stuck process and the delivery command are really killed with KILL) and, for cron, `timeout
--kill-after`. While a blocked run lasts no fresh metric is produced; the alert for that is the
absence of a fresh `host_update_check_success` (see the alert rules below). Without a limit, a
stuck systemd oneshot would block every later timer run and stuck cron runs would pile up.

Alert rule suggestions: page on `host_update_check_success == 0` or missing data; on
`host_update_state_ok == 0`; on `host_update_oldest_pending_age_seconds > 604800` (7 days); on
`host_unattended_last_run_age_seconds > 172800` for the unattended-upgrades hosts;
`host_update_held_back > 0` for longer than a day (held-back packages are also in `pending`, so
`host_update_oldest_pending_age_seconds` covers their age); and `host_update_lists_age_seconds >
172800`, to warn before the 3-day hard failure. These are rule shapes only; no rules are shipped
with the collector.

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
TimeoutStartSec=10min
TimeoutStopSec=30s
KillMode=control-group
SendSIGKILL=yes
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

**Runtime limit (systemd).** `RuntimeMaxSec=` has no effect on `Type=oneshot` services (the man page says
to use `TimeoutStartSec=` to limit them), so the unit above uses
`TimeoutStartSec=`, which for a oneshot unit limits the whole run (its default there is no
limit). At the limit systemd sends TERM (`TimeoutStartFailureMode=` defaults to `terminate`); the
collector may ignore TERM in the blocked-write interval, so after `TimeoutStopSec=` systemd sends
KILL to every process in the unit's control group (`KillMode=control-group`, `SendSIGKILL=yes`, both
the defaults, written out so a drop-in cannot silently weaken them). The worst case is about
`TimeoutStartSec` plus `TimeoutStopSec`; the unit then fails and the next timer run starts. Needs
systemd 246 or newer for `TimeoutStartFailureMode=`; the settings written in the unit have existed
since systemd 188. Read from `systemd.service(5)` and `systemd.kill(5)` (systemd 257 man pages,
2026-11-26).

Cron alternative (one user crontab line, hourly) with an equivalent bound: `timeout` sends TERM
at 10 minutes, and `--kill-after` sends KILL 30 seconds later to the whole group, so a blocked
write cannot pile up runs:

```
7 * * * * HOST_LABEL=web-1 timeout --kill-after=30s 10m sh -c '/opt/siem/scripts/host-update-metric.sh standard | /opt/siem/deliver-metrics'
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
