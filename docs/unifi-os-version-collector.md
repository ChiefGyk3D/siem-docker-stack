# UniFi OS Server version collector

`scripts/unifi-os-version-metric.sh` reports the installed UniFi OS Server version and the UniFi
Network app version of the Pi as one InfluxDB line protocol line, in the style of
`scripts/host-update-metric.sh` (see `docs/host-update-collector.md`). It is read-only. Tracked in
issue #244 (epic #62, parent #219).

Owner decision 2026-11-27: "Report versions + weekly check reminder".

## What it knows, and what it does not

It reports **installed versions only**. There is **no update-available signal** to read on the Pi:
the `uosserver` CLI has only `status`, `shell`, `support` and `version`, and the updater service has
no TCP port. So the collector can never say that an update is pending, and it can never say that none
is. It **never pages** and no alert rule reads it. The digest shows the versions with a reminder to
check for updates in the UniFi OS Server UI; a person does the check.

## What it runs

Only these, each with `env -i PATH=/usr/bin:/bin LC_ALL=C`, no stdin, no stderr and a hard time
limit of 20 seconds (`timeout -k 5`, which also kills a child that holds the pipe):

- `uosserver version` prints one line, the version (for example `5.1.42`). Only a strict string is
  accepted: digits and dots, starting and ending with a digit, no empty component, at most 32
  characters. Output is cut at 128 bytes while it is read. Anything else fails the run.
- `uosserver status` is read **only** for the `version` field of the Status line of the `unifi.service`
  block (the Network app version, for example `10.6.109`). Output is cut at 1 MiB and 20000 lines.
  Nothing else in that output is parsed, stored or printed.

plus `date`, `head`, `tr`, `timeout` and `env`. No sudo, no network, no write to disk. It runs as the
owner's user or as root, whichever the `uosserver` CLI needs on the Pi. All paths are absolute
constants at the top of the script; there are no test hooks (the tests rewrite those constant lines in
a scratch copy).

## Usage

```sh
HOST_LABEL=pi-example /opt/siem/scripts/unifi-os-version-metric.sh
/opt/siem/scripts/unifi-os-version-metric.sh pi-example     # label as the argument
```

`HOST_LABEL` (or the argument) is required: 1 to 32 characters of `A-Z a-z 0-9 _ -`, starting with a
letter or digit. The real hostname is never used. It is the only tag.

## What it prints

```
unifi_os_version,host=pi-example os_version="5.1.42",network_version="10.6.109",collected_ts=1795000000i,result="ok"
```

- `os_version` and `network_version` are strings; `collected_ts` is the unix time of collection.
- `result="ok"`: both versions were read.
- `result="network_unknown"` with `network_version="unknown"`: the OS version was read but the
  Network app version was not. This is **not an error** and the exit code is 0. It is the answer when
  there is no `unifi.service` block, not exactly one `Status:` line in it, not exactly one quoted
  `"version"` field in that line, a value that is not digits and dots, the status command failed or
  timed out, or its output was too large. The Network version is never guessed.

## Failure

If `uosserver` is missing, `uosserver version` exits non-zero, times out, prints more than 128 bytes
or anything but a strict version string, the label is invalid, or the final write fails, the script
prints **nothing** on stdout, writes a short fixed reason to stderr and exits 1. The raw text of either
command is never printed, on success or on failure. An exec runner may drop the output of a command
that exits non-zero, so a consumer must treat missing data as a failed collection, not as "no news".

## Digest line (planned, not wired yet)

The weekly digest line will read:

```
UniFi OS Server <version>, Network <version>: check for updates in the UI
```

When the Network version is `unknown` the planned line says `Network unknown`. The digest wiring is a
later change on the digest branch (see `docs/update-digest.md`); this change documents the line only.

## Install (owner steps, root-owned paths)

Not installed anywhere yet. Nothing here touches the Pi until you run it. Check the `uosserver` path
first, because the constant at the top of the script is `/usr/local/bin/uosserver` and has not been
confirmed on the Pi:

```sh
command -v uosserver
```

If it prints another path, change the `uos_bin=` line of the installed copy (the one place the path
lives). Then install, dry run first (as the user that can run `uosserver status`):

```sh
sudo install -d -m 0755 -o root -g root /opt/siem/scripts
sudo install -m 0755 -o root -g root scripts/unifi-os-version-metric.sh /opt/siem/scripts/unifi-os-version-metric.sh
HOST_LABEL=pi-example /opt/siem/scripts/unifi-os-version-metric.sh; echo "exit=$?"
```

Expected: one line starting `unifi_os_version,host=pi-example os_version="5.1.42"` and `exit=0`. If the
Network version shows `unknown`, the `unifi.service` block of your `uosserver status` is shaped
differently from what the parser expects: that is safe (it is never guessed) but needs a look; do not
paste the raw status output anywhere public.

A weekly timer is enough (versions change rarely). Cron form, one line, with the same kind of bound
as the host collector (the delivery command is a placeholder):

```
17 6 * * 1 HOST_LABEL=pi-example timeout --kill-after=30s 2m sh -c '/opt/siem/scripts/unifi-os-version-metric.sh | /opt/siem/deliver-metrics'
```

## Delivery is not decided

Exactly as for the host collector: this repo does not yet pick how the line reaches InfluxDB. It could
be piped to a writer such as `scripts/live-deploy/twingate-influx-write.py` (which accepts only
`twingate_` lines today, so reuse needs a prefix allow-list change) or read by a Telegraf `exec` input
with `data_format = "influx"` (string fields are quoted, which that format accepts). Keep credentials
in the secret manager and never in argv.

## What was verified, and what was not

Verified: `uosserver version` prints one line with the version, and the Network version sits in the
`version` field of a JSON object on the Status line of the `unifi.service` block of `uosserver status`
(read-only paste from the live Pi by the owner, 2026-11-27). All parsing, every fail-closed path, every
bound and a clean-mutant revert proof per guard are in `tests/python/test_unifi_os_version_metric.py`,
with fake binaries.

Not verified: the exact layout of the `uosserver status` blocks. The parser treats a block header as
the first word of a line (the second after a bullet) ending in `.service`, which is an assumption;
a different layout gives `unknown`, never a wrong version. Also not verified: the absolute path of
`uosserver`, and that the CLI works under the fixed environment (it may need variables such as
`XDG_RUNTIME_DIR` or `HOME`). The dry run above tells you; none of it was run on the Pi.
