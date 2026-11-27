# Synology DSM update alert

Tracked in issue #257 (the update alerting family of [update-alerting.md](update-alerting.md)).
Nothing here applies an update or changes the NAS. A read-only SNMPv3 user lets
Telegraf read one flag, InfluxDB stores it, and Grafana alerts while it stays
set. Owner decision 2026-11-27: DSM updates via SNMPv3 only, no admin Web API
credential anywhere.

## What it does

```
NAS (SNMPv3 read-only user) <-- Telegraf snmp input, hourly
                                   |
                                   v
                   InfluxDB database telegraf, measurement synology_dsm
                                   |
                                   v
                       Grafana rules (update_alert route -> n8n router)
```

- Reads `upgradeAvailable` (`.1.3.6.1.4.1.6574.1.5.4.0`, integer: 1 available,
  2 unavailable, 3 connecting, 4 disconnected, 5 others) and the DSM `version`
  (`.1.3.6.1.4.1.6574.1.5.3.0`) from SYNOLOGY-SYSTEM-MIB.
- Rules in `docker/grafana/provisioning/alerting/update-alert-rules-synology.yml`
  (all `isPaused: true`; the label `nas-example` below is a placeholder for your NAS name):

| Rule | Fires when | Labels | Repeat |
|------|------------|--------|--------|
| Synology DSM update pending over 24h | value 1 for 24 to 159 hourly buckets in 7 days | warning, P2, phone false | 84h |
| Synology DSM update pending over 7 days | value 1 for 160 or more hourly buckets | critical, P1, phone true | 24h |
| Synology update data stale | no point in `synology_dsm` for 3 hours (the poller stopped); no data also alerts, and this rule is the only no-data alert | warning, P2, phone false | 84h |
| Synology DSM update check failing | any value other than 1 or 2 (3, 4, 5 or unexpected) for 6 hours (the NAS cannot be read as current) | warning, P2, phone false | 84h |

  The warning and critical bands count hourly buckets in a rolling 7 days, so the
  titles are approximate: 24 buckets is about 24 hours and 160 buckets is about
  6 days 16 hours (a deliberate tolerance of about 8 hours of missed polls per week).
  The warning and critical bands share the number 160, the same exclusive-range
  pattern as the UniFi rules, so they never both fire. Repeats come from the
  `update_alert` route of `update-notification-policy.yml.example`. The 24h warning
  goes to chat only, like the UniFi and pfSense 24h warnings (owner decisions #152 and
  2026-11-26); only the 7-day critical pages the phone. To page on the warning
  as well, set `phone: "true"` on `update-synology-pending-24h` (the taxonomy allows it for an update rule).
- The four titles are on the router allow-list (`ALLOWED_ALERTNAMES`), so a
  critical pages at emergency priority once Pushover is enabled.

## What it does NOT cover

- Packages (DSM "packages" such as add-on apps). The only documented machine-readable signal is the DSM one. Package
  updates stay a manual check in DSM.
- Anything on the NAS other than the update flag. This is not a NAS health check.
- A NAS that is off or unreachable: that shows as stale data, not as an update.

## Secrets (names only)

Set these in your secret manager and inject them as environment variables into
the Telegraf process. Telegraf expands `${NAME}` in the config; the example file
holds no value. Do not put them in the repository, a GitHub secret or a command line.

| Name | Meaning |
|------|---------|
| `SYNOLOGY_SNMP_AGENT` | NAS address (host or IP, no scheme or port; the example builds `udp://<agent>:161`) |
| `SYNOLOGY_SNMP_USER` | the dedicated read-only SNMPv3 user |
| `SYNOLOGY_SNMP_AUTH_PASSWORD` | its authentication passphrase |
| `SYNOLOGY_SNMP_PRIV_PASSWORD` | its privacy passphrase |
| `SYNOLOGY_INFLUX_URL` | InfluxDB write URL (the stack's InfluxDB, port 8086) |
| `SYNOLOGY_INFLUX_USER` | InfluxDB account with WRITE on database `telegraf` only |
| `SYNOLOGY_INFLUX_PASSWORD` | its password |

This repository has no Telegraf container, so no existing variable covers these
(the firewall and Twingate collectors write through their own accounts, see the
live deploy runbook). Use a dev secret environment first, not prd.

## Owner steps

Nothing below is done by the repository. Do them in order, and do not unpause the rules before step 5.

1. Create the SNMPv3 user on the NAS. This is a DSM screen: ask me for a
   screenshot of the DSM SNMP settings first, and I will give the steps for
   what you see (I will not describe DSM menus from memory). Use a user that can
   only read, SHA authentication and AES privacy to match the example, and
   passphrases of at least 8 characters.
2. Create the InfluxDB write account (same pattern as `twingate_wo`, runbook
   section 10). Run these in a shell where `SYNOLOGY_INFLUX_USER` and
   `SYNOLOGY_INFLUX_PASSWORD` are already exported from the secret manager. First
   the name check (the user goes into a quoted InfluxQL identifier and the password
   into a quoted literal, so only a narrow character set is accepted; it stops
   at the first problem):

```
# validate-influx-names
set -eu
case "${SYNOLOGY_INFLUX_USER:-}" in ''|*[!A-Za-z0-9_]*) echo "SYNOLOGY_INFLUX_USER must be letters, digits and _ only" >&2; exit 1;; esac
case "${SYNOLOGY_INFLUX_PASSWORD:-}" in ''|*[!A-Za-z0-9_.@%+=-]*) echo "SYNOLOGY_INFLUX_PASSWORD must be letters, digits and _ . @ % + = - only" >&2; exit 1;; esac
echo "names ok"
```

   Then the account. The user name is passed into the container with
   `docker exec -e` (no value on the command line) so the verification sees it:

```
# create-influx-account
set -eu
siem-run bash -c 'docker exec -i influxdb sh -c '\''INFLUX_USERNAME="$INFLUXDB_ADMIN_USER" INFLUX_PASSWORD="$INFLUXDB_ADMIN_PASSWORD" influx'\'' > /dev/null <<EOSQL
CREATE USER "$SYNOLOGY_INFLUX_USER" WITH PASSWORD '\''$SYNOLOGY_INFLUX_PASSWORD'\''
GRANT WRITE ON "telegraf" TO "$SYNOLOGY_INFLUX_USER"
EOSQL'
docker exec -e SYNOLOGY_INFLUX_USER influxdb sh -c 'INFLUX_USERNAME="$INFLUXDB_ADMIN_USER" INFLUX_PASSWORD="$INFLUXDB_ADMIN_PASSWORD" influx -execute "SHOW GRANTS FOR \"$SYNOLOGY_INFLUX_USER\""'
```

   Check: the last command lists `telegraf WRITE` and no other database.
3. Confirm the OIDs with one live read (before any Telegraf or rule change). The
   passphrases go into a private temporary net-snmp config file built by the shell
   from the environment, so they never appear in a process argument. One script
   does it: it stops at the first error and deletes the file on success, failure,
   Ctrl-C and termination. Run it in a shell where the four `SYNOLOGY_SNMP_*` names are
   already exported:

```
# snmpget-confirm
set -eu
: "${SYNOLOGY_SNMP_AGENT:?required}" "${SYNOLOGY_SNMP_USER:?required}" "${SYNOLOGY_SNMP_AUTH_PASSWORD:?required}" "${SYNOLOGY_SNMP_PRIV_PASSWORD:?required}"
umask 077
dir=$(mktemp -d "${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/snmpconf.XXXXXX")
trap 'rm -f -- "$dir/snmp.conf"; rmdir -- "$dir"' EXIT
trap 'exit 130' HUP INT TERM
printf 'defVersion 3\ndefSecurityLevel authPriv\ndefSecurityName %s\ndefAuthType SHA\ndefPrivType AES\ndefAuthPassphrase %s\ndefPrivPassphrase %s\n' "$SYNOLOGY_SNMP_USER" "$SYNOLOGY_SNMP_AUTH_PASSWORD" "$SYNOLOGY_SNMP_PRIV_PASSWORD" > "$dir/snmp.conf"
SNMPCONFPATH="$dir" snmpget -v3 "udp:$SYNOLOGY_SNMP_AGENT:161" .1.3.6.1.4.1.6574.1.5.3.0 .1.3.6.1.4.1.6574.1.5.4.0
```

   Expected: two lines, a string for the DSM version and an INTEGER for
   `upgradeAvailable`. Send me the two lines (values only, no passphrases). Note
   which integer you see and whether the NAS shows an update in DSM at that moment,
   so we can confirm that 1 means pending and 2 means current (Synology's table is
   ambiguous on 2). If `snmpget` says "No Such Instance", the `.0` suffix is wrong
   for this DSM: tell me before going on.
4. Start the poller with `docs/examples/synology-snmp-telegraf.conf.example` as its
   own Telegraf instance, with the seven names above in its environment. Ask me
   for the host and how Telegraf runs there before choosing a command. Then confirm
   data lands:

```
docker exec influxdb sh -c 'INFLUX_USERNAME="$GRAFANA_INFLUX_USER" INFLUX_PASSWORD="$GRAFANA_INFLUX_PASSWORD" influx -database telegraf -execute "SELECT last(upgrade_available) FROM synology_dsm"'
```

5. Only now set `isPaused: false` on the four rules, merge the `update_alert`
   route of the notification policy example if it is not live yet, and restart
   Grafana. The rules stay paused until the NAS SNMPv3 user exists and one live
   `snmpget` has been confirmed.

## Not verified and honest limits

Not verified: everything here is built from Synology's SNMP guide (last updated
Aug 3 2026) and Telegraf's documented snmp input; no NAS, Telegraf or Grafana was
touched. Specifically not verified: the `.0` scalar suffix, that 1 means pending
and 2 means current (the guide's table for 2 is ambiguous), that DSM 7.4 offers
SHA and AES on its SNMPv3 screen (SHA-256 and others are not assumed), that
Telegraf lets the `nas` tag through unchanged, that the `defAuthType` family of
net-snmp.conf tokens matches your net-snmp version (from the net-snmp snmp.conf
manual, not re-read), and the exact DSM screens.

- DSM does not send SNMP traps, so this is polling only, hourly.
- DSM only. A package update is invisible to it.
- The 7-day bucket count does not reset when a value of 2 appears (see the
  rule file header): an update that follows an applied one within 7 days can
  escalate early.
- Value 5 (others) and any unexpected value count as a failed check (the check-failing rule).
- The pending rules treat no data as OK (UniFi pattern); the stale rule owns a dead poller. A failing query still raises the pending rule's own alert (a critical pages), as for UniFi.
- SHA and AES are the compatibility pair. During the live check pick the strongest pair DSM lists (SHA-2 with AES-192 or AES-256 if offered) and set both ends and `defAuthType` and `defPrivType` to match.
- Alert names are on the router allow-list; a rename must change both places.
