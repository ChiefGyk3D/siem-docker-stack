# UniFi fleet inventory

`scripts/unifi-fleet-inventory.sh` prints the UniFi devices that unpoller reports, with firmware and
update state, from the data already in InfluxDB. It is read-only: one query through Grafana's
`/api/ds/query` endpoint, using the Grafana Viewer token from the secret manager on your machine.
The token is never printed, never on a command line and never written to a file.

## Run it (on your laptop)

```bash
GRAFANA_BASE_URL=<your Grafana address, e.g. http://host:3000> bash scripts/unifi-fleet-inventory.sh
```

`GRAFANA_BASE_URL` has no default; the script stops with a message if it is unset. A plain `http://`
address sends the token unencrypted, the same as the Grafana export script does. Needs `jq`, `curl`
and a logged-in `doppler` (token `GRAFANA_VIEWER_TOKEN`, project `homelab`, config `prd_network`).

## Columns

| Column | Meaning |
| --- | --- |
| NAME | The `name` tag unpoller sets. Control characters are stripped and the name is cut at 60 characters. |
| MODEL | Latest `model` field. |
| FIRMWARE | Latest `version` field. |
| UPDATE | `yes` when the latest `upgradeable` value is true (or above 0), `no` when false, `?` when unknown. |
| LAST SEEN | Time of the newest `upgradeable` sample for that device (UTC) and its age. `STALE` means older than 2 hours. |

Under the table: device count, updates available, devices with unknown update state, and the age of the
newest sample anywhere. If that is older than 2 hours the script prints a `WARNING ... STALE` line, so
a dead collector is visible instead of looking like an up-to-date fleet.

## Failure behavior

Any error stops the script with a message on stderr and exit code 1: unset address, token missing or
unusable, curl failure or timeout (20 s), non-200 answer, an answer that is not the expected shape,
no devices, more than 200 devices, or a newest sample dated in the future. Nothing is printed to stdout
in those cases.

## Verified and unverified

Verified from the update digest workflow and the Grafana rule export: datasource `influxdb-unifi`,
measurements `uap`, `usw`, `ugw`, `udm`, `uxg`, field `upgradeable`, tag `name`.

**UNVERIFIED against live data:** the `model` and `version` fields (queries B and C in the script).
If Grafana rejects them, the MODEL or FIRMWARE column shows `?` and a warning is printed on stderr.
If the real field names differ, change the two field names in the script's `payload` query.
