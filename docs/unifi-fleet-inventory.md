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

## Where the data lives (VERIFIED with `--discover`, 2026-11-27)

Measurements `uap` (access points) and `usw` (switches) hold data. `ugw`, `udm` and `uxg` returned
nothing on the checked fleet; the script still queries them in case a gateway is added.

| Kind | Keys |
| --- | --- |
| Tags | `name`, `model`, `version`, `mac`, `serial`, `site_name`, `source`, `type` |
| Fields | `upgradeable` (boolean), `last_seen` (float), `uptime`, `system_uptime`, `ip` (string), `cpu`, `mem` and others |

`model` and `version` are tags, not fields. The script therefore asks one question:
`SELECT last("upgradeable") ... GROUP BY "name","model","version"`, and reads model and firmware from the
labels of each answer series. A missing tag shows `?`.

If the data ever looks wrong, list the real keys again:

```bash
GRAFANA_BASE_URL=<your Grafana address> bash scripts/unifi-fleet-inventory.sh --discover
```

`--discover` runs `SHOW FIELD KEYS` and `SHOW TAG KEYS` for the five measurements through the same call
and the same token handling and prints, per measurement, the sorted field keys with their types and the
sorted tag keys. Key names only, no values, control characters stripped.

## Columns

| Column | Meaning |
| --- | --- |
| NAME | The `name` tag. Control characters are stripped and the name is cut at 60 characters. |
| MODEL | The `model` tag of the newest sample. |
| FIRMWARE | The `version` tag of the newest sample. |
| UPDATE | `yes` when the latest `upgradeable` value is true (or above 0), `no` when false, `?` when unknown. |
| LAST SEEN | Time of the newest `upgradeable` sample for that device (UTC) and its age. `STALE` means older than 2 hours. |

Under the table: device count, updates available, devices with unknown update state, and the age of the
newest sample anywhere. If that is older than 2 hours the script prints a `WARNING ... STALE` line, so
a dead collector is visible instead of looking like an up-to-date fleet.

A device that changed firmware inside the 7-day window has one series per version. The row shows the
newest sample's firmware, and a `note:` line under the summary lists the older versions seen.

## Failure behavior

Any error stops the script with a message on stderr and exit code 1: unset address, token missing or
unusable, curl failure or timeout (20 s), non-200 answer, an answer that is not the expected shape,
no devices, more than 200 series, or a newest sample dated in the future. Nothing is printed to stdout
in those cases.
