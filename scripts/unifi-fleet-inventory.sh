#!/usr/bin/env bash
# Read-only UniFi fleet inventory (issue #252). Run on the owner's laptop:
#
#   GRAFANA_BASE_URL=<your Grafana address> bash scripts/unifi-fleet-inventory.sh
#
# Asks Grafana's datasource query endpoint (/api/ds/query) for the unpoller data already in
# InfluxDB and prints one aligned table: name, model, firmware, update available, last seen,
# then a count summary and the age of the newest sample (so stale data is visible).
#
# Security model, same as the Grafana export script:
#   - The Viewer token is read from the secret manager on this machine. It is never printed,
#     never in a command line and never written to a file; curl gets it on stdin (-K -).
#   - Read-only: one POST that only runs a query. Output is the table only (no raw JSON).
#   - Fails closed with a clear message on any error. Bounded runtime (curl --max-time).
#   - Device names, models and versions are untrusted text: control, bidi and C1 characters
#     are stripped before they are printed.
#
# Verified against the digest workflow (n8n/weekly-update-digest.json) and the Grafana rule
# export: datasource uid influxdb-unifi, measurements uap|usw|ugw|udm|uxg, the field
# "upgradeable", the tag "name".
# UNVERIFIED against live data: the fields "model" and "version" (query B and C below).
# If Grafana rejects them the table shows "?" in those columns and a warning goes to stderr.
# "Last seen" is the timestamp of the newest "upgradeable" point per device (verified field),
# not a separate last_seen field.
set -euo pipefail

STALE_SECONDS=7200   # same freshness limit as the update digest (2 hours)
MAX_DEVICES=200      # the queries ask for 201 series so a truncated answer reads as too many

die() { echo "unifi-fleet-inventory: $*" >&2; exit 1; }

command -v jq > /dev/null 2>&1 || die "jq is required"
command -v curl > /dev/null 2>&1 || die "curl is required"

MODE=table
case "${1-}" in
    "") ;;
    --discover) MODE=discover ;;
    *) die "usage: unifi-fleet-inventory.sh [--discover]" ;;
esac
[ "$#" -le 1 ] || die "usage: unifi-fleet-inventory.sh [--discover]"

BASE="${GRAFANA_BASE_URL-}"
[ -n "$BASE" ] || die "GRAFANA_BASE_URL is not set; set it to your Grafana address (http(s)://host[:port])"
BASE="${BASE%/}"
printf '%s' "$BASE" | grep -Eq '^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$' \
    || die "GRAFANA_BASE_URL is not a plain http(s)://host[:port][/path] address"

TOK=$(doppler secrets get GRAFANA_VIEWER_TOKEN --plain --project homelab --config prd_network 2> /dev/null) \
    || die "could not read the token from the secret manager"
[ -n "$TOK" ] || die "the token is empty"
case "$TOK" in
    *[[:cntrl:]]* | *'"'* | *\\*) die "the token has characters that are not allowed in a header" ;;
esac

SERIES='/^(uap|usw|ugw|udm|uxg)$/'
payload=$(jq -nc --arg s "$SERIES" '
  def q($ref; $field): {refId: $ref, datasource: {type: "influxdb", uid: "influxdb-unifi"},
    rawQuery: true, resultFormat: "time_series",
    query: ("SELECT last(\"" + $field + "\") FROM " + $s + " WHERE time > now() - 7d GROUP BY \"name\" SLIMIT 201")};
  {from: "now-7d", to: "now", queries: [q("A"; "upgradeable"), q("B"; "model"), q("C"; "version")]}')
MEASUREMENTS=(uap usw ugw udm uxg)
if [ "$MODE" = discover ]; then
    # Read-only schema discovery: key names and field types only, no values.
    payload=$(jq -nc --args '
      def s($ref; $stmt): {refId: $ref, datasource: {type: "influxdb", uid: "influxdb-unifi"},
        rawQuery: true, resultFormat: "table", query: $stmt};
      {from: "now-7d", to: "now", queries: ([$ARGS.positional | to_entries[] |
        s("F\(.key + 1)"; "SHOW FIELD KEYS FROM \"\(.value)\""), s("T\(.key + 1)"; "SHOW TAG KEYS FROM \"\(.value)\"")])}' \
        "${MEASUREMENTS[@]}")
fi

rc=0
resp=$(printf 'header = "Authorization: Bearer %s"\n' "$TOK" \
    | curl -sS -K - --max-time 20 --connect-timeout 5 --proto '=http,https' \
        --max-filesize 1048576 -H 'Content-Type: application/json' \
        --data-binary "$payload" -w '\n%{http_code}' "$BASE/api/ds/query") || rc=$?
[ "$rc" -eq 0 ] || die "curl failed (exit $rc)"
code="${resp##*$'\n'}"
body="${resp%$'\n'*}"
[ "$code" = "200" ] || die "Grafana answered HTTP $code"

if [ "$MODE" = discover ]; then
    out=$(printf '%s' "$body" | jq -r --args '
      def clean: tostring | gsub("[\\x{0}-\\x{1f}\\x{7f}-\\x{9f}\\x{200e}\\x{200f}\\x{202a}-\\x{202e}\\x{2066}-\\x{2069}]"; "")
        | .[0:60] | if . == "" then "(blank)" else . end;
      def keys($ref):
        .results[$ref] as $r
        | if ($r | type) != "object" then error("the answer has no result " + $ref)
          elif ($r | has("error")) then error("query " + $ref + " returned an error")
          elif (($r.frames | type) != "array") then error("result " + $ref + " has no frames")
          else [$r.frames[]
            | if ((.schema.fields | type) == "array") and ((.schema.fields | length) >= 1)
                 and ((.data.values | type) == "array") and ((.data.values | length) == (.schema.fields | length))
                 and ([.data.values[] | type] | all(. == "array")) and ([.data.values[] | length] | unique | length) <= 1
              then (.schema.fields | map(.name)) as $n
                | (($n | index("fieldKey")) // ($n | index("tagKey")) // 0) as $k
                | ($n | index("fieldType")) as $t
                | [range(0; (.data.values[0] | length)) as $i
                   | (.data.values[$k][$i]) as $key
                   | if ($key | type) != "string" then error("a key name is not a string")
                     else {key: $key, type: (if $t == null then null else (.data.values[$t][$i] | if type == "string" then . else "?" end) end)} end]
              else error("a result frame is malformed") end] | add // [] end;
      if (type) != "object" or has("message") or has("error") or ((.results | type) != "object")
      then error("the answer is not a Grafana query result") else . end
      | . as $root | [$ARGS.positional | to_entries[] as $e
          | {m: $e.value, f: ($root | keys("F\($e.key + 1)") | unique_by(.key)), t: ($root | keys("T\($e.key + 1)") | map(.key) | unique)}] as $all
      | if ([$all[] | (.f | length) + (.t | length)] | add) == 0 then error("no keys returned for any measurement")
        else $all[]
          | "[\(.m)]",
            (.f | sort_by(.key)[] | "  field  \(.key | clean)  \((.type // "?") | clean)"),
            (.t | sort[] | "  tag    \(. | clean)"),
            "" end' "${MEASUREMENTS[@]}" 2>&1) \
        || die "could not read the discovery answer: $(printf '%s' "$out" | head -c 300 | tr -d '[:cntrl:]')"
    printf '%s\n' "$out"
    exit 0
fi

NOW=$(date +%s)

# Pass 1: strict parse into one small JSON object, or an error message.
parsed=$(printf '%s' "$body" | jq -c --argjson now "$NOW" --argjson max "$MAX_DEVICES" '
  def frame:
    if ((.schema.fields | type) == "array") and ((.schema.fields | length) >= 2)
       and ((.data.values | type) == "array") and ((.data.values | length) >= 2)
       and ((.data.values[0] | type) == "array") and ((.data.values[1] | type) == "array")
       and ((.data.values[0] | length) == (.data.values[1] | length))
       and ((.schema.fields[1].labels.name | type) == "string")
    then (.data.values[0]) as $t | (.data.values[1]) as $v
      | [range(0; ($t | length)) | select($v[.] != null)] as $ix
      | {name: .schema.fields[1].labels.name,
         t: (if ($ix | length) > 0 then $t[$ix[-1]] else null end),
         v: (if ($ix | length) > 0 then $v[$ix[-1]] else null end)}
      | if (.t != null and (.t | type) != "number") then error("a sample time is not a number") else . end
    else error("a result frame is malformed") end;
  def frames($ref):
    .results[$ref] as $r
    | if ($r | type) != "object" then error("the answer has no result " + $ref)
      elif ($r | has("error")) then null
      elif (($r.frames | type) != "array") then error("result " + $ref + " has no frames")
      else [$r.frames[] | frame] end;
  if (type) != "object" then error("the answer is not a JSON object")
  elif has("message") or has("error") then error("Grafana returned an error")
  elif ((.results | type) != "object") then error("the answer has no results")
  else
    frames("A") as $a | frames("B") as $b | frames("C") as $c
    | if $a == null then error("the upgradeable query returned an error")
      elif ($a | length) == 0 then error("no UniFi devices in the data (last 7 days)")
      elif ($a | length) > $max then error("more than " + ($max | tostring) + " devices; refusing a truncated list")
      elif ([$a[].name] | length) != ([$a[].name] | unique | length) then error("duplicate device names in the answer")
      else
        def lookup($list): if $list == null then {} else ($list | map({key: .name, value: .v}) | from_entries) end;
        (lookup($b)) as $m | (lookup($c)) as $f
        | { warnings: ([ (if $b != null and (($b | length) == 0 or ($b | all(.v == null))) then "WARNING: the model query returned no data for any device; the field name may be wrong (run with --discover to list the real field names)" else empty end),
                         (if $c != null and (($c | length) == 0 or ($c | all(.v == null))) then "WARNING: the firmware query returned no data for any device; the field name may be wrong (run with --discover to list the real field names)" else empty end),
                         (if $b == null then "WARNING: the model query returned an error; the MODEL column shows ? (field name UNVERIFIED against live data)" else empty end),
                         (if $c == null then "WARNING: the firmware query returned an error; the FIRMWARE column shows ? (field name UNVERIFIED against live data)" else empty end) ]),
            devices: ($a | sort_by(.name) | map({
              name, t,
              model: (if ($m[.name] | type) == "string" or ($m[.name] | type) == "number" then ($m[.name] | tostring) else null end),
              version: (if ($f[.name] | type) == "string" or ($f[.name] | type) == "number" then ($f[.name] | tostring) else null end),
              upd: (if .v == true then "yes" elif .v == false then "no"
                    elif (.v | type) == "number" then (if .v > 0 then "yes" else "no" end) else "?" end)})) }
        | .newest = ([.devices[].t | select(. != null)] | max)
        | if .newest == null then error("no device has a sample time")
          elif (.newest / 1000) > ($now + 300) then error("the newest sample is in the future; not trusting the data")
          else . end
      end
  end' 2>&1) || die "could not read the Grafana answer: $(printf '%s' "$parsed" | head -c 300 | tr -d '[:cntrl:]')"

printf '%s' "$parsed" | jq -r '.warnings[]' >&2

# Pass 2: format. The only place untrusted text is printed; it is stripped here.
printf '%s' "$parsed" | jq -r --argjson now "$NOW" --argjson stale "$STALE_SECONDS" '
  def clean: tostring | gsub("[\\x{0}-\\x{1f}\\x{7f}-\\x{9f}\\x{200e}\\x{200f}\\x{202a}-\\x{202e}\\x{2066}-\\x{2069}]"; "")
    | .[0:60] | if . == "" then "(blank)" else . end;
  def age($s): if $s < 60 then "\($s)s" elif $s < 3600 then "\($s / 60 | floor)m"
    elif $s < 86400 then "\($s / 3600 | floor)h" else "\($s / 86400 | floor)d" end;
  def agesec($t): ([($now - ($t / 1000 | floor)), 0] | max);
  def pad($w): . + (" " * ($w - length));
  (.devices | map({
      n: (.name | clean), m: ((.model // "?") | clean), f: ((.version // "?") | clean), u: .upd,
      l: (if .t == null then "never"
          else ((.t / 1000 | floor | todate) + " (" + age(agesec(.t)) + (if agesec(.t) > $stale then ", STALE" else "" end) + ")") end)})) as $rows
  | ([{n: "NAME", m: "MODEL", f: "FIRMWARE", u: "UPDATE", l: "LAST SEEN"}] + $rows) as $all
  | ([$all[].n | length] | max) as $wn | ([$all[].m | length] | max) as $wm
  | ([$all[].f | length] | max) as $wf | ([$all[].u | length] | max) as $wu
  | ($all[] | [(.n | pad($wn)), (.m | pad($wm)), (.f | pad($wf)), (.u | pad($wu)), .l] | join("  ") | sub(" +$"; "")),
    "",
    "devices: \($rows | length)",
    "updates available: \([$rows[] | select(.u == "yes")] | length)",
    "update state unknown: \([$rows[] | select(.u == "?")] | length)",
    "newest sample: \(.newest / 1000 | floor | todate) (\(age(agesec(.newest))) ago)",
    (if agesec(.newest) > $stale then "WARNING: the newest sample is older than \(age($stale)); the data is STALE" else empty end),
    ([$rows[] | select(.l | test("STALE"))] | length) as $sd
    | (if $sd > 0 and agesec(.newest) <= $stale then "WARNING: \($sd) device(s) have not reported for over \(age($stale)) (STALE)" else empty end)'
