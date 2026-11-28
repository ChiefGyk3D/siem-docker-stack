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
# VERIFIED by --discover on 2026-11-27: model, version, name, mac, serial, site_name, source and
# type are TAGS (not fields); upgradeable is a boolean field. So model and firmware come from the
# tags of the upgradeable series (GROUP BY name, model, version); a missing tag shows "?".
# "Last seen" is the timestamp of the newest "upgradeable" point per device.
# A device that changed firmware inside the 7-day window has two series: the newest sample wins
# and the older versions are listed in a note line under the table.
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
# One query: model and version are TAGS on the upgradeable series (VERIFIED by --discover on
# 2026-11-27), so they arrive as labels of each result frame.
payload=$(jq -nc --arg s "$SERIES" '
  {from: "now-7d", to: "now", queries: [{refId: "A", datasource: {type: "influxdb", uid: "influxdb-unifi"},
    rawQuery: true, resultFormat: "time_series",
    query: ("SELECT last(\"upgradeable\") FROM " + $s + " WHERE time > now() - 7d GROUP BY \"name\",\"model\",\"version\" SLIMIT 201")}]}')
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
      | .schema.fields[1].labels as $l
      | ([$l.model, $l.version] | all(. == null or type == "string")) as $tagsok
      | if ($tagsok | not) then error("a model or version tag is not text") else . end
      | {name: .schema.fields[1].labels.name, model: $l.model, version: $l.version,
         t:(if ($ix | length) > 0 then $t[$ix[-1]] else null end),
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
    if (.results | keys) != ["A"] then error("the answer results do not match the query sent")
    else frames("A") as $a
    | if $a == null then error("the upgradeable query returned an error")
      elif ($a | length) == 0 then error("no UniFi devices in the data (last 7 days)")
      elif ($a | length) > $max then error("more than " + ($max | tostring) + " series; refusing a truncated list")
      else
        { devices: ($a | group_by(.name) | map(
            (sort_by(.t // -1) | reverse) as $s
            | $s[0] as $n
            | {name: $n.name, t: $n.t, model: $n.model, version: $n.version,
               older: ([$s[1:][] | select(.version != $n.version) | (.version // "?")] | unique),
               upd: (if $n.v == true then "yes" elif $n.v == false then "no"
                     elif ($n.v | type) == "number" then (if $n.v > 0 then "yes" else "no" end) else "?" end)})) }
        | .newest = ([.devices[].t | select(. != null)] | max)
        | if .newest == null then error("no device has a sample time")
          elif (.newest / 1000) > ($now + 300) then error("the newest sample is in the future; not trusting the data")
          else . end
      end
    end
  end' 2>&1) || die "could not read the Grafana answer: $(printf '%s' "$parsed" | head -c 300 | tr -d '[:cntrl:]')"

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
    (.devices[] | select((.older | length) > 0)
      | "note: \(.name | clean) also reported other firmware in the last 7 days: \(.older | map(clean) | join(", "))"),
    (if agesec(.newest) > $stale then "WARNING: the newest sample is older than \(age($stale)); the data is STALE" else empty end),
    ([$rows[] | select(.l | test("STALE"))] | length) as $sd
    | (if $sd > 0 and agesec(.newest) <= $stale then "WARNING: \($sd) device(s) have not reported for over \(age($stale)) (STALE)" else empty end)'
