#!/bin/bash
# =============================================================================
# check-env.sh — Refuse to deploy with missing or well-known secrets
# =============================================================================
# docker-compose.yml fails when a required secret is UNSET (${VAR:?}), but an
# .env copied from the example still has placeholder values that are set. This
# check rejects empty values and the well-known placeholders/old defaults.
# It prints variable names only, never values.
#
# Usage:
#   bash scripts/check-env.sh [path/to/.env]     # default: ./.env
# Exit: 0 all good, 1 problems found, 2 file not found.
# =============================================================================
set -euo pipefail

ENV_FILE="${1:-.env}"
[ -f "$ENV_FILE" ] || { echo "check-env: $ENV_FILE not found (cp .env.example .env)" >&2; exit 2; }
[ ! -L "$ENV_FILE" ] || { echo "check-env: $ENV_FILE is a symlink; point the check at the real file" >&2; exit 2; }

# Open the file once, confirm the opened file is the one at the path (so a symlink
# or a replacement swapped in meanwhile is caught), and read it once into memory as
# base64 so every byte is kept. Every later check reads this snapshot, never the
# path again, so all checks see the same bytes.
exec 3< "$ENV_FILE"
[ "$(stat -L -c '%d:%i' /dev/fd/3)" = "$(stat -c '%d:%i' -- "$ENV_FILE")" ] ||
    { echo "check-env: $ENV_FILE changed while it was being opened" >&2; exit 2; }
b64="$(base64 -w0 <&3)"
exec 3<&-
# Control bytes (NUL, carriage return, escape, bell and the rest, except tab and
# newline) make different parsers see different names and values: refuse them
# before anything is parsed. Bytes of 128 and above are allowed (UTF-8 passwords).
ctrl="$(printf '%s' "$b64" | base64 -d | LC_ALL=C tr -d '\011\012\040-\176\200-\377' | wc -c)"
if [ "$ctrl" -ne 0 ]; then
    echo "check-env: ${ENV_FILE} contains control characters (NUL, carriage return, escape or similar), so GRAFANA_WEBHOOK_SECRET and the other values cannot be validated; remove them (convert CRLF to LF)" >&2
    exit 1
fi
content="$(printf '%s' "$b64" | base64 -d; printf x)"
content="${content%x}"

REQUIRED=(
    OPENSEARCH_ADMIN_PASSWORD OPENSEARCH_LOGSTASH_PASSWORD
    OPENSEARCH_READONLY_PASSWORD OPENSEARCH_DASHBOARDS_PASSWORD
    GRAFANA_ADMIN_PASS
    INFLUXDB_ADMIN_PASSWORD GRAFANA_INFLUX_PASSWORD UNPOLLER_INFLUX_PASSWORD
    WAZUH_INDEXER_PASSWORD WAZUH_API_PASSWORD WAZUH_DASHBOARD_PASSWORD
    WAZUH_GRAFANA_RO_PASSWORD
    UNIFI_PASS
    PROMETHEUS_OTLP_SENDER_PASSWORD PROMETHEUS_OTLP_GRAFANA_PASSWORD PROMETHEUS_OTLP_SCRAPE_PASSWORD
    PROMETHEUS_GRAFANA_PASSWORD PROMETHEUS_SELF_PASSWORD
)

# One placeholder rule for every shell script lives in lib-secrets.sh.
# The helper is opened once, the OPEN file and every directory above it are checked, and that same
# descriptor is sourced, so a swap of the path after the check changes nothing (docs/container-engine.md).
# This small check stays inline in each script: a shared loader would itself have to be sourced
# unchecked first.
SL_DIR="$(/usr/bin/dirname -- "$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")")"
SL_LIB="${SL_DIR}/lib-secrets.sh"
sl_fail() { echo "check-env: refusing to source ${SL_LIB}: $1" >&2; exit 1; }
SL_UID="$(/usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null)" || SL_UID=
case "$SL_UID" in '' | *[!0-9]*) sl_fail "cannot tell who is running (no numeric user number)" ;; esac
SL_UID=$((10#$SL_UID))
[ -f "$SL_LIB" ] && [ ! -L "$SL_LIB" ] || sl_fail "it is missing or is a link"
exec 7<"$SL_LIB" || sl_fail "it cannot be opened"
SL_OWNER="$(/usr/bin/stat -L -c %u -- /proc/self/fd/7)"
SL_MODE="$(/usr/bin/stat -L -c %a -- /proc/self/fd/7)"
SL_LINKS="$(/usr/bin/stat -L -c %h -- /proc/self/fd/7)"
SL_MASK=022  # group or world write on the opened file is never allowed, root or not: a peer could edit the open inode before it is sourced
if [ ! -f /proc/self/fd/7 ] || { [ "$SL_OWNER" != 0 ] && [ "$SL_OWNER" != "$SL_UID" ]; } ||
    [ $((8#$SL_MODE & 8#$SL_MASK)) -ne 0 ] || [ "$SL_LINKS" != 1 ]; then
    sl_fail "it must be a regular file with one link, owned by root or by you, and not group or world writable (fix: chmod g-w,o-w ${SL_LIB})"
fi
SL_P="$SL_DIR"
while :; do
    [ ! -L "$SL_P" ] || sl_fail "${SL_P} is a symlink"
    SL_PO="$(/usr/bin/stat -c %u -- "$SL_P")"
    SL_PM="$(/usr/bin/stat -c %a -- "$SL_P")"
    if [ "$SL_UID" -eq 0 ]; then  # as root: root-owned and closed to group and others, all the way up
        { [ "$SL_PO" = 0 ] && [ $((8#$SL_PM & 8#022)) -eq 0 ]; } ||
            sl_fail "${SL_P} (or a directory above it) is not root-owned or is group or world writable"
    else  # root or you; world write only on a sticky directory (/tmp)
        { [ "$SL_PO" = 0 ] || [ "$SL_PO" = "$SL_UID" ]; } &&
            { [ $((8#$SL_PM & 8#002)) -eq 0 ] || [ $((8#$SL_PM & 8#1000)) -ne 0 ]; } ||
            sl_fail "${SL_P} (or a directory above it) is not owned by root or by you or is world writable"
    fi
    [ "$SL_P" = / ] && break
    SL_P="$(/usr/bin/dirname -- "$SL_P")"
done
# The checks above protect against a new open for writing (mode), a replaced or swapped path (the
# descriptor) and a planted ancestor. They cannot revoke a descriptor a peer already holds open for
# writing on this inode, and nothing here can: this only NARROWS that window. The file is read twice
# from the open inode (the second time through a fresh open of the same descriptor, from offset 0),
# size, mtime and ctime (nanoseconds) and device:inode are compared before and after, the two reads
# must match byte for byte, the byte count must equal the size, and the first copy is sourced, never
# the live inode. Not detected: a write before the first read, or a write between the reads that is
# put back before the second. The real protection is a root-owned release tree (docs/container-engine.md,
# runbook step 0a); running from a group-shared checkout accepts that residual risk.
# stat's %.9Y is GNU coreutils precision syntax (VERIFIED by running stat 9.7 here; INFERRED for the box).
SL_FMT='%s %.9Y %.9Z %d:%i'
SL_ST1="$(/usr/bin/stat -L -c "$SL_FMT" -- /proc/self/fd/7)" || sl_fail "it cannot be examined"
SL_SNAP="$(/bin/cat <&7 && printf x)" || sl_fail "it cannot be read"
SL_SNAP2="$(/bin/cat < /proc/self/fd/7 && printf x)" || sl_fail "it cannot be read a second time"
SL_ST2="$(/usr/bin/stat -L -c "$SL_FMT" -- /proc/self/fd/7)" || sl_fail "it cannot be examined"
exec 7<&-
SL_SNAP="${SL_SNAP%x}"
SL_SNAP2="${SL_SNAP2%x}"
{ [ "$SL_ST1" = "$SL_ST2" ] && [ "$SL_SNAP" = "$SL_SNAP2" ]; } || sl_fail "it changed while it was being read"
SL_SIZE="${SL_ST1%% *}"
SL_LEN="$(LC_ALL=C; echo "${#SL_SNAP}")"  # bytes, not characters
{ [ "$SL_SIZE" -gt 0 ] && [ "$SL_LEN" = "$SL_SIZE" ]; } ||
    sl_fail "it is empty or its content length (${SL_LEN} bytes) differs from its size (${SL_SIZE} bytes)"
# shellcheck source=scripts/lib-secrets.sh
source <(printf '%s' "$SL_SNAP")
is_placeholder() { secret_is_placeholder "$1"; }

bad=0
for var in "${REQUIRED[@]}"; do
    line="$(grep -E "^${var}=" <<<"$content" | tail -1 || true)"
    value="${line#*=}"
    value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
    if [ -z "$line" ] || [ -z "$value" ]; then
        echo "check-env: ${var} is missing or empty" >&2
        bad=1
    elif is_placeholder "$value"; then
        echo "check-env: ${var} still has a placeholder or known default value" >&2
        bad=1
    fi
done

# The Grafana to n8n webhook secret (docs/update-alerting.md) also needs a
# minimum length. Docker Compose reads the same .env file, but Compose, a shell
# that sources the file and an editor can each read an unusual line differently.
# So only the plain `NAME=value` form is measured, and every other form of an
# assignment to this variable is rejected: an `export` prefix, indentation,
# whitespace before the equals sign, a carriage return (a CRLF file), a
# duplicate in any of those forms, and an assignment that sits inside another
# variable's multi-line quoted value. For the plain form the value is parsed the
# way Compose parses it: an unquoted value ends at whitespace followed by '#',
# matching single or double quotes are removed, and the quoted text may be
# followed by a comment. Anything ambiguous (an unmatched quote, a backslash, a
# '$' Compose would interpolate) is rejected. The parsed value must be
# non-empty, not whitespace-only, not a placeholder and at least 32 characters.
# It is never printed.
var=GRAFANA_WEBHOOK_SECRET
qc="[\"']"
re_any="^[[:space:]]*(export[[:space:]]+)?${var}[[:space:]]*="
re_open="^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*(${qc})(.*)\$"
cr=$'\r'
count=0
line=""
odd_form=0
multiline=0
while IFS= read -r raw || [ -n "$raw" ]; do
    if [[ "$raw" =~ $re_any ]]; then
        count=$((count + 1))
        line="$raw"
        case "$raw" in "${var}="[![:space:]]* | "${var}=") ;; *) odd_form=1 ;; esac
        case "$raw" in *"$cr"*) odd_form=1 ;; esac
    elif [[ "$raw" =~ $re_open ]]; then
        # Another variable's value opens a quote it does not close on the same line,
        # or hides a quote behind a backslash. Quote counting cannot be trusted
        # there, so the webhook line cannot be told apart from the value's text:
        # refuse the whole file for this variable.
        q="${BASH_REMATCH[2]}"
        tail_text="${BASH_REMATCH[3]}"
        stripped="${tail_text//[^$q]/}"
        if [ $(( ${#stripped} % 2 )) -eq 0 ]; then multiline=1; fi
        case "$tail_text" in *\\\"* | *\\\'*) multiline=1 ;; esac
    fi
done <<<"$content"
rest="${line#*=}"
rest="${rest#"${rest%%[![:space:]]*}"}"
re_dq='^"([^"\\]*)"([[:space:]]+#.*)?[[:space:]]*$'
re_sq="^'([^']*)'([[:space:]]+#.*)?[[:space:]]*\$"
parsed=""
single=0
parse_ok=1
case "$rest" in
    \"*)
        if [[ "$rest" =~ $re_dq ]]; then parsed="${BASH_REMATCH[1]}"; else parse_ok=0; fi ;;
    \'*)
        if [[ "$rest" =~ $re_sq ]]; then parsed="${BASH_REMATCH[1]}"; single=1; else parse_ok=0; fi ;;
    *)
        parsed="${rest%%[[:space:]]#*}"
        case "$rest" in "#"*) parsed="" ;; esac
        parsed="${parsed%"${parsed##*[![:space:]]}"}"
        case "$parsed" in *\"* | *\'*) parse_ok=0 ;; esac ;;
esac
trimmed="$(printf '%s' "$parsed" | tr -d '[:space:]')"
unsafe=0
case "$parsed" in
    *\\* | *$'\r'*) unsafe=1 ;;
    *\$*) [ "$single" -eq 0 ] && unsafe=1 ;;
esac
if [ -z "$line" ] || { [ "$parse_ok" -eq 1 ] && [ -z "$trimmed" ]; }; then
    echo "check-env: ${var} is missing, empty or only whitespace" >&2
    bad=1
elif [ "$count" -gt 1 ]; then
    echo "check-env: ${var} is assigned more than once (or inside a multi-line quoted value); keep exactly one plain NAME=value assignment" >&2
    bad=1
elif [ "$multiline" -eq 1 ]; then
    echo "check-env: the file has a multi-line or backslash-escaped quoted value, so ${var} cannot be told apart from its text; keep every value on one line" >&2
    bad=1
elif [ "$odd_form" -eq 1 ]; then
    echo "check-env: ${var} must be one plain NAME=value line: no export prefix, no space around the name or on either side of the equals sign, no carriage return (convert CRLF to LF)" >&2
    bad=1
elif [ "$parse_ok" -eq 0 ]; then
    echo "check-env: ${var} has an unmatched quote or a quote inside an unquoted value" >&2
    bad=1
elif [ "$unsafe" -eq 1 ]; then
    echo "check-env: ${var} must not contain a backslash, carriage return or an unquoted dollar sign" >&2
    bad=1
elif ! [[ "$parsed" =~ ^[A-Za-z0-9+/=_.,:@%^-]*$ ]]; then
    echo "check-env: ${var} may use only letters, digits and + / = _ . , : @ % ^ - (no space, quote, backtick, redirect, semicolon or other shell character); generate it with: openssl rand -base64 32" >&2
    bad=1
elif is_placeholder "$trimmed"; then
    echo "check-env: ${var} still has a placeholder or known default value" >&2
    bad=1
elif [ "${#parsed}" -lt 32 ]; then
    echo "check-env: ${var} must be at least 32 characters (generate it with: openssl rand -base64 32)" >&2
    bad=1
fi

if [ "$bad" -ne 0 ]; then
    echo "check-env: set strong unique values in $ENV_FILE (see README, Required secrets)" >&2
    exit 1
fi
echo "check-env: all required secrets are set and none is a known default"

# Not an error: loopback ingest is the safe default. But on an upgraded stack it
# silently stops log intake from firewalls, sensors and agents on other hosts.
ingest="$(grep -E '^INGEST_BIND_ADDR=' <<<"$content" | tail -1 | cut -d= -f2- || true)"
ingest="${ingest%\"}"; ingest="${ingest#\"}"; ingest="${ingest%\'}"; ingest="${ingest#\'}"
case "$ingest" in
    "" | 127.* | localhost | ::1)
        echo "check-env: WARNING: INGEST_BIND_ADDR is unset or loopback, so syslog, EVE, Beats, Wazuh agents and Telegraf from other hosts cannot reach this stack. Set INGEST_BIND_ADDR in $ENV_FILE to this host's interface address (see README, Network exposure)." >&2
        ;;
esac
