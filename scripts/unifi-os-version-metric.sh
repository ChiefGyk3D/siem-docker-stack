#!/bin/sh
# unifi-os-version-metric.sh - print the installed UniFi OS Server version and the UniFi Network
# app version as one InfluxDB line protocol line. Issue #244 (epic #62, parent #219).
#
# Usage: HOST_LABEL=<label> unifi-os-version-metric.sh
#        unifi-os-version-metric.sh <label>
#
# This reports VERSIONS ONLY. The uosserver CLI has no update-available signal, so this never says
# an update is or is not pending and it never pages; the digest shows the versions with a reminder
# to check for updates in the UI. See docs/unifi-os-version-collector.md.
#
# READ-ONLY. The only commands it runs, with a fixed environment (env -i PATH=/usr/bin:/bin
# LC_ALL=C), no stdin and a hard time limit each:
#   uosserver version   -> the OS version; ONLY a strict string of digits and dots is accepted
#   uosserver status    -> read ONLY for the version field of the unifi service Status JSON
# plus date, head, tr, timeout and env. It runs as the owner's user or as root; it never uses sudo.
# The raw output of either command is never printed, on success or on failure.
#
# Success (exit 0), one line:
#   unifi_os_version,host=<label> os_version="5.1.42",network_version="10.6.109",collected_ts=<n>i,result="ok"
# network_version is "unknown" and result is "network_unknown" when the Network app version is missing
# or not understood (no unifi service block, not exactly one Status line in it, not exactly one quoted
# version field, a value that is not digits and dots). That is not an error: it is never guessed.
#
# Failure (the OS version cannot be read or is not a strict version string, a time limit, a missing
# command, a bad label, a failed write): NOTHING on stdout, a short fixed reason on stderr, exit 1.
#
# There are no test hooks: every path and limit below is a fixed constant. The tests rewrite the
# constant lines in a scratch copy of this file.

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

# Absolute command paths and limits (rewritten by the tests only).
uos_bin=/usr/local/bin/uosserver
env_bin=/usr/bin/env
timeout_bin=/usr/bin/timeout
head_bin=/usr/bin/head
tr_bin=/usr/bin/tr
date_bin=/usr/bin/date
cmd_timeout=20

nl='
'
tab=$(printf '\t')
ws=" $tab"
finished=0

fail() {
    finished=1
    echo "unifi-os-version-metric: $1" >&2
    exit 1
}

# Any exit that did not go through fail() or the success path (a signal, a shell error) still exits
# non-zero with nothing on stdout (nothing is printed to stdout before the final checked write).
trap 'if [ "$finished" -ne 1 ]; then finished=1; echo "unifi-os-version-metric: internal error" >&2; exit 1; fi' EXIT
trap 'exit 1' HUP INT TERM

# ---------------------------------------------------------------- label
label=${HOST_LABEL-}
if [ "$#" -gt 1 ]; then fail "usage: unifi-os-version-metric.sh [label]"; fi
if [ "$#" -eq 1 ]; then
    if [ -n "$label" ] && [ "$label" != "$1" ]; then fail "HOST_LABEL and the label argument differ"; fi
    label=$1
fi
# The label is never derived from the real hostname.
[ -n "$label" ] || fail "HOST_LABEL is required"
[ "${#label}" -le 32 ] || fail "label too long"
case "$label" in
    [!A-Za-z0-9]* | *[!A-Za-z0-9_-]*) fail "label has unexpected characters" ;;
esac

# ---------------------------------------------------------------- version strings
# A strict version: digits and dots only, starting and ending with a digit, no empty component,
# at most 32 characters.
valid_ver() {
    if [ -z "$1" ] || [ "${#1}" -gt 32 ]; then return 1; fi
    case "$1" in *[!0-9.]*) return 1 ;; esac # MUTATE:charset
    case "$1" in
        [!0-9]* | *[!0-9] | *..*) return 1 ;;
    esac
    return 0
}

# Run one uosserver subcommand: fixed environment, no stdin, no stderr, hard time limit (a child that
# holds the pipe is killed with the group).
run_uos() {
    "$timeout_bin" -k 5 "$cmd_timeout" "$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C "$uos_bin" "$1" </dev/null 2>/dev/null # MUTATE:run-cmd
}

[ -x "$uos_bin" ] || fail "uosserver not found"

# ---------------------------------------------------------------- OS version (fatal when not understood)
# The exit status travels in a last marker line; the output is cut at 128 bytes while it is read, so
# an oversized output loses its marker and fails. A NUL byte becomes "?" and fails the strict check.
os_raw=$({
    run_uos version
    printf '\nUOS_RC=%s\n' "$?"
} | "$head_bin" -c 128 | "$tr_bin" '\000' '?')
os_rc=${os_raw##*"$nl"}
[ "$os_rc" = "UOS_RC=0" ] || fail "uosserver version failed or its output is not understood" # MUTATE:os-rc
os_ver=${os_raw%"$nl"*}
while :; do
    case "$os_ver" in
        *"$nl") os_ver=${os_ver%"$nl"} ;;
        *) break ;;
    esac
done
valid_ver "$os_ver" || fail "uosserver version is not a strict version string"

# ---------------------------------------------------------------- Network app version (never fatal)
# From the Status line of the unifi service block only. Block headers are the first word of a line
# (or the second, after a bullet) ending in .service. Exactly one Status line in the unifi block(s)
# and exactly one quoted "version" field in it; anything else is "unknown". Prints one word.
net_version() {
    in_block=0
    n_status=0
    status_line=""
    n_lines=0
    last=""
    while IFS= read -r line; do
        n_lines=$((n_lines + 1))
        if [ "$n_lines" -gt 20000 ]; then
            echo unknown
            return 0
        fi
        last=$line
        t=${line#"${line%%[!"$ws"]*}"}
        w1=${t%%["$ws"]*}
        case "$w1" in
            [A-Za-z0-9]*) tok=$w1 ;;
            *)
                r=${t#"$w1"}
                r=${r#"${r%%[!"$ws"]*}"}
                tok=${r%%["$ws"]*}
                ;;
        esac
        case "$tok" in
            unifi.service) in_block=1 ;;
            *.service) in_block=0 ;; # MUTATE:net-block-scope
        esac
        if [ "$in_block" -eq 1 ]; then
            case "$t" in
                "Status:"*)
                    n_status=$((n_status + 1))
                    status_line=$t
                    ;;
            esac
        fi
    done
    if [ "$last" != "UOS_RC=0" ]; then
        echo unknown
        return 0
    fi
    if [ "$n_status" -ne 1 ]; then echo unknown; return 0; fi # MUTATE:net-status-count
    rest=$status_line
    first=""
    n_ver=0
    while :; do
        case "$rest" in
            *'"version"'*)
                n_ver=$((n_ver + 1))
                rest=${rest#*'"version"'}
                if [ "$n_ver" -eq 1 ]; then first=$rest; fi
                ;;
            *) break ;;
        esac
    done
    if [ "$n_ver" -ne 1 ]; then echo unknown; return 0; fi # MUTATE:net-version-count
    v=${first#"${first%%[!"$ws"]*}"}
    case "$v" in
        :*) v=${v#:} ;;
        *)
            echo unknown
            return 0
            ;;
    esac
    v=${v#"${v%%[!"$ws"]*}"}
    case "$v" in
        '"'*) v=${v#'"'} ;;
        *)
            echo unknown
            return 0
            ;;
    esac
    case "$v" in
        *'"'*) v=${v%%'"'*} ;;
        *)
            echo unknown
            return 0
            ;;
    esac
    if valid_ver "$v"; then echo "$v"; else echo unknown; fi
}

# A failed or hung status command, an oversized output or a missing marker all mean "unknown".
net_ver=$({
    run_uos status
    printf '\nUOS_RC=%s\n' "$?"
} | "$head_bin" -c 1048577 | "$tr_bin" '\000' '?' | net_version) || net_ver=unknown # MUTATE:status-bound
[ -n "$net_ver" ] || net_ver=unknown

# ---------------------------------------------------------------- output
now=$("$date_bin" +%s 2>/dev/null) || fail "date failed"
case "$now" in
    "" | 0* | *[!0-9]*) fail "non-numeric time" ;;
esac
result=ok
[ "$net_ver" != unknown ] || result=network_unknown
# The whole line is built first and written in one checked step; a failed write exits non-zero.
payload=$(printf 'unifi_os_version,host=%s os_version="%s",network_version="%s",collected_ts=%si,result="%s"' \
    "$label" "$os_ver" "$net_ver" "$now" "$result") || fail "cannot build the output"
trap '' HUP INT TERM
if ! printf '%s\n' "$payload"; then exit 1; fi # MUTATE:output-check
finished=1
exit 0
