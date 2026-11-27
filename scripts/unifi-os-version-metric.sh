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
# plus id, date, head, tr, timeout and env. It REFUSES TO RUN AS ROOT (uid 0): it executes the vendor
# CLI by a fixed path, and root must never run a binary this script cannot vouch for. Run it as an
# ordinary user that can run `uosserver version` and `uosserver status`. It never uses sudo.
# The raw output of either command is never printed, on success or on failure.
#
# Success (exit 0), one line:
#   unifi_os_version,host=<label> os_version="5.1.42",network_version="10.6.109",collected_ts=<n>i,result="ok"
# network_version is "unknown" and result is "network_unknown" when the Network app version is missing
# or not understood (no unifi service block, not exactly one Status line in it, a Status value that is
# not an object whose FIRST member is "version" with a strict version string). That is not an error:
# it is never guessed. Only that first member is read; the rest of the JSON is not validated.
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
id_bin=/usr/bin/id
cmd_timeout=20
# Extra seconds the reader of a command's output waits after the command's own limit (the 5 second
# kill grace included in that). A descendant that detached from the process group and still holds the
# pipe cannot keep this script alive past cmd_timeout + reader_slack.
reader_slack=10

nl='
'
tab=$(printf '\t')
cr=$(printf '\r')
ws=" $tab$cr"
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

# ---------------------------------------------------------------- never root
me=$("$id_bin" -u 2>/dev/null) || fail "cannot determine the user id"
case "$me" in
    "" | *[!0-9]* | 0?* | ???????????*) fail "unexpected user id" ;;
esac
[ "$me" != "0" ] || fail "refusing to run as root (uid 0); use an ordinary user that can run uosserver" # MUTATE:root

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

# The reader of a command's output: at most $1 bytes, and never longer than the command's own limit
# plus reader_slack seconds. A descendant that escaped the process group and still holds the pipe
# open would otherwise keep this script (and the cron run) waiting for end of file.
bounded_read() {
    "$timeout_bin" -k 2 "$((cmd_timeout + reader_slack))" "$head_bin" -c "$1" # MUTATE:reader-bound
}

[ -x "$uos_bin" ] || fail "uosserver not found"

# ---------------------------------------------------------------- OS version (fatal when not understood)
# The exit status travels in a last marker line; the output is cut at 128 bytes while it is read, so
# an oversized output loses its marker and fails. A NUL byte becomes "?" and fails the strict check.
os_raw=$({
    run_uos version
    printf '\nUOS_RC=%s\n' "$?"
} | bounded_read 128 | "$tr_bin" '\000' '?')
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
# and its value must be an object whose FIRST member is "version" with a strict version string; nothing
# after that member is read or validated (display only). Anything else is "unknown". Prints one word.
# A bound was hit: a fixed reason on stderr (never any status text) and an unknown Network version.
net_cap() {
    echo "unifi-os-version-metric: $1; Network version unknown" >&2
    echo unknown
}

net_version() {
    in_block=0
    n_status=0
    status_line=""
    n_lines=0
    last=""
    while IFS= read -r line; do
        n_lines=$((n_lines + 1))
        if [ "$n_lines" -gt 20000 ]; then net_cap "status output has too many lines"; return 0; fi
        if [ "${#line}" -gt 8192 ]; then net_cap "a status line is over 8192 bytes"; return 0; fi # MUTATE:net-line-cap
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
    # The Network version is trusted ONLY when the Status value starts with an opening brace and its
    # FIRST member is "version" with a plain string value that passes the strict version check, directly
    # followed by a comma or the closing brace. Nothing after that point is read or validated, and any
    # other shape (version not first, an escaped name, a nested version, extra text before the brace)
    # is unknown. The value is for display only: no decision depends on it.
    rest=${status_line#"Status:"}
    rest=${rest#"${rest%%[!"$ws"]*}"}
    case "$rest" in
        "{"*) rest=${rest#"{"} ;;
        *) net_cap "the Status value does not start with an opening brace"; return 0 ;; # MUTATE:net-brace
    esac
    rest=${rest#"${rest%%[!"$ws"]*}"}
    case "$rest" in
        '"version"'*) rest=${rest#'"version"'} ;;
        *) net_cap "the first member of the Status object is not version"; return 0 ;; # MUTATE:net-first
    esac
    rest=${rest#"${rest%%[!"$ws"]*}"}
    case "$rest" in
        ":"*) rest=${rest#:} ;;
        *) net_cap "no colon after the version name"; return 0 ;;
    esac
    rest=${rest#"${rest%%[!"$ws"]*}"}
    case "$rest" in
        '"'*) rest=${rest#'"'} ;;
        *) net_cap "the version value is not a string"; return 0 ;;
    esac
    case "$rest" in
        *'"'*)
            v=${rest%%'"'*}
            rest=${rest#*'"'}
            ;;
        *) net_cap "the version string is not closed"; return 0 ;;
    esac
    if ! valid_ver "$v"; then net_cap "the version value is not a strict version"; return 0; fi
    case "$rest" in
        "," | ","* | "}" | "}"*) ;;
        *) net_cap "the version member is not followed by a comma or a closing brace"; return 0 ;; # MUTATE:net-delim
    esac
    echo "$v"
}

# A failed or hung status command, an oversized output or a missing marker all mean "unknown".
net_ver=$({
    run_uos status
    printf '\nUOS_RC=%s\n' "$?"
} | bounded_read 1048577 | "$tr_bin" '\000' '\001' | net_version) || net_ver=unknown # MUTATE:status-bound
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
