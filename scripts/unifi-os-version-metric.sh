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
# or not understood (no unifi service block, not exactly one Status line in it, not exactly one
# top-level version member, a value that is not digits and dots). That is not an error: it is never guessed.
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
# and, in that line's JSON object, exactly one TOP-LEVEL member named version holding a strict version
# string (see top_version); anything else is "unknown". Prints one word.
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
    rest=${status_line#"Status:"}
    rest=${rest#"${rest%%[!"$ws"]*}"}
    # Hard cap on what the walker is fed: the shell walks one character at a time, so its time grows
    # with the square of the size. A real Status object is a few hundred bytes.
    if [ "${#rest}" -gt 2048 ]; then net_cap "status JSON is over 2048 bytes"; return 0; fi # MUTATE:net-json-cap
    top_version "$rest"
}

# Strict reader of one JSON object text. Prints the value of the TOP-LEVEL (depth 1) member named
# version when there is exactly one such member and its value is a string holding a strict version;
# otherwise prints unknown. Brackets nested inside values and string contents (with backslash escapes)
# are tracked, so a version key in a nested object or inside a string is never taken. Any text outside
# the one object, or an unexpected token in a member position, gives unknown.
top_version() {
    js=$1
    depth=0
    instr=0
    esc=0
    uhex=0
    cur=""
    st=k
    pv=0
    nv=0
    ver=""
    done_obj=0
    while [ -n "$js" ]; do
        rest_js=${js#?}
        c=${js%"$rest_js"}
        js=$rest_js
        top=0
        [ "$depth" -eq 1 ] && top=1 # MUTATE:net-depth
        if [ "$instr" -eq 1 ]; then
            if [ "$uhex" -gt 0 ]; then
                # four hex digits after \u
                case "$c" in
                    [0-9A-Fa-f]) uhex=$((uhex - 1)); cur="$cur$c" ;;
                    *) echo unknown; return 0 ;;
                esac
            elif [ "$esc" -eq 1 ]; then
                esc=0
                case "$c" in
                    '"' | "\\" | "/" | b | f | n | r | t) ;;
                    u) uhex=4 ;;
                    *) echo unknown; return 0 ;; # MUTATE:net-escape
                esac
                cur="$cur$c"
            else
                case "$c" in
                    "\\") esc=1; cur="$cur$c" ;;
                    '"')
                        instr=0
                        if [ "$top" -eq 1 ]; then
                            case "$st" in
                                K)
                                    st=c
                                    pv=0
                                    [ "$cur" != version ] || pv=1
                                    ;;
                                V)
                                    st=o
                                    if [ "$pv" -eq 1 ]; then nv=$((nv + 1)); ver=$cur; pv=0; fi
                                    ;;
                            esac
                        fi
                        ;;
                    *) cur="$cur$c" ;;
                esac
            fi
            continue
        fi
        case "$c" in
            " " | "$tab") continue ;;
        esac
        if [ "$done_obj" -eq 1 ]; then echo unknown; return 0; fi
        if [ "$depth" -eq 0 ]; then
            if [ "$c" != "{" ]; then echo unknown; return 0; fi
            depth=1
            st=k
            continue
        fi
        if [ "$top" -eq 1 ]; then
            case "$st" in
                k | m)
                    # k: right after the opening brace (a key or the closing brace);
                    # m: right after a comma (a key only, so no leading, doubled or trailing comma)
                    case "$c" in
                        '"') instr=1; cur=""; st=K; continue ;;
                        "}") [ "$st" = k ] || { echo unknown; return 0; } ;;
                        *) echo unknown; return 0 ;;
                    esac
                    ;;
                c)
                    if [ "$c" != ":" ]; then echo unknown; return 0; fi
                    st=v
                    continue
                    ;;
                v)
                    case "$c" in
                        '"') instr=1; cur=""; st=V; continue ;;
                        "," | "}") echo unknown; return 0 ;;
                    esac
                    # a value that is not a string: a version member holding one is not accepted
                    if [ "$pv" -eq 1 ]; then nv=$((nv + 1)); ver=""; pv=0; fi
                    st=o
                    ;;
                o)
                    case "$c" in
                        ",") st=m; continue ;; # MUTATE:net-comma
                    esac
                    ;;
            esac
        fi
        case "$c" in
            "{" | "[") depth=$((depth + 1)) ;;
            "}" | "]")
                depth=$((depth - 1))
                if [ "$depth" -lt 0 ]; then echo unknown; return 0; fi
                if [ "$depth" -eq 0 ]; then
                    if [ "$c" != "}" ]; then echo unknown; return 0; fi
                    done_obj=1
                fi
                ;;
            '"') instr=1; cur="" ;;
        esac
    done
    if [ "$done_obj" -ne 1 ] || [ "$instr" -ne 0 ] || [ "$depth" -ne 0 ]; then echo unknown; return 0; fi
    if [ "$nv" -ne 1 ]; then echo unknown; return 0; fi # MUTATE:net-version-count
    if valid_ver "$ver"; then echo "$ver"; else echo unknown; fi
}

# A failed or hung status command, an oversized output or a missing marker all mean "unknown".
net_ver=$({
    run_uos status
    printf '\nUOS_RC=%s\n' "$?"
} | bounded_read 1048577 | "$tr_bin" '\000' '?' | net_version) || net_ver=unknown # MUTATE:status-bound
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
