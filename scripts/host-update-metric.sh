#!/bin/sh
# host-update-metric.sh - print pending OS updates of a Debian-family host as InfluxDB line
# protocol. Issue #219. Same contract and fail-closed style as pfsense-update-metric.sh.
#
# Usage: HOST_LABEL=<label> host-update-metric.sh [--max-lists-age-days=N] <critical|standard>
#        host-update-metric.sh [--max-lists-age-days=N] <critical|standard> <label>
# N is a whole number from 1 to 30 (default 3): the oldest apt package lists the check accepts.
#
# READ-ONLY and UNPRIVILEGED. It never runs apt update, never opens the network, never uses sudo.
# The only commands that look at the host are:
#   env -i PATH=/usr/bin:/bin LC_ALL=C APT_CONFIG=/dev/null /usr/bin/apt-get -s
#       -o Debug::NoLocking=1 dist-upgrade   (simulation; no caller APT_* or DPKG_* variable reaches it)
#   test -e /var/run/reboot-required
#   a bounded read of /var/log/unattended-upgrades/unattended-upgrades.log (and its .1)
#   stat of /var/lib/apt/periodic/update-success-stamp and of the InRelease/Release files in /var/lib/apt/lists
# plus date, stat, id, head, tail, grep, timeout, env, mv and chmod on its own private state directory.
# It refuses to run as uid 0.
#
# Success (exit 0), tags host=<label>,tier=<tier> on every line:
#   host_update_pending,kind=package,security=false value=<n>i   (non-security packages)
#   host_update_pending,kind=package,security=true value=<n>i    (security packages)
#   host_update_held_back value=<n>i                             (apt "not upgraded" count; also in pending, non-security)
#   host_reboot_required value=0i|1i
#   host_update_lists_age_seconds value=<n>i                     (older of the update stamp and the oldest security list)
#   host_unattended_last_run_age_seconds value=<n>i
#   host_update_oldest_pending_age_seconds value=<n>i            (only when state_ok is 1)
#   host_update_state_ok value=1i|0i
#   host_update_check_success value=1i
#
# Failure (anything below is not understood or not readable, including an unattended-upgrades age
# that cannot be determined, or apt lists that are missing or older than the maximum): prints only `host_update_check_success value=0i` (with the tags when
# label and tier are valid) and exits 1; an EXIT trap prints it too on any unexpected internal
# error. Zero-valued update metrics are never printed after a
# failure, so a broken check cannot look healthy.
#
# The first-seen state is separate: if it is lost, unreadable, owned by someone else, has the wrong
# mode or is corrupt, the check itself still succeeds, host_update_state_ok is 0 and NO oldest-age
# metric is printed (never a 0 age). See docs/host-update-collector.md.
#
# There are no test hooks: every path below is fixed. The tests rewrite the fixed default lines in a
# scratch copy of this file. The state directory is $STATE_DIRECTORY (set by systemd), else
# ${XDG_STATE_HOME:-$HOME/.local/state}/host-update-metric.

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

nl='
'
tags=""
finished=0

fail() {
    finished=1
    echo "host-update-metric: $1" >&2
    printf 'host_update_check_success%s value=0i\n' "$tags"
    exit 1
}

# Any exit that did not go through fail() or the success path (a shell arithmetic error, a signal)
# still prints the failure line (the EXIT trap below).
trap 'if [ "$finished" -ne 1 ]; then finished=1; echo "host-update-metric: internal error" >&2; printf "host_update_check_success%s value=0i\n" "$tags"; exit 1; fi' EXIT # MUTATE:exit-trap
trap 'exit 1' HUP INT TERM

# Canonical non-negative integer: 0 or [1-9][0-9]*, at most 11 digits. A leading zero would be
# read as octal (or an error) by shell arithmetic.
is_uint() {
    case "$1" in
        0) return 0 ;;
        "" | 0* | *[!0-9]*) return 1 ;; # MUTATE:uint
    esac
    [ "${#1}" -le 11 ]
}

# ---------------------------------------------------------------- arguments
max_days=3
case "${1-}" in
    --max-lists-age-days=*)
        max_days=${1#--max-lists-age-days=}
        shift
        if ! is_uint "$max_days" || [ "$max_days" -lt 1 ] || [ "$max_days" -gt 30 ]; then
            fail "--max-lists-age-days must be a whole number from 1 to 30" # MUTATE:lists-arg
        fi
        ;;
esac
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then fail "usage: host-update-metric.sh [--max-lists-age-days=N] <critical|standard> [label]"; fi
tier=$1
label=${HOST_LABEL-}
if [ "$#" -eq 2 ]; then
    if [ -n "$label" ] && [ "$label" != "$2" ]; then
        fail "HOST_LABEL and the label argument differ"
    fi
    label=$2
fi
case "$tier" in
    critical | standard) ;;
    *) fail "tier must be critical or standard" ;;
esac
# The label is never derived from the real hostname.
[ -n "$label" ] || fail "HOST_LABEL is required"
[ "${#label}" -le 32 ] || fail "label too long"
case "$label" in
    [!A-Za-z0-9]* | *[!A-Za-z0-9_-]*) fail "label has unexpected characters" ;;
esac
tags=",host=$label,tier=$tier"

# Paths are fixed. The tests rewrite these lines in a scratch copy of this script.
id_bin=/usr/bin/id
reboot_file=/var/run/reboot-required
uu_log=/var/log/unattended-upgrades/unattended-upgrades.log
apt_bin=/usr/bin/apt-get
stamp_file=/var/lib/apt/periodic/update-success-stamp
lists_dir=/var/lib/apt/lists

me=$("$id_bin" -u 2>/dev/null) || fail "cannot determine the user id"
is_uint "$me" || fail "unexpected user id"
[ "$me" -ne 0 ] || fail "refusing to run as root (uid 0); use an unprivileged user" # MUTATE:root
now=$(date +%s 2>/dev/null) || fail "date failed"
is_uint "$now" || fail "non-numeric time"

valid_version() {
    # $1 candidate; Debian version characters only
    if [ -z "$1" ] || [ "${#1}" -gt 128 ]; then return 1; fi
    case "$1" in
        *[!A-Za-z0-9.+:~_-]*) return 1 ;; # MUTATE:version-charset
    esac
    return 0
}

abs_path() {
    case "$1" in
        /*) return 0 ;;
    esac
    return 1
}

# ---------------------------------------------------------------- reboot required
[ -d "${reboot_file%/*}/." ] || fail "reboot file directory is not readable"
reboot=0
[ -e "$reboot_file" ] && reboot=1

# ---------------------------------------------------------------- unattended-upgrades age
uu_re='^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} INFO (All upgrades installed|No packages found that can be upgraded unattended and no pending auto-removals)$' # MUTATE:uu-anchor
last=""
for f in "$uu_log" "$uu_log.1"; do # MUTATE:uu-fallback
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then continue; fi
    last=$(tail -c 1048576 "$f" 2>/dev/null | grep -a -E "$uu_re" | tail -n 1)
    if [ -n "$last" ]; then break; fi
done
# An age that cannot be determined is a failure, never 0.
[ -n "$last" ] || fail "no successful unattended-upgrades run found" # MUTATE:unknown-age
stamp=${last%%,*}
case "$stamp" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]) ;;
    *) fail "unparsable unattended-upgrades timestamp" ;;
esac
last_ts=$(date -d "$stamp" +%s 2>/dev/null) || fail "unattended-upgrades timestamp not understood"
is_uint "$last_ts" || fail "non-numeric time"
uu_age=$((now - last_ts))
[ "$uu_age" -ge 0 ] || fail "unattended-upgrades timestamp is in the future"

# ---------------------------------------------------------------- apt list freshness
# This script never refreshes the lists, so stale, empty or wiped lists would report "nothing
# pending". Two things are both required: the apt update success stamp, and at least one non-empty,
# non-symlink InRelease or Release file. The list age is the OLDEST such file of the security
# archives (a suite ending in -security, read from the file name); if there is none, the oldest of
# all InRelease/Release files. One fresh third-party list therefore cannot hide a stale security
# list. The reported age is the older of the stamp and that list age. Anything over the maximum, a
# missing stamp or a missing list, or an mtime more than 1 day in the future, fails the check.
stamp_m=""
if [ -f "$stamp_file" ] && [ ! -L "$stamp_file" ]; then # MUTATE:stamp-symlink
    stamp_m=$(stat -c %Y "$stamp_file" 2>/dev/null) || stamp_m=""
    is_uint "$stamp_m" || stamp_m=""
fi
[ -n "$stamp_m" ] || fail "apt success stamp missing or unreadable" # MUTATE:stamp-required
[ "$stamp_m" -le $((now + 86400)) ] || fail "apt stamp is more than 1 day in the future" # MUTATE:stamp-future
oldest_sec=""
oldest_all=""
for f in "$lists_dir"/*_Release "$lists_dir"/*_InRelease; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi # MUTATE:lists-symlink
    [ -s "$f" ] || continue # MUTATE:lists-nonempty
    m=$(stat -c %Y "$f" 2>/dev/null) || continue
    is_uint "$m" || continue
    [ "$m" -le $((now + 86400)) ] || fail "an apt list file is more than 1 day in the future" # MUTATE:lists-future
    if [ -z "$oldest_all" ] || [ "$m" -lt "$oldest_all" ]; then oldest_all=$m; fi # MUTATE:lists-oldest
    case "$f" in
        *-security_InRelease | *-security_Release)
            if [ -z "$oldest_sec" ] || [ "$m" -lt "$oldest_sec" ]; then oldest_sec=$m; fi # MUTATE:lists-oldest-sec
            ;;
    esac
done
[ -n "$oldest_all" ] || fail "no usable apt InRelease or Release file found" # MUTATE:lists-missing
list_m=$oldest_all
[ -z "$oldest_sec" ] || list_m=$oldest_sec # MUTATE:lists-security
[ "$stamp_m" -lt "$list_m" ] && list_m=$stamp_m
lists_age=$((now - list_m))
[ "$lists_age" -ge 0 ] || lists_age=0 # MUTATE:lists-clamp
[ "$lists_age" -le $((max_days * 86400)) ] || fail "apt package lists are older than $max_days days" # MUTATE:lists-stale

# ---------------------------------------------------------------- apt simulation
abs_path "$apt_bin" || fail "apt-get path must be absolute" # MUTATE:apt-abs
[ -x "$apt_bin" ] || fail "apt-get not found"
# No caller APT_* or DPKG_* variable reaches apt. The exit status travels in a last marker line and
# the output is bounded (4 MiB) while it is read, so a huge output never sits in memory.
apt_out=$({
    timeout -k 10 120 env -i PATH=/usr/bin:/bin LC_ALL=C APT_CONFIG=/dev/null "$apt_bin" -s -o Debug::NoLocking=1 dist-upgrade </dev/null 2>/dev/null # MUTATE:apt-env
    printf '\nAPT_RC=%s\n' "$?"
} | head -c 4194305) # MUTATE:apt-bound
apt_rc=${apt_out##*"$nl"}
[ "$apt_rc" = "APT_RC=0" ] || fail "apt-get simulation failed or its output is too large" # MUTATE:apt-rc
apt_out=${apt_out%"$nl"*}

pend_sec=0
pend_other=0
n_inst=0
n_lines=0
summary_total=""
n_held=0
keys=""
held_names=""
n_held_names=0
in_kept=0
while IFS= read -r line; do
    n_lines=$((n_lines + 1))
    [ "$n_lines" -le 50000 ] || fail "apt-get output has too many lines" # MUTATE:line-cap
    case "$line" in
        "The following packages have been kept back:") in_kept=1 ;;
        "  "*)
            if [ "$in_kept" -eq 1 ]; then
                # held-back package names: validated, deduplicated, bounded
                set -f
                # shellcheck disable=SC2086 # intentional split on blanks, globbing is off
                for hn in $line; do
                    [ "${#hn}" -le 128 ] || fail "bad held-back package name length"
                    case "$hn" in
                        [!a-z0-9]* | *[!a-z0-9+.:-]*) fail "unexpected characters in held-back package name" ;; # MUTATE:held-charset
                    esac
                    case "$nl$held_names" in
                        *"$nl$hn$nl"*) fail "duplicate held-back package" ;;
                    esac
                    held_names="$held_names$hn$nl"
                    n_held_names=$((n_held_names + 1))
                    [ "$n_held_names" -le 1000 ] || fail "too many held-back packages"
                done
                set +f
            fi
            ;;
        "Inst "*)
            in_kept=0
            n_inst=$((n_inst + 1))
            [ "$n_inst" -le 1000 ] || fail "too many pending packages" # MUTATE:inst-cap
            rest=${line#Inst }
            name=${rest%% *}
            [ "$name" != "$rest" ] || fail "malformed Inst line"
            if [ -z "$name" ] || [ "${#name}" -gt 128 ]; then fail "bad package name length"; fi
            case "$name" in
                [!a-z0-9]* | *[!a-z0-9+.:-]*) fail "unexpected characters in package name" ;; # MUTATE:name-charset
            esac
            rest=${rest#"$name "}
            case "$rest" in
                "["*"] ("*)
                    old=${rest#\[}
                    old=${old%%\] \(*}
                    valid_version "$old" || fail "bad installed version"
                    rest=${rest#*\] \(}
                    ;;
                "("*) rest=${rest#\(} ;;
                *) fail "malformed Inst line" ;;
            esac
            case "$rest" in
                *")"*) ;;
                *) fail "malformed Inst line" ;;
            esac
            inner=${rest%%\)*}
            after=${rest#*\)}
            case "$after" in
                "") ;;
                " ["*"]")
                    after=${after# \[}
                    after=${after%\]}
                    case "$after" in
                        *[!A-Za-z0-9.+:_\ -]*) fail "bad trailing bracket in Inst line" ;;
                    esac
                    ;;
                *) fail "unexpected text after Inst line" ;;
            esac
            arch=${inner##* }
            case "$arch" in
                "["*"]") ;;
                *) fail "missing architecture" ;;
            esac
            arch=${arch#\[}
            arch=${arch%\]}
            case "$arch" in
                "" | *[!a-z0-9-]*) fail "bad architecture" ;; # MUTATE:arch-charset
            esac
            inner=${inner% *}
            new=${inner%% *}
            origins=${inner#"$new "}
            if [ "$origins" = "$inner" ] || [ -z "$origins" ]; then fail "missing origin"; fi
            valid_version "$new" || fail "bad candidate version"
            # An origin label with unexpected characters is counted as non-security, not a failure.
            # A repository can label itself "security"; that is accepted (see the doc).
            origin_ok=1
            case "$origins" in
                *[!A-Za-z0-9._:/+,\ -]*) origin_ok=0 ;; # MUTATE:origin-label
            esac
            case "$nl$keys" in
                *"$nl$name $new$nl"*) fail "duplicate package in simulation" ;;
            esac
            keys="$keys$name $new$nl"
            # Security by origin: an archive whose label is a security origin and whose suite
            # (the part after the last slash) ends in -security. The package name is never read.
            is_sec=0
            if [ "$origin_ok" -eq 1 ]; then
                oldifs=$IFS
                IFS=,
                set -f
                # shellcheck disable=SC2086 # intentional split on commas, globbing is off
                set -- $origins
                set +f
                IFS=$oldifs
                for o in "$@"; do
                    o=${o# }
                    case "$o" in
                        *:*)
                            org=${o%%:*}
                            suite=${o#*:}
                            suite=${suite##*/}
                            case "$org" in
                                Debian-Security | Ubuntu | UbuntuESM | UbuntuESMApps)
                                    case "$suite" in
                                        *-security) is_sec=1 ;;
                                    esac
                                    ;;
                            esac
                            ;;
                    esac
                done
            fi
            if [ "$is_sec" -eq 1 ]; then
                pend_sec=$((pend_sec + 1))
            else
                pend_other=$((pend_other + 1))
            fi
            ;;
        [0-9]*" upgraded, "*" newly installed, "*" to remove and "*" not upgraded.")
            in_kept=0
            [ -z "$summary_total" ] || fail "two summary lines"
            n_up=${line%% upgraded, *}
            tmp=${line#*" upgraded, "}
            n_new=${tmp%% newly installed, *}
            tmp=${tmp#*" to remove and "}
            n_held=${tmp%" not upgraded."} # MUTATE:held-back
            is_uint "$n_up" || fail "malformed summary line"
            is_uint "$n_new" || fail "malformed summary line"
            is_uint "$n_held" || fail "malformed summary line"
            summary_total=$((n_up + n_new))
            ;;
        "Conf "* | "Remv "* | "Reading "* | "Building "* | "Calculating "* | "NOTE: "* | \
            "The following "* | "Suggested packages:" | "Recommended packages:" | "Use 'apt autoremove' to remove "*)
            in_kept=0
            ;;
        " "* | "") ;;
        *) fail "unrecognized apt-get output" ;;
    esac
done <<EOF
$apt_out
EOF
# The summary line proves the output is complete, and its count must match the Inst lines.
[ -n "$summary_total" ] || fail "apt-get summary line missing" # MUTATE:summary-required
[ "$summary_total" -eq "$n_inst" ] || fail "apt-get summary does not match the Inst lines" # MUTATE:summary-match
# Held-back (kept back) packages are pending, non-security, with their own first-seen clock: state
# keys carry the "held-back:" name prefix, a separate kind. The listed names must not exceed the
# summary count; held packages apt does not list share one "held-back:unlisted" key.
[ "$n_held_names" -le "$n_held" ] || fail "more held-back names than the summary count"
# (with no held-back package the Inst cap above already bounds the state file)
[ "$n_held" -eq 0 ] || [ $((n_inst + n_held)) -le 1000 ] || fail "too many pending packages" # MUTATE:held-cap
pend_other=$((pend_other + n_held)) # MUTATE:held-pending
while IFS= read -r hn; do
    [ -n "$hn" ] || continue
    keys="${keys}held-back:$hn 0$nl" # MUTATE:held-key
done <<EOH
$held_names
EOH
[ "$n_held_names" -ge "$n_held" ] || keys="${keys}held-back:unlisted 0$nl"

# ---------------------------------------------------------------- first-seen state
# Never fails the check; sets state_ok and, only when the state is trustworthy, oldest_age.
state_ok=0
oldest_age=""
state_dir=""
if [ -n "${STATE_DIRECTORY-}" ]; then
    # systemd sets this (StateDirectory=); with several directories it is colon separated.
    state_dir=${STATE_DIRECTORY%%:*}
elif [ -n "${HOME-}" ]; then
    state_dir=${XDG_STATE_HOME:-$HOME/.local/state}/host-update-metric
fi

state_run() {
    abs_path "$state_dir" || return 1 # MUTATE:state-abs
    first_run=0
    if [ -L "$state_dir" ]; then
        return 1
    elif [ ! -e "$state_dir" ]; then
        mkdir -p "$state_dir" 2>/dev/null || return 1
        chmod 700 "$state_dir" 2>/dev/null || return 1
        first_run=1
    fi
    if [ ! -d "$state_dir" ] || [ -L "$state_dir" ]; then return 1; fi
    [ "$(stat -c '%u %a' "$state_dir" 2>/dev/null)" = "$me 700" ] || return 1 # MUTATE:state-dir-mode
    sfile=$state_dir/first-seen
    old_text=""
    seed_only=0
    future=0
    if [ -L "$sfile" ]; then
        return 1
    elif [ -e "$sfile" ]; then
        [ -f "$sfile" ] || return 1
        [ "$(stat -c '%u %a' "$sfile" 2>/dev/null)" = "$me 600" ] || return 1
        size=$(stat -c '%s' "$sfile" 2>/dev/null) || return 1
        is_uint "$size" || return 1
        [ "$size" -le 262144 ] || return 1 # MUTATE:state-size
        header=1
        count=0
        while IFS= read -r l || [ -n "$l" ]; do
            if [ "$header" -eq 1 ]; then
                [ "$l" = "host-update-state v1" ] || return 1 # MUTATE:state-parse
                header=0
                continue
            fi
            count=$((count + 1))
            [ "$count" -le 1000 ] || return 1 # MUTATE:state-count
            s_name=${l%% *}
            s_rest=${l#* }
            [ "$s_name" != "$l" ] || return 1
            s_ver=${s_rest%% *}
            [ "$s_ver" != "$s_rest" ] || return 1
            s_epoch=${s_rest#* }
            case "$s_name" in
                "" | [!a-z0-9]* | *[!a-z0-9+.:-]*) return 1 ;;
            esac
            [ "${#s_name}" -le 128 ] || return 1
            valid_version "$s_ver" || return 1
            is_uint "$s_epoch" || return 1 # MUTATE:state-uint
            # A first-seen time after now (beyond clock jitter) cannot be true: do not trust the file.
            if [ "$s_epoch" -gt $((now + 60)) ]; then future=1; fi # MUTATE:state-future
            case "$nl$old_text" in
                *"$nl$s_name $s_ver "*) return 1 ;;
            esac
            old_text="$old_text$s_name $s_ver $s_epoch$nl"
        done <"$sfile"
        [ "$header" -eq 0 ] || return 1
        if [ "$future" -eq 1 ]; then
            # Forget every stored time and start the clocks again from now; this run reports no age.
            old_text=""
            seed_only=1
        fi
    elif [ "$first_run" -eq 0 ]; then
        # The directory exists but the file is gone: the clock is lost. Re-seed it below, but
        # report state_ok 0 and no age for this run.
        seed_only=1
    fi
    new_text="host-update-state v1$nl"
    oldest=""
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        e=""
        case "$nl$old_text" in
            *"$nl$k "*)
                # Anchored at a line start: the key "foo 2 " must not match inside "libfoo 2 ".
                e=$nl$old_text
                e=${e#*"$nl$k "} # MUTATE:state-anchor
                e=${e%%"$nl"*}
                ;;
        esac
        [ -n "$e" ] || e=$now
        new_text="$new_text$k $e$nl"
        if [ -z "$oldest" ] || [ "$e" -lt "$oldest" ]; then
            oldest=$e
        fi
    done <<EOK
$keys
EOK
    tmpf="$state_dir/.first-seen.$$"
    if ! (
        set -C # MUTATE:noclobber
        printf '%s' "$new_text" >"$tmpf"
    ) 2>/dev/null; then
        rm -f "$tmpf" 2>/dev/null
        return 1
    fi
    if ! chmod 600 "$tmpf" 2>/dev/null || ! mv -f "$tmpf" "$sfile" 2>/dev/null; then
        rm -f "$tmpf" 2>/dev/null
        return 1
    fi
    [ "$seed_only" -eq 0 ] || return 1 # MUTATE:state-lost
    if [ -z "$oldest" ]; then
        oldest_age=0
    else
        oldest_age=$((now - oldest))
        [ "$oldest_age" -ge 0 ] || oldest_age=0 # MUTATE:oldest-clamp
    fi
    return 0
}

if state_run; then
    state_ok=1
else
    oldest_age=""
fi

# ---------------------------------------------------------------- output
# The whole payload is built first and written in one checked step; success is declared only after
# the write succeeded. A failed write exits non-zero, so a partial metric set cannot look healthy.
emit_all() {
    printf 'host_update_pending%s,kind=package,security=false value=%di\n' "$tags" "$pend_other"
    printf 'host_update_pending%s,kind=package,security=true value=%di\n' "$tags" "$pend_sec"
    printf 'host_update_held_back%s value=%di\n' "$tags" "$n_held"
    printf 'host_update_lists_age_seconds%s value=%di\n' "$tags" "$lists_age"
    printf 'host_reboot_required%s value=%di\n' "$tags" "$reboot"
    printf 'host_unattended_last_run_age_seconds%s value=%di\n' "$tags" "$uu_age"
    if [ "$state_ok" -eq 1 ] && [ -n "$oldest_age" ]; then
        printf 'host_update_oldest_pending_age_seconds%s value=%di\n' "$tags" "$oldest_age"
    fi
    printf 'host_update_state_ok%s value=%di\n' "$tags" "$state_ok"
    printf 'host_update_check_success%s value=1i' "$tags"
}
# a failed capture exits non-zero before anything is printed, so a partial payload never reaches stdout
if ! payload=$(emit_all); then exit 1; fi # MUTATE:capture-check
# From here the payload is the only terminal output: ignore termination signals so none can land
# between the write and the finished flag and add a contradictory failure line after a complete payload.
trap '' HUP INT TERM # MUTATE:signal-block
if ! printf '%s\n' "$payload"; then exit 1; fi # MUTATE:output-check
finished=1
exit 0
