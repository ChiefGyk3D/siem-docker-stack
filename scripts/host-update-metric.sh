#!/bin/sh
# host-update-metric.sh - print pending OS updates of a Debian-family host as InfluxDB line
# protocol. Issue #219. Same contract and fail-closed style as pfsense-update-metric.sh.
#
# Usage: HOST_LABEL=<label> host-update-metric.sh <critical|standard>
#        host-update-metric.sh <critical|standard> <label>
#
# READ-ONLY and UNPRIVILEGED. It never runs apt update, never opens the network, never uses sudo.
# The only commands that look at the host are:
#   apt-get -s -o Debug::NoLocking=1 dist-upgrade   (simulation, LC_ALL=C)
#   test -e /var/run/reboot-required
#   a bounded read of /var/log/unattended-upgrades/unattended-upgrades.log (and its .1)
# plus date, stat, id, tail, grep, timeout, mv and chmod on its own private state directory.
#
# Success (exit 0), tags host=<label>,tier=<tier> on every line:
#   host_update_pending,kind=package,security=false value=<n>i   (non-security packages)
#   host_update_pending,kind=package,security=true value=<n>i    (security packages)
#   host_reboot_required value=0i|1i
#   host_unattended_last_run_age_seconds value=<n>i
#   host_update_oldest_pending_age_seconds value=<n>i            (only when state_ok is 1)
#   host_update_state_ok value=1i|0i
#   host_update_check_success value=1i
#
# Failure (anything below is not understood or not readable, including an unattended-upgrades age
# that cannot be determined): prints only `host_update_check_success value=0i` (with the tags when
# label and tier are valid) and exits 1. Zero-valued update metrics are never printed after a
# failure, so a broken check cannot look healthy.
#
# The first-seen state is separate: if it is lost, unreadable, owned by someone else, has the wrong
# mode or is corrupt, the check itself still succeeds, host_update_state_ok is 0 and NO oldest-age
# metric is printed (never a 0 age). See docs/host-update-collector.md.
#
# Test hooks (absolute paths, defaults in the code): HOST_UPDATE_APT_GET, HOST_UPDATE_REBOOT_FILE,
# HOST_UPDATE_UU_LOG, HOST_UPDATE_STATE_DIR.

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

nl='
'
tags=""

fail() {
    echo "host-update-metric: $1" >&2
    printf 'host_update_check_success%s value=0i\n' "$tags"
    exit 1
}

# ---------------------------------------------------------------- arguments
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail "usage: host-update-metric.sh <critical|standard> [label]"
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

valid_version() {
    # $1 candidate; Debian version characters only
    [ -n "$1" ] && [ "${#1}" -le 128 ] || return 1
    case "$1" in
        *[!A-Za-z0-9.+:~_-]*) return 1 ;;
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
reboot_file=${HOST_UPDATE_REBOOT_FILE:-/var/run/reboot-required}
abs_path "$reboot_file" || fail "reboot file path must be absolute"
[ -d "${reboot_file%/*}/." ] || fail "reboot file directory is not readable"
reboot=0
[ -e "$reboot_file" ] && reboot=1

# ---------------------------------------------------------------- unattended-upgrades age
uu_log=${HOST_UPDATE_UU_LOG:-/var/log/unattended-upgrades/unattended-upgrades.log}
abs_path "$uu_log" || fail "unattended-upgrades log path must be absolute"
uu_re='^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} INFO (All upgrades installed|No packages found that can be upgraded unattended and no pending auto-removals)$'
last=""
for f in "$uu_log" "$uu_log.1"; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    last=$(tail -c 1048576 "$f" 2>/dev/null | grep -a -E "$uu_re" | tail -n 1)
    [ -n "$last" ] && break
done
# An age that cannot be determined is a failure, never 0.
[ -n "$last" ] || fail "no successful unattended-upgrades run found" # MUTATE:unknown-age
stamp=${last%%,*}
case "$stamp" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]) ;;
    *) fail "unparsable unattended-upgrades timestamp" ;;
esac
now=$(date +%s 2>/dev/null) || fail "date failed"
last_ts=$(date -d "$stamp" +%s 2>/dev/null) || fail "unattended-upgrades timestamp not understood"
case "$now$last_ts" in
    *[!0-9]* | "") fail "non-numeric time" ;;
esac
uu_age=$((now - last_ts))
[ "$uu_age" -ge 0 ] || fail "unattended-upgrades timestamp is in the future"

# ---------------------------------------------------------------- apt simulation
apt_bin=${HOST_UPDATE_APT_GET:-/usr/bin/apt-get}
abs_path "$apt_bin" || fail "apt-get path must be absolute"
[ -x "$apt_bin" ] || fail "apt-get not found"
apt_out=$(timeout 120 "$apt_bin" -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null) || fail "apt-get simulation failed" # MUTATE:apt-rc
[ "${#apt_out}" -le 4194304 ] || fail "apt-get output too large"

pend_sec=0
pend_other=0
n_inst=0
n_lines=0
summary_total=""
keys=""
while IFS= read -r line; do
    n_lines=$((n_lines + 1))
    [ "$n_lines" -le 50000 ] || fail "apt-get output has too many lines"
    case "$line" in
        "Inst "*)
            n_inst=$((n_inst + 1))
            [ "$n_inst" -le 1000 ] || fail "too many pending packages"
            rest=${line#Inst }
            name=${rest%% *}
            [ "$name" != "$rest" ] || fail "malformed Inst line"
            [ -n "$name" ] && [ "${#name}" -le 128 ] || fail "bad package name length"
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
                "" | *[!a-z0-9-]*) fail "bad architecture" ;;
            esac
            inner=${inner% *}
            new=${inner%% *}
            origins=${inner#"$new "}
            [ "$origins" != "$inner" ] && [ -n "$origins" ] || fail "missing origin"
            valid_version "$new" || fail "bad candidate version"
            case "$origins" in
                *[!A-Za-z0-9._:/+,\ -]*) fail "unexpected characters in origin" ;;
            esac
            case "$nl$keys" in
                *"$nl$name $new$nl"*) fail "duplicate package in simulation" ;;
            esac
            keys="$keys$name $new$nl"
            # Security by origin: an archive whose label is a security origin and whose suite
            # (the part after the last slash) ends in -security. The package name is never read.
            is_sec=0
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
            if [ "$is_sec" -eq 1 ]; then
                pend_sec=$((pend_sec + 1))
            else
                pend_other=$((pend_other + 1))
            fi
            ;;
        [0-9]*" upgraded, "*" newly installed, "*" to remove and "*" not upgraded.")
            [ -z "$summary_total" ] || fail "two summary lines"
            n_up=${line%% upgraded, *}
            tmp=${line#*" upgraded, "}
            n_new=${tmp%% newly installed, *}
            case "$n_up$n_new" in
                *[!0-9]* | "") fail "malformed summary line" ;;
            esac
            summary_total=$((n_up + n_new))
            ;;
        "Conf "* | "Remv "* | "Reading "* | "Building "* | "Calculating "* | "NOTE: "* | \
            "The following "* | "Suggested packages:" | "Recommended packages:" | " "* | "" | \
            "Use 'apt autoremove' to remove "*)
            ;;
        *) fail "unrecognized apt-get output" ;;
    esac
done <<EOF
$apt_out
EOF
# The summary line proves the output is complete, and its count must match the Inst lines.
[ -n "$summary_total" ] || fail "apt-get summary line missing" # MUTATE:summary-required
[ "$summary_total" -eq "$n_inst" ] || fail "apt-get summary does not match the Inst lines" # MUTATE:summary-match

# ---------------------------------------------------------------- first-seen state
# Never fails the check; sets state_ok and, only when the state is trustworthy, oldest_age.
state_ok=0
oldest_age=""
state_dir=${HOST_UPDATE_STATE_DIR:-}
if [ -z "$state_dir" ] && [ -n "${HOME-}" ]; then
    state_dir=${XDG_STATE_HOME:-$HOME/.local/state}/host-update-metric
fi

state_run() {
    abs_path "$state_dir" || return 1
    me=$(id -u 2>/dev/null) || return 1
    case "$me" in
        "" | *[!0-9]*) return 1 ;;
    esac
    first_run=0
    if [ -L "$state_dir" ]; then
        return 1
    elif [ ! -e "$state_dir" ]; then
        mkdir -p "$state_dir" 2>/dev/null || return 1
        chmod 700 "$state_dir" 2>/dev/null || return 1
        first_run=1
    fi
    [ -d "$state_dir" ] && [ ! -L "$state_dir" ] || return 1
    [ "$(stat -c '%u %a' "$state_dir" 2>/dev/null)" = "$me 700" ] || return 1 # MUTATE:state-dir-mode
    sfile=$state_dir/first-seen
    old_text=""
    seed_only=0
    if [ -L "$sfile" ]; then
        return 1
    elif [ -e "$sfile" ]; then
        [ -f "$sfile" ] || return 1
        [ "$(stat -c '%u %a' "$sfile" 2>/dev/null)" = "$me 600" ] || return 1
        size=$(stat -c '%s' "$sfile" 2>/dev/null) || return 1
        case "$size" in
            "" | *[!0-9]*) return 1 ;;
        esac
        [ "$size" -le 262144 ] || return 1
        header=1
        count=0
        while IFS= read -r l || [ -n "$l" ]; do
            if [ "$header" -eq 1 ]; then
                [ "$l" = "host-update-state v1" ] || return 1 # MUTATE:state-parse
                header=0
                continue
            fi
            count=$((count + 1))
            [ "$count" -le 1000 ] || return 1
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
            case "$s_epoch" in
                "" | *[!0-9]*) return 1 ;;
            esac
            [ "${#s_epoch}" -le 11 ] || return 1
            [ "$s_epoch" -le $((now + 86400)) ] || return 1
            case "$nl$old_text" in
                *"$nl$s_name $s_ver "*) return 1 ;;
            esac
            old_text="$old_text$s_name $s_ver $s_epoch$nl"
        done <"$sfile"
        [ "$header" -eq 0 ] || return 1
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
                e=${old_text#*"$k "}
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
        set -C
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
        [ "$oldest_age" -ge 0 ] || oldest_age=0
    fi
    return 0
}

if state_run; then
    state_ok=1
else
    oldest_age=""
fi

# ---------------------------------------------------------------- output
printf 'host_update_pending%s,kind=package,security=false value=%di\n' "$tags" "$pend_other"
printf 'host_update_pending%s,kind=package,security=true value=%di\n' "$tags" "$pend_sec"
printf 'host_reboot_required%s value=%di\n' "$tags" "$reboot"
printf 'host_unattended_last_run_age_seconds%s value=%di\n' "$tags" "$uu_age"
if [ "$state_ok" -eq 1 ] && [ -n "$oldest_age" ]; then
    printf 'host_update_oldest_pending_age_seconds%s value=%di\n' "$tags" "$oldest_age"
fi
printf 'host_update_state_ok%s value=%di\n' "$tags" "$state_ok"
printf 'host_update_check_success%s value=1i\n' "$tags"
exit 0
