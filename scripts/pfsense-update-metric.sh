#!/bin/sh
# pfsense-update-metric.sh - print pending pfSense updates as Telegraf exec
# input (InfluxDB line protocol). Issue #53.
#
# READ-ONLY. It runs exactly two commands: `pfSense-upgrade -c` (check only)
# and `pkg-static version -qRl '<'` (installed packages with a newer version
# in the catalog). It prints metrics on stdout and nothing else. It never
# installs, upgrades or rewrites anything.
#
# Success: six update lines plus the health metric, exit 0:
#   pfsense_update_pending,kind=core,security=false value=1i
#   pfsense_update_check_success value=1i
# kind is core|kernel|package, security is true|false (best effort: true when
# the `pfSense-upgrade -c` text mentions "security").
#
# Failure (a command is missing or fails, or a package name has unexpected
# characters): prints only `pfsense_update_check_success value=0i` and exits
# non-zero. It never prints zero-valued update metrics after a failure, so a
# broken check cannot look healthy. Telegraf may drop the output of a command
# that exits non-zero; the Grafana rule "pfSense update check failing or
# stale" therefore also alerts on missing data.
#
# Run it on the firewall from a Telegraf exec input (see
# docs/update-alerting.md). Not deployed by this repo.

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export PATH

fail() {
    echo "pfsense-update-metric: $1" >&2
    printf 'pfsense_update_check_success value=0i\n'
    exit 1
}

command -v pfSense-upgrade >/dev/null 2>&1 || fail "pfSense-upgrade not found"
command -v pkg-static >/dev/null 2>&1 || fail "pkg-static not found"

# Exit 0 and exit 2 are the only understood exit codes. `pfSense-upgrade -c`
# exits 2 when an update is pending (seen on a live firewall); any other code
# (1, 3 and above) is a failure. Exit 2 additionally needs a recognized update
# line below, or it fails closed.
up_rc=0
check_out=$(pfSense-upgrade -c 2>&1) || up_rc=$?
case "$up_rc" in
    0 | 2) ;;
    *) fail "pfSense-upgrade -c failed" ;;
esac
pending=$(pkg-static version -qRl '<' 2>/dev/null) || fail "pkg-static version failed"

core=0
kernel=0
package=0
security=false

# Classify the pfSense-upgrade text. Only two shapes are understood: the
# healthy "up to date" text and an "update available" text. Anything else, an
# empty result, or any text that also mentions an error or warning is an
# unknown result and fails closed (it must never look healthy).
lc=$(printf '%s' "$check_out" | tr '[:upper:]' '[:lower:]')
case "$lc" in
    *error* | *fail* | *unable* | *cannot* | *"can't"* | *"could not"* | *warning* | \
        *"timed out"* | *timeout* | *unavailable* | *unreachable* | *"not found"* | *denied*)
        fail "pfSense-upgrade output mentions a problem" ;;
esac
# Negations and staleness phrases are never healthy, whatever else the text says.
case " $lc " in
    *" not "* | *"no longer"* | *"n't"* | *"out of date"* | *outdated* | *stale*)
        fail "pfSense-upgrade output is negated or stale" ;;
esac

# Every non-blank line must be a complete, known form (lowercased, trailing
# punctuation removed): "your system is up to date" is healthy; "version X is
# available", "X version of pfSense is available" and "a new version ... is
# available" mean an update is pending. ">>> ...done." progress lines are
# ignored.
# A mix of the two, or any other line, is an unknown result.
healthy=0
pending_core=0
while IFS= read -r l; do
    l="${l#"${l%%[![:space:]]*}"}"
    l="${l%"${l##*[![:space:]]}"}"
    l="${l%[.!]}"
    [ -n "$l" ] || continue
    case "$l" in
        "your system is up to date") healthy=1 ;;
        ">>> "*"...done") ;;
        [0-9]*" version of pfsense is available"*)
            pending_core=1
            case "$l" in *security*) security=true ;; esac ;;
        "version "*" is available"* | "a new version "*" is available"* | "new version available"*)
            pending_core=1
            case "$l" in *security*) security=true ;; esac ;;
        *) fail "unrecognized pfSense-upgrade output" ;;
    esac
done <<EOF
$lc
EOF
if [ "$up_rc" -eq 2 ] && [ "$pending_core" -eq 0 ]; then
    fail "pfSense-upgrade exit 2 without a recognized update line"
fi
if [ "$healthy" -eq 1 ] && [ "$pending_core" -eq 1 ]; then
    fail "pfSense-upgrade output mixes healthy and update text"
fi
if [ "$healthy" -eq 0 ] && [ "$pending_core" -eq 0 ]; then
    fail "empty pfSense-upgrade output"
fi
core=$pending_core

# One package name per line; no word splitting or globbing.
while IFS= read -r name; do
    [ -n "$name" ] || continue
    case "$name" in
        *[!A-Za-z0-9._+-]*) fail "unexpected characters in package name" ;;
        *-[0-9]*) ;;
        *) fail "unexpected package name shape" ;;
    esac
    case "$name" in
        pfSense-kernel-*) kernel=1 ;;
        pfSense-[0-9]* | pfSense-base-* | pfSense-rc-*) core=1 ;;
        *) package=1 ;;
    esac
done <<EOF
$pending
EOF

emit() {
    # $1 kind, $2 pending (0/1)
    for sec in false true; do
        val=0
        if [ "$2" -eq 1 ] && [ "$sec" = "$security" ]; then
            val=1
        fi
        printf 'pfsense_update_pending,kind=%s,security=%s value=%di\n' "$1" "$sec" "$val"
    done
}

emit core "$core"
emit kernel "$kernel"
emit package "$package"
printf 'pfsense_update_check_success value=1i\n'
exit 0
