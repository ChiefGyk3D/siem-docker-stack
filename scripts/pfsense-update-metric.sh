#!/bin/sh
# pfsense-update-metric.sh - print pending pfSense updates as Telegraf exec
# input (InfluxDB line protocol). Issue #53.
#
# READ-ONLY. It runs `pfSense-upgrade -c` (check only) and
# `pkg-static version` (compares installed against the repo catalog), prints
# metrics on stdout and nothing else. It never installs, upgrades, rewrites
# configuration or contacts anything but what those two checks already read.
# It always exits 0 so Telegraf does not log a failed input; if a check
# cannot run, it prints nothing, which Grafana treats as "no data" (OK).
#
# Output: six lines, one per kind (core|kernel|package) and security flag
# (true|false), each `value=0i` or `value=1i`:
#   pfsense_update_pending,kind=core,security=false value=1i
# The security flag is a best-effort match: it is true when the
# `pfSense-upgrade -c` text mentions "security" (case-insensitive).
#
# Run it on the firewall from a Telegraf exec input (see
# docs/update-alerting.md). Not deployed by this repo.

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export PATH

command -v pfSense-upgrade >/dev/null 2>&1 || exit 0
command -v pkg-static >/dev/null 2>&1 || exit 0

check_out=$(pfSense-upgrade -c 2>&1)
check_rc=$?
if [ "$check_rc" -ne 0 ]; then
    echo "pfsense-update-metric: update check failed (rc=$check_rc), no metrics" >&2
    exit 0
fi

# Names of installed packages that have a newer version in the catalog.
pending=$(pkg-static version -qRl '<' 2>/dev/null)

core=0
kernel=0
package=0
security=false

# Core: pfSense-upgrade reports a newer base version.
case "$check_out" in
    *[Uu]p\ to\ date* | *[Nn]o\ updates* | '') ;;
    *[Aa]vailable* | *[Nn]ew\ version* | *[Uu]pgrade\ *) core=1 ;;
esac

case "$check_out" in
    *[Ss]ecurity* | *SECURITY*) security=true ;;
esac

for name in $pending; do
    case "$name" in
        pfSense-kernel-*) kernel=1 ;;
        pfSense-[0-9]* | pfSense-base-* | pfSense-rc-*) core=1 ;;
        *) package=1 ;;
    esac
done

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
exit 0
