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

check_out=$(pfSense-upgrade -c 2>&1) || fail "pfSense-upgrade -c failed"
pending=$(pkg-static version -qRl '<' 2>/dev/null) || fail "pkg-static version failed"

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

# One package name per line; no word splitting or globbing.
while IFS= read -r name; do
    [ -n "$name" ] || continue
    case "$name" in
        *[!A-Za-z0-9._+-]*) fail "unexpected characters in package name" ;;
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
