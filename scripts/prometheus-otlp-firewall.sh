#!/bin/bash
# =============================================================================
# prometheus-otlp-firewall.sh - Allow-list for the Prometheus OTLP receiver
# =============================================================================
# Docker-published ports bypass UFW, so the receiver port is guarded in the
# DOCKER-USER chain: only the approved senders may open a connection to the
# receiver's published address and port; everything else is dropped.
#
# Usage (as root):
#   sudo bash scripts/prometheus-otlp-firewall.sh apply <bind-ipv4> <sender> [<sender>...]
#   sudo bash scripts/prometheus-otlp-firewall.sh remove
#
#   <bind-ipv4>  the address the receiver will be published on
#                (PROMETHEUS_OTLP_BIND_ADDR). Not 0.0.0.0: the rule matches the
#                original destination address, which a wildcard would not equal.
#   <sender>     an IPv4 address or CIDR (placeholders in the docs: 192.0.2.10)
#
# The port is read from the running container (docker port), exactly one IPv4
# line, so the rule always follows PROMETHEUS_OTLP_PORT in .env. Apply it BEFORE
# you widen the bind address, so the address is never reachable unguarded.
#
# Re-running builds a new chain, puts it in front, then removes the old jump and
# chain, so at no point is the port without a rule. The two chains alternate
# between PROM-OTLP-A and PROM-OTLP-B. IPv4 and iptables only (docs).
# =============================================================================

set -euo pipefail

[ "${EUID:-1}" -ne 0 ] || { PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; }  # root: fixed PATH before any command runs

CHAIN_A=PROM-OTLP-A
CHAIN_B=PROM-OTLP-B

die() { echo "prometheus-otlp-firewall: $*" >&2; exit 1; }

LIB_NAME=lib-container-engine.sh

chain_ok() { # <path>: root-owned and not group or world writable, the path and every ancestor up to /
    local p="$1" owner mode
    while :; do
        owner="$(/usr/bin/stat -c %u -- "$p")" || return 1
        mode="$(/usr/bin/stat -c %a -- "$p")" || return 1
        [ "$owner" -eq 0 ] && [ $((8#$mode & 8#022)) -eq 0 ] || return 1
        [ "$p" = / ] && return 0
        p="$(/usr/bin/dirname -- "$p")"
    done
}

# Resolve every symlink first: the helper is the one next to the REAL script, never one next to a
# link someone else placed.
SELF="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")" || die "cannot resolve this script's real path"
SCRIPT_DIR="$(/usr/bin/dirname -- "$SELF")"
if [ "${EUID:-1}" -eq 0 ]; then
    # As root: no IPTABLES/DOCKER overrides, and only code nobody else can edit (the script, its
    # helper and every directory above them are checked). Run the root-owned copy (docs).
    IPT=iptables
    chain_ok "$SELF" ||
        die "${SELF} (or a directory above it) is not root-owned or is group or world writable; run the root-owned copy of the script and its ${LIB_NAME} (docs/prometheus-otlp.md)"
else
    [ "${PROM_FW_NO_SUDO:-}" = 1 ] || die "run as root (sudo)"
    IPT="${IPTABLES:-iptables}"
fi
CE_LIB="${SCRIPT_DIR}/${LIB_NAME}"
ce_boot_fail() { echo "refusing to source ${CE_LIB}: $1" >&2; exit 1; }
CE_STRICT=0
[ "${EUID:-1}" -ne 0 ] || CE_STRICT=1
if [ "$CE_STRICT" = 1 ]; then  # as root: the helper and every directory above it must be root-owned and not writable
    CE_P="$CE_LIB"
    while :; do
        [ "$(/usr/bin/stat -c %u -- "$CE_P")" = 0 ] && [ $((8#$(/usr/bin/stat -c %a -- "$CE_P") & 8#022)) -eq 0 ] ||
            ce_boot_fail "${CE_P} (or a directory above it) is not root-owned or is group or world writable"
        [ "$CE_P" = / ] && break
        CE_P="$(/usr/bin/dirname -- "$CE_P")"
    done
fi
[ -f "$CE_LIB" ] && [ ! -L "$CE_LIB" ] || ce_boot_fail "it is missing or is a link"
# Open the helper once, check the OPEN file (-L: the descriptor link points at the file), and source
# that same descriptor, so a rename or replacement of the path after this point changes nothing.
exec 9<"$CE_LIB" || ce_boot_fail "it cannot be opened"
CE_OWNER="$(/usr/bin/stat -L -c %u -- /proc/self/fd/9)"
CE_MODE="$(/usr/bin/stat -L -c %a -- /proc/self/fd/9)"
CE_MASK=002  # world write is never allowed; group write too when running as root
[ "$CE_STRICT" != 1 ] || CE_MASK=022
if [ ! -f /proc/self/fd/9 ] || { [ "$CE_OWNER" != 0 ] && [ "$CE_OWNER" != "$(/usr/bin/id -u)" ]; } ||
    [ $((8#$CE_MODE & 8#$CE_MASK)) -ne 0 ]; then
    ce_boot_fail "it must be a regular file owned by root or by you, not world writable (and not group writable when run as root)"
fi
# shellcheck source=scripts/lib-container-engine.sh
source /proc/self/fd/9
exec 9<&-
if [ "${EUID:-1}" -eq 0 ]; then
    ce_init || exit 1
    DOCKER_BIN="$CE_BIN"
else
    ce_init_name || exit 1
    # Test mode only (root ignores this): DOCKER may name a stub engine binary.
    CE_BIN="${DOCKER:-}"
    [ -n "$CE_BIN" ] || CE_BIN="$(ce_resolve "$CE_NAME")" || die "no trusted '${CE_NAME}' found"
    DOCKER_BIN="$CE_BIN"
fi

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
IPV4="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$"
CIDR="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}/([0-9]|[12][0-9]|3[0-2])$"

discover_port() { # prints the single published IPv4 port of the receiver
    local out line port="" n=0
    out="$(ce_run port prometheus-otlp 9090/tcp)" || die "${CE_NAME} port failed: is the prometheus-otlp container running?"
    while IFS= read -r line; do
        if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:([0-9]+)$ ]]; then
            port="${BASH_REMATCH[1]}"
            n=$((n + 1))
        fi
    done <<<"$out"
    [ "$n" -eq 1 ] || die "expected exactly one IPv4 published port for prometheus-otlp, found ${n}"
    { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || die "port ${port} is out of range"
    printf '%s' "$port"
}

# The live rule list is read once, and a failed read stops the script before
# anything is changed (never treat "could not read" as "nothing there").
RULES=""
read_rules() {
    RULES="$("$IPT" -S DOCKER-USER)" || die "could not read the DOCKER-USER rules; nothing was changed"
}

live_chain() { # the chain the live jump points at, if any (uses RULES)
    printf '%s\n' "$RULES" | grep -o -- '-j PROM-OTLP-[AB]' | head -1 | sed 's/^-j //' || true
}

remove_jumps_to() { # <chain>: delete every DOCKER-USER rule that jumps to it (uses RULES)
    local chain="$1" line spec
    while IFS= read -r line; do
        spec="${line#-A DOCKER-USER }"
        # shellcheck disable=SC2086  # the saved rule is a word list on purpose
        "$IPT" -D DOCKER-USER $spec
    done < <(printf '%s\n' "$RULES" | grep -- "-j ${chain}\$" || true)
}

drop_chain() { # <chain>
    "$IPT" -F "$1" 2>/dev/null && "$IPT" -X "$1" || true
}

cmd="${1:-}"
case "$cmd" in
    apply)
        shift
        bind="${1:-}"
        [ -n "$bind" ] || die "usage: apply <bind-ipv4> <sender>..."
        shift
        [[ "$bind" =~ $IPV4 ]] || die "bind address '${bind}' is not an IPv4 address"
        [ "$bind" != "0.0.0.0" ] || die "bind address must be one interface address, not 0.0.0.0"
        [ "$#" -ge 1 ] || die "give at least one approved sender"
        for s in "$@"; do
            [[ "$s" =~ $IPV4 || "$s" =~ $CIDR ]] || die "sender '${s}' is not an IPv4 address or CIDR"
            [ "$s" != "0.0.0.0" ] || die "sender '${s}' would allow everyone"
            # Any /0 matches every address, whatever the base address says.
            [[ "$s" != */0 ]] || die "sender '${s}' has prefix length 0 and would allow everyone"
        done
        port="$(discover_port)"

        read_rules
        current="$(live_chain)"
        if [ "$current" = "$CHAIN_A" ]; then new="$CHAIN_B"; else new="$CHAIN_A"; fi
        # The new chain is not referenced by any live rule, so flushing a leftover is safe.
        "$IPT" -N "$new" 2>/dev/null || "$IPT" -F "$new"
        for s in "$@"; do
            "$IPT" -A "$new" -s "$s" -j RETURN
        done
        "$IPT" -A "$new" -j DROP
        # Only the original direction (client to receiver) goes through the allow-list.
        # Reply packets of an approved connection travel the other way and must not
        # be matched, or the DROP would cut the receiver's own answers.
        "$IPT" -I DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL \
            --ctorigdst "$bind" --ctorigdstport "$port" -j "$new"
        if [ -n "$current" ]; then
            remove_jumps_to "$current"
            drop_chain "$current"
        fi
        "$IPT" -C DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctdir ORIGINAL \
            --ctorigdst "$bind" --ctorigdstport "$port" -j "$new" || die "the rule is not in place after applying"
        echo "guarding ${bind}:${port}; allowed: $*"
        ;;
    remove)
        read_rules
        for chain in "$CHAIN_A" "$CHAIN_B"; do
            remove_jumps_to "$chain"
        done
        for chain in "$CHAIN_A" "$CHAIN_B"; do
            drop_chain "$chain"
        done
        echo "removed the OTLP receiver allow-list"
        ;;
    *)
        die "usage: apply <bind-ipv4> <sender>... | remove"
        ;;
esac
