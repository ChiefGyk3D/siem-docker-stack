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

CHAIN_A=PROM-OTLP-A
CHAIN_B=PROM-OTLP-B

die() { echo "prometheus-otlp-firewall: $*" >&2; exit 1; }

LIB_NAME=lib-container-engine.sh

chain_ok() { # <path>: root-owned and not group or world writable, the path and every ancestor up to /
    local p="$1" owner mode
    while :; do
        owner="$(stat -c %u -- "$p")" || return 1
        mode="$(stat -c %a -- "$p")" || return 1
        [ "$owner" -eq 0 ] && [ $((8#$mode & 8#022)) -eq 0 ] || return 1
        [ "$p" = / ] && return 0
        p="$(dirname -- "$p")"
    done
}

if [ "$(id -u)" -eq 0 ]; then
    # As root: fixed PATH, fixed program names (no IPTABLES/DOCKER overrides), and
    # only code nobody else can edit. Run the root-owned copy (docs).
    if [ "$EUID" -eq 0 ]; then
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
    fi
    IPT=iptables
    # Resolve every symlink first: the helper is the one next to the REAL script, never one
    # next to a link someone else placed. The whole chain to / must be root-owned and not writable.
    SELF="$(readlink -f -- "${BASH_SOURCE[0]}")" || die "cannot resolve this script's real path"
    SELF_DIR="$(dirname -- "$SELF")"
    LIB="${SELF_DIR}/${LIB_NAME}"
    [ -f "$LIB" ] && [ ! -L "$LIB" ] || die "${LIB} is missing or is a link; install the real file next to the script (docs/prometheus-otlp.md)"
    for f in "$SELF_DIR" "$SELF" "$LIB"; do
        chain_ok "$f" ||
            die "${f} (or a directory above it) is not root-owned or is group or world writable; run the root-owned copy of the script and its ${LIB_NAME} (docs/prometheus-otlp.md)"
    done
    # Open the helper once, check the OPEN file, and source that same descriptor: a rename or
    # replacement of the path after this point cannot change what runs.
    exec 9<"$LIB"
    [ "$(stat -c %u -- /proc/self/fd/9)" -eq 0 ] && [ $((8#$(stat -c %a -- /proc/self/fd/9) & 8#022)) -eq 0 ] ||
        die "the opened ${LIB_NAME} is not root-owned or is group or world writable"
    # shellcheck source=scripts/lib-container-engine.sh
    source /proc/self/fd/9
    exec 9<&-
    ce_init || exit 1
    DOCKER_BIN="$CE_BIN"
else
    [ "${PROM_FW_NO_SUDO:-}" = 1 ] || die "run as root (sudo)"
    IPT="${IPTABLES:-iptables}"
    SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
    # shellcheck source=scripts/lib-container-engine.sh
    source "$(dirname -- "$SELF")/${LIB_NAME}"
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
