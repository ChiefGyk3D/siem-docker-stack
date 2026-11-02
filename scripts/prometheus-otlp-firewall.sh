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

IPT="${IPTABLES:-iptables}"
DOCKER_BIN="${DOCKER:-docker}"
CHAIN_A=PROM-OTLP-A
CHAIN_B=PROM-OTLP-B

die() { echo "prometheus-otlp-firewall: $*" >&2; exit 1; }

if [ "$EUID" -ne 0 ] && [ "${PROM_FW_NO_SUDO:-}" != 1 ]; then
    die "run as root (sudo)"
fi

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
IPV4="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$"
CIDR="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}/([0-9]|[12][0-9]|3[0-2])$"

discover_port() { # prints the single published IPv4 port of the receiver
    local out line port="" n=0
    out="$("$DOCKER_BIN" port prometheus-otlp 9090/tcp)" || die "docker port failed: is the prometheus-otlp container running?"
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

live_chain() { # the chain the live jump points at, if any
    { "$IPT" -S DOCKER-USER || true; } | grep -o -- '-j PROM-OTLP-[AB]' | head -1 | sed 's/^-j //' || true
}

remove_jumps_to() { # <chain>: delete every DOCKER-USER rule that jumps to it
    local chain="$1" line spec
    while IFS= read -r line; do
        spec="${line#-A DOCKER-USER }"
        # shellcheck disable=SC2086  # the saved rule is a word list on purpose
        "$IPT" -D DOCKER-USER $spec
    done < <({ "$IPT" -S DOCKER-USER || true; } | grep -- "-j ${chain}\$" || true)
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
            [ "$s" != "0.0.0.0" ] && [ "$s" != "0.0.0.0/0" ] || die "sender '${s}' would allow everyone"
        done
        port="$(discover_port)"

        current="$(live_chain)"
        if [ "$current" = "$CHAIN_A" ]; then new="$CHAIN_B"; else new="$CHAIN_A"; fi
        # The new chain is not referenced by any live rule, so flushing a leftover is safe.
        "$IPT" -N "$new" 2>/dev/null || "$IPT" -F "$new"
        for s in "$@"; do
            "$IPT" -A "$new" -s "$s" -j RETURN
        done
        "$IPT" -A "$new" -j DROP
        "$IPT" -I DOCKER-USER -p tcp -m conntrack --ctstate DNAT \
            --ctorigdst "$bind" --ctorigdstport "$port" -j "$new"
        if [ -n "$current" ]; then
            remove_jumps_to "$current"
            drop_chain "$current"
        fi
        "$IPT" -C DOCKER-USER -p tcp -m conntrack --ctstate DNAT \
            --ctorigdst "$bind" --ctorigdstport "$port" -j "$new" || die "the rule is not in place after applying"
        echo "guarding ${bind}:${port}; allowed: $*"
        ;;
    remove)
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
