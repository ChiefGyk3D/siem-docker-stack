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

if [ "$EUID" -eq 0 ]; then
    # As root: the fixed PATH comes first, before any external program runs, and the
    # root test uses bash's own numeric id, never a program found on PATH. Fixed
    # program names (no IPTABLES/DOCKER overrides, PROM_FW_NO_SUDO ignored), and only
    # code nobody else can edit. Run the root-owned copy (docs).
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    IPT=iptables
    DOCKER_BIN=docker
    SELF="${BASH_SOURCE[0]}"
    for f in "${SELF%/*}" "$SELF"; do
        [ "$(stat -c '%u' "$f")" -eq 0 ] && [ $((8#$(stat -c '%a' "$f") & 8#022)) -eq 0 ] ||
            die "${f} is not root-owned (or is group or world writable); run the root-owned copy of the script (docs/prometheus-otlp.md)"
    done
else
    [ "${PROM_FW_NO_SUDO:-}" = 1 ] || die "run as root (sudo)"
    IPT="${IPTABLES:-iptables}"
    DOCKER_BIN="${DOCKER:-docker}"
fi

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
IPV4="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$"
CIDR="^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}/([0-9]|[12][0-9]|3[0-2])$"

quote() { printf '%q' "$1"; } # show an untrusted value on one line, never raw

check_bind() { # <value>: one usable IPv4 interface address, or refuse with the reason
    local b="$1"
    case "$b" in
        *:*) die "bind address $(quote "$b") has a colon: IPv6 and IPv4-mapped (::ffff:a.b.c.d) addresses are not supported, give one IPv4 interface address" ;;
    esac
    [[ "$b" =~ $IPV4 ]] || die "bind address $(quote "$b") is not a plain IPv4 address (four dotted numbers, no spaces, brackets, prefix length or name)"
    [ "$b" != "0.0.0.0" ] || die "bind address must be one interface address, not 0.0.0.0"
    case "${b%%.*}" in
        0 | 127) die "bind address ${b} is not an interface address (this-network or loopback); give the host's interface address" ;;
        22[4-9] | 2[3-5][0-9]) die "bind address ${b} is a multicast, reserved or broadcast address; give the host's interface address" ;;
    esac
}

discover_port() { # prints "<address> <port>" of the receiver's single published IPv4 mapping
    local out line addr="" port="" n=0
    out="$("$DOCKER_BIN" port prometheus-otlp 9090/tcp)" || die "docker port failed: is the prometheus-otlp container running?"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        if [[ "$line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$ ]]; then
            addr="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
            n=$((n + 1))
        else
            # An IPv6 mapping (or anything else) would be reachable past an IPv4-only rule.
            die "prometheus-otlp has a published mapping that this IPv4 rule does not guard (an IPv6 mapping or unexpected docker port output); publish on one IPv4 address only"
        fi
    done <<<"$out"
    [ "$n" -eq 1 ] || die "expected exactly one IPv4 published port for prometheus-otlp, found ${n} (an IPv6-only publish is not covered by this IPv4 rule)"
    { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || die "port ${port} is out of range"
    printf '%s %s' "$addr" "$port"
}

# The live rule list is read once, and a failed read stops the script before
# anything is changed (never treat "could not read" as "nothing there").
RULES=""
read_rules() {
    local line
    RULES="$("$IPT" -S DOCKER-USER)" || die "could not read the DOCKER-USER rules; nothing was changed"
    # Every rule that mentions one of our chains must be a plain word list of safe
    # characters ending in the jump, so it can be passed back to iptables as an
    # argument list. Anything else is refused untouched, never word-split or evaluated.
    while IFS= read -r line; do
        case "$line" in "-N PROM-OTLP-"[AB]) continue ;; *PROM-OTLP-[AB]*) ;; *) continue ;; esac
        [[ "$line" =~ ^-A\ DOCKER-USER\ [A-Za-z0-9./:_\ -]+\ -j\ PROM-OTLP-[AB]$ ]] ||
            die "a DOCKER-USER rule that mentions PROM-OTLP-A or PROM-OTLP-B has an unexpected shape; nothing was changed. Inspect it with: iptables -S DOCKER-USER"
    done <<<"$RULES"
}

has_jump_to() { # <chain>: does a live DOCKER-USER rule jump to it (uses RULES)
    printf '%s\n' "$RULES" | grep -q -- " -j ${1}\$"
}

live_chain() { # the one chain the live jump points at, if any (uses RULES)
    local a="" b=""
    if has_jump_to "$CHAIN_A"; then a="$CHAIN_A"; fi
    if has_jump_to "$CHAIN_B"; then b="$CHAIN_B"; fi
    if [ -n "$a" ] && [ -n "$b" ]; then
        die "DOCKER-USER jumps to both ${CHAIN_A} and ${CHAIN_B}; nothing was changed. Run 'remove' first, then apply again"
    fi
    printf '%s' "$a$b"
}

remove_jumps_to() { # <chain>: delete every DOCKER-USER rule that jumps to it (uses RULES)
    local chain="$1" line
    local -a words
    while IFS= read -r line; do
        read -r -a words <<<"${line#-A DOCKER-USER }"
        "$IPT" -D DOCKER-USER "${words[@]}"
    done < <(printf '%s\n' "$RULES" | grep -- " -j ${chain}\$" || true)
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
        check_bind "$bind"
        [ "$#" -ge 1 ] || die "give at least one approved sender"
        senders=()
        for s in "$@"; do
            [[ "$s" =~ $IPV4 || "$s" =~ $CIDR ]] || die "sender $(quote "$s") is not an IPv4 address or CIDR"
            [ "$s" != "0.0.0.0" ] || die "sender '${s}' would allow everyone"
            # Any /0 matches every address, whatever the base address says.
            [[ "$s" != */0 ]] || die "sender '${s}' has prefix length 0 and would allow everyone"
            # One rule per distinct sender, so a repeated argument is harmless.
            case " ${senders[*]-} " in *" ${s} "*) ;; *) senders+=("$s") ;; esac
        done
        read -r published port <<<"$(discover_port)"
        case "$published" in
            0.0.0.0) die "prometheus-otlp is published on every address (0.0.0.0); the rule guards only ${bind}. Set PROMETHEUS_OTLP_BIND_ADDR to one address and recreate the container first" ;;
            127.* | "$bind") ;;
            *) die "prometheus-otlp is published on ${published}, which the rule for ${bind} would not guard; publish it on loopback or on ${bind}" ;;
        esac

        read_rules
        current="$(live_chain)"
        if [ "$current" = "$CHAIN_A" ]; then new="$CHAIN_B"; else new="$CHAIN_A"; fi
        # The new chain is not referenced by any live rule, so flushing a leftover is safe.
        "$IPT" -N "$new" 2>/dev/null || "$IPT" -F "$new"
        for s in "${senders[@]}"; do
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
        echo "guarding ${bind}:${port}; allowed: ${senders[*]}"
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
