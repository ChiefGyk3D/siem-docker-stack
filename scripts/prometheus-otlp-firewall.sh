#!/bin/bash -p
# =============================================================================
# prometheus-otlp-firewall.sh - Allow-list for the Prometheus OTLP receiver
# =============================================================================
# Docker-published ports bypass UFW, so the receiver port is guarded in the
# DOCKER-USER chain: only the approved senders may open a connection to the
# receiver's published address and port; everything else is dropped.
#
# Usage (as root; run the script by its path, never as `bash script`: the
# privileged-mode shebang is what stops BASH_ENV and exported shell functions
# from running as root before the first line, and an explicit interpreter
# bypasses it, so root refuses to continue that way):
#   sudo scripts/prometheus-otlp-firewall.sh apply <bind-ipv4> <sender> [<sender>...]
#   sudo scripts/prometheus-otlp-firewall.sh remove
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

set +x
# SHELLOPTS and BASHOPTS are readonly in bash and are ignored in privileged mode.
unset BASH_ENV ENV CDPATH GLOBIGNORE PS4
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH  # fixed PATH before any command runs

# Root decision, privileged-mode check and the trusted script and helper tree come FIRST.
die() { echo "prometheus-otlp-firewall: $*" >&2; exit 1; }
LIB_NAME=lib-container-engine.sh
# Resolve every symlink first: the helper is the one next to the REAL script, never one next to a
# link someone else placed.
SELF="$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")" || die "cannot resolve this script's real path"
SCRIPT_DIR="$(/usr/bin/dirname -- "$SELF")"
CE_LIB="${SCRIPT_DIR}/${LIB_NAME}"
ce_boot_fail() { echo "refusing to source ${CE_LIB}: $1" >&2; exit 1; }
CE_UID="$(/usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null)" || CE_UID=
case "$CE_UID" in '' | *[!0-9]*) ce_boot_fail "cannot tell who is running (no numeric user number)" ;; esac
CE_UID=$((10#$CE_UID))  # asked of the kernel through id, never taken from an environment variable
CE_STRICT=0
[ "$CE_UID" != 0 ] || CE_STRICT=1
if [ "$CE_STRICT" = 1 ] && ! [[ "$-" == *p* ]]; then  # as root the privileged shebang must be in force
    ce_boot_fail "as root, run this script by its path (not as 'bash script'): the privileged shebang that keeps BASH_ENV and exported functions out is bypassed otherwise"
fi
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
if [ ! -f /proc/self/fd/9 ] || { [ "$CE_OWNER" != 0 ] && [ "$CE_OWNER" != "$CE_UID" ]; } ||
    [ $((8#$CE_MODE & 8#$CE_MASK)) -ne 0 ]; then
    ce_boot_fail "it must be a regular file owned by root or by you, not world writable (and not group writable when run as root)"
fi
# shellcheck source=scripts/lib-container-engine.sh
source /proc/self/fd/9
exec 9<&-

CHAIN_A=PROM-OTLP-A
CHAIN_B=PROM-OTLP-B



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

if [ "$CE_STRICT" = 1 ]; then
    # As root: no IPTABLES/DOCKER overrides, and only code nobody else can edit (the script, its
    # helper and every directory above them are checked). Run the root-owned copy (docs).
    IPT=iptables
    chain_ok "$SELF" ||
        die "${SELF} (or a directory above it) is not root-owned or is group or world writable; run the root-owned copy of the script and its ${LIB_NAME} (docs/prometheus-otlp.md)"
    ce_init || exit 1
    DOCKER_BIN="$CE_BIN"
else
    [ "${PROM_FW_NO_SUDO:-}" = 1 ] || die "run as root (sudo)"
    IPT="${IPTABLES:-iptables}"
    ce_init_name || exit 1
    # Test mode only (root ignores this): DOCKER may name a stub engine binary.
    CE_BIN="${DOCKER:-}"
    [ -n "$CE_BIN" ] || CE_BIN="$(ce_resolve "$CE_NAME")" || die "no trusted '${CE_NAME}' found"
    DOCKER_BIN="$CE_BIN"
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
    out="$(ce_run port prometheus-otlp 9090/tcp)" || die "${CE_NAME} port failed: is the prometheus-otlp container running?"
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
