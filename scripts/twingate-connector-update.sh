#!/bin/sh
# twingate-connector-update.sh - update ONE Twingate Connector container on the
# host it runs on. Issue #220. Owner decision 2026-11-26: a one-command action
# the owner runs on each host, one host at a time. No automatic updates.
#
# Usage: twingate-connector-update.sh [--dry-run] [--yes] [--force] <connector-container-name>
#
# Fail closed. It refuses unless NOTHING would be dropped by a recreate that
# uses only: --network host, --env-file, --name, --restart=unless-stopped and
# the image (an allowlist, see docs/twingate-connector-update-script.md).
# It never prunes images, never prints an env value, and keeps no copy of the
# full docker inspect output on disk. The env file (TWINGATE_* variables only)
# lives in a private (mode 700) temp dir that exists only from just before the
# stop until the end, and is removed on every exit path. If the rollback also
# fails it is kept in a private runtime dir (mode 600) so you can recover.
# From just before the stop until the new container is verified (or rolled
# back) INT, TERM, HUP, PIPE and QUIT are ignored so a signal cannot leave the
# Connector gone. SIGKILL cannot be handled by any program.
# PATH is fixed to the system directories; the inherited PATH is not used.
# One run at a time per host (one host-wide lock dir directly under /run, which
# only root can write, so no other user can pre-create or squat it; real runs
# need root, --dry-run does not). Tokens and the lock never use the
# inherited TMPDIR or XDG_RUNTIME_DIR. TWINGATE_API_KEY and NOTIFY_WEBHOOK_URL
# are copied into unexported shell variables and unset at once, so no child
# process (docker, jq) inherits them.
#
# The whole environment is cleared: at start the script re-executes itself under
# `env -i` with a fixed PATH, LANG=C, DOCKER_HOST=unix:///var/run/docker.sock,
# and a DOCKER_CONFIG and HOME of its own (empty root-only dirs under /run).
# Only the inputs listed below are carried over, once, through a private file
# descriptor (never argv). DOCKER_*, SSL_CERT_*, CURL_CA_BUNDLE, proxy and XDG_*
# variables from the caller never reach docker, curl or jq.
#
# Environment (all optional, never put secrets in argv):
#   NOTIFY_WEBHOOK_URL   https URL; a short JSON notice is POSTed at the end
#                        (5 s timeout). A failed notice never fails the update.
#                        Sent only if NOTIFY_WEBHOOK_ALLOWED_HOSTS is set.
#   NOTIFY_WEBHOOK_ALLOWED_HOSTS
#                        comma-separated exact host names (no wildcards, no
#                        default). The URL host must match one entry. IP
#                        literals, localhost and names without a dot are
#                        refused. Unset: the notice is skipped.
#   HOST_LABEL           label for the notice (default: short hostname)
#   TWINGATE_API_KEY, TWINGATE_NETWORK_URL
#                        if both set, a read-only Admin API pre-check looks at
#                        the other Connectors in THIS Connector's remote
#                        network, and after the update this Connector must be
#                        seen ALIVE with the new version. TWINGATE_NETWORK_URL
#                        must be <network>.twingate.com (https:// optional).
#                        A pre-check warning aborts under --yes unless --force.
#   TWINGATE_UPDATE_WAIT_SECS (default and maximum 60), TWINGATE_UPDATE_POLL_SECS
#                        (plain integers 1-60 without leading zeros, else the
#                        default is used)
# See docs/twingate-connector-update-script.md.

umask 077
TRUSTED_UID=0
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

early_die() { printf 'refused: %s\n' "$1" >&2; exit 2; }
NL='
'
# acl_present PATH: succeeds (0) when PATH has an extended ACL OR when that
# cannot be determined (fail closed). Mode bits alone do not show a POSIX ACL
# that gives another user write access. Two detections, no extra package needed
# for the first: (1) the long listing of the mode ends in a plus sign when an
# extended ACL exists (GNU ls); (2) where getfacl is installed, anything beyond
# the three base entries (named users or groups, mask, default entries, or
# empty, malformed or duplicate output) counts.
# Other extended attributes (security.*, user.*) do not change who may write a
# file, so they are not checked; the ACL attributes are the ones that do.
acl_present() {
    _l=$(ls -ldn -- "$1" 2>/dev/null) || return 0
    case "$_l" in
        [-d]?????????+*) return 0 ;;
        [-d]?????????" "*|[-d]?????????.*) ;;
        *) return 0 ;;
    esac
    if command -v getfacl >/dev/null 2>&1; then
        _x=$(getfacl -p -c -- "$1" 2>/dev/null) || return 0
        # Fail closed: exactly one user::, one group:: and one other:: base entry
        # and nothing else. Empty, malformed, duplicate or incomplete output
        # (and any named, mask or default entry) counts as "cannot be trusted".
        _nu=0; _ng=0; _no=0
        while IFS= read -r _ln; do
            case "$_ln" in
                "") ;;
                user::[r-][w-][x-]) _nu=$((_nu + 1)) ;;
                group::[r-][w-][x-]) _ng=$((_ng + 1)) ;;
                other::[r-][w-][x-]) _no=$((_no + 1)) ;;
                *) return 0 ;;
            esac
        done <<EOF_ACL
$_x
EOF_ACL
        if [ "$_nu" != 1 ] || [ "$_ng" != 1 ] || [ "$_no" != 1 ]; then return 0; fi
    fi
    return 1
}
# ---- clean environment --------------------------------------------------------
# First run: collect the documented inputs and re-exec under `env -i`. The
# inputs travel on fd 3 (a heredoc), so secrets never appear in argv.
if [ "${TWINGATE_UPDATE_CLEAN_ENV:-}" != "1" ]; then
    SELF="$0"
    case "$SELF" in
        */*) ;;
        *) [ -f "./$SELF" ] && SELF="./$SELF" ;;
    esac
    [ -f "$SELF" ] || early_die "cannot locate this script to restart it with a clean environment"
    # Hardening: the script must live in a root-owned location. Make the path
    # absolute and physical (the directory through `pwd -P`; the file itself must
    # not be a link), then require the file and EVERY directory up to / to be
    # owned by root and not group- or world-writable. Every invocation refuses
    # otherwise (any user, dry run included).
    PATH_OK=1
    PATH_WHY=""
    SELF_DIR=$(cd "$(dirname -- "$SELF")" 2>/dev/null && pwd -P) || SELF_DIR=""
    if [ -z "$SELF_DIR" ] || [ -L "$SELF" ]; then
        PATH_OK=0; PATH_WHY="cannot resolve this script to a canonical path (it must not be a symbolic link)"
    else
        case "$SELF_DIR" in
            /) SELF="/${SELF##*/}" ;;
            *) SELF="$SELF_DIR/${SELF##*/}" ;;
        esac
        p="$SELF"
        while :; do
            if [ -z "$(find "$p" -maxdepth 0 -user "${TRUSTED_UID:-0}" ! -perm /022 2>/dev/null)" ]; then
                PATH_OK=0; PATH_WHY="this script or one of its parent directories is not owned by root or is group- or world-writable; install it in a root-owned location such as /usr/local/sbin (mode 0755 root:root)"
                break
            fi
            if acl_present "$p"; then
                PATH_OK=0; PATH_WHY="this script or one of its parent directories has an extended access control list (ACL) or its ACL cannot be checked; install it in a root-owned location such as /usr/local/sbin (mode 0755 root:root, no ACL)"
                break
            fi
            [ "$p" = "/" ] && break
            p="${p%/*}"
            [ -n "$p" ] || p="/"
        done
    fi
    if [ "$PATH_OK" != 1 ]; then
        # EVERY invocation from a path that fails validation is refused, whatever
        # the user and whether or not it is a dry run. This shell is already
        # reading the file, and a user with access to the Docker socket is
        # root-equivalent, so even an unprivileged run of an untrusted copy is
        # inside the threat model. Use the installed, trusted copy to preview.
        early_die "$PATH_WHY"
    fi
    # Read the script text ONCE and run the clean second stage from that text,
    # so the path is never opened a second time.
    SCRIPT_TEXT=$(cat -- "$SELF" 2>/dev/null) || early_die "cannot read this script"
    if ! { [ -n "$SCRIPT_TEXT" ] && [ "$(printf '%s' "$SCRIPT_TEXT" | wc -c)" -lt 100000 ]; }; then early_die "this script is empty or too large to restart"; fi
    for v in "${TWINGATE_API_KEY:-}" "${TWINGATE_NETWORK_URL:-}" "${TWINGATE_UPDATE_WAIT_SECS:-}" \
        "${TWINGATE_UPDATE_POLL_SECS:-}" "${NOTIFY_WEBHOOK_URL:-}" "${NOTIFY_WEBHOOK_ALLOWED_HOSTS:-}" "${HOST_LABEL:-}"; do
        case "$v" in *"$NL"*) early_die "an input variable contains a newline" ;; esac
    done
    RUN_TOKEN=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n') || RUN_TOKEN=""
    case "$RUN_TOKEN" in ''|*[!0-9a-f]*) early_die "cannot create a run token" ;; esac
    exec env -i PATH="$PATH" LC_ALL=C LANG=C TWINGATE_UPDATE_CLEAN_ENV=1 \
        TWINGATE_UPDATE_RUN_TOKEN="$RUN_TOKEN" sh -c "$SCRIPT_TEXT" "$SELF" "$@" 3<<EOF
TWINGATE_API_KEY=${TWINGATE_API_KEY:-}
TWINGATE_NETWORK_URL=${TWINGATE_NETWORK_URL:-}
TWINGATE_UPDATE_WAIT_SECS=${TWINGATE_UPDATE_WAIT_SECS:-}
TWINGATE_UPDATE_POLL_SECS=${TWINGATE_UPDATE_POLL_SECS:-}
NOTIFY_WEBHOOK_URL=${NOTIFY_WEBHOOK_URL:-}
NOTIFY_WEBHOOK_ALLOWED_HOSTS=${NOTIFY_WEBHOOK_ALLOWED_HOSTS:-}
HOST_LABEL=${HOST_LABEL:-}
EOF
fi
# Second run: the environment must hold nothing but the fixed names.
for n in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'); do
    case "$n" in
        PATH|LC_ALL|LANG|TWINGATE_UPDATE_CLEAN_ENV|TWINGATE_UPDATE_RUN_TOKEN|PWD|OLDPWD|SHLVL|_|DOCKER_HOST|DOCKER_CONFIG|HOME) ;;
        *) early_die "the environment was not cleared; refusing to run" ;;
    esac
done
RUN_TOKEN="${TWINGATE_UPDATE_RUN_TOKEN:-}"
case "$RUN_TOKEN" in ''|*[!0-9a-f]*) early_die "missing run token" ;; esac
SELF="$0"
case "$SELF" in */*) ;; *) SELF="./$SELF" ;; esac
# Read the inputs once; only these names are accepted.
API_KEY_V=""; NET_URL=""; IN_WAIT=""; IN_POLL=""; NOTIFY_URL=""; NOTIFY_ALLOWED=""; IN_LABEL=""
while IFS= read -r line <&3; do
    case "$line" in
        TWINGATE_API_KEY=*) API_KEY_V="${line#*=}" ;;
        TWINGATE_NETWORK_URL=*) NET_URL="${line#*=}" ;;
        TWINGATE_UPDATE_WAIT_SECS=*) IN_WAIT="${line#*=}" ;;
        TWINGATE_UPDATE_POLL_SECS=*) IN_POLL="${line#*=}" ;;
        NOTIFY_WEBHOOK_URL=*) NOTIFY_URL="${line#*=}" ;;
        NOTIFY_WEBHOOK_ALLOWED_HOSTS=*) NOTIFY_ALLOWED="${line#*=}" ;;
        HOST_LABEL=*) IN_LABEL="${line#*=}" ;;
    esac
done
exec 3<&-
unset TWINGATE_UPDATE_RUN_TOKEN
LC_ALL=C
LANG=C
export LC_ALL LANG
# Fixed, trusted locations. Never taken from the environment.
# /run is writable by root only, so only root can create, pre-create or hold
# the lock and the private runtime dir. Real runs need root (TRUSTED_UID).
LOCK_BASE="/run"
RUN_BASE="/run"
# docker talks to the local socket only, with a config dir and HOME of its own
# (empty, root-only dirs under the runtime dir; see the lock block below).
DOCKER_HOST="unix:///var/run/docker.sock"
DOCKER_CONFIG="$RUN_BASE/twingate-connector-update/docker-config"
HOME="$RUN_BASE/twingate-connector-update/home"
export DOCKER_HOST DOCKER_CONFIG HOME

IMAGE_TAG="twingate/connector:1"
ROLLBACK_TAG="twingate/connector:rollback-$$"
MAX_PAGES=10
DRY=0
YES=0
FORCE=0
NAME=""
TMPD=""
ENVF=""
RUNDIR=""
LOCKD=""
LOCKED=0
KEEP_TMPD=0
SELF_ID=""
SELF_RN=""
MAX_BYTES=1048576
FROM="unknown"
TO="unknown"
PRECHECK_WARN=0
API_OK=0
API_URL=""
NODES="[]"
GQL_INCOMPLETE=0

say() { printf '%s\n' "$*"; }
step() { if [ "$DRY" = 1 ]; then printf 'DRY-RUN would: %s\n' "$*"; else printf '==> %s\n' "$*"; fi; }

# secure_rmdir DIR: shred every regular file in DIR, then remove DIR. Callers
# pass only a directory they created or have just proven root-owned and not a link.
# It refuses (returns 1, removes nothing further) when DIR holds a mount point:
# the listing that descends into mounts must equal the one that stays on one
# filesystem (find -xdev). The removal itself also stays on one filesystem and
# never follows links.
secure_rmdir() {
    if ! _all=$(find "$1" -mindepth 1 2>/dev/null); then
        printf 'refused: cannot scan %s; not removing it\n' "$1" >&2
        return 1
    fi
    if ! _one=$(find "$1" -mindepth 1 -xdev 2>/dev/null); then
        printf 'refused: cannot scan %s; not removing it\n' "$1" >&2
        return 1
    fi
    if [ "$_all" != "$_one" ]; then
        printf 'refused: %s holds a mount point; not removing it\n' "$1" >&2
        return 1
    fi
    for f in "$1"/*; do
        if ! { [ -f "$f" ] && [ ! -L "$f" ]; }; then continue; fi
        if command -v shred >/dev/null 2>&1; then shred -u "$f" >/dev/null 2>&1 || rm -f "$f"; else rm -f "$f"; fi
    done
    # The one-file-system form is required: there is no unrestricted fallback.
    # If it fails (including an rm without the option) nothing more is tried.
    if ! rm -rf --one-file-system -- "$1" 2>/dev/null; then
        printf 'refused: cannot remove %s on one file system (rm --one-file-system is required)\n' "$1" >&2
        return 1
    fi
}

cleanup() {
    if [ -n "$TMPD" ] && [ -d "$TMPD" ] && [ "$KEEP_TMPD" != 1 ]; then
        secure_rmdir "$TMPD"
    fi
    if [ "$LOCKED" = 1 ] && [ -n "$LOCKD" ]; then
        rmdir "$RUNDIR/docker-config" "$RUNDIR/home" 2>/dev/null
        [ -z "$RUNDIR" ] || rmdir "$RUNDIR" 2>/dev/null
        rm -f "$LOCKD/pid" "$LOCKD/start" "$LOCKD/ident" "$LOCKD/rundir"
        rmdir "$LOCKD" 2>/dev/null
        LOCKED=0
    fi
    return 0
}
set_traps() {
    trap 'cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    trap 'exit 141' PIPE
    trap 'exit 131' QUIT
}
block_signals() { trap '' INT TERM HUP PIPE QUIT; }
# After the Connector is verified or rolled back: INT TERM HUP QUIT work again.
# PIPE stays ignored so a closed pipe cannot stop the final report or notice.
unblock_signals() {
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    trap 'exit 131' QUIT
}
set_traps

notify() {
    # $1 = result. Never fails the update, never prints the URL.
    [ "$DRY" = 1 ] && return 0
    [ -n "$NOTIFY_URL" ] || return 0
    [ -n "$NOTIFY_ALLOWED" ] || { say "notice skipped: NOTIFY_WEBHOOK_ALLOWED_HOSTS is not set (no default; list the trusted webhook host names)"; return 0; }
    case "$NOTIFY_URL" in
        https://[A-Za-z0-9]*) ;;
        *) say "notice skipped: NOTIFY_WEBHOOK_URL is not an https URL"; return 0 ;;
    esac
    case "$NOTIFY_URL" in
        *[!A-Za-z0-9._~:/?\&=%+@,\;-]*) say "notice skipped: NOTIFY_WEBHOOK_URL has unexpected characters"; return 0 ;;
    esac
    # Host check: exact match against the allowlist; never an IP literal,
    # localhost, a userinfo URL or a name without a dot.
    auth="${NOTIFY_URL#https://}"
    auth="${auth%%[/?#]*}"
    case "$auth" in
        *@*|*\[*) say "notice skipped: NOTIFY_WEBHOOK_URL host is not allowed"; return 0 ;;
    esac
    whost="${auth%%:*}"
    wport=""
    [ "$whost" = "$auth" ] || wport="${auth#*:}"
    case "$wport" in *[!0-9]*) say "notice skipped: NOTIFY_WEBHOOK_URL has a bad port"; return 0 ;; esac
    whost=$(printf '%s' "$whost" | tr '[:upper:]' '[:lower:]')
    case "$whost" in
        *.*) ;;
        *) say "notice skipped: NOTIFY_WEBHOOK_URL host is not allowed"; return 0 ;;
    esac
    case "$whost" in
        *[!a-z0-9.-]*|.*|*..*|*-.*|localhost|*.localhost) say "notice skipped: NOTIFY_WEBHOOK_URL host is not allowed"; return 0 ;;
    esac
    # The last label must be letters only: this rejects every IPv4 spelling
    # (dotted, octal, hex, decimal) and any IP literal.
    case "${whost##*.}" in
        ''|*[!a-z]*) say "notice skipped: NOTIFY_WEBHOOK_URL host is not allowed"; return 0 ;;
    esac
    hostok=0
    oldifs="$IFS"; IFS=","; set -f
    for entry in $NOTIFY_ALLOWED; do
        entry=$(printf '%s' "$entry" | tr '[:upper:]' '[:lower:]')
        [ "$entry" = "$whost" ] && hostok=1
    done
    set +f; IFS="$oldifs"
    [ "$hostok" = 1 ] || { say "notice skipped: the NOTIFY_WEBHOOK_URL host is not in NOTIFY_WEBHOOK_ALLOWED_HOSTS"; return 0; }
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        say "notice skipped: curl or jq missing"
        return 0
    fi
    label="${IN_LABEL:-$(hostname -s 2>/dev/null || echo host)}"
    body=$(jq -nc --arg h "$label" --arg c "$NAME" --arg f "$FROM" --arg t "$TO" --arg r "$1" \
        '{"host-label":$h,connector:$c,from:$f,to:$t,result:$r}') || { say "notice skipped"; return 0; }
    # URL goes to curl on stdin (config), not argv.
    # -q first: ignore any .curlrc. No redirects, no proxy, https only.
    if printf 'url = "%s"\n' "$NOTIFY_URL" |
        curl -q -sS -K - --proto '=https' --max-redirs 0 --noproxy '*' --max-time 5 -X POST \
            -H 'Content-Type: application/json' --data "$body" >/dev/null 2>&1; then
        say "notice sent"
    else
        say "notice failed (update result unaffected)"
    fi
}

finish() {
    # $1 = result word, $2 = exit code
    say "RESULT: connector=$NAME from=$FROM to=$TO result=$1"
    notify "$1"
    return "$2"
}

owned() { [ -n "$(find "$1" -maxdepth 0 -user "$TRUSTED_UID" 2>/dev/null)" ]; }
die() { say "refused: $1" >&2; exit 2; }
warn() { say "WARNING: $*"; PRECHECK_WARN=1; }

# ---- arguments -------------------------------------------------------------
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --yes) YES=1 ;;
        --force) FORCE=1 ;;
        -h|--help) sed -n '2,/^umask 077/{/^umask 077/!p;}' "$0"; exit 0 ;;
        -*) die "unknown option '$a'" ;;
        *) [ -z "$NAME" ] || die "exactly one container name is allowed"; NAME="$a" ;;
    esac
done
[ -n "$NAME" ] || die "usage: $0 [--dry-run] [--yes] [--force] <connector-container-name>"
case "$NAME" in
    [A-Za-z0-9]*) ;;
    *) die "invalid container name" ;;
esac
case "$NAME" in
    *[!A-Za-z0-9_.-]*) die "invalid container name" ;;
esac
[ "${#NAME}" -le 63 ] || die "invalid container name"
# The name is validated above; the only regex metacharacter it can hold is '.'.
NAME_RE=$(printf '%s' "$NAME" | sed 's/\./\\./g')

command -v docker >/dev/null 2>&1 || die "docker not found"
command -v jq >/dev/null 2>&1 || die "jq not found"

# ---- private runtime dir and host-wide lock (real runs only) -----------------
# Both live under fixed locations (LOCK_BASE, RUN_BASE); the environment
# (TMPDIR, XDG_RUNTIME_DIR) is never consulted.
RUNDIR="$RUN_BASE/twingate-connector-update"
# proc_start PID: field 22 of /proc/PID/stat (process start time). The command
# name (field 2) may contain spaces and parentheses, so cut after the last ')'.
proc_start() {
    [ -r "/proc/$1/stat" ] || return 1
    st=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    rest="${st##*) }"
    printf '%s\n' "$rest" | cut -d' ' -f20
}
# holder_live PID: a lock holder counts as live only if the PID exists AND its
# start time, command line (this script's path) and run token all match what
# the lock recorded. A reused PID never matches, so it is stale.
holder_live() {
    kill -0 "$1" 2>/dev/null || return 1
    [ -r "/proc/$1/stat" ] || return 0
    cur=$(proc_start "$1") || return 0
    rec=$(cat "$LOCKD/start" 2>/dev/null) || return 1
    [ -n "$rec" ] && [ "$cur" = "$rec" ] || return 1
    rec_script=$(sed -n 's/^script=//p' "$LOCKD/ident" 2>/dev/null | head -n 1)
    rec_token=$(sed -n 's/^token=//p' "$LOCKD/ident" 2>/dev/null | head -n 1)
    [ -n "$rec_script" ] && [ -n "$rec_token" ] || return 1
    tr '\0' '\n' <"/proc/$1/cmdline" 2>/dev/null | grep -qxF -- "$rec_script" || return 1
    tr '\0' '\n' <"/proc/$1/environ" 2>/dev/null | grep -qxF -- "TWINGATE_UPDATE_RUN_TOKEN=$rec_token" || return 1
    return 0
}
if [ "$DRY" != 1 ]; then
    [ "$(id -u)" = "$TRUSTED_UID" ] || die "a real run needs root (use sudo); --dry-run works without it"
    private() { [ -d "$1" ] && [ ! -L "$1" ] && [ -n "$(find "$1" -maxdepth 0 -user "$TRUSTED_UID" -perm 700 2>/dev/null)" ]; }
    if ! { [ -d "$RUN_BASE" ] && [ ! -L "$RUN_BASE" ]; }; then die "no trusted runtime dir"; fi
    if ! { [ -d "$LOCK_BASE" ] && [ ! -L "$LOCK_BASE" ]; }; then die "no host-wide lock dir; refusing to run without a lock"; fi
    LOCKD="$LOCK_BASE/twingate-connector-update.lock.d"
    if ! mkdir "$LOCKD" 2>/dev/null; then
        # An existing lock path not owned by root is hostile: never read, use or
        # remove it, and the message names nothing taken from it.
        { [ -d "$LOCKD" ] && [ ! -L "$LOCKD" ] && owned "$LOCKD"; } || die "the lock path is not a root-owned directory; refusing to use it"
        holder=$(cat "$LOCKD/pid" 2>/dev/null) || holder=""
        case "$holder" in ''|*[!0-9]*) die "another run holds the lock and its pid is unreadable ($LOCKD); if no run is active, remove that directory" ;; esac
        if holder_live "$holder"; then die "another run is in progress (pid $holder)"; fi
        say "removing a stale lock left by pid $holder"
        # The dead run may have left its private dir (with the env file) behind
        # after a SIGKILL. Remove only the recorded root-owned, non-link dir.
        old_run=$(cat "$LOCKD/rundir" 2>/dev/null) || old_run=""
        case "$old_run" in
            "$RUNDIR"/run.*)
                case "${old_run#"$RUNDIR"/}" in
                    */*|*..*) ;;
                    *) if [ -d "$old_run" ] && [ ! -L "$old_run" ] && owned "$old_run"; then
                           say "removing the private dir left by the dead run"
                           secure_rmdir "$old_run"
                       fi ;;
                esac ;;
        esac
        rm -f "$LOCKD/pid" "$LOCKD/start" "$LOCKD/ident" "$LOCKD/rundir"
        rmdir "$LOCKD" 2>/dev/null
        mkdir "$LOCKD" 2>/dev/null || die "cannot take the lock"
    fi
    LOCKED=1
    # PID plus start time plus an updater-specific identity (this script's path
    # and a random token that sits in this process's environment).
    printf '%s\n' "$$" >"$LOCKD/pid"
    proc_start "$$" >"$LOCKD/start"
    printf 'script=%s\ntoken=%s\n' "$SELF" "$RUN_TOKEN" >"$LOCKD/ident"
    mkdir -m 700 "$RUNDIR" 2>/dev/null
    private "$RUNDIR" || die "runtime dir $RUNDIR is not a private (mode 700) directory owned by you"
    # The docker config and home dirs must start empty: remove anything left
    # there (we hold the lock and RUNDIR is private), then create them fresh.
    for d in "$RUNDIR/docker-config" "$RUNDIR/home"; do
        if [ -L "$d" ]; then
            rm -f "$d" || die "cannot reset $d"
        elif [ -e "$d" ]; then
            { [ -d "$d" ] && owned "$d"; } || die "$d is not a directory owned by you"
            secure_rmdir "$d"
            [ ! -e "$d" ] || die "cannot reset $d"
        fi
    done
    mkdir -m 700 "$RUNDIR/docker-config" "$RUNDIR/home" 2>/dev/null
    for d in "$RUNDIR/docker-config" "$RUNDIR/home"; do
        [ -z "$(ls -A "$d" 2>/dev/null)" ] || die "$d is not empty"
    done
    if ! private "$RUNDIR/docker-config" || ! private "$RUNDIR/home"; then
        die "docker config or home dir under $RUNDIR is not a private directory owned by you"
    fi
    # Per-run private dir: recorded in the lock BEFORE it is created, so a
    # SIGKILL can never leave an unrecorded dir.
    TMPD="$RUNDIR/run.$$"
    printf '%s\n' "$TMPD" >"$LOCKD/rundir"
    mkdir -m 700 "$TMPD" 2>/dev/null || die "cannot create private temp dir"
else
    TMPD=$(mktemp -d) || die "cannot create a temp dir"
fi

# ---- inspect and layout allowlist -------------------------------------------
INSPECT=$(docker inspect "$NAME" 2>/dev/null) || die "container '$NAME' not found"
printf '%s' "$INSPECT" | jq -e 'type=="array" and length==1' >/dev/null 2>&1 || die "unexpected docker inspect output"

OLD_ID=$(printf '%s' "$INSPECT" | jq -r '.[0].Image')
case "$OLD_ID" in
    sha256:[0-9a-f]*) ;;
    *) die "cannot read the running image id" ;;
esac
case "$OLD_ID" in
    *[!A-Za-z0-9:]*) die "cannot read the running image id" ;;
esac

# The old image must exist locally: rollback depends on it.
IMGI=$(docker image inspect "$OLD_ID" 2>/dev/null) || die "the running image $OLD_ID is not present on this host, so a rollback would be impossible. Nothing was changed."
IMG0=$(printf '%s' "$IMGI" | jq -ce 'if type=="array" and length==1 then .[0] else error("bad") end' 2>/dev/null) || die "cannot read the running image's config. Nothing was changed."

LOGDRV=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null | head -n 1) || LOGDRV=""
case "$LOGDRV" in ''|*[!A-Za-z0-9._-]*) LOGDRV="json-file" ;; esac
# Docker gives a host-networked container with no --hostname the HOST's hostname
# (moby daemon/container.go), so that value is the default for NetworkMode host.
HOSTNAME_HOST=$(uname -n 2>/dev/null) || HOSTNAME_HOST=""

why=$(printf '%s' "$INSPECT" | jq -r --arg img "$IMAGE_TAG" --arg logdrv "$LOGDRV" --arg hosthn "$HOSTNAME_HOST" --argjson i "$IMG0" '
  def blank: . == null or . == [] or . == {} or . == "" or . == 0 or . == false;
  def norm: if blank then null else . end;
  def handled_host: ["NetworkMode","RestartPolicy","Binds","Privileged","CapAdd","CapDrop","SecurityOpt","PidMode","UsernsMode","ReadonlyRootfs","Memory","MemorySwap","MemoryReservation","CpuShares","NanoCpus","CpuQuota","LogConfig","Dns","DnsSearch","DnsOptions","ExtraHosts","Tmpfs","Ulimits","Devices","DeviceCgroupRules","DeviceRequests","Sysctls","GroupAdd","AutoRemove"];
  def host_defaults: {"CgroupnsMode":["private"],"IpcMode":["private","shareable"],"ShmSize":[67108864],"Runtime":["runc"],"ConsoleSize":[[0,0]],"Isolation":["default"],"MemorySwappiness":[-1],"PidsLimit":[-1]};
  def masked_ok: ["/proc/asound","/proc/acpi","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap"];
  def readonly_ok: ["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"];
  def handled_cfg: ["Image","Env","Hostname","AttachStdin","AttachStdout","AttachStderr","Tty","User","Entrypoint","Cmd","Labels","Healthcheck","WorkingDir"];
  def hasbyte($b): explode | any(. == $b);
  .[0] as $c | ($c.HostConfig // {}) as $h | ($c.Config // {}) as $cc | ($i.Config // {}) as $ic
  | ($h.LogConfig // {}) as $l | ($cc.Env // []) as $env
  | ($h | to_entries | map(select((.key as $k | handled_host | index($k)) | not))
       | map(select((.value | norm) != null))
       | map(select(
           if .key == "MaskedPaths" then ((.value - masked_ok) | length) > 0
           elif .key == "ReadonlyPaths" then ((.value - readonly_ok) | length) > 0
           else (. as $e | (host_defaults[.key] // []) | any(.[]; . == $e.value) | not) end))
       | map(.key)) as $hostextra
  | ($cc | to_entries | map(select((.key as $k | handled_cfg | index($k)) | not))
       | map(select(((.value | norm)) != (($ic[.key]) | norm)))
       | map(.key)) as $cfgextra
  | ([ $env[] | select(type == "string" and startswith("TWINGATE_")) ]) as $kept
  | [ (if $cc.Image != $img then "image is not " + $img else empty end),
      (if $h.NetworkMode != "host" then "network mode is not host" else empty end),
      (if ($h.RestartPolicy.Name != "unless-stopped") or (($h.RestartPolicy.MaximumRetryCount // 0) != 0) then "restart policy is not unless-stopped" else empty end),
      (if ($h.Binds | blank | not) or ($c.Mounts | blank | not) then "binds or mounts present" else empty end),
      (if ($cc.User | norm) != ($ic.User | norm) then "user override" else empty end),
      (if ($cc.Entrypoint | norm) != ($ic.Entrypoint | norm) then "entrypoint override" else empty end),
      (if ($cc.Cmd | norm) != ($ic.Cmd | norm) then "command override" else empty end),
      (if ($cc.Labels | norm) != ($ic.Labels | norm) then "labels beyond the image labels" else empty end),
      (if ($cc.Healthcheck | norm) != ($ic.Healthcheck | norm) then "healthcheck override" else empty end),
      (if ($cc.WorkingDir | norm) != ($ic.WorkingDir | norm) then "working dir override" else empty end),
      (if $cc.Tty == true then "tty" else empty end),
      (if $h.Privileged == true then "privileged" else empty end),
      (if ($h.CapAdd | blank | not) then "extra capabilities" else empty end),
      (if ($h.CapDrop | blank | not) then "dropped capabilities" else empty end),
      (if ($h.SecurityOpt | blank | not) then "security options" else empty end),
      (if ($h.PidMode | blank | not) then "pid mode" else empty end),
      (if ($h.UsernsMode | blank | not) then "userns mode" else empty end),
      (if $h.ReadonlyRootfs == true then "read-only root filesystem" else empty end),
      (if ([$h.Memory, $h.MemorySwap, $h.MemoryReservation, $h.CpuShares, $h.NanoCpus, $h.CpuQuota] | map(select(. | blank | not)) | length) > 0 then "resource limits" else empty end),
      (if (($l.Type // "") != "" and $l.Type != $logdrv) or ($l.Config | blank | not) then "non-default log config" else empty end),
      (if ($h.Dns | blank | not) or ($h.DnsSearch | blank | not) or ($h.DnsOptions | blank | not) then "dns settings" else empty end),
      (if ($h.ExtraHosts | blank | not) then "extra hosts" else empty end),
      (if ($h.Tmpfs | blank | not) then "tmpfs" else empty end),
      (if ($h.Ulimits | blank | not) then "ulimits" else empty end),
      (if ($h.Devices | blank | not) or ($h.DeviceCgroupRules | blank | not) or ($h.DeviceRequests | blank | not) then "devices present" else empty end),
      (if ($h.Sysctls | blank | not) then "sysctls present" else empty end),
      (if ($h.GroupAdd | blank | not) then "extra groups" else empty end),
      (if $h.AutoRemove == true then "auto-remove" else empty end),
      (if ($hostextra | length) > 0 then "host settings a recreate would drop: " + ($hostextra | join(",")) else empty end),
      (if ($cc.OpenStdin == true or $cc.StdinOnce == true) then "stdin open" else empty end),
      (if ($cc.Domainname | norm) != null then "domain name override" else empty end),
      (if ($cc.Hostname | norm) != null and $cc.Hostname != ($c.Id // "")[0:12]
          and (($h.NetworkMode == "host" and ($h.UTSMode | blank) and $hosthn != "" and $cc.Hostname == $hosthn) | not)
        then "hostname override (only the default is accepted: the host name with host networking, else the container-ID prefix)" else empty end),
      (if ($cc.AttachStdin // false) != false or ($cc.AttachStdout // false) != false or ($cc.AttachStderr // false) != false then "attach settings differ from a detached run" else empty end),
      (if ($cfgextra | length) > 0 then "container settings a recreate would drop: " + ($cfgextra | join(",")) else empty end),
      (if ($env | map(select((type != "string") or hasbyte(10) or hasbyte(13) or hasbyte(0) or (contains("=") | not))) | length) > 0 then "malformed environment entry (newline, CR, NUL or missing =)" else empty end),
      (if ($kept | map(select(test("^TWINGATE_[A-Za-z0-9_]+=") | not)) | length) > 0 then "malformed environment entry (invalid variable name)" else empty end),
      (if ($kept | map(select(sub("^[^=]*="; "") | test("^[A-Za-z0-9._~:/+@,=-]*\\z") | not)) | length) > 0 then "environment value not safe for an env file (only A-Za-z0-9 . _ ~ : / + @ , = - are allowed)" else empty end),
      (if ($kept | map(select(utf8bytelength > 8192)) | length) > 0 then "malformed environment entry (line too long)" else empty end),
      (if ($kept | map(sub("=.*$"; "")) | (length) != (unique | length)) then "malformed environment entry (duplicate variable)" else empty end),
      (if ($env | map(select(type == "string" and startswith("TWINGATE_"))) | length) == 0 then "no TWINGATE_ environment" else empty end),
      (if ($env | map(select(type == "string" and (startswith("TWINGATE_") | not))) - ($ic.Env // []) | length) > 0 then "environment variables a recreate would drop" else empty end)
    ] | join("; ")' 2>/dev/null) || die "cannot read layout"
[ -z "$why" ] || die "layout differs from the verified one ($why). Nothing was changed."

# ---- Twingate Admin API (read only) -----------------------------------------
api_setup() {
    [ -n "$API_KEY_V" ] && [ -n "$NET_URL" ] || return 1
    v="${NET_URL#https://}"
    sub="${v%.twingate.com}"
    if [ "$sub" = "$v" ] || [ -z "$sub" ]; then
        warn "TWINGATE_NETWORK_URL is not <network>.twingate.com; pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0
    fi
    case "$sub" in
        *[!A-Za-z0-9-]*) warn "TWINGATE_NETWORK_URL is not <network>.twingate.com (no path, port or userinfo allowed); pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0 ;;
    esac
    case "$API_KEY_V" in
        *[!A-Za-z0-9._~+/=-]*) warn "TWINGATE_API_KEY has unexpected characters; pre-check skipped."; return 0 ;;
    esac
    command -v curl >/dev/null 2>&1 || { warn "curl missing; pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0; }
    API_URL="https://$sub.twingate.com"
    API_OK=1
    return 0
}

# Fills NODES with every Connector (paged, capped); returns 1 on a failure.
gql_fetch() {
    cursor=""; page=0; NODES="[]"; GQL_INCOMPLETE=0
    while :; do
        page=$((page + 1))
        body=$(jq -nc --arg c "$cursor" '{query:"query($after: String) { connectors(first: 100, after: $after) { pageInfo { hasNextPage endCursor } edges { node { id name state version remoteNetwork { id } } } } }",variables:{after:(if $c=="" then null else $c end)}}') || return 1
        # curl: -q first (no .curlrc), no redirects, no proxy, https only, hard
        # size cap. The key goes to this one curl on stdin (a config), never
        # into the environment or argv. The output goes to a file in the private
        # dir so curl's exit status is not lost; its size is checked below.
        apif="$TMPD/api.out"
        rm -f "$apif"
        printf 'url = "%s/api/graphql/"\nheader = "X-API-KEY: %s"\n' "$API_URL" "$API_KEY_V" |
            curl -q -sS --fail -K - --proto '=https' --max-redirs 0 --noproxy '*' --max-filesize "$MAX_BYTES" --max-time 10 -X POST -H 'Content-Type: application/json' --data "$body" -o "$apif" 2>/dev/null
        crc=$?
        # Trust the output only if curl itself exited 0 (no pipeline here, so the
        # status is curl's own), and only within the byte bound.
        if [ "$crc" != 0 ] || [ ! -f "$apif" ] || [ -L "$apif" ]; then rm -f "$apif"; return 1; fi
        sz=$(wc -c <"$apif" 2>/dev/null) || sz=""
        case "$sz" in ''|*[!0-9]*) rm -f "$apif"; return 1 ;; esac
        if [ "$sz" -gt "$MAX_BYTES" ] || [ "$sz" -eq 0 ]; then rm -f "$apif"; return 1; fi
        resp=$(cat "$apif") || { rm -f "$apif"; return 1; }
        rm -f "$apif"
        [ -n "$resp" ] || return 1
        printf '%s' "$resp" | jq -e '(.errors // null) == null and (.data.connectors.edges | type) == "array"' >/dev/null 2>&1 || return 1
        got=$(printf '%s' "$resp" | jq -c '[.data.connectors.edges[].node]' 2>/dev/null) || return 1
        NODES=$(jq -nc --argjson a "$NODES" --argjson b "$got" '$a + $b' 2>/dev/null) || return 1
        more=$(printf '%s' "$resp" | jq -r '.data.connectors.pageInfo.hasNextPage // false' 2>/dev/null) || return 1
        [ "$more" = "true" ] || return 0
        cursor=$(printf '%s' "$resp" | jq -r '.data.connectors.pageInfo.endCursor // ""' 2>/dev/null) || return 1
        [ -n "$cursor" ] || return 1
        if [ "$page" -ge "$MAX_PAGES" ]; then GQL_INCOMPLETE=1; return 0; fi
    done
}

precheck() {
    if api_setup; then
        [ "$API_OK" = 1 ] || return 0
        if ! gql_fetch; then
            warn "could not read Connector state from the Twingate API. Confirm the other Connector is ALIVE before continuing."
            return 0
        fi
        [ "$GQL_INCOMPLETE" != 1 ] || warn "more than $MAX_PAGES pages of Connectors; the list is incomplete."
        selfn=$(printf '%s' "$NODES" | jq -c --arg n "$NAME" '[.[] | select(.name == $n)]')
        if [ "$(printf '%s' "$selfn" | jq 'length')" != 1 ]; then
            warn "this Connector was not found (exactly once) by name '$NAME' in the Twingate network, so its remote network is unknown. Confirm the other Connector is ALIVE yourself."
            return 0
        fi
        rn=$(printf '%s' "$selfn" | jq -r '.[0].remoteNetwork.id // ""')
        sid=$(printf '%s' "$selfn" | jq -r '.[0].id // ""')
        SELF_ID="$sid"; SELF_RN="$rn"
        if [ -z "$rn" ] || [ -z "$sid" ]; then
            warn "this Connector's remote network could not be read. Confirm the other Connector is ALIVE yourself."
            return 0
        fi
        alive=$(printf '%s' "$NODES" | jq -r --arg rn "$rn" --arg sid "$sid" '[.[] | select(.remoteNetwork.id == $rn and .id != $sid and .state == "ALIVE")] | length' 2>/dev/null) || alive=""
        case "$alive" in
            ''|*[!0-9]*) warn "could not count the other Connectors. Confirm the other Connector is ALIVE before continuing." ;;
            *) if [ "$alive" -ge 1 ]; then say "pre-check: $alive other Connector(s) ALIVE in this Connector's remote network."; else warn "no OTHER Connector is ALIVE in this Connector's remote network. Updating this one may cut access."; fi ;;
        esac
    else
        say "REMINDER: confirm the OTHER Connector in this remote network is ALIVE in Twingate before continuing (set TWINGATE_API_KEY and TWINGATE_NETWORK_URL for an automatic read-only check)."
    fi
}
precheck

if [ "$DRY" != 1 ] && [ "$YES" = 1 ] && [ "$FORCE" != 1 ] && [ "$PRECHECK_WARN" = 1 ]; then
    say "A pre-check warning is present, so --yes will not continue. Fix it or re-run with --force. Nothing was changed." >&2
    { finish "aborted-precheck" 3; exit "$?"; }
fi

# ---- pull and compare -------------------------------------------------------
if [ "$DRY" = 1 ]; then
    step "docker pull $IMAGE_TAG (skipped in dry-run; comparing against the local copy)"
else
    step "docker pull $IMAGE_TAG"
    docker pull "$IMAGE_TAG" >/dev/null 2>&1 || { say "docker pull failed; nothing was changed." >&2; FROM="unknown"; { finish "failed-pull" 1; exit "$?"; }; }
fi
NEW_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG" 2>/dev/null) || NEW_ID=""
case "$NEW_ID" in
    sha256:[0-9a-f]*) ;;
    *) say "cannot read the id of $IMAGE_TAG; nothing was changed." >&2; { finish "failed-image-id" 1; exit "$?"; } ;;
esac

FROM=$(docker exec "$NAME" ./connectord --version 2>/dev/null | head -n 1) || FROM=""
[ -n "$FROM" ] || FROM="unknown"

if [ "$OLD_ID" = "$NEW_ID" ]; then
    TO="$FROM"
    say "already up to date ($FROM)"
    { finish "up-to-date" 0; exit "$?"; }
fi

if [ "$DRY" = 1 ]; then
    TO="unknown (not determined in dry-run)"
else
    TO=$(docker run --rm --network none --entrypoint ./connectord "$NEW_ID" --version 2>/dev/null | head -n 1) || TO=""
    [ -n "$TO" ] || TO="unknown"
fi
say "current version: $FROM"
say "new version:     $TO"

# ---- confirmation -----------------------------------------------------------
if [ "$DRY" = 1 ]; then
    step "ask for confirmation unless --yes"
elif [ "$YES" != 1 ]; then
    if [ "$FROM" = "unknown" ] || [ "$TO" = "unknown" ]; then
        say "A version could not be determined, so no safe prompt is possible. Re-run with --yes to proceed." >&2
        { finish "aborted-unknown-version" 3; exit "$?"; }
    fi
    printf 'Update %s from %s to %s? Type yes to continue: ' "$NAME" "$FROM" "$TO"
    ans=""
    read -r ans || ans=""
    [ "$ans" = "yes" ] || { say "aborted by operator; nothing was changed."; { finish "aborted" 3; exit "$?"; }; }
fi

# ---- helpers ----------------------------------------------------------------
# secs VALUE DEFAULT MAX: print VALUE only if it is a canonical integer
# (no sign, no leading zero, 1-2 digits) within 1..MAX, else DEFAULT.
secs() {
    case "$1" in
        [1-9]|[1-9][0-9]) if [ "$1" -le "$3" ]; then printf '%s' "$1"; return 0; fi ;;
    esac
    printf '%s' "$2"
}

# Deadline helpers: elapsed wall time, never unchecked arithmetic on input.
now() { date +%s 2>/dev/null || echo 0; }
# nap POLL DEADLINE_LEFT: sleep min(poll, left) seconds.
nap() { if [ "$2" -lt "$1" ]; then sleep "$2"; else sleep "$1"; fi; }

wait_healthy() {
    maxw=$(secs "${IN_WAIT:-60}" 60 60)
    poll=$(secs "${IN_POLL:-2}" 2 60)
    t0=$(now); iter=0
    while :; do
        st=$(docker ps --filter "name=^${NAME_RE}\$" --format '{{.Status}}' 2>/dev/null) || st=""
        case "$st" in
            Up*unhealthy*|Up*"health: starting"*|"") ;;
            Up*)
                if docker exec "$NAME" ./connectord --version >/dev/null 2>&1; then return 0; fi ;;
        esac
        left=$((maxw - ($(now) - t0))); iter=$((iter + 1))
        { [ "$left" -gt 0 ] && [ "$((iter * poll))" -le "$maxw" ]; } || return 1
        nap "$poll" "$left"
    done
}

recreate() {
    # $1 = image
    docker stop "$NAME" >/dev/null 2>&1
    docker rm "$NAME" >/dev/null 2>&1
    docker run -d --network host --env-file "$ENVF" --name "$NAME" --restart=unless-stopped "$1" >/dev/null 2>&1
}

# Returns 0 confirmed, 1 not confirmed, 2 not configured. The Connector must be
# the one seen before the update (same id and remote network; else exactly one
# Connector of that exact name), ALIVE, on exactly the new version, from a
# complete, error-free API answer.
confirm_twingate() {
    [ "$API_OK" = 1 ] || return 2
    ver=$(printf '%s' "$TO" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n 1)
    [ -n "$ver" ] || return 1
    maxw=$(secs "${IN_WAIT:-60}" 60 60)
    poll=$(secs "${IN_POLL:-2}" 2 60)
    t0=$(now); iter=0
    while :; do
        if gql_fetch && [ "$GQL_INCOMPLETE" != 1 ]; then
            ok=$(printf '%s' "$NODES" | jq -r --arg n "$NAME" --arg v "$ver" --arg id "$SELF_ID" --arg rn "$SELF_RN" '
              [.[] | select(.state == "ALIVE"
                and (((.version // "") | sub("^Connector "; "")) == $v)
                and (if $id != "" then (.id == $id and .remoteNetwork.id == $rn) else (.name == $n) end))] | length' 2>/dev/null) || ok=""
            [ "$ok" = 1 ] && return 0
        fi
        left=$((maxw - ($(now) - t0))); iter=$((iter + 1))
        { [ "$left" -gt 0 ] && [ "$((iter * poll))" -le "$maxw" ]; } || return 1
        nap "$poll" "$left"
    done
}

step "block INT TERM HUP PIPE QUIT from here until the new container is verified or rolled back"
step "tag the old image $OLD_ID as $ROLLBACK_TAG so a prune cannot drop it"
step "write an env file with only the TWINGATE_* variables in a private temp dir"
step "docker stop $NAME; docker rm $NAME"
step "docker run -d --network host --env-file <private env file> --name $NAME --restart=unless-stopped $IMAGE_TAG"
step "wait up to 60 s for the container to be Up and healthy and answer connectord --version"
step "on failure: recreate from $ROLLBACK_TAG with the same env and exit non-zero; if that fails too, keep the env file privately and say so"
step "if the Admin API is configured: require this Connector ALIVE with the new version"
step "never prune images; the old image stays on the host"
[ "$DRY" != 1 ] || { finish "dry-run" 0; exit "$?"; }

# ---- protected window: from here no signal may leave the Connector gone -------
block_signals
ENVF="$TMPD/connector.env"
printf '%s' "$INSPECT" | jq -r '.[0].Config.Env[] | select(startswith("TWINGATE_"))' >"$ENVF" 2>/dev/null || die "cannot build the env file"
chmod 600 "$ENVF"
[ -s "$ENVF" ] || die "env file is empty"
INSPECT=""
docker tag "$OLD_ID" "$ROLLBACK_TAG" >/dev/null 2>&1 || die "cannot tag the old image for rollback. Nothing was changed."

if recreate "$IMAGE_TAG" && wait_healthy; then
    unblock_signals
    NOW=$(docker exec "$NAME" ./connectord --version 2>/dev/null | head -n 1) || NOW=""
    [ -z "$NOW" ] || TO="$NOW"
    say "old image kept as $ROLLBACK_TAG (remove it with docker rmi when you no longer need it)"
    confirm_twingate; rc=$?
    case "$rc" in
        0) say "Twingate confirms this Connector is ALIVE on $TO."; { finish "updated" 0; exit "$?"; } ;;
        2) say "Health was NOT confirmed in Twingate (no Admin API configured); only the local container check passed. Look at the Connector in Twingate yourself."; { finish "updated" 0; exit "$?"; } ;;
        *) say "The container is up and healthy locally, but Twingate did NOT show this Connector ALIVE on the new version within the wait. Health is NOT confirmed in Twingate; check it now." >&2
           { finish "updated-unconfirmed" 4; exit "$?"; } ;;
    esac
fi

say "New container did not become healthy within the wait. Rolling back from $ROLLBACK_TAG." >&2
if recreate "$ROLLBACK_TAG" && wait_healthy; then
    unblock_signals
    say "Rollback succeeded: $NAME runs the old image again (kept as $ROLLBACK_TAG)." >&2
    TO="$FROM (rolled back)"
    { finish "rolled-back" 1; exit "$?"; }
fi
unblock_signals
say "ROLLBACK FAILED: the rollback container did not start healthy. $NAME is DOWN or unhealthy. Fix it by hand now." >&2
if docker image inspect "$ROLLBACK_TAG" >/dev/null 2>&1; then
    say "The old image is still on this host as $ROLLBACK_TAG (id $OLD_ID)." >&2
else
    say "The old image is NOT present on this host any more (was $OLD_ID, tag $ROLLBACK_TAG). Pull the image again to recover." >&2
fi
KEEP="$RUNDIR/connector-env-$NAME-$$.env"
if mv "$ENVF" "$KEEP" 2>/dev/null; then
    chmod 600 "$KEEP" 2>/dev/null
else
    KEEP="$ENVF"
    KEEP_TMPD=1
fi
say "The saved env file (TWINGATE_* values, mode 600) is KEPT at: $KEEP" >&2
say "Use it to recreate the container (docker run -d --network host --env-file <that file> --name $NAME --restart=unless-stopped <image>), then shred it: shred -u '$KEEP'" >&2
finish "rollback-failed" 2
