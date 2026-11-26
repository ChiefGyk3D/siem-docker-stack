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
# One run at a time per host (lock dir in a private runtime dir).
#
# Environment (all optional, never put secrets in argv):
#   NOTIFY_WEBHOOK_URL   https URL; a short JSON notice is POSTed at the end
#                        (5 s timeout). A failed notice never fails the update.
#   HOST_LABEL           label for the notice (default: short hostname)
#   TWINGATE_API_KEY, TWINGATE_NETWORK_URL
#                        if both set, a read-only Admin API pre-check looks at
#                        the other Connectors in THIS Connector's remote
#                        network, and after the update this Connector must be
#                        seen ALIVE with the new version. TWINGATE_NETWORK_URL
#                        must be <network>.twingate.com (https:// optional).
#                        A pre-check warning aborts under --yes unless --force.
#   TWINGATE_UPDATE_WAIT_SECS (default and maximum 60), TWINGATE_UPDATE_POLL_SECS
#   TWINGATE_UPDATE_BIN_DIR   test seam: ONE absolute directory put first on
#                        PATH (used by the tests for fake docker and curl).
# See docs/twingate-connector-update-script.md.

umask 077
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
case "${TWINGATE_UPDATE_BIN_DIR:-}" in
    "") ;;
    /*:*|*[!A-Za-z0-9_./-]*) echo "refused: TWINGATE_UPDATE_BIN_DIR must be one plain absolute path" >&2; exit 2 ;;
    /*) PATH="$TWINGATE_UPDATE_BIN_DIR:$PATH" ;;
    *) echo "refused: TWINGATE_UPDATE_BIN_DIR must be absolute" >&2; exit 2 ;;
esac
export PATH

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
FROM="unknown"
TO="unknown"
PRECHECK_WARN=0
API_OK=0
API_URL=""
NODES="[]"
GQL_INCOMPLETE=0

say() { printf '%s\n' "$*"; }
step() { if [ "$DRY" = 1 ]; then printf 'DRY-RUN would: %s\n' "$*"; else printf '==> %s\n' "$*"; fi; }

cleanup() {
    if [ -n "$TMPD" ] && [ -d "$TMPD" ] && [ "$KEEP_TMPD" != 1 ]; then
        for f in "$TMPD"/*; do
            [ -f "$f" ] || continue
            if command -v shred >/dev/null 2>&1; then shred -u "$f" >/dev/null 2>&1 || rm -f "$f"; else rm -f "$f"; fi
        done
        rm -rf "$TMPD"
    fi
    if [ "$LOCKED" = 1 ] && [ -n "$LOCKD" ]; then
        rm -f "$LOCKD/pid"
        rmdir "$LOCKD" 2>/dev/null
        LOCKED=0
    fi
    [ -z "$RUNDIR" ] || rmdir "$RUNDIR" 2>/dev/null
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
    [ -n "${NOTIFY_WEBHOOK_URL:-}" ] || return 0
    case "$NOTIFY_WEBHOOK_URL" in
        https://[A-Za-z0-9]*) ;;
        *) say "notice skipped: NOTIFY_WEBHOOK_URL is not an https URL"; return 0 ;;
    esac
    case "$NOTIFY_WEBHOOK_URL" in
        *[!A-Za-z0-9._~:/?\&=%+@,\;-]*) say "notice skipped: NOTIFY_WEBHOOK_URL has unexpected characters"; return 0 ;;
    esac
    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        say "notice skipped: curl or jq missing"
        return 0
    fi
    label="${HOST_LABEL:-$(hostname -s 2>/dev/null || echo host)}"
    body=$(jq -nc --arg h "$label" --arg c "$NAME" --arg f "$FROM" --arg t "$TO" --arg r "$1" \
        '{"host-label":$h,connector:$c,from:$f,to:$t,result:$r}') || { say "notice skipped"; return 0; }
    # URL goes to curl on stdin (config), not argv.
    if printf 'url = "%s"\n' "$NOTIFY_WEBHOOK_URL" |
        curl -sS -K - --proto '=https' --max-time 5 -X POST \
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

owned() { [ -n "$(find "$1" -maxdepth 0 -user "$(id -u)" 2>/dev/null)" ]; }
die() { say "refused: $1" >&2; exit 2; }
warn() { say "WARNING: $*"; PRECHECK_WARN=1; }

# ---- arguments -------------------------------------------------------------
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --yes) YES=1 ;;
        --force) FORCE=1 ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
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

# ---- private runtime dir and lock (real runs only) ---------------------------
if [ "$DRY" != 1 ]; then
    case "${XDG_RUNTIME_DIR:-}" in
        /*) if [ -d "$XDG_RUNTIME_DIR" ] && [ ! -L "$XDG_RUNTIME_DIR" ] && owned "$XDG_RUNTIME_DIR"; then
                RUNDIR="$XDG_RUNTIME_DIR/twingate-connector-update"
            fi ;;
    esac
    [ -n "$RUNDIR" ] || RUNDIR="${TMPDIR:-/tmp}/twingate-connector-update-$(id -u)"
    mkdir -p "$RUNDIR" 2>/dev/null || die "cannot create the private runtime dir"
    if [ -L "$RUNDIR" ] || [ ! -d "$RUNDIR" ] || ! owned "$RUNDIR"; then die "runtime dir is not a private directory owned by you"; fi
    chmod 700 "$RUNDIR" || die "cannot secure the runtime dir"
    LOCKD="$RUNDIR/lock.d"
    if ! mkdir "$LOCKD" 2>/dev/null; then
        holder=$(cat "$LOCKD/pid" 2>/dev/null) || holder=""
        case "$holder" in ''|*[!0-9]*) die "another run holds the lock and its pid is unreadable ($LOCKD); if no run is active, remove that directory" ;; esac
        if kill -0 "$holder" 2>/dev/null; then die "another run is in progress (pid $holder)"; fi
        say "removing a stale lock left by pid $holder"
        rm -f "$LOCKD/pid"
        rmdir "$LOCKD" 2>/dev/null
        mkdir "$LOCKD" 2>/dev/null || die "cannot take the lock"
    fi
    LOCKED=1
    printf '%s\n' "$$" >"$LOCKD/pid"
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

why=$(printf '%s' "$INSPECT" | jq -r --arg img "$IMAGE_TAG" --arg logdrv "$LOGDRV" --argjson i "$IMG0" '
  def blank: . == null or . == [] or . == {} or . == "" or . == 0 or . == false;
  def norm: if blank then null else . end;
  .[0] as $c | ($c.HostConfig // {}) as $h | ($c.Config // {}) as $cc | ($i.Config // {}) as $ic
  | ($h.LogConfig // {}) as $l | ($cc.Env // []) as $env
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
      (if ($env | map(select((type != "string") or contains("\n") or (contains("=") | not))) | length) > 0 then "malformed environment entry (newline or missing =)" else empty end),
      (if ($env | map(select(type == "string" and startswith("TWINGATE_"))) | length) == 0 then "no TWINGATE_ environment" else empty end),
      (if ($env | map(select(type == "string" and (startswith("TWINGATE_") | not))) - ($ic.Env // []) | length) > 0 then "environment variables a recreate would drop" else empty end)
    ] | join("; ")' 2>/dev/null) || die "cannot read layout"
[ -z "$why" ] || die "layout differs from the verified one ($why). Nothing was changed."

# ---- Twingate Admin API (read only) -----------------------------------------
api_setup() {
    [ -n "${TWINGATE_API_KEY:-}" ] && [ -n "${TWINGATE_NETWORK_URL:-}" ] || return 1
    v="${TWINGATE_NETWORK_URL#https://}"
    sub="${v%.twingate.com}"
    if [ "$sub" = "$v" ] || [ -z "$sub" ]; then
        warn "TWINGATE_NETWORK_URL is not <network>.twingate.com; pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0
    fi
    case "$sub" in
        *[!A-Za-z0-9-]*) warn "TWINGATE_NETWORK_URL is not <network>.twingate.com (no path, port or userinfo allowed); pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0 ;;
    esac
    case "$TWINGATE_API_KEY" in
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
        resp=$(printf 'url = "%s/api/graphql/"\nheader = "X-API-KEY: %s"\n' "$API_URL" "$TWINGATE_API_KEY" |
            curl -sS -K - --proto '=https' --max-time 10 -X POST -H 'Content-Type: application/json' --data "$body" 2>/dev/null) || return 1
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
wait_healthy() {
    maxw="${TWINGATE_UPDATE_WAIT_SECS:-60}"
    poll="${TWINGATE_UPDATE_POLL_SECS:-2}"
    case "$maxw" in ''|*[!0-9]*) maxw=60 ;; esac
    case "$poll" in ''|*[!0-9]*|0) poll=2 ;; esac
    [ "$maxw" -le 60 ] || maxw=60
    waited=0
    while :; do
        st=$(docker ps --filter "name=^${NAME_RE}\$" --format '{{.Status}}' 2>/dev/null) || st=""
        case "$st" in
            Up*unhealthy*|Up*"health: starting"*|"") ;;
            Up*)
                if docker exec "$NAME" ./connectord --version >/dev/null 2>&1; then return 0; fi ;;
        esac
        [ "$waited" -lt "$maxw" ] || return 1
        sleep "$poll"
        waited=$((waited + poll))
    done
}

recreate() {
    # $1 = image
    docker stop "$NAME" >/dev/null 2>&1
    docker rm "$NAME" >/dev/null 2>&1
    docker run -d --network host --env-file "$ENVF" --name "$NAME" --restart=unless-stopped "$1" >/dev/null 2>&1
}

# Returns 0 confirmed, 1 not confirmed, 2 not configured.
confirm_twingate() {
    [ "$API_OK" = 1 ] || return 2
    ver=$(printf '%s' "$TO" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n 1)
    [ -n "$ver" ] || return 1
    maxw="${TWINGATE_UPDATE_WAIT_SECS:-60}"
    poll="${TWINGATE_UPDATE_POLL_SECS:-2}"
    case "$maxw" in ''|*[!0-9]*) maxw=60 ;; esac
    case "$poll" in ''|*[!0-9]*|0) poll=2 ;; esac
    [ "$maxw" -le 60 ] || maxw=60
    waited=0
    while :; do
        if gql_fetch; then
            ok=$(printf '%s' "$NODES" | jq -r --arg n "$NAME" --arg v "$ver" '[.[] | select(.name == $n and .state == "ALIVE" and ((.version // "") | contains($v)))] | length' 2>/dev/null) || ok=""
            [ "$ok" = 1 ] && return 0
        fi
        [ "$waited" -lt "$maxw" ] || return 1
        sleep "$poll"
        waited=$((waited + poll))
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
TMPD=$(mktemp -d) || die "cannot create private temp dir"
chmod 700 "$TMPD" || die "cannot secure temp dir"
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
