#!/bin/sh
# twingate-connector-update.sh - update ONE Twingate Connector container on the
# host it runs on. Issue #220. Owner decision 2026-11-26: a one-command action
# the owner runs on each host, one host at a time. No automatic updates.
#
# Usage: twingate-connector-update.sh [--dry-run] [--yes] <connector-container-name>
#
# Fail closed. It refuses anything but the verified layout (image
# twingate/connector:1, host networking, no binds or mounts, restart policy
# unless-stopped, no extra privileges) and changes nothing in that case.
# It never prunes images, never prints an env value, and keeps the saved
# inspect output and env file only in a private (mode 700) temp dir that is
# removed on exit and on error.
#
# Environment (all optional, never put secrets in argv):
#   NOTIFY_WEBHOOK_URL   https URL; a short JSON notice is POSTed at the end
#                        (5 s timeout). A failed notice never fails the update.
#   HOST_LABEL           label for the notice (default: short hostname)
#   TWINGATE_API_KEY, TWINGATE_NETWORK_URL
#                        if both set, a read-only Admin API pre-check warns
#                        when fewer than two Connectors are ALIVE.
#   TWINGATE_UPDATE_WAIT_SECS (default and maximum 60), TWINGATE_UPDATE_POLL_SECS
# See docs/twingate-connector-update-script.md.

umask 077
PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

IMAGE_TAG="twingate/connector:1"
DRY=0
YES=0
NAME=""
TMPD=""
FROM="unknown"
TO="unknown"

say() { printf '%s\n' "$*"; }
step() { if [ "$DRY" = 1 ]; then printf 'DRY-RUN would: %s\n' "$*"; else printf '==> %s\n' "$*"; fi; }

cleanup() {
    if [ -n "$TMPD" ] && [ -d "$TMPD" ]; then
        for f in "$TMPD"/*; do
            [ -f "$f" ] || continue
            if command -v shred >/dev/null 2>&1; then shred -u "$f" >/dev/null 2>&1 || rm -f "$f"; else rm -f "$f"; fi
        done
        rm -rf "$TMPD"
    fi
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

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

die() { say "refused: $1" >&2; exit 2; }

# ---- arguments -------------------------------------------------------------
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --yes) YES=1 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        -*) die "unknown option '$a'" ;;
        *) [ -z "$NAME" ] || die "exactly one container name is allowed"; NAME="$a" ;;
    esac
done
[ -n "$NAME" ] || die "usage: $0 [--dry-run] [--yes] <connector-container-name>"
case "$NAME" in
    [A-Za-z0-9]*) ;;
    *) die "invalid container name" ;;
esac
case "$NAME" in
    *[!A-Za-z0-9_.-]*) die "invalid container name" ;;
esac
[ "${#NAME}" -le 63 ] || die "invalid container name"

command -v docker >/dev/null 2>&1 || die "docker not found"
command -v jq >/dev/null 2>&1 || die "jq not found"

TMPD=$(mktemp -d) || die "cannot create private temp dir"
chmod 700 "$TMPD" || die "cannot secure temp dir"
INSPECT="$TMPD/inspect.json"
ENVF="$TMPD/connector.env"

# ---- inspect and layout check ---------------------------------------------
docker inspect "$NAME" >"$INSPECT" 2>/dev/null || die "container '$NAME' not found"
jq -e 'type=="array" and length==1' "$INSPECT" >/dev/null 2>&1 || die "unexpected docker inspect output"

why=$(jq -r --arg img "$IMAGE_TAG" '
  .[0] as $c
  | [ (if $c.Config.Image != $img then "image is not " + $img else empty end),
      (if $c.HostConfig.NetworkMode != "host" then "network mode is not host" else empty end),
      (if (($c.HostConfig.Binds // []) | length) > 0 or (($c.Mounts // []) | length) > 0 then "binds or mounts present" else empty end),
      (if $c.HostConfig.RestartPolicy.Name != "unless-stopped" then "restart policy is not unless-stopped" else empty end),
      (if $c.HostConfig.Privileged == true then "privileged" else empty end),
      (if (($c.HostConfig.CapAdd // []) | length) > 0 then "extra capabilities" else empty end),
      (if (($c.HostConfig.Devices // []) | length) > 0 then "devices present" else empty end),
      (if (($c.HostConfig.Sysctls // {}) | length) > 0 then "sysctls present" else empty end),
      (if (($c.Config.Env // []) | length) == 0 then "no environment" else empty end)
    ] | join("; ")' "$INSPECT" 2>/dev/null) || die "cannot read layout"
[ -z "$why" ] || die "layout differs from the verified one ($why). Nothing was changed."

OLD_ID=$(jq -r '.[0].Image' "$INSPECT")
case "$OLD_ID" in
    sha256:[0-9a-f]*) ;;
    *) die "cannot read the running image id" ;;
esac
case "$OLD_ID" in
    *[!A-Za-z0-9:]*) die "cannot read the running image id" ;;
esac

# ---- Twingate API pre-check (read only) -------------------------------------
precheck() {
    if [ -n "${TWINGATE_API_KEY:-}" ] && [ -n "${TWINGATE_NETWORK_URL:-}" ]; then
        case "$TWINGATE_NETWORK_URL" in
            https://[A-Za-z0-9-]*.twingate.com) ;;
            *) say "WARNING: TWINGATE_NETWORK_URL is not https://<network>.twingate.com; pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0 ;;
        esac
        case "$TWINGATE_NETWORK_URL" in
            *[!A-Za-z0-9.:/-]*) say "WARNING: TWINGATE_NETWORK_URL has unexpected characters; pre-check skipped."; return 0 ;;
        esac
        command -v curl >/dev/null 2>&1 || { say "WARNING: curl missing; pre-check skipped. Confirm the other Connector is ALIVE yourself."; return 0; }
        q='{"query":"{ connectors(first: 100) { edges { node { state } } } }"}'
        resp=$(printf 'url = "%s/api/graphql/"\nheader = "X-API-KEY: %s"\n' "$TWINGATE_NETWORK_URL" "$TWINGATE_API_KEY" |
            curl -sS -K - --proto '=https' --max-time 10 -X POST -H 'Content-Type: application/json' --data "$q" 2>/dev/null) || resp=""
        alive=$(printf '%s' "$resp" | jq -r '[.data.connectors.edges[].node | select(.state=="ALIVE")] | length' 2>/dev/null) || alive=""
        case "$alive" in
            ''|*[!0-9]*) say "WARNING: could not read Connector state from the Twingate API. Confirm the other Connector is ALIVE before continuing." ;;
            *) if [ "$alive" -ge 2 ]; then say "pre-check: $alive Connectors ALIVE in the network."; else say "WARNING: only $alive Connector(s) ALIVE in the network. The other Connector cannot be confirmed ALIVE; updating this one may cut access."; fi ;;
        esac
    else
        say "REMINDER: confirm the OTHER Connector in this remote network is ALIVE in Twingate before continuing (set TWINGATE_API_KEY and TWINGATE_NETWORK_URL for an automatic read-only check)."
    fi
}
precheck

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

# ---- env file ---------------------------------------------------------------
step "write env file from Config.Env (without PATH) in the private temp dir"
if [ "$DRY" != 1 ]; then
    jq -r '.[0].Config.Env[] | select(startswith("PATH=") | not)' "$INSPECT" >"$ENVF" 2>/dev/null || die "cannot build the env file"
    chmod 600 "$ENVF"
    [ -s "$ENVF" ] || die "env file is empty"
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
        st=$(docker ps --filter "name=^${NAME}\$" --format '{{.Status}}' 2>/dev/null) || st=""
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

step "docker stop $NAME; docker rm $NAME"
step "docker run -d --network host --env-file <private env file> --name $NAME --restart=unless-stopped $IMAGE_TAG"
step "wait up to 60 s for the container to be Up and healthy and answer connectord --version"
step "on failure: recreate from the saved old image $OLD_ID with the same env and exit non-zero"
step "never prune images; the old image stays on the host"
[ "$DRY" != 1 ] || { finish "dry-run" 0; exit "$?"; }

# ---- update -----------------------------------------------------------------
if recreate "$IMAGE_TAG" && wait_healthy; then
    NOW=$(docker exec "$NAME" ./connectord --version 2>/dev/null | head -n 1) || NOW=""
    [ -z "$NOW" ] || TO="$NOW"
    { finish "updated" 0; exit "$?"; }
fi

say "New container did not become healthy within the wait. Rolling back to $OLD_ID." >&2
if recreate "$OLD_ID" && wait_healthy; then
    say "Rollback succeeded: $NAME runs the old image again." >&2
    TO="$FROM (rolled back)"
    { finish "rolled-back" 1; exit "$?"; }
fi
say "ROLLBACK FAILED: $NAME is not healthy. Old image is $OLD_ID (kept). Fix by hand now." >&2
finish "rollback-failed" 2
