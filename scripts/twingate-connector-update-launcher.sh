#!/bin/sh
# twingate-connector-update-launcher.sh - the one trusted entry point for the
# Twingate Connector updater (issue #220). Install it root-owned (0755) in a
# root-only directory such as /usr/local/sbin; see
# docs/twingate-connector-update-script.md. THIS FILE IS THE TRUST ROOT: nothing
# can vouch for it, so where it is installed is the control. It holds no
# functions and runs nothing but its own checks before it hands over.
# It refuses unless: it is run by its absolute path, as root; then it validates
# the updater at the fixed path below (never from arguments or the environment),
# opens it once and checks the OPEN descriptor (type, owner, mode, ACL, size),
# then runs the text read from that descriptor in a cleared environment. The
# updater path is not opened a second time.
umask 077
TRUSTED_UID=0
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
# Every external program is run by a fixed absolute path; the launcher itself
# never resolves a command through PATH (PATH is only handed to the updater).
# On Debian 13 and Ubuntu 24.04 /usr/bin holds all of them (/bin is a link to it).
ID=/usr/bin/id
DIRNAME=/usr/bin/dirname
FIND=/usr/bin/find
LS=/usr/bin/ls
GETFACL=/usr/bin/getfacl
HEAD=/usr/bin/head
TEE=/usr/bin/tee
WC=/usr/bin/wc
OD=/usr/bin/od
TR=/usr/bin/tr
ENV=/usr/bin/env
SH=/usr/bin/sh
UPDATER="/usr/local/libexec/twingate-connector-update/twingate-connector-update.sh"
NL='
'
WHY=""
case "$0" in /*) ;; *) WHY="run this launcher by its absolute installed path" ;; esac
if [ -z "$WHY" ] && [ "$("$ID" -u)" != "$TRUSTED_UID" ]; then WHY="it must be run as root (use sudo)"; fi
if [ -z "$WHY" ]; then
    # Open FIRST, then check what was opened. Read-write mode is used because it
    # does not block on a FIFO under Linux (a read-only open waits for a writer,
    # and POSIX sh cannot ask for a non-blocking open); the file is never written.
    # The test only keeps the open from creating a missing file, and a read-only
    # file system (or a file root cannot write) is refused here for the same reason.
    if [ -e "$UPDATER" ] && [ -w "$UPDATER" ] && [ ! -d "$UPDATER" ]; then exec 4<>"$UPDATER"; else WHY="the updater is missing, not writable by root (the open needs it), or not a regular file"; fi
    if [ -z "$WHY" ] && { [ ! -f /dev/fd/4 ] || [ -L "$UPDATER" ]; }; then WHY="the updater is not a regular file (or is a symbolic link)"; fi
fi
if [ -z "$WHY" ]; then
    DIR=$(cd "$("$DIRNAME" -- "$UPDATER")" 2>/dev/null && pwd -P) || DIR=""
    if [ "$DIR/${UPDATER##*/}" != "$UPDATER" ]; then WHY="the updater path is not canonical (a directory in it is a symbolic link)"; fi
fi
# The updater and EVERY directory above it, up to /: owned by root, not group-
# or world-writable, and no extended ACL (the long listing shows a plus sign;
# where getfacl exists it must show exactly one user::, group:: and other::
# entry). Anything that cannot be read counts as untrusted.
# The first pass inspects the open descriptor itself, the second the path.
p=/dev/fd/4
while [ -z "$WHY" ]; do
    if [ -z "$("$FIND" -H "$p" -maxdepth 0 -user "$TRUSTED_UID" ! -perm /022 2>/dev/null)" ]; then
        WHY="the updater or one of its parent directories is not owned by root or is group- or world-writable"; break
    fi
    ACL=1
    L=$("$LS" -Lldn -- "$p" 2>/dev/null) || L=""
    case "$L" in
        [-d]?????????" "*|[-d]?????????.*) ACL=0 ;;
    esac
    if [ "$ACL" = 0 ] && [ -x "$GETFACL" ]; then
        X=$("$GETFACL" -p -c -- "$p" 2>/dev/null) || ACL=1
        NU=0; NG=0; NO=0
        while [ "$ACL" = 0 ] && IFS= read -r LN; do
            case "$LN" in
                "") ;;
                user::[r-][w-][x-]) NU=$((NU + 1)) ;;
                group::[r-][w-][x-]) NG=$((NG + 1)) ;;
                other::[r-][w-][x-]) NO=$((NO + 1)) ;;
                *) ACL=1 ;;
            esac
        done <<EOF_ACL
$X
EOF_ACL
        if [ "$NU" != 1 ] || [ "$NG" != 1 ] || [ "$NO" != 1 ]; then ACL=1; fi
    fi
    if [ "$ACL" != 0 ]; then
        WHY="the updater or one of its parent directories has an extended access control list (ACL) or its ACL cannot be checked"; break
    fi
    if [ "$p" = "/" ]; then break; fi
    if [ "$p" = /dev/fd/4 ]; then p="$UPDATER"; continue; fi
    p="${p%/*}"
    if [ -z "$p" ]; then p="/"; fi
done
if [ -n "$WHY" ]; then printf 'refused: %s\n' "$WHY" >&2; exit 2; fi
# Read the text ONCE from the open descriptor; the path is not reopened. At
# most 100001 bytes are read. The bytes are COUNTED as they pass (tee feeds one
# copy to wc), because command substitution drops NUL bytes and trailing
# newlines: the text must be exactly as long as the count, the count must equal
# the file's size, and 100000 or more is refused.
RAW=$(exec 7>&1; N=$("$HEAD" -c 100001 <&4 | "$TEE" /dev/fd/7 | "$WC" -c) && printf 'x%s' "$N") || RAW=""
COUNT=${RAW##*x}
case "$COUNT" in ''|*[!0-9]*) COUNT="" ;; esac
TEXT=${RAW%x"$COUNT"}
TLEN=$(printf '%s' "$TEXT" | "$WC" -c) || TLEN=""
if [ -z "$COUNT" ] || [ "$COUNT" -lt 1 ] || [ "$COUNT" -ge 100000 ] || [ "$TLEN" != "$COUNT" ]; then
    printf 'refused: the updater is empty or too large (or holds a NUL byte)\n' >&2; exit 2
fi
if [ -z "$("$FIND" -H /dev/fd/4 -maxdepth 0 -size "${COUNT}c" 2>/dev/null)" ]; then printf 'refused: the updater was not read completely\n' >&2; exit 2; fi
# Descriptors 4 to 9 are closed here. Higher ones cannot be named in POSIX sh, so
# any that were inherited are refused (the listing is of the ls process, whose
# own directory descriptor is a low number now that these are closed).
exec 4<&- 5<&- 6<&- 7<&- 8<&- 9<&-
FDS=$("$LS" -1 -- /proc/self/fd 2>/dev/null) || FDS="?"
case "$FDS" in ''|*[!0-9"$NL"]*|*[0-9][0-9]*) printf 'refused: an inherited file descriptor above 9 is open (or the descriptors cannot be listed)\n' >&2; exit 2 ;; esac
for v in "${TWINGATE_API_KEY:-}" "${TWINGATE_NETWORK_URL:-}" "${TWINGATE_UPDATE_WAIT_SECS:-}" \
    "${TWINGATE_UPDATE_POLL_SECS:-}" "${NOTIFY_WEBHOOK_URL:-}" "${NOTIFY_WEBHOOK_ALLOWED_HOSTS:-}" "${HOST_LABEL:-}"; do
    case "$v" in *"$NL"*) printf 'refused: an input variable contains a newline\n' >&2; exit 2 ;; esac
done
TOKEN=$("$OD" -An -N16 -tx1 /dev/urandom 2>/dev/null | "$TR" -d ' \n') || TOKEN=""
case "$TOKEN" in ''|*[!0-9a-f]*) printf 'refused: cannot create a run token\n' >&2; exit 2 ;; esac
# Only the documented inputs are carried over, on fd 3 (never argv).
exec "$ENV" -i PATH="$PATH" LC_ALL=C LANG=C TWINGATE_UPDATE_CLEAN_ENV=1 \
    TWINGATE_UPDATE_RUN_TOKEN="$TOKEN" "$SH" -c "$TEXT" "$UPDATER" "$@" 3<<EOF
TWINGATE_API_KEY=${TWINGATE_API_KEY:-}
TWINGATE_NETWORK_URL=${TWINGATE_NETWORK_URL:-}
TWINGATE_UPDATE_WAIT_SECS=${TWINGATE_UPDATE_WAIT_SECS:-}
TWINGATE_UPDATE_POLL_SECS=${TWINGATE_UPDATE_POLL_SECS:-}
NOTIFY_WEBHOOK_URL=${NOTIFY_WEBHOOK_URL:-}
NOTIFY_WEBHOOK_ALLOWED_HOSTS=${NOTIFY_WEBHOOK_ALLOWED_HOSTS:-}
HOST_LABEL=${HOST_LABEL:-}
EOF
