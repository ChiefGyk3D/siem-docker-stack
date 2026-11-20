# shellcheck shell=sh
# =============================================================================
# lib-container-engine.sh - the CONTAINER_ENGINE setting for shell scripts (source me)
# =============================================================================
# One setting, CONTAINER_ENGINE: exactly "docker" or "podman"; unset or empty
# means docker; anything else is an error. The Python twin is
# scripts/container_engine.py (same rules, same fixed directories); the tests in
# tests/python/test_container_engine.py hold the two together. POSIX sh, so it
# works when sourced from bash or dash. Needs GNU stat and readlink (Linux).
#
#   ce_name                       print the validated engine name
#   ce_resolve NAME [DIRS UID ROOT]
#                                 print the canonical path of NAME found only in the
#                                 fixed root-owned directories (never PATH); fails
#                                 when there is none. NAME must be docker or podman.
#   ce_init                       set CE_NAME and CE_BIN (the resolved binary);
#                                 returns 1 with a message on stderr on failure
#   ce_init_name                  set CE_NAME only (for a command run on another host)
#   ce_run ARGS...                run "$CE_BIN" ARGS with a minimal environment and a private empty HOME
#
# Callers run the engine as an argument list through ce_run. The raw value of
# CONTAINER_ENGINE is never put in a command string, evaluated, or echoed. Only the
# validated fixed token CE_NAME (exactly "docker" or "podman") is placed in the command
# strings that scripts send to another host.
# =============================================================================

CE_TRUSTED_DIRS="/usr/bin /usr/local/bin /bin /snap/bin"

ce_name() {
    case "${CONTAINER_ENGINE-}" in
        "") printf '%s' docker ;;
        docker) printf '%s' docker ;;
        podman) printf '%s' podman ;;
        *)
            echo "CONTAINER_ENGINE must be one of: docker, podman (unset means docker)" >&2
            return 1
            ;;
    esac
}

# ce_dirs_ok DIR UID ROOT: DIR (canonical) is at or below ROOT and every directory
# from DIR up to ROOT is owned by UID and not group or world writable.
ce_dirs_ok() {
    _ce_p=$1
    _ce_own=$2
    _ce_top=$(/usr/bin/readlink -f -- "$3") || return 1
    while :; do
        [ -d "$_ce_p" ] && [ ! -L "$_ce_p" ] || return 1
        _ce_st=$(/usr/bin/stat -c '%u %a' -- "$_ce_p") || return 1
        [ "${_ce_st%% *}" = "$_ce_own" ] || return 1
        [ $((0${_ce_st#* } & 022)) -eq 0 ] || return 1
        [ "$_ce_p" = "$_ce_top" ] && return 0
        _ce_parent=$(/usr/bin/dirname -- "$_ce_p")
        [ "$_ce_parent" = "$_ce_p" ] && return 1
        _ce_p=$_ce_parent
    done
}

ce_resolve() {
    case "${1-}" in
        docker | podman) ;;
        *) return 1 ;;
    esac
    _ce_name=$1
    _ce_dirs=${2-$CE_TRUSTED_DIRS}
    _ce_uid=${3-0}
    _ce_root=${4-/}
    for _ce_d in $_ce_dirs; do
        _ce_real=$(/usr/bin/readlink -f -- "$_ce_d/$_ce_name" 2>/dev/null) || continue
        [ -f "$_ce_real" ] && [ ! -L "$_ce_real" ] || continue
        _ce_rd=$(/usr/bin/readlink -f -- "$_ce_d" 2>/dev/null) || continue
        ce_dirs_ok "$_ce_rd" "$_ce_uid" "$_ce_root" || continue
        ce_dirs_ok "$(/usr/bin/dirname -- "$_ce_real")" "$_ce_uid" "$_ce_root" || continue
        _ce_fst=$(/usr/bin/stat -c '%u %a' -- "$_ce_real") || continue
        [ "${_ce_fst%% *}" = "$_ce_uid" ] || continue
        [ $((0${_ce_fst#* } & 022)) -eq 0 ] || continue
        [ -x "$_ce_real" ] || continue
        printf '%s' "$_ce_real"
        return 0
    done
    return 1
}

# ce_run ARGS...: run the resolved engine ($CE_BIN) with an explicit minimal environment and a
# fresh private EMPTY home: HOME, DOCKER_CONFIG and the XDG_* directories all point into a mode 0700
# directory made for this one call and removed after it (also on failure, HUP, INT and TERM), so no
# per-user engine configuration (docker config.json and contexts, CLI plugins, credential helpers,
# podman containers.conf and connections) and no caller runtime directory is ever read. The home is
# made under a validated fixed base (CE_HOME_BASES); TMPDIR is never consulted. PATH is fixed; only
# LANG LC_ALL TERM TZ are passed through, each only when its value matches that variable's own strict
# pattern (see ce_ok_locale, ce_ok_term, ce_ok_tz; anything else is dropped). The environment is built as separate
# arguments, never by splitting a string. Everything else (DOCKER_HOST, CONTAINER_HOST, LD_*,
# BASH_ENV, proxies, ...) is dropped. Same rules as engine_env in container_engine.py. Standard
# input and output pass through. Consequence: rootless podman (its storage lives under HOME) is
# not supported; use rootful.
CE_SAFE_PATH="/usr/bin:/usr/local/bin:/bin:/snap/bin"
CE_HOME_BASES="/run /var/tmp /tmp"  # assigned, never read from the environment
CE_HOME_BASE_UID=0

# Per-variable value checks (same rules as ENV_PATTERNS in container_engine.py).
ce_ok_locale() { # C, POSIX, C.UTF-8, ll_CC or ll_CC.charset
    case "$1" in
        C | POSIX | C.UTF-8 | [a-z][a-z]_[A-Z][A-Z]) return 0 ;;
        [a-z][a-z]_[A-Z][A-Z].?*)
            _ce_s=${1#??_??.}
            case "$_ce_s" in *[!A-Za-z0-9-]*) return 1 ;; esac
            [ "${#_ce_s}" -le 16 ]
            ;;
        *) return 1 ;;
    esac
}

ce_ok_term() { # terminal-name characters only
    case "$1" in
        "" | [!A-Za-z0-9]* | *[!A-Za-z0-9._+-]*) return 1 ;;
    esac
    [ "${#1}" -le 32 ]
}

ce_ok_tz() { # a zone name: no leading colon or slash, no dots, no empty component
    case "$1" in
        "" | [!A-Za-z]* | *[!A-Za-z0-9_+/-]* | */ | *//*) return 1 ;;
    esac
    [ "${#1}" -le 40 ]
}

ce_mkhome() { # set _ce_home to a fresh private home; fail closed when no safe base exists
    for _ce_b in $CE_HOME_BASES; do
        [ -d "$_ce_b" ] && [ ! -L "$_ce_b" ] || continue
        _ce_bs=$(/usr/bin/stat -c '%u %a' -- "$_ce_b") || continue
        [ "${_ce_bs%% *}" = "$CE_HOME_BASE_UID" ] || continue
        _ce_bm=${_ce_bs#* }
        # usable when nobody else can write it, or when it is sticky (others cannot rename our entry)
        if [ $((0$_ce_bm & 022)) -ne 0 ] && [ $((0$_ce_bm & 01000)) -eq 0 ]; then continue; fi
        _ce_h=$(TMPDIR= /usr/bin/mktemp -d -p "$_ce_b" engine-home.XXXXXXXX 2>/dev/null) || continue
        if [ -d "$_ce_h" ] && [ ! -L "$_ce_h" ] &&
            [ "$(/usr/bin/stat -c '%u %a' -- "$_ce_h")" = "$(/usr/bin/id -u) 700" ]; then
            _ce_home=$_ce_h
            return 0
        fi
        /usr/bin/rm -rf -- "$_ce_h"
    done
    echo "ce_run: no safe base directory for a private engine home ($CE_HOME_BASES)" >&2
    return 1
}

ce_stop() { # N: stop the engine child promptly (TERM, then KILL after 5 s), then leave with status N
    if [ -n "${_ce_child-}" ]; then
        kill -TERM "$_ce_child" 2>/dev/null
        ( /bin/sleep 5; kill -KILL "$_ce_child" 2>/dev/null ) >/dev/null 2>&1 </dev/null &  # holds no pipe of ours
        _ce_dog=$!
        wait "$_ce_child" 2>/dev/null
        kill "$_ce_dog" 2>/dev/null
    fi
    exit "$1"  # the EXIT trap removes the private home
}

ce_fwd() { # N: a signal reached the invoking shell: stop the runner (its trap stops the engine), then leave with N
    if [ -n "${_ce_runner-}" ]; then
        kill -TERM "$_ce_runner" 2>/dev/null
        wait "$_ce_runner" 2>/dev/null
    fi
    exit "$1"
}

ce_run() {
    [ -n "${CE_BIN-}" ] || { echo "ce_run: no engine resolved (call ce_init first)" >&2; return 1; }
    # The runner below is a child of the invoking shell, so a signal sent to the script itself would
    # not reach it. The invoking shell therefore forwards HUP, INT and TERM to the runner, waits for
    # it to stop the engine and remove the home, and leaves with 128 + signal. HUP, INT and TERM go
    # back to their defaults afterwards (EXIT traps are never touched; no script of ours sets the
    # others). A script that calls ce_run inside $(...) or a pipeline relies on the signal reaching
    # the process group, which every terminal and supervisor kill does.
    _ce_runner=
    trap 'ce_fwd 129' HUP
    trap 'ce_fwd 130' INT
    trap 'ce_fwd 143' TERM
    exec 4<&0  # an async command gets /dev/null as stdin unless it is redirected from another descriptor
    ce_runner "$@" <&4 4<&- &
    _ce_runner=$!
    exec 4<&-
    _ce_rc=0
    wait "$_ce_runner" || _ce_rc=$?
    _ce_runner=
    trap - HUP INT TERM
    return "$_ce_rc"
}

ce_runner() {
    _ce_n=$#
    {  # always called as an async command by ce_run, so this is already its own shell process
        # the EXIT and signal traps exist before the home does, so a signal at any point removes it
        _ce_home=
        trap '[ -z "$_ce_home" ] || /usr/bin/rm -rf -- "$_ce_home"' EXIT
        _ce_child=
        # the engine runs as a tracked child and the shell waits for it, so a signal is handled at once
        # (a trap does not run while a foreground command is executing); the status is 128 + signal
        trap 'ce_stop 129' HUP
        trap 'ce_stop 130' INT
        trap 'ce_stop 143' TERM
        ce_mkhome || exit 1
        # engine arguments are "$@"; append the env command after them, then rotate them to the end
        set -- "$@" /usr/bin/env -i "PATH=$CE_SAFE_PATH" "HOME=$_ce_home" "DOCKER_CONFIG=$_ce_home/docker" \
            "XDG_CONFIG_HOME=$_ce_home/config" "XDG_DATA_HOME=$_ce_home/data" "XDG_CACHE_HOME=$_ce_home/cache" \
            "XDG_STATE_HOME=$_ce_home/state"
        if [ -n "${LANG-}" ] && ce_ok_locale "$LANG"; then set -- "$@" "LANG=$LANG"; fi
        if [ -n "${LC_ALL-}" ] && ce_ok_locale "$LC_ALL"; then set -- "$@" "LC_ALL=$LC_ALL"; fi
        if [ -n "${TERM-}" ] && ce_ok_term "$TERM"; then set -- "$@" "TERM=$TERM"; fi
        if [ -n "${TZ-}" ] && ce_ok_tz "$TZ"; then set -- "$@" "TZ=$TZ"; fi
        set -- "$@" "$CE_BIN"
        while [ "$_ce_n" -gt 0 ]; do
            set -- "$@" "$1"
            shift
            _ce_n=$((_ce_n - 1))
        done
        exec 3<&0  # an async command gets /dev/null as stdin unless it is redirected from another descriptor
        "$@" <&3 3<&- &
        exec 3<&-
        _ce_child=$!
        _ce_rc=0
        wait "$_ce_child" || _ce_rc=$?
        exit "$_ce_rc"
    }
}

# ce_source_env FILE: source a shell-syntax .env safely. The file must be a regular file, not a link;
# as root it and every directory above it must be root-owned and not group or world writable; for
# anyone it must be owned by root or by the running user and not world writable. The file is opened
# once, the OPEN file is checked, and that same descriptor is sourced, so replacing the path after the
# check changes nothing. Needs the bootstrap's CE_STRICT and CE_UID. Variables are exported.
ce_source_env() {
    _ce_ef=$1
    if [ ! -f "$_ce_ef" ] || [ -L "$_ce_ef" ]; then
        echo "refusing to source ${_ce_ef}: it must be a regular file and not a link" >&2
        return 1
    fi
    if [ "${CE_STRICT-0}" = 1 ]; then
        _ce_ep=$(/usr/bin/readlink -f -- "$_ce_ef") || return 1
        while :; do
            if [ "$(/usr/bin/stat -c %u -- "$_ce_ep")" != 0 ] || [ $((0$(/usr/bin/stat -c %a -- "$_ce_ep") & 022)) -ne 0 ]; then
                echo "refusing to source ${_ce_ef}: ${_ce_ep} (or a directory above it) is not root-owned or is group or world writable" >&2
                return 1
            fi
            [ "$_ce_ep" = / ] && break
            _ce_ep=$(/usr/bin/dirname -- "$_ce_ep")
        done
    fi
    exec 8<"$_ce_ef" || return 1
    _ce_eo=$(/usr/bin/stat -L -c %u -- /proc/self/fd/8)
    _ce_em=$(/usr/bin/stat -L -c %a -- /proc/self/fd/8)
    _ce_mask=002
    [ "${CE_STRICT-0}" != 1 ] || _ce_mask=022
    if [ ! -f /proc/self/fd/8 ] || { [ "$_ce_eo" != 0 ] && [ "$_ce_eo" != "${CE_UID-}" ]; } ||
        [ $((0$_ce_em & _ce_mask)) -ne 0 ]; then
        exec 8<&-
        echo "refusing to source ${_ce_ef}: it must be owned by root or by you and not world writable (and not group writable when run as root)" >&2
        return 1
    fi
    set -a
    . /proc/self/fd/8
    set +a
    exec 8<&-
}

ce_init_name() {
    CE_NAME=
    CE_NAME=$(ce_name) || return 1
}

ce_init() {
    CE_BIN=
    ce_init_name || return 1
    CE_BIN=$(ce_resolve "$CE_NAME") || {
        echo "no trusted '$CE_NAME' found in $CE_TRUSTED_DIRS (root-owned, not writable by others)" >&2
        CE_BIN=
        return 1
    }
}
