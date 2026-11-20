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
# directory made for this one call and removed after it, so no per-user engine configuration (docker
# config.json and contexts, CLI plugins, credential helpers, podman containers.conf and connections)
# and no caller runtime directory is ever read. PATH is fixed; only USER LOGNAME LANG LC_ALL TERM TZ
# are passed through. Everything else (DOCKER_HOST, CONTAINER_HOST, LD_*, BASH_ENV, proxies, ...) is
# dropped. Same rules as engine_env in container_engine.py. Standard input and output pass through.
# Consequence: rootless podman (its storage lives under HOME) is not supported; use rootful.
CE_SAFE_PATH="/usr/bin:/usr/local/bin:/bin:/snap/bin"
ce_run() {
    [ -n "${CE_BIN-}" ] || { echo "ce_run: no engine resolved (call ce_init first)" >&2; return 1; }
    _ce_home=$(/usr/bin/mktemp -d) || return 1
    /usr/bin/env -i "PATH=$CE_SAFE_PATH" "HOME=$_ce_home" "DOCKER_CONFIG=$_ce_home/docker" \
        "XDG_CONFIG_HOME=$_ce_home/config" "XDG_DATA_HOME=$_ce_home/data" "XDG_CACHE_HOME=$_ce_home/cache" \
        "XDG_STATE_HOME=$_ce_home/state" \
        ${USER+"USER=$USER"} ${LOGNAME+"LOGNAME=$LOGNAME"} \
        ${LANG+"LANG=$LANG"} ${LC_ALL+"LC_ALL=$LC_ALL"} ${TERM+"TERM=$TERM"} ${TZ+"TZ=$TZ"} \
        "$CE_BIN" "$@"
    _ce_rc=$?
    /usr/bin/rm -rf -- "$_ce_home"
    return $_ce_rc
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
