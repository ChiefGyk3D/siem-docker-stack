#!/bin/bash -p
# =============================================================================
# secure-curl.sh — run curl with HTTP basic credentials that never touch argv
# =============================================================================
# Usage (start it by its path, never through an explicit `bash`):
#   scripts/secure-curl.sh USER CURL_ARGS...
#   scripts/secure-curl.sh admin -sk https://localhost:9200/_cluster/health
#
# The password is read without echo from the terminal (or, when standard input is
# not a terminal, from its first line), held in an unexported variable, and sent to
# curl on standard input as a config (`curl -q -K -`). It is never in an argument, the
# environment of any child, the shell history, or a shell trace of this script.
# Only a short list of curl options is accepted (see sc_refuse below), checked
# before the password is read: curl's own diagnostics (--libcurl, --trace*, -v,
# -K/--config) could print the credential, so they are refused, not documented away.
# Because standard input carries the password and then the config, curl arguments
# must not read standard input: use `-d 'literal'` or `-d @file`, never `-d @-`.
# A NUL byte in piped input is refused; one typed at a terminal (Ctrl-@) is dropped
# by bash's terminal read and cannot be detected.
#
# Needs bash 4.2 or newer. Exits 2 on a refused input, otherwise curl's status.
# =============================================================================

set +x
# Nothing may trace or hook the lines below: clear every trace and trap setting first.
unset PS4 ENV BASH_ENV CDPATH GLOBIGNORE
trap - DEBUG RETURN ERR EXIT
set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C; export LC_ALL

if [ -n "${BASH_XTRACEFD:-}" ]; then
    echo "secure-curl: BASH_XTRACEFD is set; refusing to run with a trace file descriptor" >&2
    exit 2
fi
if [ -n "$(trap -p)" ]; then
    echo "secure-curl: an inherited trap is set; refusing to run" >&2
    exit 2
fi
if [ "$#" -lt 2 ]; then
    echo "Usage: scripts/secure-curl.sh USER CURL_ARGS..." >&2
    exit 2
fi

# Take the export attribute off the working names in case a caller exported them.
unset sc_user sc_pw sc_cred sc_args CURL_DEBUG
sc_user="$1"
shift

# Only these curl options are accepted, by exact spelling, and they are checked BEFORE the password is
# read. Anything else (including abbreviated long options and attached values) is refused: curl can write
# the credential out through --libcurl, --trace*, --verbose, a -K/--config file and similar, and a caller
# could override the account with -u/--user or netrc. A value of @- would read the password stream.
sc_refuse() {
    echo "secure-curl: curl option '$1' is not allowed here (allowed: -s -S -k -f -I -L, -X -H -d -o -w -m," \
        "--max-time --connect-timeout --cacert --resolve --data-binary, and URLs)" >&2
    exit 2
}
sc_args=()
while [ "$#" -gt 0 ]; do
    sc_a="$1"
    shift
    case "$sc_a" in
        -X | -H | -d | -o | -w | --max-time | --connect-timeout | --cacert | --resolve | --data-binary)
            [ "$#" -gt 0 ] || sc_refuse "$sc_a (needs a value)"
            [ "$1" != "@-" ] || sc_refuse "$sc_a @-"
            sc_args+=("$sc_a" "$1")
            shift
            ;;
        -[sSkfILg]*)
            [[ "$sc_a" =~ ^-[sSkfILg]+$ ]] || sc_refuse "$sc_a"
            sc_args+=("$sc_a")
            ;;
        -*) sc_refuse "$sc_a" ;;
        *) sc_args+=("$sc_a") ;;
    esac
done

if [ -t 0 ]; then
    # Typed input: bash read cannot see a NUL (Ctrl-@) typed here; it is dropped by the terminal read.
    IFS= read -rs -p "Password for ${sc_user}: " sc_pw || sc_pw=""
    echo >&2
else
    # -d '' reads to the first NUL or the end of input: a NUL makes read succeed, a plain line does not.
    if IFS= read -r -d '' sc_pw; then
        echo "secure-curl: the password may not contain a NUL byte" >&2
        exit 2
    fi
    sc_pw="${sc_pw%$'\n'}"
fi

case "$sc_user$sc_pw" in
    *[[:cntrl:]]*)
        echo "secure-curl: the user and password may not contain control characters or line breaks" >&2
        exit 2
        ;;
esac
if [ -z "$sc_user" ] || [ -z "$sc_pw" ]; then
    echo "secure-curl: the user and the password may not be empty" >&2
    exit 2
fi
case "$sc_user" in
    *:*)
        echo "secure-curl: the user name may not contain a colon" >&2
        exit 2
        ;;
esac

# Backslash first, then double quote: the curl config syntax inside a quoted string.
sc_cred="${sc_user}:${sc_pw}"
sc_cred="${sc_cred//\\/\\\\}"
sc_cred="${sc_cred//\"/\\\"}"
unset sc_pw

# printf is a builtin: no process holds the value, and the pipe carries it to curl only.
# -q first: no .curlrc. The only config curl reads is the one on stdin.
printf 'user = "%s"\n' "$sc_cred" | curl -q -K - "${sc_args[@]}"
status="${PIPESTATUS[1]}"
unset sc_cred
exit "$status"
