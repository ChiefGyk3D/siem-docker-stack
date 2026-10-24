#!/usr/bin/env bash
# =============================================================================
# lib-secrets.sh — the one placeholder rule for shell scripts (source me)
# =============================================================================
# A secret is unusable when it is empty or a well-known placeholder or old
# default, compared case-insensitively. The Python client scripts carry the same
# rule (is_placeholder in each deploy-*.py); tests/python/test_required_secrets.py
# fails if the two disagree. Messages name the variable and never print its value.
#
#   secret_is_placeholder VALUE      exit 0 when VALUE must be rejected
#   require_secret NAME [VALUE]      exit 1 with a message when unusable
#                                    (VALUE defaults to the variable NAME)
# =============================================================================

secret_is_placeholder() {
    local v
    v="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$v" in
        "" | changeme* | change_me* | change-me* | your_* | your-* | "<"* | xxx* | example* | placeholder* | \
            secretpassword | my[s]3cr3tp4ssw0rd | kibanaserver | admin | password | \
            *your-password* | *strong-password*) return 0 ;;
    esac
    return 1
}

require_secret() {
    local name="$1" value
    if [ "$#" -ge 2 ]; then value="$2"; else value="${!name-}"; fi
    if secret_is_placeholder "$value"; then
        echo "ERROR: ${name} is missing, empty, or a placeholder. Set a real value (see README, Required secrets)." >&2
        return 1
    fi
}
