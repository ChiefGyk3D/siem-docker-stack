#!/usr/bin/env python3
"""Resolve the n8n base URL at run time instead of hard-coding a bridge address.

The n8n container's address on the siem network is assigned by Docker and changes
after a recreate or a restart, so no script should name it. This helper asks the
container runtime for the address on the siem network. As a command it prints the
base URL (used by shell scripts); as a module, scripts call resolve_n8n_base().

Environment (all optional):
  N8N_BASE        full base URL; when set it wins and the runtime is not asked
  N8N_CONTAINER   container name (default: n8n)
  SIEM_NETWORK    exact name of the network to read the address from. Unset:
                  the one attached network named siem-net or ending in _siem-net
                  (compose prefixes the project name, for example siem_siem-net;
                  `docker network ls` shows the real name). Zero or several
                  matches is an error that tells you to set this.
  N8N_PORT        port on that address (default: 80)

Exit status 1 with a message on stderr when the address cannot be found.
"""
import json
import os
import subprocess
import sys


class N8nAddressError(Exception):
    """The n8n address could not be resolved; the message says what to do."""


def resolve_n8n_base(env=None, run=subprocess.run):
    """Return the n8n base URL. `env` and `run` are injectable for tests."""
    env = os.environ if env is None else env
    override = (env.get("N8N_BASE") or "").strip()
    if override:
        return override.rstrip("/")

    container = env.get("N8N_CONTAINER") or "n8n"
    explicit = env.get("SIEM_NETWORK") or ""
    port = env.get("N8N_PORT") or "80"
    hint = "Set N8N_BASE to the full URL (for example http://192.0.2.10:80) to skip the lookup."

    try:
        proc = run(
            ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        raise N8nAddressError(f"docker command not found, cannot look up the address of '{container}'. {hint}")
    except subprocess.TimeoutExpired:
        raise N8nAddressError(f"docker inspect of '{container}' timed out. {hint}")
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise N8nAddressError(f"could not inspect container '{container}': {detail}. {hint}")

    try:
        networks = json.loads(proc.stdout)
        if not isinstance(networks, dict):
            raise ValueError("not an object")
    except ValueError:
        raise N8nAddressError(f"docker inspect of '{container}' returned unexpected output. {hint}")

    attached = ", ".join(sorted(networks)) or "none"
    if explicit:
        network = explicit  # an explicit name is an exact match
        if network not in networks:
            raise N8nAddressError(
                f"container '{container}' is not attached to network '{network}' "
                f"(attached: {attached}). Reattach it with: docker network connect {network} {container}  "
                f"and fix its compose file so a recreate keeps the network. {hint}"
            )
    else:
        matches = sorted(n for n in networks if n == "siem-net" or n.endswith("_siem-net"))
        if not matches:
            raise N8nAddressError(
                f"container '{container}' is not attached to a siem network "
                f"(looked for siem-net or *_siem-net; attached: {attached}). Reattach it with: "
                f"docker network connect <network-name> {container}  (find the name with "
                f"`docker network ls`, usually the compose project name plus _siem-net), "
                f"or set SIEM_NETWORK to the exact name. {hint}"
            )
        if len(matches) > 1:
            raise N8nAddressError(
                f"container '{container}' is on more than one siem network ({', '.join(matches)}). "
                f"Set SIEM_NETWORK to the exact name to use. {hint}"
            )
        network = matches[0]
    address = (networks[network] or {}).get("IPAddress") or ""
    if not address:
        raise N8nAddressError(f"container '{container}' has no address on network '{network}'. {hint}")
    return f"http://{address}:{port}"


def main():
    try:
        print(resolve_n8n_base())
    except N8nAddressError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
