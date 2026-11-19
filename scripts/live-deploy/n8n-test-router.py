#!/usr/bin/env python3
"""Pre-deploy checks for the authenticated alert router. Runs on the SIEM host
under siem-run. Prints only status codes and plain words; never a value.

Cases (each posts to the NEW workflow's private webhook path):
  1. no Authorization header           -> expect 401 or 403
  2. wrong Authorization value         -> expect 401 or 403
  3. wrong scheme (Basic, right value) -> expect 401 or 403
  4. valid header, malformed body      -> expect 200 (a visible malformed notice goes to Discord)
  5. valid header, firing test alert   -> expect 200 (one Discord message; no phone, Pushover is off)
  6. valid header, resolved test alert -> expect 200 (one Discord message)

Usage:
  siem-run python3 -I n8n-test-router.py
  siem-run python3 -I n8n-test-router.py --phone | --phone-resolve   (real phone pushes, Pushover on)

Environment (all optional):
  N8N_BASE         base URL used for the checks. Default: looked up at run time
                   from the n8n container's address on the siem Docker network
                   (a macvlan address is not reachable from its own host). Set it
                   to skip the lookup. Lookup variables: N8N_CONTAINER (n8n),
                   SIEM_NETWORK (siem-net), N8N_PORT (80). See scripts/n8n_address.py.
  SIEM_CONFIG_DIR  private config directory with the file "router-path"
                   (default: $HOME/.config/doppler-siem)
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = None  # resolved in main(), so importing this file never calls docker
CONFIG_DIR = os.environ.get("SIEM_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "doppler-siem")
PATH_FILE = os.path.join(CONFIG_DIR, "router-path")


def post(path, headers, body):
    req = urllib.request.Request(
        BASE + "/webhook/" + path,
        data=body.encode(),
        headers=dict({"Content-Type": "application/json"}, **headers),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except Exception as err:  # connection problems
        return "error:" + type(err).__name__


def alert(status, name):
    return json.dumps({
        "status": status,
        "alerts": [{
            "status": status,
            "labels": {"alertname": name, "severity": "warning"},
            "annotations": {"summary": "Router test, safe to ignore"},
            "fingerprint": "00ab12cd34ef5678",
        }],
    })


def phone(mode, path, good):
    """Phone tests with real allowlisted alert names (Pushover must be on in the router)."""
    def one(name, severity, status):
        body = json.dumps({
            "status": status,
            "alerts": [{
                "status": status,
                "labels": {"alertname": name, "severity": severity, "name": "router test"},
                "annotations": {"summary": "Router phone test, safe to ignore"},
                "fingerprint": "00ab12cd34ef5678",
            }],
        })
        return post(path, good, body)
    if mode == "--phone":
        print("warning (priority 1, plain buzz)      ->", one("UniFi update pending over 24h", "warning", "firing"))
        print("critical (priority 2, repeats)        ->", one("UniFi update pending over 7 days", "critical", "firing"))
        return 0
    if mode == "--phone-resolve":
        print("critical resolved (cancels repeats)   ->", one("UniFi update pending over 7 days", "critical", "resolved"))
        return 0
    return 2


def main():
    global BASE
    secret = os.environ.get("GRAFANA_WEBHOOK_SECRET", "")
    if not secret:
        sys.exit("missing environment value: GRAFANA_WEBHOOK_SECRET")
    with open(PATH_FILE, encoding="utf-8") as handle:
        path = handle.read().strip()
    # -I removes the script directory from sys.path, so add the parent scripts/ directory.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import n8n_address
    try:
        BASE = n8n_address.resolve_n8n_base()
    except n8n_address.N8nAddressError as err:
        sys.exit(f"ERROR: {err}")
    good = {"Authorization": "Bearer " + secret}
    if len(sys.argv) > 1 and sys.argv[1] in ("--phone", "--phone-resolve"):
        return phone(sys.argv[1], path, good)
    cases = [
        ("1 no header", {}, alert("firing", "router test"), (401, 403)),
        ("2 wrong value", {"Authorization": "Bearer " + "x" * 40}, alert("firing", "router test"), (401, 403)),
        ("3 wrong scheme", {"Authorization": "Basic " + secret}, alert("firing", "router test"), (401, 403)),
        ("4 malformed body, valid header", good, '{"status": "weird", "alerts": [{}]}', (200,)),
        ("5 firing test alert, valid header", good, alert("firing", "router test"), (200,)),
        ("6 resolved test alert, valid header", good, alert("resolved", "router test"), (200,)),
    ]
    failed = 0
    for label, headers, body, expect in cases:
        code = post(path, headers, body)
        ok = code in expect
        failed += 0 if ok else 1
        print("%-36s -> %s  (expected %s)  %s" % (label, code, "/".join(map(str, expect)), "PASS" if ok else "FAIL"))
    print("failed cases:", failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
