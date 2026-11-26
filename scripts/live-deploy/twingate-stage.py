#!/usr/bin/python3 -I
"""One stage of the Twingate collector (issue #222, review round 4).

Started by a stage unit with `collector` or `writer` as its only argument. The unit runs as its
own dynamic user and cannot reach the secret manager's token: its secrets arrive as one systemd
credential (a JSON file in $CREDENTIALS_DIRECTORY that only this unit can read). This wrapper
checks the names against the stage's allowlist, builds a clean environment and replaces itself
with the stage program. The writer also gets the collector's output as its standard input from
the credential "metrics". No value is printed or put on a command line.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PYTHON = "/usr/bin/python3"
MAX_BYTES = 65536
STAGES = {
    "collector": {
        "secrets": ("TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                    "TWINGATE_CONNECTOR_MANAGED_BY", "TWINGATE_EXPECTED_CONNECTORS"),
        "plain": ("SSL_CERT_FILE", "SSL_CERT_DIR"),
        "program": os.path.join(REPO, "scripts", "twingate-update-metric.py"),
        "stdin": None,
    },
    "writer": {
        "secrets": ("TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD"),
        "plain": ("SSL_CERT_FILE", "SSL_CERT_DIR", "INFLUX_URL", "TWINGATE_INFLUX_DB"),
        "program": os.path.join(HERE, "twingate-influx-write.py"),
        "stdin": "metrics",
    },
}


def fail(msg):
    print("twingate-stage: " + msg, file=sys.stderr)
    return 1


def main(argv):
    if len(argv) != 2 or argv[1] not in STAGES:
        return fail("usage: twingate-stage collector|writer")
    stage = STAGES[argv[1]]
    cred = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not os.path.isabs(cred):
        return fail("no credentials directory")
    try:
        with open(os.path.join(cred, "env"), "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return fail("credential too large")
        loaded = json.loads(raw)
    except (OSError, ValueError):
        return fail("credential unreadable")
    if not isinstance(loaded, dict):
        return fail("credential malformed")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for name, value in loaded.items():
        if name not in stage["secrets"] or not isinstance(value, str):
            return fail("credential holds a name this stage does not take")
        env[name] = value
    for name in stage["plain"]:
        if name in os.environ:
            env[name] = os.environ[name]
    if stage["stdin"]:
        try:
            fd = os.open(os.path.join(cred, stage["stdin"]), os.O_RDONLY)
        except OSError:
            return fail("input credential unreadable")
        os.dup2(fd, 0)
        os.close(fd)
    os.execve(PYTHON, [PYTHON, "-I", stage["program"]], env)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
