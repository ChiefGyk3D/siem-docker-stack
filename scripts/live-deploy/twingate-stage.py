#!/usr/bin/python3 -I
"""One stage of the Twingate collector (issue #222, review rounds 4 and 5).

Started by a stage unit with `collector` or `writer` as its only argument. The unit runs as its
own dynamic user and cannot reach the secret manager's token: its secrets arrive as systemd
credentials (files in $CREDENTIALS_DIRECTORY that only this unit can read).

Generation check (round 5): every run has a random run id. The credential "manifest" names the
id and the SHA-256 of each stage file; the stage file repeats the id. This wrapper refuses to
start when the manifest is missing or malformed, the stage file does not match the manifest
digest, or the ids disagree, so a stale file from an earlier run is never used. The collector
prints the header line "# twingate-run <id>" before its own output; the writer accepts the
collector's output only when that header carries the same id, and strips it.

The wrapper then checks the secret names against the stage's allowlist, builds a clean
environment and replaces itself with the stage program. No value is printed or put on a command line.
"""
import hashlib
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PYTHON = "/usr/bin/python3"
MAX_BYTES = 65536
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
HEADER = "# twingate-run "
STAGES = {
    "collector": {
        "file": "collector.json",
        "secrets": ("TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                    "TWINGATE_CONNECTOR_MANAGED_BY", "TWINGATE_EXPECTED_CONNECTORS"),
        "plain": ("SSL_CERT_FILE", "SSL_CERT_DIR"),
        "program": os.path.join(REPO, "scripts", "twingate-update-metric.py"),
        "metrics": False,
    },
    "writer": {
        "file": "writer.json",
        "secrets": ("TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD"),
        "plain": ("SSL_CERT_FILE", "SSL_CERT_DIR", "INFLUX_URL", "TWINGATE_INFLUX_DB"),
        "program": os.path.join(HERE, "twingate-influx-write.py"),
        "metrics": True,
    },
}


def fail(msg):
    print("twingate-stage: " + msg, file=sys.stderr)
    return 1


def read_credential(cred, name, limit=MAX_BYTES):
    with open(os.path.join(cred, name), "rb") as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("too large")
    return raw


def load_generation(cred, stage):
    """Return (run_id, secrets dict) for this stage, or raise ValueError/OSError."""
    manifest = json.loads(read_credential(cred, "manifest"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise ValueError("manifest")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID.match(run_id):
        raise ValueError("run id")
    raw = read_credential(cred, "env")
    want = manifest["files"].get(stage["file"])
    if not isinstance(want, str) or hashlib.sha256(raw).hexdigest() != want:
        raise ValueError("generation mismatch")
    loaded = json.loads(raw)
    if not isinstance(loaded, dict) or loaded.get("run_id") != run_id or not isinstance(loaded.get("secrets"), dict):
        raise ValueError("generation mismatch")
    return run_id, loaded["secrets"]


def metrics_stdin(cred, run_id):
    """Check the collector's header against run_id; return an open file with the body."""
    raw = read_credential(cred, "metrics", MAX_BYTES + 128).decode("utf-8")
    head, sep, body = raw.partition("\n")
    if not sep or head != HEADER + run_id or not body.strip():
        raise ValueError("metrics from another run")
    tmp = tempfile.TemporaryFile()
    tmp.write(body.encode("utf-8"))
    tmp.flush()
    tmp.seek(0)
    return tmp


def main(argv):
    if len(argv) != 2 or argv[1] not in STAGES:
        return fail("usage: twingate-stage collector|writer")
    stage = STAGES[argv[1]]
    cred = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not os.path.isabs(cred):
        return fail("no credentials directory")
    try:
        run_id, loaded = load_generation(cred, stage)
    except (OSError, ValueError, UnicodeError):
        return fail("credential unreadable or from another run")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for name, value in loaded.items():
        if name not in stage["secrets"] or not isinstance(value, str):
            return fail("credential holds a name this stage does not take")
        env[name] = value
    for name in stage["plain"]:
        if name in os.environ:
            env[name] = os.environ[name]
    if stage["metrics"]:
        try:
            tmp = metrics_stdin(cred, run_id)
        except (OSError, ValueError, UnicodeError):
            return fail("input credential unreadable or from another run")
        os.dup2(tmp.fileno(), 0)
        tmp.close()
    else:
        sys.stdout.write(HEADER + run_id + "\n")
        sys.stdout.flush()
    os.execve(PYTHON, [PYTHON, "-I", stage["program"]], env)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
