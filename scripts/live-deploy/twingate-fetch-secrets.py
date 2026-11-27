#!/usr/bin/python3 -I
"""Broker step of the Twingate collector (issue #222, review rounds 4 and 5).

Runs under siem-run inside the broker unit (a dynamic user), the only place the secret manager's
service token is readable. It receives the named secrets as environment variables and writes one
GENERATION: a new directory named by a random run id (32 hex characters) under TWINGATE_STAGE_DIR
(the broker's own runtime directory, a tmpfs path). The generation holds collector.json and
writer.json (one file per stage, so the collector never sees the InfluxDB login and the writer never
sees the Twingate key) and, written last, manifest.json with the run id and the SHA-256 of both
files. Any older generation found in the directory is removed first, and on any failure the whole
new generation is removed. Only counts are printed.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import sys

RUN_ID = re.compile(r"[0-9a-f]{32}")   # always used with fullmatch
STAGE_NAMES = {
    "collector.json": ("TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                       "TWINGATE_CONNECTOR_MANAGED_BY", "TWINGATE_EXPECTED_CONNECTORS"),
    "writer.json": ("TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD"),
}


def write_private(directory, name, data):
    """Create `name` exclusively (mode 600, no symlink followed); return the SHA-256 of its bytes."""
    raw = json.dumps(data).encode("utf-8")
    fd = os.open(os.path.join(directory, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return hashlib.sha256(raw).hexdigest()


def remove_generations(directory):
    for entry in os.listdir(directory):
        if RUN_ID.fullmatch(entry):
            path = os.path.join(directory, entry)
            if os.path.islink(path):
                os.unlink(path)
            else:
                shutil.rmtree(path, ignore_errors=True)


def main():
    directory = os.environ.get("TWINGATE_STAGE_DIR", "")
    if not os.path.isabs(directory) or not os.path.isdir(directory):
        print("twingate-fetch: stage directory missing", file=sys.stderr)
        return 2
    run_id = secrets.token_hex(16)
    gen = os.path.join(directory, run_id)
    created = False
    try:
        remove_generations(directory)
        os.mkdir(gen, 0o700)
        created = True
        total, digests = 0, {}
        for fname, names in STAGE_NAMES.items():
            data = {n: os.environ[n] for n in names if os.environ.get(n)}
            total += len(data)
            digests[fname] = write_private(gen, fname, {"run_id": run_id, "secrets": data})
        if total == 0:
            raise ValueError("no secret arrived")
        manifest = {"version": 1, "run_id": run_id, "files": digests}
        write_private(gen, "manifest.json.tmp", manifest)
        os.replace(os.path.join(gen, "manifest.json.tmp"), os.path.join(gen, "manifest.json"))
    except (OSError, ValueError):
        if created:
            shutil.rmtree(gen, ignore_errors=True)
        print("twingate-fetch: failed", file=sys.stderr)
        return 1
    print("twingate-fetch: files=3 secrets=%d" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
