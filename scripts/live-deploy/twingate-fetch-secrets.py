#!/usr/bin/python3 -I
"""Broker step of the Twingate collector (issue #222, review round 4).

Runs under siem-run inside the broker unit, the only place the secret manager's service token
is readable. It receives the named secrets as environment variables and writes them to two
credential files for systemd to hand to the two stage units, one file per stage, so the
collector never sees the InfluxDB login and the writer never sees the Twingate key. The files
are mode 600 in a private directory (TWINGATE_STAGE_DIR, a tmpfs path). Only counts are printed.
"""
import json
import os
import sys

STAGE_NAMES = {
    "collector.json": ("TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                       "TWINGATE_CONNECTOR_MANAGED_BY", "TWINGATE_EXPECTED_CONNECTORS"),
    "writer.json": ("TWINGATE_INFLUX_USER", "TWINGATE_INFLUX_PASSWORD"),
}


def write_private(directory, name, data):
    final, tmp = os.path.join(directory, name), os.path.join(directory, name + ".tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data))
    os.replace(tmp, final)


def main():
    directory = os.environ.get("TWINGATE_STAGE_DIR", "")
    if not os.path.isabs(directory) or not os.path.isdir(directory):
        print("twingate-fetch: stage directory missing", file=sys.stderr)
        return 2
    written = []
    try:
        total = 0
        for fname, names in STAGE_NAMES.items():
            data = {n: os.environ[n] for n in names if os.environ.get(n)}
            total += len(data)
            write_private(directory, fname, data)
            written.append(fname)
        if total == 0:
            raise ValueError("no secret arrived")
    except (OSError, ValueError):
        for fname in written:
            try:
                os.unlink(os.path.join(directory, fname))
            except OSError:
                pass
        print("twingate-fetch: failed", file=sys.stderr)
        return 1
    print("twingate-fetch: files=%d secrets=%d" % (len(written), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
