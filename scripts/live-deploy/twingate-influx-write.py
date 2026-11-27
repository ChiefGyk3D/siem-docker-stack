#!/usr/bin/env python3
"""twingate-influx-write.py - write Twingate collector line protocol (stdin) to InfluxDB 1.x.
Issue #222. Stdlib only. Run it under siem-run so the credentials come from the secret manager.

Environment (never argv, never printed):
  TWINGATE_INFLUX_USER      write-only account (twingate_wo)
  TWINGATE_INFLUX_PASSWORD  its password
  INFLUX_URL                default http://127.0.0.1:8086 (the compose file publishes InfluxDB
                            on 127.0.0.1:8086 unless INGEST_BIND_ADDR says otherwise). Plain http
                            is accepted only for a loopback host; any other host needs https.
  TWINGATE_INFLUX_DB        default telegraf (the database of datasource influxdb-twingate)

One POST to /write?db=<db>&precision=s with Basic auth, 5 s timeout. http.client is used on
purpose: it never follows a redirect, so the password cannot be carried to another host, and
the write is never retried or replayed. Input is bounded and every line must be a twingate_
metric. It prints only counts and the HTTP status. Exit 0 only on a 2xx answer; an empty
input, a 401, any other non-2xx, a redirect or a connection failure exits 1.
"""
import base64
import http.client
import os
import re
import sys
import urllib.parse

DEFAULT_URL = "http://127.0.0.1:8086"
DEFAULT_DB = "telegraf"
MAX_BYTES = 64 * 1024
MAX_LINES = 500
TIMEOUT = 5
LINE = re.compile(r"twingate_[a-z_]{1,60}(?:,[A-Za-z0-9_]{1,32}=[A-Za-z0-9._-]{1,128}){0,4} value=-?[0-9]{1,15}i")
DB = re.compile(r"[A-Za-z0-9_-]{1,64}")
LOOPBACK = ("127.0.0.1", "localhost", "::1")


class WriteError(Exception):
    """The message is fixed text and safe to print."""


def parse_url(raw):
    u = urllib.parse.urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password \
            or u.path not in ("", "/") or u.query or u.fragment:
        raise WriteError("INFLUX_URL must be a plain http(s) URL without credentials or a path")
    if u.scheme == "http" and u.hostname not in LOOPBACK:
        raise WriteError("INFLUX_URL uses cleartext http to a non-loopback host; use https")
    try:
        port = u.port
    except ValueError:
        raise WriteError("INFLUX_URL has a bad port")
    return u.scheme, u.hostname, port


def read_lines(stream):
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise WriteError("input too large")
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    lines = [ln for ln in text.split("\n") if ln.strip()]
    if not lines:
        raise WriteError("empty input, nothing to write")
    if len(lines) > MAX_LINES:
        raise WriteError("too many lines")
    for ln in lines:
        if not LINE.fullmatch(ln):
            raise WriteError("input line is not a twingate_ metric in the expected form")
    return lines


def main(env=None, stdin=None, stdout=None, stderr=None):
    env = os.environ if env is None else env
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        user, password = env.get("TWINGATE_INFLUX_USER", ""), env.get("TWINGATE_INFLUX_PASSWORD", "")
        if not user or not password or ":" in user:
            raise WriteError("TWINGATE_INFLUX_USER and TWINGATE_INFLUX_PASSWORD must be set")
        db = env.get("TWINGATE_INFLUX_DB") or DEFAULT_DB
        if not DB.fullmatch(db):
            raise WriteError("TWINGATE_INFLUX_DB has characters outside letters, digits, _ and -")
        scheme, host, port = parse_url(env.get("INFLUX_URL") or DEFAULT_URL)
        lines = read_lines(stdin)
        body = ("\n".join(lines) + "\n").encode("ascii")
        auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        conn = cls(host, port, timeout=TIMEOUT)
        try:
            conn.request("POST", f"/write?db={db}&precision=s", body=body,
                         headers={"Authorization": auth, "Content-Type": "text/plain; charset=utf-8"})
            status = conn.getresponse().status
        finally:
            conn.close()
    except WriteError as e:
        stderr.write(f"twingate-influx-write: {e}\n")
        return 1
    except Exception:  # connection, TLS or encoding failure: fixed text only, never the exception
        stderr.write("twingate-influx-write: write failed (connection error)\n")
        return 1
    if 200 <= status < 300:
        stdout.write(f"twingate-influx-write: lines={len(lines)} status={status}\n")
        return 0
    why = "unauthorized (401): check the write account" if status == 401 else "write refused"
    stderr.write(f"twingate-influx-write: {why}\ntwingate-influx-write: lines={len(lines)} status={status}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
