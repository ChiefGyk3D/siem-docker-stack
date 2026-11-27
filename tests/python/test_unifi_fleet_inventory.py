"""Guards for issue #252: scripts/unifi-fleet-inventory.sh prints a read-only UniFi fleet table.

The script runs against a fake curl and a fake doppler placed first on PATH in a scratch
directory; it is never pointed at a real network. The fakes record what the script gave them
(curl's argv and stdin) so the tests can prove the token reaches curl only on stdin and never
reaches the output. INV_SCRIPT_UNDER_TEST points the same tests at a mutated copy, to prove a
guard bites.
"""
import json
import os
import stat
import subprocess
import time

import pytest

from conftest import REPO_ROOT

SCRIPT = os.environ.get("INV_SCRIPT_UNDER_TEST") or str(REPO_ROOT / "scripts" / "unifi-fleet-inventory.sh")
TOKEN = "glsa_FAKEtokenValue0123456789"
BASE = "http://grafana.invalid:3000"

FAKE_CURL = r'''#!/usr/bin/env bash
printf '%s\n' "$@" > "$FAKE_DIR/curl.argv"
cat > "$FAKE_DIR/curl.stdin"
if [ -n "${FAKE_CURL_EXIT:-}" ]; then echo "curl: (28) timed out" >&2; exit "$FAKE_CURL_EXIT"; fi
cat "$FAKE_DIR/body.json"
printf '\n%s' "${FAKE_CURL_CODE:-200}"
'''
FAKE_DOPPLER = r'''#!/usr/bin/env bash
printf '%s\n' "$@" > "$FAKE_DIR/doppler.argv"
if [ -n "${FAKE_DOPPLER_FAIL:-}" ]; then echo "not logged in" >&2; exit 1; fi
printf '%s' "${FAKE_TOKEN-}"
'''


def frame(name, values, times, field="last"):
    return {"schema": {"fields": [{"name": "Time", "type": "time"},
                                  {"name": field, "labels": {"name": name}}]},
            "data": {"values": [times, values]}}


def answer(devices, now_ms, age_s=60):
    """devices: list of (name, model, version, upgradeable)."""
    t = [now_ms - age_s * 1000]
    a = [frame(n, [u], t) for n, _, _, u in devices]
    b = [frame(n, [m], t) for n, m, _, _ in devices]
    c = [frame(n, [v], t) for n, _, v, _ in devices]
    return {"results": {"A": {"status": 200, "frames": a},
                        "B": {"status": 200, "frames": b},
                        "C": {"status": 200, "frames": c}}}


@pytest.fixture
def env(tmp_path):
    d = tmp_path / "fake"
    d.mkdir()
    for name, body in (("curl", FAKE_CURL), ("doppler", FAKE_DOPPLER)):
        p = d / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    e = dict(os.environ)
    e.update(PATH=f"{d}:{os.environ['PATH']}", FAKE_DIR=str(d), FAKE_TOKEN=TOKEN,
             GRAFANA_BASE_URL=BASE)
    for k in ("FAKE_CURL_EXIT", "FAKE_CURL_CODE", "FAKE_DOPPLER_FAIL"):
        e.pop(k, None)
    return e, d


def run(env, body=None, **extra):
    e, d = env
    if body is not None:
        (d / "body.json").write_text(body if isinstance(body, str) else json.dumps(body))
    e = {**e, **extra}
    for k in [k for k, v in e.items() if v is None]:
        del e[k]
    return subprocess.run(["bash", SCRIPT], capture_output=True, text=True, env=e,
                          stdin=subprocess.DEVNULL, timeout=60, check=False)


def now_ms():
    return int(time.time() * 1000)


def test_happy_path_table_and_summary(env):
    devs = [("Core Switch", "USW-Pro-48", "7.0.50", True), ("Office AP", "U6-Pro", "6.6.77", False),
            ("Gateway", "UDM-Pro", "4.0.6", 0)]
    r = run(env, answer(devs, now_ms()))
    assert r.returncode == 0, r.stderr
    out = r.stdout
    for w in ("NAME", "MODEL", "FIRMWARE", "UPDATE", "LAST SEEN", "Core Switch", "USW-Pro-48", "7.0.50",
              "Office AP", "U6-Pro", "Gateway", "UDM-Pro"):
        assert w in out
    rows = {ln[:12].strip(): ln for ln in out.splitlines()}
    assert "yes" in rows["Core Switch"] and "no" in rows["Office AP"] and "no" in rows["Gateway"]
    assert "devices: 3" in out and "updates available: 1" in out
    assert "newest sample:" in out and "STALE" not in out
    cols = {rows[k].index(m) for k, m in (("NAME", "MODEL"), ("Core Switch", "USW-Pro-48"),
                                          ("Office AP", "U6-Pro"), ("Gateway", "UDM-Pro"))}
    assert len(cols) == 1  # aligned
    assert r.stderr == ""


def test_token_only_on_stdin_never_printed(env):
    _, d = env
    r = run(env, answer([("AP1", "U6", "1.0", False)], now_ms()))
    assert r.returncode == 0
    assert TOKEN not in r.stdout and TOKEN not in r.stderr
    assert TOKEN not in (d / "curl.argv").read_text()
    assert TOKEN not in (d / "doppler.argv").read_text()
    assert f"Authorization: Bearer {TOKEN}" in (d / "curl.stdin").read_text()
    argv = (d / "curl.argv").read_text()
    assert "--max-time" in argv and "-K" in argv and BASE + "/api/ds/query" in argv


def test_token_not_printed_on_failures(env):
    for body, extra in (("{not json", {}), ("{}", {"FAKE_CURL_CODE": "500"}), ("{}", {"FAKE_CURL_EXIT": "28"}),
                        ("{}", {"FAKE_TOKEN": TOKEN + "\nx"}), ("{}", {"GRAFANA_BASE_URL": "ftp://x"})):
        r = run(env, body, **extra)
        assert r.returncode != 0
        assert TOKEN not in r.stdout + r.stderr


def test_hostile_names_control_chars_stripped(env):
    esc, bel, nl = chr(27), chr(7), chr(10)
    devs = [(f"AP{esc}[31mRED{bel}\r{nl}FAKE ROW", "U6\tX", f"1.0{esc}]0;pwn{bel}", False),
            (f"bidi{chr(0x202e)}evil{chr(0x85)}", "M", "2", True)]
    r = run(env, answer(devs, now_ms()))
    assert r.returncode == 0, r.stderr
    for ch in (esc, bel, "\r", chr(0x202e), chr(0x85), "\t"):
        assert ch not in r.stdout
    assert len([ln for ln in r.stdout.splitlines() if "FAKE ROW" in ln]) == 1
    assert "devices: 2" in r.stdout


def test_missing_token(env):
    for extra in ({"FAKE_TOKEN": ""}, {"FAKE_DOPPLER_FAIL": "1"}):
        r = run(env, answer([("AP", "U6", "1", False)], now_ms()), **extra)
        assert r.returncode == 1
        assert "token" in r.stderr.lower() and r.stdout == ""


def test_token_with_control_characters_refused(env):
    r = run(env, answer([("AP", "U6", "1", False)], now_ms()), FAKE_TOKEN="abc\ndef")
    assert r.returncode == 1 and r.stdout == ""


def test_base_url_unset_or_bad(env):
    for url in (None, "", "ftp://x", "http://u:p@host", "http://host/ a", "host:3000"):
        r = run(env, "{}", GRAFANA_BASE_URL=url)
        assert r.returncode == 1 and "GRAFANA_BASE_URL" in r.stderr and r.stdout == ""


def test_curl_failure(env):
    r = run(env, "{}", FAKE_CURL_EXIT="28")
    assert r.returncode == 1 and r.stdout == "" and "curl" in r.stderr.lower()


def test_http_error_status(env):
    r = run(env, '{"message":"Unauthorized"}', FAKE_CURL_CODE="401")
    assert r.returncode == 1 and "401" in r.stderr and r.stdout == ""


@pytest.mark.parametrize("body", [
    "{not json", "[]", "{}", '{"results":{}}', '{"results":{"A":{"frames":[]}}}',
    '{"message":"boom"}',
    '{"results":{"A":{"error":"bad","status":400},"B":{"frames":[]},"C":{"frames":[]}}}',
    '{"results":{"A":{"frames":[{"schema":{"fields":[]},"data":{"values":[]}}]},"B":{"frames":[]},"C":{"frames":[]}}}',
    '{"results":{"A":{"frames":[{"schema":{"fields":[{},{"labels":{"name":5}}]},"data":{"values":[[1],[true]]}}]},"B":{"frames":[]},"C":{"frames":[]}}}',
])
def test_malformed_json_fails_closed(env, body):
    r = run(env, body)
    assert r.returncode == 1, r.stdout
    assert r.stdout == "" and r.stderr.strip()


def test_empty_result(env):
    r = run(env, answer([], now_ms()))
    assert r.returncode == 1 and "no UniFi devices" in r.stderr and r.stdout == ""


def test_stale_data_warning(env):
    r = run(env, answer([("AP", "U6", "1", False)], now_ms(), age_s=3 * 3600))
    assert r.returncode == 0
    assert "WARNING" in r.stdout and "STALE" in r.stdout


def test_too_many_devices_fails(env):
    devs = [(f"AP{i}", "U6", "1", False) for i in range(201)]
    r = run(env, answer(devs, now_ms()))
    assert r.returncode == 1 and "200" in r.stderr


def test_model_and_version_queries_failing_degrades_visibly(env):
    t = [now_ms() - 60000]
    body = {"results": {"A": {"frames": [frame("AP", [True], t)]},
                        "B": {"error": "field not found", "status": 400},
                        "C": {"frames": []}}}
    r = run(env, body)
    assert r.returncode == 0, r.stderr
    assert "UNVERIFIED" in r.stderr
    assert "AP" in r.stdout and "?" in r.stdout


def test_script_is_read_only_shape():
    text = open(SCRIPT, encoding="utf-8").read()
    for bad in ("-X DELETE", "-X PUT", "-X PATCH", "set -x", "--insecure", " -k "):
        assert bad not in text
    assert "set -eu" in text and "--max-time" in text
