"""Daybreak review round 1 guards for the expiry watch slice 2 (issue #97): no proxy for
credential-bearing calls, a failure envelope is not an empty inventory, saved state always
loads, extreme timestamps are errors, and the fetch really ends at its deadline.
"""
import dataclasses
import datetime as dt
import http.server
import json
import threading
import time

import pytest

from test_expiry_watch import RUNBOOK, _at, _run, _write_setup, ew
from test_expiry_watch_providers import (DOPPLER_PATH, ENV, GRAFANA_PATH, TOKEN, FakeVendor, _dp_tok, _doppler,
                                         _grafana, _setup, _tok, router)  # noqa: F401  (router is a fixture)


def _fetch_threads():
    return {t for t in threading.enumerate() if t.name.startswith("expiry-get-") and t.is_alive()}


# --- 1. a proxy from the environment never sees a bearer --------------------------------------------

@pytest.fixture
def proxy_env(monkeypatch):
    proxy = FakeVendor()
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, proxy.base)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")  # does not cover 127.0.0.2
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    yield proxy
    proxy.close()


def test_a_vendor_call_to_another_loopback_address_never_goes_through_an_environment_proxy(proxy_env):
    target = FakeVendor(host="127.0.0.2")
    try:
        target.reply("/x", [])
        assert ew.http_get_json(target.base + "/x", TOKEN, 3) == []
        assert proxy_env.requests == [], "the bearer must not be handed to a proxy"
        assert target.requests and target.requests[0][1]["Authorization"] == f"Bearer {TOKEN}"
        target.reply(GRAFANA_PATH, [])
        assert _grafana(type("V", (), {"base": target.base})).items() == []
        assert proxy_env.requests == []
    finally:
        target.close()


def test_the_router_post_to_loopback_http_does_not_use_a_proxy_either(proxy_env):
    target = FakeVendor(host="127.0.0.2")
    try:
        target.reply("/h", {})
        ew.post_json(target.base + "/h", "router-secret-value", {"a": 1}, timeout=3)
        assert proxy_env.requests == [] and len(target.requests) == 1
    finally:
        target.close()


# --- 2. a failure envelope is an error, not an empty inventory -------------------------------------------

@pytest.mark.parametrize("payload", [
    {"success": False, "tokens": []},
    {"success": False, "messages": ["Could not find project"], "tokens": []},
    {"success": "true", "tokens": []},
    {"success": 0, "tokens": []},
    {"tokens": [], "error": "internal"},
    {"tokens": [], "errors": ["x"]},
])
def test_doppler_failure_envelopes_are_errors(payload):
    v = FakeVendor()
    try:
        v.reply(DOPPLER_PATH, payload)
        with pytest.raises(ew.ExpiryWatchError, match="(?i)success|error|failure"):
            _doppler(v).items()
    finally:
        v.close()


def test_a_200_failure_envelope_does_not_make_known_tokens_disappear(tmp_path, router):
    base, rec = router
    v = FakeVendor()
    try:
        cfg = _setup(tmp_path, base, v.base)
        v.reply(DOPPLER_PATH, {"success": True, "tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
        assert _run(cfg, _at(100), env=ENV)[0] == 0
        v.reply(DOPPLER_PATH, {"success": False, "tokens": []})
        code, _, err = _run(cfg, _at(99), env=ENV)
        assert code == 1 and "provider error" in err and not rec.seen
        v.reply(DOPPLER_PATH, {"success": True, "tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
        assert _run(cfg, _at(98), env=ENV)[0] == 0 and not rec.seen
    finally:
        v.close()


# --- 3. the state the watch writes is always state it can read back ----------------------------------------

def _items(prefix, n, long_text=False):
    owner = "o" * 99 if long_text else "ops@example.com"
    runbook = "https://wiki.example.com/" + "r" * 400 if long_text else RUNBOOK
    return [ew.Item.build(name=f"{prefix}{j}", kind="k" * (40 if long_text else 3), expires="2027-01-01",
                          owner=owner, runbook=runbook) for j in range(n)]


@pytest.mark.parametrize("providers,per,long_text", [
    (1, 10, False), (1, 1000, False), (4, 1000, False), (5, 1000, False), (30, 1000, False),
    (1, 1000, True), (2, 1000, True), (4, 1000, True),
])
def test_whatever_the_watch_saves_can_be_loaded_and_what_cannot_be_loaded_is_refused_before_writing(
        tmp_path, providers, per, long_text):
    results = {f"p{i}": (_items(f"i{i}_", per, long_text), set(), True) for i in range(providers)}
    _, seen = ew.track_disappeared({}, results, 1)
    state = {}
    path = tmp_path / "state.json"
    try:
        ew.save_state(path, state, seen=seen)
    except ew.ExpiryWatchError as e:
        assert "limit" in str(e).lower()
        assert not path.exists(), "an unloadable state must not be written"
    else:
        assert ew.load_memory(path) == (state, seen), "a saved state must load back unchanged"


def test_the_bound_is_hit_by_both_count_and_size_and_a_small_state_is_still_fine(tmp_path):
    outcomes = {}
    for label, providers, per, long_text in (("small", 1, 10, False), ("count", 5, 1000, False),
                                             ("bytes", 4, 1000, True)):
        results = {f"p{i}": (_items(f"i{i}_", per, long_text), set(), True) for i in range(providers)}
        _, seen = ew.track_disappeared({}, results, 1)
        try:
            ew.check_state_fits({}, seen)
            outcomes[label] = "fits"
        except ew.ExpiryWatchError as e:
            outcomes[label] = str(e)
    assert outcomes["small"] == "fits"
    assert outcomes["count"] != "fits" and outcomes["bytes"] != "fits"


def test_a_run_whose_state_would_not_load_fails_before_notifying_or_writing(tmp_path, router):
    base, rec = router

    class Many:
        def __init__(self, config):
            self.state_key = f"many:{config['n']}"
            self.n = config["n"]

        def items(self):
            got = _items(f"m{self.n}_", 1000)
            if self.n == 0:  # one item that is due now, so a notice WOULD be posted
                got.append(ew.Item.build(name="due", kind="k", expires="2026-03-01", owner="o@example.com",
                                         runbook=RUNBOOK))
            return got

    ew.register_provider("many-test", Many)
    try:
        cfg = _write_setup(tmp_path, base)
        text = cfg.read_text().replace('type = "registry"\npath = "registry.toml"', 'type = "many-test"\nn = 0')
        text += "".join(f'\n[[providers]]\ntype = "many-test"\nn = {k}\n' for k in range(1, 5))
        cfg.write_text(text)
        code, out, err = _run(cfg, _at(14))
        assert code == 1 and "state" in err and not rec.seen
        assert not (tmp_path / "state.json").exists()
    finally:
        del ew.PROVIDER_TYPES["many-test"]


# --- 4. extreme zoned timestamps are errors, not crashes ---------------------------------------------------

@pytest.mark.parametrize("bad", ["9999-12-31T23:59:59-23:00", "0001-01-01T00:00:00+23:00",
                                 "9999-12-31T23:59:59-23:59", "0001-01-01T00:00:00+23:59"])
def test_parse_expiry_overflow_at_the_calendar_edges_is_an_error(bad):
    with pytest.raises(ew.ExpiryWatchError):
        ew.parse_expiry("t", bad)


def test_parse_expiry_still_accepts_the_last_good_year():
    assert ew.parse_expiry("t", "9999-12-30T00:00:00Z") == dt.date(9999, 12, 30)


def test_a_hostile_timestamp_from_a_vendor_does_not_crash_the_run(tmp_path, router):
    base, rec = router
    v = FakeVendor()
    try:
        cfg = _setup(tmp_path, base, v.base)
        v.reply(DOPPLER_PATH, {"success": True, "tokens": [_dp_tok("ci", "9999-12-31T23:59:59-23:00")]})
        code, _, err = _run(cfg, _at(30), env=ENV)  # the other providers still work
        assert code == 1 and "provider error" in err
    finally:
        v.close()


# --- 5. the fetch ends at its deadline, it is not just abandoned ------------------------------------------------

def test_a_hanging_vendor_leaves_no_fetch_thread_behind():
    before = _fetch_threads()
    v = FakeVendor()
    try:
        v.hang = True
        with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out"):
            _grafana(v, timeout_seconds=1).items()
        assert _fetch_threads() - before == set(), "the worker must be stopped, with the vendor still hanging"
    finally:
        v.close()


def test_a_slow_drip_leaves_no_fetch_thread_behind():
    before = _fetch_threads()
    done = threading.Event()

    class Drip(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    if done.wait(0.2):
                        return
                    self.wfile.write(b" ")
                    self.wfile.flush()
            except OSError:
                pass

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fake = type("V", (), {"base": f"http://127.0.0.1:{srv.server_address[1]}"})
        t0 = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out"):
            _grafana(fake, timeout_seconds=1).items()
        assert time.monotonic() - t0 < 2.5
        assert _fetch_threads() - before == set(), "the drip must be cut off, not left running"
    finally:
        done.set()
        srv.shutdown()
        t.join(5)
        srv.server_close()
