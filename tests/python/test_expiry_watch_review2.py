"""Daybreak review round 2 guards (issue #97): the writer applies the loader's own validators,
and name resolution (which cannot be interrupted) cannot pile up worker threads.
"""
import socket
import threading
import time

import pytest

from test_expiry_watch import RUNBOOK, _at, _run, _write_setup, ew
from test_expiry_watch_providers import GRAFANA_PATH, FakeVendor, _grafana
from test_expiry_watch_review1 import _fetch_threads, _items, router  # noqa: F401  (router is a fixture)


def _rec():
    return {"missed": 0, "item": {"kind": "k", "expires": "2027-01-01", "owner": "o@example.com",
                                  "runbook": RUNBOOK}}


# --- the writer and the loader agree -------------------------------------------------------------------

def test_one_provider_with_1001_items_is_refused_by_the_writer_before_any_file_exists(tmp_path):
    seen = {"plugin:one": {f"x{n}": _rec() for n in range(ew.MAX_ITEMS + 1)}}
    with pytest.raises(ew.ExpiryWatchError):
        ew.check_state_fits({}, seen)
    with pytest.raises(ew.ExpiryWatchError):
        ew.save_state(tmp_path / "state.json", {}, seen=seen)
    assert list(tmp_path.iterdir()) == [], "nothing, not even a temp file, may be created"


@pytest.mark.parametrize("seen", [
    {f"p{n}": {} for n in range(201)},                                    # more than 200 provider keys
    {"p": {"a": {"missed": -1, "item": _rec()["item"]}}},                 # bad record fields
    {"p": {"a": {"missed": 0, "item": {"kind": "k"}}}},
    {"p\x00": {"a": _rec()}},
    {"p": {"a\nb": _rec()}},
    {"": {"a": _rec()}},
])
def test_whatever_the_loader_refuses_the_writer_refuses_too(tmp_path, seen):
    path = tmp_path / "state.json"
    path.write_text('{"version": 2, "items": {}, "seen": %s}' % __import__("json").dumps(seen))
    with pytest.raises(ew.ExpiryWatchError):
        ew.load_memory(path)
    with pytest.raises(ew.ExpiryWatchError):
        ew.check_state_fits({}, seen)


def test_a_run_with_1001_items_in_one_provider_fails_before_notifying_or_writing(tmp_path, router):
    base, rec = router

    class Big:
        def __init__(self, config):
            self.state_key = "big:1"

        def items(self):
            got = _items("b", ew.MAX_ITEMS + 1)
            got.append(ew.Item.build(name="due", kind="k", expires="2026-03-01", owner="o@example.com",
                                     runbook=RUNBOOK))
            return got

    ew.register_provider("big-test", Big)
    try:
        cfg = _write_setup(tmp_path, base)
        cfg.write_text(cfg.read_text().replace('type = "registry"\npath = "registry.toml"', 'type = "big-test"'))
        code, _, err = _run(cfg, _at(14))
        assert code == 1 and "state error" in err and not rec.seen
        assert not (tmp_path / "state.json").exists()
    finally:
        del ew.PROVIDER_TYPES["big-test"]


# --- name resolution cannot be interrupted, so it is bounded instead --------------------------------------

def test_stuck_name_lookups_cannot_pile_up_threads_beyond_the_bound(monkeypatch):
    release = threading.Event()

    def stuck(*args, **kwargs):
        release.wait(20)
        raise socket.gaierror("released")

    monkeypatch.setattr(socket, "getaddrinfo", stuck)
    before = _fetch_threads()
    bound = ew.MAX_STUCK_FETCHES
    try:
        messages = []
        for _ in range(bound + 3):
            t0 = time.monotonic()
            with pytest.raises(ew.ExpiryWatchError) as exc:
                ew.http_get_json("https://vendor.example.com/x", "tok-value", 0.2)
            messages.append(str(exc.value))
            assert time.monotonic() - t0 < 2.5
        assert sum("timed out" in m for m in messages) == bound, "only `bound` lookups may be started"
        assert all("cannot be interrupted" in m for m in messages[bound:]), messages[bound:]
        assert len(_fetch_threads() - before) <= bound, "stuck lookups must not accumulate beyond the bound"
    finally:
        release.set()
    for _ in range(100):  # once the lookups return, the slots are free again
        if not _fetch_threads() - before:
            break
        time.sleep(0.05)
    assert not _fetch_threads() - before
    v = FakeVendor()
    try:
        monkeypatch.undo()
        v.reply(GRAFANA_PATH, [])
        assert _grafana(v).items() == [], "after the stuck lookups end, requests work again"
    finally:
        v.close()
