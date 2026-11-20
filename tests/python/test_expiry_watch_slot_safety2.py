"""Issue #132, review round 1: a fatal after an accepted delivery never makes the notice be sent
again, a start() that raises after the thread started keeps the slot with the worker, and a fatal
raised after the deadline is parked and raised by the next call.
"""
import http.client
import threading
import time

import pytest

from test_expiry_watch import ew
from test_expiry_watch_channels import _pending, _run, _setup, _start_smtp, _stop, _at, _Matrix, matrix  # noqa: F401

URL = "https://vendor.example.com/x"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(ew, "_FETCH_SLOTS", threading.BoundedSemaphore(ew.MAX_STUCK_FETCHES))
    monkeypatch.setattr(ew, "_LATE_FATALS", [], raising=False)


def _full():
    return ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES


def _wait_full():
    for _ in range(200):
        if _full():
            return True
        time.sleep(0.02)
    return False


class _Dl:
    delivered = False

    def __init__(self, seconds=2.0):
        self.seconds = seconds
        self.end = time.monotonic() + seconds

    def abort(self):
        pass


def _fatal_after_send(monkeypatch, exc):
    """Run the real send, then raise a fatal from the worker (the receiver has the message)."""
    real = ew._run_deadline

    def wrapped(dl, fn):
        def after():
            fn()
            raise exc
        return real(dl, after)

    monkeypatch.setattr(ew, "_run_deadline", wrapped)
    return real


# --- finding 1: the outcome is recorded before the fatal propagates ---------------------------------

@pytest.mark.parametrize("exc", [SystemExit(23), KeyboardInterrupt()])
def test_a_fatal_after_an_accepted_smtp_delivery_does_not_send_the_notice_again(tmp_path, monkeypatch, exc):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        real = _fatal_after_send(monkeypatch, exc)
        with pytest.raises(type(exc)):
            _run(cfg, _at(14))
        monkeypatch.setattr(ew, "_run_deadline", real)
        assert len([s for s in srv.sessions if s["data"]]) == 1
        assert _run(cfg, _at(14, hour=15))[0] == 0
        assert len([s for s in srv.sessions if s["data"]]) == 1, "the accepted notice was sent again"
        assert _pending(tmp_path) == {}
    finally:
        _stop(srv, t)


def test_a_fatal_with_unknown_acceptance_keeps_the_notice_due_under_the_same_generation(tmp_path, monkeypatch,
                                                                                        matrix):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    real = _fatal_after_send(monkeypatch, SystemExit(23))
    with pytest.raises(SystemExit):
        _run(cfg, _at(14))
    monkeypatch.setattr(ew, "_run_deadline", real)
    first = dict(_pending(tmp_path))
    assert len(first) == 1, "the generation must be saved before the fatal propagates"
    assert _run(cfg, _at(14, hour=15))[0] == 0
    assert len(_Matrix.seen) == 2 and _Matrix.seen[0][1] == _Matrix.seen[1][1], "same transaction id on the retry"
    assert _pending(tmp_path) == {}


# --- finding 2: a start() that raises after the thread started keeps the slot with the worker -------

def test_a_start_that_raises_after_the_worker_started_keeps_the_slot_until_the_worker_ends(monkeypatch):
    real = threading.Thread
    hold, entered, workers = threading.Event(), threading.Event(), []

    class StartThenInterrupt(real):
        def start(self):
            real.start(self)
            workers.append(self)
            assert entered.wait(5)
            raise KeyboardInterrupt

    class Conn:
        sock = None

        def __init__(self, host, port=None, timeout=None):
            pass

        def request(self, *args, **kwargs):
            entered.set()
            hold.wait(5)
            raise OSError("refused")

        def close(self):
            pass

    monkeypatch.setattr(ew.threading, "Thread", StartThenInterrupt)
    monkeypatch.setattr(http.client, "HTTPSConnection", Conn)
    with pytest.raises(KeyboardInterrupt):
        ew.http_get_json(URL, "tok-value", 2)
    assert workers[0].is_alive()
    assert ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES - 1, "the live worker must keep its slot"
    hold.set()
    workers[0].join(5)
    assert _wait_full()
    assert ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES, "released exactly once, never over the bound"


# --- finding 3: a fatal after the deadline is parked and raised by the next call --------------------

def test_a_fatal_raised_after_the_delivery_deadline_is_raised_by_the_next_call():
    go = threading.Event()

    def late():
        go.wait(5)
        raise SystemExit(17)

    with pytest.raises(ew._Overrun):
        ew._run_deadline(_Dl(0.05), late)
    go.set()
    assert _wait_full()
    with pytest.raises(SystemExit):
        ew._run_deadline(_Dl(), lambda: 1)
    assert ew._run_deadline(_Dl(), lambda: 1) == 1, "raised once, then the way is clear"


def test_a_fatal_raised_after_the_fetch_deadline_is_raised_by_the_next_call(monkeypatch):
    go = threading.Event()

    class Conn:
        sock = None

        def __init__(self, host, port=None, timeout=None):
            pass

        calls = []

        def request(self, *args, **kwargs):
            type(self).calls.append(1)
            if len(type(self).calls) > 1:
                raise OSError("refused")  # only the first connection raises the fatal
            go.wait(5)
            raise SystemExit(17)

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Conn)
    timer = threading.Timer(1.3, go.set)  # after the 0.1 s deadline and the 1 s grace join
    timer.start()
    try:
        with pytest.raises(ew.ExpiryWatchError):
            ew.http_get_json(URL, "tok-value", 0.1)
        assert _wait_full()
        with pytest.raises(SystemExit):
            ew.http_get_json(URL, "tok-value", 0.1)
    finally:
        timer.cancel()
        go.set()
