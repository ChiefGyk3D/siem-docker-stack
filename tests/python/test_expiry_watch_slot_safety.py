"""Issue #132: the fetch slot is exception-safe around thread construction and startup, a slot is
released exactly once (a double release can never raise), and a BaseException raised inside a worker
(SystemExit, KeyboardInterrupt) reaches the caller after the slot is free.
"""
import http.client
import threading

import pytest

from test_expiry_watch import ew

URL = "https://vendor.example.com/x"


class _Resp:
    status = 200

    def getheader(self, name):
        return None

    def read1(self, size):
        return b""


def _conn_class(request_error=None):
    class Conn:
        sock = None

        def __init__(self, host, port=None, timeout=None):
            pass

        def request(self, *args, **kwargs):
            if request_error is not None:
                raise request_error

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    return Conn


@pytest.fixture(autouse=True)
def _fresh_slots(monkeypatch):
    """A leak in one test must not starve the next one."""
    monkeypatch.setattr(ew, "_FETCH_SLOTS", threading.BoundedSemaphore(ew.MAX_STUCK_FETCHES))


def _full():
    return ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES


def test_a_start_that_raises_frees_the_slot_and_a_later_fetch_works(monkeypatch):
    real = threading.Thread

    class BadStart(real):
        def start(self):
            raise RuntimeError("cannot start new thread")

    monkeypatch.setattr(ew.threading, "Thread", BadStart)
    for _ in range(ew.MAX_STUCK_FETCHES + 2):
        with pytest.raises(RuntimeError):
            ew.http_get_json(URL, "tok-value", 2)
    assert _full()
    monkeypatch.setattr(ew.threading, "Thread", real)
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class())
    chunks = [b"[1]", b""]
    monkeypatch.setattr(_Resp, "read1", lambda self, size: chunks.pop(0))
    assert ew.http_get_json(URL, "tok-value", 2) == [1]
    assert _full()


def test_a_start_that_raises_after_the_worker_ran_releases_exactly_once(monkeypatch):
    real = threading.Thread

    class RunThenRaise(real):
        def start(self):
            real.start(self)
            self.join()  # the worker's own finally has run
            raise RuntimeError("start failed late")

    monkeypatch.setattr(ew.threading, "Thread", RunThenRaise)
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class(request_error=OSError("refused")))
    with pytest.raises(RuntimeError):  # not ValueError from a second release
        ew.http_get_json(URL, "tok-value", 2)
    assert _full()


def test_a_thread_constructor_that_raises_frees_the_slot(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("constructor failed")

    monkeypatch.setattr(ew.threading, "Thread", boom)
    for _ in range(ew.MAX_STUCK_FETCHES + 2):
        with pytest.raises(RuntimeError):
            ew.http_get_json(URL, "tok-value", 2)
    assert _full()


@pytest.mark.parametrize("exc", [SystemExit(3), KeyboardInterrupt()])
def test_a_base_exception_in_the_worker_reaches_the_caller_and_frees_the_slot(monkeypatch, exc):
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class(request_error=exc))
    for _ in range(ew.MAX_STUCK_FETCHES + 2):
        with pytest.raises(type(exc)):
            ew.http_get_json(URL, "tok-value", 2)
    assert _full()


def test_an_ordinary_exception_keeps_its_existing_handling(monkeypatch):
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class(request_error=OSError("refused")))
    with pytest.raises(ew.ExpiryWatchError) as exc:
        ew.http_get_json(URL, "tok-value", 2)
    assert "unreachable: refused" in str(exc.value)
    assert _full()


# --- the delivery runner shares the same slots and the same rules -----------------------------------

class _Dl:
    seconds = 2.0
    delivered = False

    def __init__(self):
        import time
        self.end = time.monotonic() + 2

    def abort(self):
        pass


def test_run_deadline_start_failure_frees_the_slot(monkeypatch):
    real = threading.Thread

    class BadStart(real):
        def start(self):
            raise RuntimeError("cannot start new thread")

    monkeypatch.setattr(ew.threading, "Thread", BadStart)
    for _ in range(ew.MAX_STUCK_FETCHES + 2):
        with pytest.raises(RuntimeError):
            ew._run_deadline(_Dl(), lambda: 1)
    assert _full()


@pytest.mark.parametrize("exc", [SystemExit(3), KeyboardInterrupt()])
def test_run_deadline_base_exception_reaches_the_caller_and_frees_the_slot(exc):
    def fn():
        raise exc

    with pytest.raises(type(exc)):
        ew._run_deadline(_Dl(), fn)
    assert _full()
    assert ew._run_deadline(_Dl(), lambda: 7) == 7
