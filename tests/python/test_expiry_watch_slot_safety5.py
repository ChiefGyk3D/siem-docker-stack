"""Issue #132, extra review round: a restoration that cannot be completed is loud, a retry that
succeeds ends clean, and a save that cannot be shielded says so.
"""
import signal
import threading

import pytest

from test_expiry_watch import ew
from test_expiry_watch_channels import _at, _run, _setup, _start_smtp, _stop

SIGS = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]


@pytest.fixture
def originals():
    """Known handlers, put back after the test whatever it did."""
    saved = {s: signal.getsignal(s) for s in SIGS}
    mine = {}
    for s in SIGS:
        def h(signum, frame):
            pass
        mine[s] = h
        signal.signal(s, h)
    yield mine
    for s, h in saved.items():
        signal.signal(s, h)


def _blocking(monkeypatch, mine, sig, failures):
    """signal.signal raises KeyboardInterrupt BEFORE installing, for the first `failures` attempts to
    restore `sig`."""
    real = signal.signal
    seen = []

    def broken(s, handler):
        if s == sig and handler is mine[s]:
            seen.append(1)
            if len(seen) <= failures:
                raise KeyboardInterrupt("restore blocked")
        return real(s, handler)

    monkeypatch.setattr(signal, "signal", broken)
    return real


@pytest.mark.parametrize("sig", SIGS)
def test_a_restoration_that_cannot_be_completed_is_reported_by_signal_name(monkeypatch, originals, sig):
    real = _blocking(monkeypatch, originals, sig, 3)
    with pytest.raises(ew.ExpiryWatchError, match=sig.name):
        ew._commit_state(lambda: None)
    monkeypatch.setattr(signal, "signal", real)
    assert signal.getsignal(sig) is not originals[sig]  # the stub really did leave the recorder in place
    for other in SIGS:
        if other != sig:
            assert signal.getsignal(other) is originals[other]


@pytest.mark.parametrize("sig", SIGS)
def test_one_failed_attempt_is_retried_and_ends_clean(monkeypatch, originals, sig):
    real = _blocking(monkeypatch, originals, sig, 1)
    result = ew._commit_state(lambda: None)  # no error: the second attempt restored it
    monkeypatch.setattr(signal, "signal", real)
    assert isinstance(result, KeyboardInterrupt)
    for s in SIGS:
        assert signal.getsignal(s) is originals[s]


def test_the_run_fails_loudly_when_restoration_cannot_be_completed(tmp_path, monkeypatch, originals):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        real = _blocking(monkeypatch, originals, signal.SIGTERM, 3)
        code, _, err = _run(cfg, _at(14))
        monkeypatch.setattr(signal, "signal", real)
        assert code == 1 and "SIGTERM" in err and "could not be restored" in err
    finally:
        _stop(srv, t)


def test_a_save_off_the_main_thread_warns_that_the_shield_is_not_active():
    warnings, ran = [], []
    t = threading.Thread(target=lambda: ew._commit_state(lambda: ran.append(1), warn=warnings.append))
    t.start()
    t.join(5)
    assert ran == [1] and len(warnings) == 1 and "not active" in warnings[0]


def test_a_run_off_the_main_thread_says_so_on_stderr(tmp_path):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        box = []
        th = threading.Thread(target=lambda: box.append(_run(cfg, _at(14))))
        th.start()
        th.join(30)
        code, _, err = box[0]
        assert code == 0 and "shield is not active" in err
    finally:
        _stop(srv, t)


def test_an_unknown_native_handler_is_never_replaced(monkeypatch, originals):
    real_get, real_set = signal.getsignal, signal.signal
    calls = []

    monkeypatch.setattr(signal, "getsignal", lambda s: None if s == signal.SIGTERM else real_get(s))
    monkeypatch.setattr(signal, "signal", lambda s, h: (calls.append(s), real_set(s, h))[1])
    warnings = []
    assert ew._commit_state(lambda: None, warn=warnings.append) is None
    assert calls == [], "no handler is touched when one cannot be represented"
    assert len(warnings) == 1 and "not active" in warnings[0]
