"""Issue #132, review round 3: the handler swap around the final save is restored completely even
when an interrupt lands during the restoration, and every distinct held signal is re-delivered.
"""
import os
import signal
import time

import pytest

from test_expiry_watch import ew

SIGS = [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]


@pytest.fixture
def handlers():
    """Three known handlers (not the process defaults), put back after the test."""
    saved = {s: signal.getsignal(s) for s in SIGS}
    got = []
    mine = {}
    for s in SIGS:
        def h(signum, frame, got=got):
            got.append(signum)
        mine[s] = h
        signal.signal(s, h)
    yield mine, got
    for s, h in saved.items():
        signal.signal(s, h)


def _settle():
    for _ in range(50):  # a pending Python-level handler runs at the next bytecode; give it a moment
        time.sleep(0.01)


@pytest.mark.parametrize("which", [0, 1, 2])
def test_an_interrupt_during_restoration_still_restores_every_handler(monkeypatch, handlers, which):
    mine, got = handlers
    real = signal.signal
    restored = []

    def flaky(sig, handler):
        out = real(sig, handler)
        if handler is mine[sig]:  # a restoration, not the swap to the recorder
            restored.append(sig)
            if len(restored) == which + 1 and not any(r == sig for r in restored[:-1]):
                raise KeyboardInterrupt  # lands after this handler is back, before the loop moves on
        return out

    monkeypatch.setattr(signal, "signal", flaky)
    result = ew._commit_state(lambda: None)
    monkeypatch.setattr(signal, "signal", real)
    for s in SIGS:
        assert signal.getsignal(s) is mine[s], f"{s!r} was left replaced"
    assert isinstance(result, KeyboardInterrupt), "the interrupt is handed on after every handler is back"


def test_an_interrupt_during_the_swap_still_restores_every_handler(monkeypatch, handlers):
    mine, got = handlers
    real = signal.signal
    calls = []

    def flaky(sig, handler):
        calls.append(sig)
        if len(calls) == 2 and handler is not mine[sig]:  # the second swap to the recorder fails
            raise ValueError("swap failed")
        return real(sig, handler)

    monkeypatch.setattr(signal, "signal", flaky)
    with pytest.raises(ValueError):
        ew._commit_state(lambda: None)
    monkeypatch.setattr(signal, "signal", real)
    for s in SIGS:
        assert signal.getsignal(s) is mine[s]


def test_two_distinct_signals_held_during_one_save_are_both_delivered_afterwards(handlers):
    mine, got = handlers

    def save():
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGHUP)
        _settle()
        assert got == [], "held: nothing is delivered while the save runs"

    assert ew._commit_state(save) is None
    _settle()
    assert got == [signal.SIGTERM, signal.SIGHUP]


def test_sigint_is_delivered_first_and_the_other_signals_are_not_dropped(handlers):
    mine, got = handlers
    signal.signal(signal.SIGINT, signal.default_int_handler)

    def save():
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGINT)
        _settle()

    result = ew._commit_state(save)
    _settle()
    assert isinstance(result, KeyboardInterrupt)
    assert got == [signal.SIGTERM]
