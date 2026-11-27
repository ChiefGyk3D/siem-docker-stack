"""Issue #132, review round 2: the final state save, which records what was delivered, survives an
interrupt: signals are held until the commit is done, a one-shot interrupt raised inside the save is
retried, and the fatal that triggered the save is raised only after the state is on disk.
"""
import os
import signal

import pytest

from test_expiry_watch import ew
from test_expiry_watch_channels import _at, _run, _setup, _start_smtp, _stop


def _mails(srv):
    return len([s for s in srv.sessions if s["data"]])


def _fatal_after_send(monkeypatch, exc):
    real = ew._run_deadline

    def wrapped(dl, fn):
        def after():
            fn()
            raise exc
        return real(dl, after)

    monkeypatch.setattr(ew, "_run_deadline", wrapped)
    return real


def _interrupt_first_save(monkeypatch, exc):
    real = ew.save_state
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise exc
        return real(*args, **kwargs)

    monkeypatch.setattr(ew, "save_state", flaky)
    return real, calls


@pytest.mark.parametrize("second", [KeyboardInterrupt(), SystemExit(9)])
def test_an_interrupt_during_the_save_keeps_the_delivery_fatal_and_the_state(tmp_path, monkeypatch, second):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        real_run = _fatal_after_send(monkeypatch, SystemExit(23))
        real_save, calls = _interrupt_first_save(monkeypatch, second)
        with pytest.raises(SystemExit) as raised:
            _run(cfg, _at(14))
        assert raised.value.code == 23, "the delivery fatal and its exit code survive the interrupted save"
        assert len(calls) == 2, "the save was retried once"
        monkeypatch.setattr(ew, "_run_deadline", real_run)
        monkeypatch.setattr(ew, "save_state", real_save)
        assert _mails(srv) == 1
        assert _run(cfg, _at(14, hour=15))[0] == 0
        assert _mails(srv) == 1, "the accepted notice was sent again"
    finally:
        _stop(srv, t)


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(9)])
def test_an_interrupt_during_the_save_is_raised_after_the_state_is_complete(tmp_path, monkeypatch, exc):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        real_save, calls = _interrupt_first_save(monkeypatch, exc)
        with pytest.raises(type(exc)):
            _run(cfg, _at(14))
        assert len(calls) == 2
        monkeypatch.setattr(ew, "save_state", real_save)
        assert _mails(srv) == 1
        assert _run(cfg, _at(14, hour=15))[0] == 0
        assert _mails(srv) == 1, "the delivered notice was sent again"
    finally:
        _stop(srv, t)


def test_an_ordinary_save_error_behaves_as_before(tmp_path, monkeypatch):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')

        def broken(*args, **kwargs):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(ew, "save_state", broken)
        code, _, err = _run(cfg, _at(14))
        assert code == 1 and "state error: cannot write" in err
    finally:
        _stop(srv, t)


def test_a_real_signal_during_the_save_waits_until_the_commit_is_done(tmp_path, monkeypatch):
    srv, t = _start_smtp()
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        real_save = ew.save_state
        before = signal.getsignal(signal.SIGINT)

        def signalled(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGINT)  # arrives while the commit is running
            return real_save(*args, **kwargs)

        monkeypatch.setattr(ew, "save_state", signalled)
        with pytest.raises(KeyboardInterrupt):
            _run(cfg, _at(14))
        monkeypatch.setattr(ew, "save_state", real_save)
        assert signal.getsignal(signal.SIGINT) == before, "the signal handler is restored"
        assert _mails(srv) == 1
        assert _run(cfg, _at(14, hour=15))[0] == 0
        assert _mails(srv) == 1, "the interrupt arrived before the state was complete"
    finally:
        _stop(srv, t)
