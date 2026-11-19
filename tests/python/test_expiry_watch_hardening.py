"""Hardening guards for the expiry watch (issue #76, security review round 1).

Hostile or inconsistent state, DER bounds, one overall probe deadline, and symlinked
directory components. The main behavior tests live in test_expiry_watch.py.
"""
import datetime as dt
import socket
import threading
import time

import pytest

from test_expiry_watch import EXPIRES, REG_OK, RUNBOOK, UTC, _at, _cfg, _item, _tls, ew  # one module object


def _state(expires, threshold=None, daily=None, expired=False):
    return {"deploy-key": {"expires": expires.isoformat(), "threshold": threshold, "daily": daily,
                           "expired": expired}}


def test_reviewer_state_reproduction_still_notifies_expired():
    cfg = ew.parse_config({"router": {"url": "https://example.test/h", "token_env": "T"}})
    state = {"victim": {"expires": "2026-01-01", "threshold": -999999999999999999999999, "daily": None,
                        "expired": True}}
    item = ew.Item.build(name="victim", kind="key", expires="2025-01-01", owner="ops", runbook=RUNBOOK)
    notices, _ = ew.decide([item], dt.datetime(2026, 1, 1, tzinfo=UTC), cfg, state)
    assert [n.stage for n in notices] == ["expired"]


@pytest.mark.parametrize("state,days,stage", [
    (_state(EXPIRES, threshold=-5), 14, "14"),                         # negative threshold
    (_state(EXPIRES, threshold=10**30), 14, "14"),                     # huge threshold
    (_state(EXPIRES, threshold=3), 14, "14"),                          # not a configured threshold
    (_state(EXPIRES, threshold=7), 14, "14"),                          # 7 cannot have fired with 14 days left
    (_state(EXPIRES, expired=True), 14, "14"),                         # expired flag while expiry is ahead
    (_state(EXPIRES, threshold=7, daily="2099-01-01"), 5, "daily"),               # a daily date in the future
    (_state(EXPIRES + dt.timedelta(days=90), threshold=7), 14, "14"),  # provider now reports an EARLIER expiry
])
def test_inconsistent_state_fails_closed_toward_notifying(state, days, stage):
    notices, _ = ew.decide([_item()], _at(days), _cfg(), state)
    assert [n.stage for n in notices] == [stage]


def test_consistent_state_still_suppresses_repeats():
    assert ew.decide([_item()], _at(14), _cfg(), _state(EXPIRES, threshold=14))[0] == []


def test_an_earlier_expiry_resets_the_state():
    earlier = EXPIRES - dt.timedelta(days=20)
    _, state = ew.decide([_item()], _at(7), _cfg(), {})
    notices, new = ew.decide([_item(earlier)], _at(10, earlier), _cfg(), state)
    assert [n.stage for n in notices] == ["14"] and new["deploy-key"]["expires"] == earlier.isoformat()


def _tlv(tag, body):
    return bytes([tag, len(body)]) + body


def _utc(value):
    return _tlv(0x17, value.encode())


def test_der_reader_refuses_validity_outside_the_tbs_structure():
    validity = _tlv(0x30, _utc("250101000000Z") + _utc("491231235959Z"))
    # the reviewer's shape: the TBS declares only three fields, the validity is an outer sibling
    tbs = bytes([0x30, 0x06]) + _tlv(0x02, b"\x01") + _tlv(0x30, b"") + _tlv(0x30, b"")
    with pytest.raises(ew.ExpiryWatchError):
        ew.der_not_after(_tlv(0x30, tbs + validity))


def test_der_reader_refuses_a_validity_whose_content_spills_out_of_the_tbs():
    validity = _tlv(0x30, _utc("250101000000Z") + _utc("491231235959Z"))
    fields = _tlv(0x02, b"\x01") + _tlv(0x30, b"") + _tlv(0x30, b"") + validity[:2]  # header only inside the TBS
    tbs = _tlv(0x30, fields)
    der = _tlv(0x30, tbs + validity[2:] + _tlv(0x30, b"") + _tlv(0x03, b"\x00"))
    with pytest.raises(ew.ExpiryWatchError, match="(?i)enclosing"):
        ew.der_not_after(der)


def _cert(validity, extra_in_validity=b"", trailing=b""):
    if extra_in_validity:
        validity = _tlv(0x30, validity[2:] + extra_in_validity)
    fields = _tlv(0x02, b"\x01") + _tlv(0x30, b"") + _tlv(0x30, b"") + validity + _tlv(0x30, b"") + _tlv(0x30, b"")
    return _tlv(0x30, _tlv(0x30, fields) + _tlv(0x30, b"") + _tlv(0x03, b"\x00")) + trailing


def test_der_reader_enforces_every_enclosing_length():
    good = _tlv(0x30, _utc("250101000000Z") + _utc("261231235959Z"))
    assert ew.der_not_after(_cert(good)).year == 2026
    with pytest.raises(ew.ExpiryWatchError):  # extra bytes after notAfter inside the validity
        ew.der_not_after(_cert(good, extra_in_validity=b"\x05\x00"))
    with pytest.raises(ew.ExpiryWatchError):  # trailing bytes after the certificate
        ew.der_not_after(_cert(good, trailing=b"\x00"))
    der = _cert(good)
    with pytest.raises(ew.ExpiryWatchError):  # non-minimal long-form length for the outer sequence
        ew.der_not_after(bytes([0x30, 0x81]) + der[1:])


def test_tls_probe_has_one_overall_deadline_even_when_name_resolution_stalls(monkeypatch):
    release = threading.Event()

    def slow(*args, **kwargs):
        release.wait(10)
        raise socket.gaierror("released")

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    try:
        t0 = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError, match="(?i)tls.*(time|deadline)"):
            _tls(443, host="resolver-stall.example.com", verify=False, timeout_seconds=1).items()
        assert time.monotonic() - t0 < 3
    finally:
        release.set()


def test_registry_refuses_a_symlinked_directory_component(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "registry.toml").write_text(REG_OK)
    (tmp_path / "linked").symlink_to(real)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)symbolic link"):
        ew.RegistryProvider({"path": "linked/registry.toml"}, base_dir=tmp_path).items()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)symbolic link"):
        ew.RegistryProvider({"path": str(tmp_path / "linked" / "registry.toml")}, base_dir=tmp_path).items()
    # a plain path works, and so does a base directory that is itself reached through a link
    assert len(ew.RegistryProvider({"path": "registry.toml"}, base_dir=real).items()) == 2
    assert len(ew.RegistryProvider({"path": "registry.toml"}, base_dir=tmp_path / "linked").items()) == 2
    with pytest.raises(ew.ExpiryWatchError):
        ew.RegistryProvider({"path": "../real/registry.toml"}, base_dir=real).items()
