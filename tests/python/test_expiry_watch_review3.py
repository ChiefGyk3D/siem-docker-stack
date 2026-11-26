"""Daybreak review round 3 guards (issue #102): a connection whose close raises cannot leak a fetch
slot or turn a good answer into a failure, and the writer and the loader share one state-key rule.
"""
import http.client

import pytest

from test_expiry_watch import ew


class _Resp:
    status = 200

    def __init__(self):
        self._chunks = [b"[1, 2]", b""]

    def getheader(self, name):
        return None

    def read1(self, size):
        return self._chunks.pop(0)


def _conn_class(close_raises=True, request_error=None):
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
            if close_raises:
                raise RuntimeError("close failed")

    return Conn


def test_a_close_that_raises_does_not_leak_the_slot_or_spoil_a_good_answer(monkeypatch):
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class())
    for _ in range(ew.MAX_STUCK_FETCHES + 3):  # more calls than slots: a leak would refuse the later ones
        assert ew.http_get_json("https://vendor.example.com/x", "tok-value", 2) == [1, 2]
    assert ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES


def test_a_close_that_raises_keeps_the_real_error_and_frees_the_slot(monkeypatch):
    monkeypatch.setattr(http.client, "HTTPSConnection", _conn_class(request_error=OSError("refused")))
    for _ in range(ew.MAX_STUCK_FETCHES + 3):
        with pytest.raises(ew.ExpiryWatchError) as exc:
            ew.http_get_json("https://vendor.example.com/x", "tok-value", 2)
        assert "unreachable: refused" in str(exc.value), "the request's error, not the cleanup's"
        assert "close failed" not in str(exc.value)
    assert ew._FETCH_SLOTS._value == ew.MAX_STUCK_FETCHES


# --- one state-key rule for the writer (_provider_key) and the loader (_check_seen) -----------------

KEYS = ["tls:host:443:x", "k" * 300, "k" * 301, "", "a" + chr(10) + "b", "a" + chr(127) + "b",
        "a" + chr(0) + "b", 7]


@pytest.mark.parametrize("key", KEYS)
def test_the_writer_and_the_loader_accept_exactly_the_same_state_keys(key):
    class Prov:
        state_key = key

    def writer_ok():
        try:
            ew._provider_key({"type": "t"}, Prov(), 0)
        except ew.ExpiryWatchError:
            return False
        return True

    def loader_ok():
        try:
            ew._check_seen("state", {key: {}})
        except (ew.ExpiryWatchError, TypeError):
            return False
        return True

    expected = isinstance(key, str) and 0 < len(key) <= 300 and not ew._CONTROL.search(key)
    assert writer_ok() == expected
    assert loader_ok() == expected


def test_both_sides_use_the_one_validator():
    assert ew._valid_state_key("a")
    assert not ew._valid_state_key("a" + chr(10) + "b")
    assert not ew._valid_state_key("k" * 301)
    assert not ew._valid_state_key(7)
