"""Round 3 guards for the expiry watch (issue #76): whole-entry state validation, the exact
probe deadline, and a pinned config directory (no retarget race, raw path inspection).
"""
import datetime as dt
import socket
import threading
import time

import pytest

from test_expiry_watch import EXPIRES, REG_OK, RUNBOOK, UTC, _at, _cfg, _item, _tls, ew
from test_expiry_watch_hardening import _state

START_UTC = dt.datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# --- state: one bad field discards the whole entry --------------------------------------------

def test_one_invalid_field_discards_the_whole_state_entry():
    """Reviewer reproduction 1: an invalid threshold must not leave expired=True suppressing the notice."""
    item = ew.Item.build(name="victim", kind="key", expires="2026-01-01", owner="ops", runbook=RUNBOOK)
    cfg = ew.parse_config({"router": {"url": "https://example.test/h", "token_env": "T"}})
    state = {"victim": {"expires": "2026-01-01", "threshold": -1, "daily": None, "expired": True}}
    notices, _ = ew.decide([item], dt.datetime(2026, 1, 2, tzinfo=UTC), cfg, state)
    assert [n.stage for n in notices] == ["expired"]


def test_a_future_daily_date_discards_a_plausible_threshold():
    """Reviewer reproduction 2: threshold 14 looks fine, the daily date cannot be, so nothing is trusted."""
    item = ew.Item.build(name="victim", kind="key", expires="2026-03-01", owner="ops", runbook=RUNBOOK)
    cfg = ew.parse_config({"router": {"url": "https://example.test/h", "token_env": "T"}})
    state = {"victim": {"expires": "2026-03-01", "threshold": 14, "daily": "2099-01-01", "expired": False}}
    notices, _ = ew.decide([item], dt.datetime(2026, 2, 15, tzinfo=UTC), cfg, state)
    assert [n.stage for n in notices] == ["14"]


def test_a_fully_consistent_entry_still_suppresses_repeats():
    state = _state(EXPIRES, threshold=7, daily=(EXPIRES - dt.timedelta(days=5)).isoformat())
    assert ew.decide([_item()], _at(5), _cfg(), state)[0] == []
    expired = _state(EXPIRES, threshold=7, expired=True)
    assert ew.decide([_item()], _at(-2), _cfg(), expired)[0] == []


# --- the probe stops at its real deadline -----------------------------------------------------------

def test_the_probe_stops_at_the_real_deadline_not_a_quarter_second_later(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: release.wait(10))
    try:
        t0 = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError, match="(?i)deadline"):
            _tls(443, host="resolver-stall.example.com", verify=False, timeout_seconds=0.5).items()
        elapsed = time.monotonic() - t0
        assert 0.45 <= elapsed < 0.65, elapsed
    finally:
        release.set()


# --- raw path inspection --------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["./registry.toml", "sub/./registry.toml", "sub//registry.toml",
                                 "sub/../registry.toml", "../registry.toml", "sub/registry.toml/",
                                 "/./abs", "."])
def test_dot_and_empty_components_are_refused_before_normalization(tmp_path, bad):
    (tmp_path / "sub").mkdir()
    (tmp_path / "registry.toml").write_text(REG_OK)
    (tmp_path / "sub" / "registry.toml").write_text(REG_OK)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)component"):
        ew.RegistryProvider({"path": bad}, base_dir=tmp_path).items()


def test_dot_components_in_the_state_file_setting_are_a_config_error(tmp_path):
    (tmp_path / "registry.toml").write_text(REG_OK)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[watch]\nstate_file = "./state.json"\n[router]\nurl = "https://example.test/h"\n'
                   'token_env = "T"\n[[providers]]\ntype = "registry"\npath = "registry.toml"\n')
    out, err = [], []
    code = ew.run(cfg, now=START_UTC, env={"T": "x"}, out=out.append, err=err.append)
    assert code == 2 and "component" in "\n".join(err)


# --- the config directory is opened once ----------------------------------------------------------------

def test_the_config_directory_is_opened_once_so_a_retargeted_link_changes_nothing(tmp_path):
    """The config folder is named by the operator and may itself be a link: it is resolved ONCE and
    pinned. Retargeting the link mid-run must not move later reads or the state write elsewhere."""
    a, b = tmp_path / "dir-a", tmp_path / "dir-b"
    a.mkdir()
    b.mkdir()
    link = tmp_path / "current"
    link.symlink_to(a)
    reg = ('[[item]]\nname = "{n}"\nkind = "k"\nexpires = 2030-01-01\nowner = "o"\n'
           'runbook = "https://wiki.example.com/r"\n')
    (a / "registry.toml").write_text(reg.format(n="from-a"))
    (b / "registry.toml").write_text(reg.format(n="from-b"))
    (a / "config.toml").write_text('[watch]\nstate_file = "state.json"\n[router]\nurl = "https://example.test/h"\n'
                                   'token_env = "T"\n[[providers]]\ntype = "swap-link"\n'
                                   '[[providers]]\ntype = "registry"\npath = "registry.toml"\n')

    class Swap:
        def __init__(self, cfg):
            pass

        def items(self):
            link.unlink()
            link.symlink_to(b)  # the attacker retargets the link after the config was read
            return []

    ew.register_provider("swap-link", Swap)
    try:
        out, err = [], []
        code = ew.run(str(link / "config.toml"), now=START_UTC, env={"T": "x"}, out=out.append, err=err.append)
    finally:
        del ew.PROVIDER_TYPES["swap-link"]
    assert code == 0, err
    assert sorted(ew.load_state("state.json", a)) == ["from-a"], "the registry came from the pinned folder"
    assert not (b / "state.json").exists(), "the state write must not follow the retargeted link"
    assert [f.name for f in b.iterdir()] == ["registry.toml"]


def test_state_write_is_relative_to_a_held_directory_and_leaves_no_temp_file(tmp_path):
    held = ew.Root(tmp_path)
    try:
        ew.save_state("state.json", {"a": {"expires": "2026-03-01", "threshold": None, "daily": None,
                                           "expired": False}}, held)
        with pytest.raises(ew.ExpiryWatchError, match="(?i)component"):
            ew.save_state("../state.json", {}, held)
    finally:
        held.close()
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"]
    assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600


def test_ca_file_is_read_through_the_pinned_directory(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "ca.pem").write_text("not a certificate")
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    prov = ew.TlsProvider({"host": "127.0.0.1", "port": 9, "owner": "o", "runbook": RUNBOOK, "verify": True,
                           "ca_file": "linked/ca.pem", "_base_dir": ew.Root(tmp_path)})
    with pytest.raises(ew.ExpiryWatchError, match="(?i)symbolic link"):
        prov.items()
