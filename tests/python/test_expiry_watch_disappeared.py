"""Slice 2 guards for the expiry watch (issues #94 and #97): the daily-date interval check in
state reconcile, and the "item disappeared" notice that works for every provider.

The provider tests for Grafana and the secret manager are in test_expiry_watch_providers.py.
"""
import datetime as dt
import json

import pytest

from test_expiry_watch import EXPIRES, RUNBOOK, UTC, _at, _cfg, _item, _run, _write_setup, ew
from test_expiry_watch_hardening import _state


# --- #94: the saved daily date must be one the watch could have recorded ---------------------

def _day(offset_before_expiry):
    return (EXPIRES - dt.timedelta(days=offset_before_expiry)).isoformat()


@pytest.mark.parametrize("daily", [
    _day(8),    # before the 7 day window opened
    _day(30),   # long before
    _day(0),    # the expiry day itself: a daily notice is never recorded then
    _day(-3),   # after the expiry date
    _day(4),    # after today (today is 5 days before expiry)
])
def test_a_daily_date_outside_the_window_voids_the_whole_entry(daily):
    # today is 5 days before expiry; threshold 7 already fired, so a trusted entry would stay silent
    state = _state(EXPIRES, threshold=7, daily=daily)
    notices, new = ew.decide([_item()], _at(5), _cfg(), state)
    assert [n.stage for n in notices] == ["7"], "an impossible daily date must not suppress a notice"
    assert new["deploy-key"]["daily"] == _day(5)


@pytest.mark.parametrize("daily", [_day(7), _day(6), _day(5)])
def test_a_daily_date_inside_the_window_and_not_after_today_is_trusted(daily):
    state = _state(EXPIRES, threshold=7, daily=_day(5))
    assert ew.decide([_item()], _at(5), _cfg(), state)[0] == []
    notices, _ = ew.decide([_item()], _at(5), _cfg(), _state(EXPIRES, threshold=7, daily=daily))
    assert [n.stage for n in notices] == ([] if daily == _day(5) else ["daily"])


def test_a_daily_date_on_or_after_the_expiry_day_is_void_even_when_it_is_not_in_the_future():
    # two days after expiry: a daily date equal to the expiry date is "not after today", yet the
    # watch never records a daily notice on a day with no days left
    state = _state(EXPIRES, threshold=7, daily=_day(0))
    _, new = ew.decide([_item()], _at(-2), _cfg(), state)
    assert new["deploy-key"]["daily"] is None and new["deploy-key"]["threshold"] is None, "the whole entry is void"
    _, kept = ew.decide([_item()], _at(-2), _cfg(), _state(EXPIRES, threshold=7, daily=_day(1)))
    assert kept["deploy-key"]["threshold"] == 7, "a daily date one day before expiry is a real one"


def test_with_daily_notices_off_only_a_null_daily_date_is_valid():
    cfg = _cfg(daily_below_days=0)
    notices, _ = ew.decide([_item()], _at(5), cfg, _state(EXPIRES, threshold=7, daily=_day(5)))
    assert [n.stage for n in notices] == ["7"], "daily_below_days = 0 can never have recorded a daily date"
    assert ew.decide([_item()], _at(5), cfg, _state(EXPIRES, threshold=7, daily=None))[0] == []


# --- the disappeared engine ---------------------------------------------------------------------

def _rec(missed=0, kind="ssh-key", expires="2026-03-01"):
    return {"missed": missed, "item": {"kind": kind, "expires": expires, "owner": "ops@example.com",
                                       "runbook": RUNBOOK}}


def test_an_item_seen_before_and_gone_now_is_reported_once_and_resets():
    a, b = _item(name="a"), _item(name="b")
    gone, seen = ew.track_disappeared({}, {"p": ([a, b], set(), True)}, 1)
    assert gone == [] and set(seen["p"]) == {"a", "b"}
    gone, seen = ew.track_disappeared(seen, {"p": ([a], set(), True)}, 1)
    assert [(k, i.name, m) for k, i, m in gone] == [("p", "b", 1)]
    assert gone[0][1].expires == EXPIRES and gone[0][1].owner == "ops@example.com"
    assert set(seen["p"]) == {"a"}, "reported once: it is forgotten after the notice"
    gone, seen = ew.track_disappeared(seen, {"p": ([a], set(), True)}, 1)
    assert gone == []
    gone, seen = ew.track_disappeared(seen, {"p": ([a, b], set(), True)}, 1)  # it came back
    gone, seen = ew.track_disappeared(seen, {"p": ([a], set(), True)}, 1)     # and went again
    assert [i.name for _, i, _ in gone] == ["b"]


def test_disappeared_after_runs_counts_consecutive_misses_and_a_return_resets_the_count():
    a = _item(name="a")
    seen = {"p": {"a": _rec()}}
    gone, seen = ew.track_disappeared(seen, {"p": ([], set(), True)}, 3)
    assert gone == [] and seen["p"]["a"]["missed"] == 1
    gone, seen = ew.track_disappeared(seen, {"p": ([a], set(), True)}, 3)  # back: the count restarts
    assert gone == [] and seen["p"]["a"]["missed"] == 0
    for expected in (1, 2):
        gone, seen = ew.track_disappeared(seen, {"p": ([], set(), True)}, 3)
        assert gone == [] and seen["p"]["a"]["missed"] == expected
    gone, seen = ew.track_disappeared(seen, {"p": ([], set(), True)}, 3)
    assert [i.name for _, i, _ in gone] == ["a"] and seen["p"] == {}


def test_an_acknowledged_removal_is_silent_and_forgotten():
    seen = {"p": {"a": _rec(), "b": _rec()}}
    gone, seen = ew.track_disappeared(seen, {"p": ([], {"a"}, True)}, 1)
    assert [i.name for _, i, _ in gone] == ["b"] and seen["p"] == {}


def test_a_failed_provider_keeps_its_memory_and_reports_nothing():
    seen = {"p": {"a": _rec(missed=1)}}
    gone, new = ew.track_disappeared(seen, {"p": (None, set(), True)}, 2)
    assert gone == [] and new == seen, "an outage is not a vanished item"


def test_a_provider_removed_from_the_config_is_forgotten_silently():
    gone, new = ew.track_disappeared({"old": {"a": _rec()}}, {"p": ([], set(), True)}, 1)
    assert gone == [] and "old" not in new


def test_a_disabled_provider_neither_remembers_nor_reports():
    gone, new = ew.track_disappeared({"p": {"a": _rec()}}, {"p": ([], set(), False)}, 1)
    assert gone == [] and new == {"p": {}}
    gone, new = ew.track_disappeared({}, {"p": ([_item(name="a")], set(), False)}, 1)
    assert new == {"p": {}}


def test_providers_do_not_report_each_others_items():
    a = _item(name="a")
    seen = {"p": {"a": _rec()}}
    gone, _ = ew.track_disappeared(seen, {"p": ([], set(), True), "q": ([a], set(), True)}, 1)
    assert [(k, i.name) for k, i, _ in gone] == [("p", "a")]


# --- the state file carries the memory --------------------------------------------------------------

def test_the_memory_round_trips_and_the_old_state_format_still_loads(tmp_path):
    p = tmp_path / "state.json"
    items = {"a": {"expires": "2026-03-01", "threshold": 14, "daily": None, "expired": False}}
    p.write_text(json.dumps(items))  # a slice 1 file: just the items
    assert ew.load_memory(p) == (items, {})
    ew.save_state(p, items, seen={"p": {"a": _rec()}})
    assert ew.load_memory(p) == (items, {"p": {"a": _rec()}})
    assert ew.load_state(p) == items
    assert (p.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("doc", [
    {"version": 2, "items": {}, "seen": []},
    {"version": 2, "items": {}, "seen": {"p": []}},
    {"version": 2, "items": {}, "seen": {"p": {"a": 1}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": {"missed": -1, "item": _rec()["item"]}}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": {"missed": True, "item": _rec()["item"]}}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": {"missed": 10**9, "item": _rec()["item"]}}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": {"missed": 0, "item": {"kind": "k"}}}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": _rec(expires="2026-13-45")}}},
    {"version": 2, "items": {}, "seen": {"p": {"a\nb": _rec()}}},
    {"version": 2, "items": {}, "seen": {"p": {"a": _rec(kind="x" * 41)}}},
    {"version": 2, "items": {}, "seen": {"p\x00": {"a": _rec()}}},
    {"version": 2, "items": {}},
    {"version": 3, "items": {}, "seen": {}},
    {"version": 2, "items": {}, "seen": {}, "extra": 1},
])
def test_a_bad_memory_is_refused_not_trusted(tmp_path, doc):
    p = tmp_path / "state.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(ew.ExpiryWatchError):
        ew.load_memory(p)


def test_the_memory_is_size_capped(tmp_path):
    p = tmp_path / "state.json"
    many = {f"i{n}": _rec() for n in range(ew.MAX_ITEMS + 1)}
    p.write_text(json.dumps({"version": 2, "items": {}, "seen": {"p": many}}))
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too many|shape"):
        ew.load_memory(p)


# --- the runner, with the registry provider -------------------------------------------------------

TWO_ITEMS = """
[[item]]
name = "deploy-key"
kind = "ssh-key"
expires = 2026-03-01
owner = "ops@example.com"
runbook = "{rb}"

[[item]]
name = "other-key"
kind = "ssh-key"
expires = 2026-09-01
owner = "ops@example.com"
runbook = "{rb}"
""".format(rb=RUNBOOK)

ONE_ITEM = "[[item]]" + TWO_ITEMS.split("[[item]]")[2]  # only other-key


@pytest.fixture
def router():
    from test_expiry_watch import _Recorder
    import http.server
    import threading
    _Recorder.seen, _Recorder.status, _Recorder.redirect_to = [], 200, None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}", _Recorder
    srv.shutdown()
    t.join(5)
    srv.server_close()


def _stages(rec):
    return [(json.loads(b)["alerts"][0]["labels"]["item"], json.loads(b)["alerts"][0]["labels"]["stage"])
            for _, _, b in rec.seen]


def test_registry_item_removed_without_acknowledgement_notifies_once(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0 and not rec.seen
    reg.write_text(ONE_ITEM)  # only other-key remains
    code, out, err = _run(cfg, _at(99))
    assert code == 0 and _stages(rec) == [("deploy-key", "disappeared")]
    body = json.loads(rec.seen[0][2])["alerts"][0]
    assert body["labels"]["severity"] == "warning" and "2026-03-01" in body["annotations"]["description"]
    assert "secret-token-value" not in out + err
    assert _run(cfg, _at(98))[0] == 0 and len(rec.seen) == 1, "one notice, not one per run"
    reg.write_text(TWO_ITEMS)  # it returns
    assert _run(cfg, _at(97))[0] == 0 and len(rec.seen) == 1
    reg.write_text(ONE_ITEM)
    assert _run(cfg, _at(96))[0] == 0 and _stages(rec) == [("deploy-key", "disappeared")] * 2, "the memory resets"


def test_acknowledging_the_removal_in_config_keeps_it_silent(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0
    cfg.write_text(cfg.read_text().replace('path = "registry.toml"',
                                           'path = "registry.toml"\nacknowledge_removed = ["deploy-key"]'))
    reg.write_text(ONE_ITEM)
    assert _run(cfg, _at(99))[0] == 0 and not rec.seen


def test_the_switch_turns_the_notice_off_globally_and_per_provider(tmp_path, router):
    srv, base, rec = router
    reg = tmp_path / "registry.toml"
    for edit in ('[watch]\nstate_file = "state.json"\nnotify_disappeared = false',
                 'path = "registry.toml"\nnotify_disappeared = false'):
        cfg = _write_setup(tmp_path, base)
        text = cfg.read_text()
        cfg.write_text(text.replace('[watch]\nstate_file = "state.json"', edit) if edit.startswith("[watch]")
                       else text.replace('path = "registry.toml"', edit))
        (tmp_path / "state.json").unlink(missing_ok=True)
        reg.write_text(TWO_ITEMS)
        assert _run(cfg, _at(100))[0] == 0
        reg.write_text(ONE_ITEM)
        assert _run(cfg, _at(99))[0] == 0 and not rec.seen


def test_a_failed_delivery_keeps_the_disappeared_notice_due(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0
    reg.write_text(ONE_ITEM)
    rec.status = 500
    code, _, err = _run(cfg, _at(99))
    assert code == 1 and "disappeared" in err
    rec.status = 200
    assert _run(cfg, _at(98))[0] == 0
    assert [s for _, s in _stages(rec)][-1] == "disappeared" and len(rec.seen) == 2
    assert _run(cfg, _at(97))[0] == 0 and len(rec.seen) == 2


def test_a_broken_provider_does_not_make_items_look_vanished(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0
    reg.write_text("not toml [[")
    code, _, err = _run(cfg, _at(99))
    assert code == 1 and not rec.seen
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(98))[0] == 0 and not rec.seen, "the outage left the memory alone"


def test_the_disappeared_threshold_is_config(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    cfg.write_text(cfg.read_text().replace('[watch]\n', '[watch]\ndisappeared_after_runs = 2\n'))
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0
    reg.write_text(ONE_ITEM)
    assert _run(cfg, _at(99))[0] == 0 and not rec.seen
    assert _run(cfg, _at(98))[0] == 0 and _stages(rec) == [("deploy-key", "disappeared")]


def test_dry_run_reports_it_and_saves_nothing(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    reg = tmp_path / "registry.toml"
    reg.write_text(TWO_ITEMS)
    assert _run(cfg, _at(100))[0] == 0
    before = (tmp_path / "state.json").read_bytes()
    reg.write_text(ONE_ITEM)
    code, out, _ = _run(cfg, _at(99), env={}, dry_run=True)
    assert code == 0 and "disappeared" in out and not rec.seen
    assert (tmp_path / "state.json").read_bytes() == before


@pytest.mark.parametrize("extra,match", [
    ('acknowledge_removed = "deploy-key"', "(?i)acknowledge_removed"),
    ('acknowledge_removed = [1]', "(?i)acknowledge_removed|string"),
    ('acknowledge_removed = ["a\\nb"]', "(?i)control"),
    ('notify_disappeared = "yes"', "(?i)notify_disappeared"),
])
def test_bad_disappeared_settings_are_config_errors(tmp_path, router, extra, match):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    cfg.write_text(cfg.read_text().replace('path = "registry.toml"', 'path = "registry.toml"\n' + extra))
    code, _, err = _run(cfg, _at(100))
    assert code == 2 and not rec.seen
    import re
    assert re.search(match, err)


@pytest.mark.parametrize("watch", [{"disappeared_after_runs": 0}, {"disappeared_after_runs": 1000},
                                   {"disappeared_after_runs": "1"}, {"notify_disappeared": 1}])
def test_bad_watch_settings_are_rejected(watch):
    with pytest.raises(ew.ExpiryWatchError):
        ew.parse_config({"watch": watch, "router": {"url": "https://n8n.example.com/h", "token_env": "T"}})


def test_two_providers_reading_the_same_source_are_refused(tmp_path, router):
    srv, base, rec = router
    cfg = _write_setup(tmp_path, base)
    cfg.write_text(cfg.read_text() + '\n[[providers]]\ntype = "registry"\npath = "registry.toml"\n')
    code, _, err = _run(cfg, _at(100))
    assert code == 2 and "same" in err
