"""Guards for the weekly digest (issue #69). Fakes only: provider functions, a Grafana on loopback and
an SMTP server on loopback. No real network, mail server or token is ever used."""
import datetime as dt
import http.server
import json
import threading

import pytest

from conftest import REPO_ROOT, import_module_from_path
from test_expiry_watch_channels import SMTP_PASSWORD, _start_smtp, _stop, smtp_plain  # noqa: F401  fixtures

wd = import_module_from_path("weekly_digest", REPO_ROOT / "scripts" / "weekly_digest.py")
ew = wd.ew
UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
GRAFANA_TOKEN = "grafana-read-only-token-value"


def _write(tmp_path, smtp_port=2525, extra="", grafana=None, digest="", state=None):
    (tmp_path / "state.json").write_text(json.dumps(state if state is not None else {}))
    text = f'''
[digest]
{digest}
[expiry]
state_file = "state.json"
[email]
host = "127.0.0.1"
port = {smtp_port}
security = "plaintext"
allow_plaintext = true
from = "digest@example.com"
to = ["ops@example.com"]
'''
    if grafana:
        text += f'\n[grafana]\nurl = "{grafana}"\ntoken_env = "DIGEST_GRAFANA_TOKEN"\ntimeout_seconds = 3\n'
    cfg = tmp_path / "digest.toml"
    cfg.write_text(text + extra)
    return cfg


def _sec(title, lines=(), note=""):
    return wd.Section(title, tuple(lines), note)


def _fakes(**over):
    p = {"patched": lambda ctx: _sec("Patched automatically", ["pkg a"]),
         "grafana": lambda ctx: (_sec("Alerts that fired this week", ["alert x: fired 2 times"]),
                                 _sec("Needs action", ["update y"])),
         "expiry": lambda ctx: _sec("Stale", ["cert z"])}
    p.update(over)
    return p


class _Grafana(http.server.BaseHTTPRequestHandler):
    seen, body, status = [], b"[]", 200

    def do_GET(self):
        type(self).seen.append((self.path, dict(self.headers)))
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *a):
        pass


@pytest.fixture
def grafana():
    _Grafana.seen, _Grafana.body, _Grafana.status = [], b"[]", 200
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Grafana)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    t.join(5)
    srv.server_close()


def _run(cfg, send=False, providers=None, env=None):
    out, err = [], []
    code = wd.run(cfg, NOW, env=env if env is not None else {}, out=out.append, err=err.append, send=send,
                  providers=providers)
    return code, "\n".join(out), "\n".join(err)


# --- safe by default ------------------------------------------------------------------------

def test_dry_run_prints_the_email_and_makes_no_network_call(tmp_path, grafana, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1], grafana=grafana)
    code, out, _ = _run(cfg, env={"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN})
    assert code == 0 and "PATCHED AUTOMATICALLY" in out and "PLACEHOLDER" in out
    assert "Not fetched" in out
    assert _Grafana.seen == [] and smtp_plain.sessions == []


def test_dry_run_never_calls_the_grafana_provider(tmp_path):
    cfg = _write(tmp_path)

    def boom(ctx):
        raise AssertionError("network provider called in a dry run")
    code, out, _ = _run(cfg, providers=_fakes(grafana=boom))
    assert code == 0 and "boom" not in out


def test_send_delivers_exactly_one_email(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    code, out, _ = _run(cfg, send=True, providers=_fakes())
    assert code == 0
    (s,) = smtp_plain.sessions
    head = s["data"].partition("\r\n\r\n")[0]
    assert "From: digest@example.com" in head and "To: ops@example.com" in head and "Message-ID: <digest-" in head
    assert "alert x: fired 2 times" in s["data"] and "cert z" in s["data"] and len(s["rcpt"]) == 1


def test_cli_default_is_a_dry_run_and_send_is_explicit(monkeypatch):
    calls = []
    monkeypatch.setattr(wd, "run", lambda path, now, send=False, **kw: calls.append(send) or 0)
    assert wd.main(["--config", "x.toml"]) == 0 and wd.main(["--config", "x.toml", "--send"]) == 0
    assert calls == [False, True]


# --- sanitizing -----------------------------------------------------------------------------

EVIL = "x\r\nBcc: attacker@example.com\r\n\r\nINJECTED\x00\x1b[31m more\x85end"


def test_provider_strings_are_cleaned_in_every_section(tmp_path):
    cfg = _write(tmp_path)
    evil = _fakes(patched=lambda c: _sec(EVIL, [EVIL], EVIL),
                  grafana=lambda c: (_sec(EVIL, [EVIL]), _sec(EVIL, [EVIL])),
                  expiry=lambda c: _sec(EVIL, [EVIL]))
    code, out, _ = _run(cfg, send=False, providers=evil)
    body = out.partition("\n\n")[2]
    assert "\r" not in body and "\x00" not in body and "\x1b" not in body and " " not in body
    assert "INJECTED" in body  # kept as text, but never on its own line start with a header shape
    assert all(not ln.startswith("Bcc:") for ln in body.splitlines())


def test_injection_cannot_reach_the_mail_headers_or_recipients(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    _run(cfg, send=True, providers=_fakes(expiry=lambda c: _sec("Stale", [EVIL])))
    (s,) = smtp_plain.sessions
    head = s["data"].partition("\r\n\r\n")[0]
    assert "\nBcc:" not in head and len(s["rcpt"]) == 1


def test_subject_never_contains_provider_text(tmp_path):
    cfg = _write(tmp_path)
    code, out, _ = _run(cfg, providers=_fakes(patched=lambda c: _sec("Patched automatically", [EVIL])))
    subject = out.splitlines()[0]
    assert subject.startswith("Subject: Weekly digest:") and "INJECTED" not in subject


# --- size cap and one email -----------------------------------------------------------------

def test_body_is_capped_by_bytes(tmp_path):
    cfg = _write(tmp_path, digest="max_body_bytes = 1024\nmax_entries_per_section = 200")
    many = _fakes(expiry=lambda c: _sec("Stale", [f"item {i} " + "y" * 150 for i in range(150)]))
    code, out, _ = _run(cfg, providers=many)
    body = out.partition("\n\n")[2]
    assert len(body.encode()) <= 1100 and "[digest truncated at the size limit]" in body


def test_entries_over_the_section_cap_are_counted_not_dropped_silently(tmp_path):
    cfg = _write(tmp_path, digest="max_entries_per_section = 2")
    code, out, _ = _run(cfg, providers=_fakes(expiry=lambda c: _sec("Stale", [f"i{n}" for n in range(9)])))
    assert "... and 7 more not shown" in out and "- i1" in out and "- i2" not in out


def test_a_failing_source_still_sends_one_email_and_exits_1(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])

    def bad(ctx):
        raise wd.DigestError("grafana: rejected the request: HTTP 401")
    code, _, err = _run(cfg, send=True, providers=_fakes(grafana=bad))
    assert code == 1 and len(smtp_plain.sessions) == 1
    assert "SOURCE FAILED: grafana" in smtp_plain.sessions[0]["data"] and "source failed" in err


def test_a_provider_bug_is_contained(tmp_path):
    cfg = _write(tmp_path)

    def bug(ctx):
        raise KeyError("secret-looking-detail")
    code, out, err = _run(cfg, providers=_fakes(expiry=bug))
    assert code == 1 and "KeyError" in out and "secret-looking-detail" not in out + err


def test_delivery_failure_exits_3_and_does_not_retry(tmp_path, smtp_plain):
    smtp_plain.data_reply = "554 no"
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    code, _, err = _run(cfg, send=True, providers=_fakes())
    assert code == 3 and "554" in err and len(smtp_plain.sessions) == 1


def test_config_errors_exit_2(tmp_path):
    for extra in ("\n[bogus]\nx = 1\n",):
        cfg = _write(tmp_path, extra=extra)
        assert _run(cfg)[0] == 2
    (tmp_path / "nomail.toml").write_text("[digest]\n")
    assert _run(tmp_path / "nomail.toml")[0] == 2


def test_send_needs_the_smtp_login_variable(tmp_path):
    cfg = _write(tmp_path, extra="")
    text = cfg.read_text().replace('security = "plaintext"\nallow_plaintext = true',
                                   'security = "starttls"\nusername_env = "D_U"\npassword_env = "D_P"')
    cfg.write_text(text)
    code, _, err = _run(cfg, send=True, providers=_fakes(), env={"D_U": "u"})
    assert code == 2 and "D_P" in err


def test_secrets_are_names_only_and_never_printed(tmp_path):
    cfg = _write(tmp_path, grafana="http://127.0.0.1:1")
    with pytest.raises(ew.ExpiryWatchError):
        wd.parse_config(ew.read_toml("digest.toml", "config", ew.Root(str(tmp_path))) | {"grafana": {
            "url": "http://127.0.0.1:1", "token_env": "not a name; secret-token"}})


# --- the Grafana provider (fake server) -----------------------------------------------------

def _events():
    ms = int(NOW.timestamp() * 1000)
    return [{"time": ms - 5000, "alertName": "pfSense update pending over 24h", "newState": "Alerting"},
            {"time": ms - 4000, "alertName": "Disk full", "newState": "Alerting"},
            {"time": ms - 3000, "alertName": "Disk full", "newState": "Normal"},
            {"time": ms - 2000, "alertName": "Disk full", "newState": "Alerting"},
            {"time": "bad", "alertName": "junk", "newState": "Alerting"}, "junk", {"alertName": 5}]


def test_grafana_provider_reads_read_only_with_the_token_from_the_environment(tmp_path, grafana, smtp_plain):
    _Grafana.body = json.dumps(_events()).encode()
    cfg = _write(tmp_path, smtp_plain.server_address[1], grafana=grafana)
    code, _, _ = _run(cfg, send=True, env={"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN})
    assert code == 0
    ((path, headers),) = _Grafana.seen
    assert path.startswith("/api/annotations?type=alert&from=") and "limit=500" in path
    assert headers["Authorization"] == f"Bearer {GRAFANA_TOKEN}"
    data = smtp_plain.sessions[0]["data"]
    assert "Disk full: fired 2 times" in data and "pfSense update pending over 24h: still Alerting" in data
    assert GRAFANA_TOKEN not in data


def test_grafana_missing_token_is_a_named_failure_not_a_crash(tmp_path, grafana):
    cfg = _write(tmp_path, grafana=grafana)
    code, out, _ = _run(cfg, send=False, providers={"patched": _fakes()["patched"]})
    assert code == 0  # dry run: grafana not called
    ctx = {"config": wd.parse_config(ew.read_toml("digest.toml", "c", ew.Root(str(tmp_path)))), "now": NOW, "env": {}}
    with pytest.raises(wd.DigestError, match="DIGEST_GRAFANA_TOKEN"):
        wd._grafana_events(ctx)


def test_grafana_http_error_and_bad_shape_are_failures(tmp_path, grafana):
    cfg = _write(tmp_path, grafana=grafana)
    conf = wd.parse_config(ew.read_toml("digest.toml", "c", ew.Root(str(tmp_path))))
    ctx = {"config": conf, "now": NOW, "env": {"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN}}
    _Grafana.status = 403
    with pytest.raises(wd.DigestError, match="403"):
        wd._grafana_events(ctx)
    _Grafana.status, _Grafana.body = 200, b'{"not": "a list"}'
    with pytest.raises(wd.DigestError, match="not a list"):
        wd._grafana_events(ctx)


def test_grafana_url_must_be_https_or_loopback(tmp_path):
    with pytest.raises(wd.DigestError):
        wd.parse_grafana({"url": "http://grafana.example.com", "token_env": "T"})
    with pytest.raises(wd.DigestError):
        wd.parse_grafana({"url": "https://u:p@grafana.example.com", "token_env": "T"})


# --- the expiry state (read-only) -----------------------------------------------------------

def test_stale_items_come_from_the_state_file_and_it_is_never_written(tmp_path):
    state = {"old-key": {"expires": "2026-11-10", "threshold": 7, "daily": None, "expired": True},
             "soon": {"expires": "2026-12-01", "threshold": 14, "daily": None, "expired": False},
             "far": {"expires": "2027-06-01", "threshold": None, "daily": None, "expired": False}}
    cfg = _write(tmp_path, state=state)
    before = (tmp_path / "state.json").read_bytes()
    mtime = (tmp_path / "state.json").stat().st_mtime_ns
    code, out, _ = _run(cfg, providers={"patched": _fakes()["patched"]})
    assert "old-key: EXPIRED 10 days ago" in out and "soon: expires in 11 days" in out and "far" not in out
    assert (tmp_path / "state.json").read_bytes() == before and (tmp_path / "state.json").stat().st_mtime_ns == mtime
    assert sorted(p.name for p in tmp_path.iterdir()) == ["digest.toml", "state.json"]


def test_missing_and_symlinked_state_are_reported_not_followed(tmp_path):
    cfg = _write(tmp_path)
    (tmp_path / "state.json").unlink()
    assert "was not found" in _run(cfg, providers={"patched": _fakes()["patched"]})[1]
    secret = tmp_path / "other.json"
    secret.write_text("{}")
    (tmp_path / "state.json").symlink_to(secret)
    code, out, _ = _run(cfg, providers={"patched": _fakes()["patched"]})
    assert code == 1 and "SOURCE FAILED: expiry" in out


def test_a_state_file_nobody_updated_is_itself_stale(tmp_path):
    import os
    cfg = _write(tmp_path)
    old = NOW.timestamp() - 10 * 86400
    os.utime(tmp_path / "state.json", (old, old))
    assert "has not saved its state for 10 days" in _run(cfg, providers={"patched": _fakes()["patched"]})[1]


def test_patch_gremlin_section_is_a_labeled_placeholder(tmp_path):
    code, out, _ = _run(_write(tmp_path))
    assert "PLACEHOLDER: no Patch Gremlin state source" in out


def test_the_example_config_parses():
    import tomllib
    raw = tomllib.loads((REPO_ROOT / "docs" / "weekly-digest.example.toml").read_text())
    cfg = wd.parse_config(raw)
    assert cfg.grafana.token_env == "WEEKLY_DIGEST_GRAFANA_TOKEN" and cfg.email.security == "starttls"


# --- Daybreak round 1 ----------------------------------------------------------------------

def test_one_out_of_range_timestamp_does_not_drop_the_valid_results(tmp_path, grafana, smtp_plain):
    ms = int(NOW.timestamp() * 1000)
    _Grafana.body = json.dumps([
        {"time": ms - 1000, "alertName": "real update pending", "newState": "Alerting"},
        {"time": 10 ** 300, "alertName": "poison huge", "newState": "Alerting"},
        {"time": -5, "alertName": "poison negative", "newState": "Alerting"},
        {"time": ms + 10 * 86_400_000, "alertName": "poison future", "newState": "Normal"},
        {"time": ms - 30 * 86_400_000, "alertName": "poison old", "newState": "Alerting"},
        {"time": True, "alertName": "poison bool", "newState": "Alerting"},
    ]).encode()
    cfg = _write(tmp_path, smtp_plain.server_address[1], grafana=grafana)
    code, _, _ = _run(cfg, send=True, env={"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN})
    data = smtp_plain.sessions[0]["data"]
    assert code == 0 and "real update pending: still Alerting" in data
    assert "poison" not in data and data.count("SOURCE NOTE") == 1 and "SOURCE FAILED" not in data


BIDI = "‮‪‬⁦⁧⁨⁩​‌‍﻿‎‏؜⁠­"


def test_clean_removes_bidi_and_format_characters_but_keeps_text():
    out = wd.clean(f"Disk safe{BIDI}Update café 日本 مرحبا x y")
    assert not any(c in out for c in BIDI + "  ")
    assert "café" in out and "日本" in out and "مرحبا" in out


def test_bidi_controls_never_reach_the_email(tmp_path):
    cfg = _write(tmp_path)
    evil = _fakes(patched=lambda c: _sec("T" + BIDI, ["a" + BIDI], "n" + BIDI),
                  expiry=lambda c: _sec("Stale", ["b" + BIDI]))
    out = _run(cfg, providers=evil)[1]
    assert not any(c in out for c in BIDI)


def _send(cfg, **kw):
    return wd.run(cfg, kw.pop("now", NOW), env={}, out=lambda m: None, err=lambda m: None, send=True,
                  providers=_fakes(), **kw)


def test_a_second_send_in_the_same_week_is_refused(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    assert (_send(cfg), _send(cfg)) == (0, 4) and len(smtp_plain.sessions) == 1


def test_force_sends_again_and_a_new_week_does_not_need_it(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    assert (_send(cfg), _send(cfg, force=True)) == (0, 0) and len(smtp_plain.sessions) == 2
    assert _send(cfg, now=NOW + dt.timedelta(days=7)) == 0 and len(smtp_plain.sessions) == 3


def test_an_existing_lock_refuses_the_send_and_is_released_after_a_run(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    d = tmp_path / "weekly-digest-state"
    d.mkdir(mode=0o700)
    (d / "lock").write_text("1")
    code, _, err = _run(cfg, send=True, providers=_fakes())
    assert code == 4 and "lock" in err and not smtp_plain.sessions
    (d / "lock").unlink()
    assert _run(cfg, send=True, providers=_fakes())[0] == 0 and not (d / "lock").exists()
    assert oct(d.stat().st_mode & 0o777) == "0o700" and (d / "last-sent").read_text().strip() == "2026-W47"


def test_a_failed_delivery_leaves_no_marker_and_releases_the_lock(tmp_path, smtp_plain):
    smtp_plain.data_reply = "554 no"
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    assert _run(cfg, send=True, providers=_fakes())[0] == 3
    d = tmp_path / "weekly-digest-state"
    assert not (d / "last-sent").exists() and not (d / "lock").exists()


def test_dry_run_touches_no_state(tmp_path):
    cfg = _write(tmp_path)
    _run(cfg, providers=_fakes())
    assert not (tmp_path / "weekly-digest-state").exists()


def test_the_cli_has_a_force_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(wd, "run", lambda path, now, send=False, force=False, **kw: calls.append(force) or 0)
    wd.main(["--config", "x.toml", "--send"])
    wd.main(["--config", "x.toml", "--send", "--force"])
    assert calls == [False, True]


def test_the_whole_encoded_message_is_bounded(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1],
                 digest="max_body_bytes = 200000\nmax_message_bytes = 20000\nmax_entries_per_section = 200")
    big = _fakes(expiry=lambda c: _sec("Stale", ["é" * 150 for _ in range(200)]))
    assert _run(cfg, send=True, providers=big)[0] == 0
    (s,) = smtp_plain.sessions
    assert len(s["data"].encode("utf-8", "surrogateescape")) <= 20000
    assert "truncated" in s["data"]


# --- Daybreak round 2 ----------------------------------------------------------------------

LONE = "safe\ud800name\udfff"


def test_clean_replaces_lone_surrogates_and_stays_encodable():
    out = wd.clean(LONE)
    assert "\ud800" not in out and "\udfff" not in out
    out.encode("utf-8")


def test_lone_surrogates_from_grafana_do_not_stop_the_digest(tmp_path, grafana, smtp_plain):
    ms = int(NOW.timestamp() * 1000)
    # json.loads accepts an escaped lone surrogate, so this reaches the renderer from the API.
    _Grafana.body = ('[{"time": %d, "alertName": "update safe\\ud800name", "newState": "Alerting"}]' % (ms - 1000)).encode()
    cfg = _write(tmp_path, smtp_plain.server_address[1], grafana=grafana)
    code, _, _ = _run(cfg, send=True, env={"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN})
    assert code == 0 and "update safe name: still Alerting" in smtp_plain.sessions[0]["data"]


def test_lone_surrogates_in_an_expiry_item_name_do_not_stop_the_digest(tmp_path, smtp_plain):
    state = {"key\ud800x": {"expires": "2026-11-10", "threshold": 7, "daily": None, "expired": True}}
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    (tmp_path / "state.json").write_text(json.dumps(state, ensure_ascii=True))
    code, _, _ = _run(cfg, send=True, providers={"patched": _fakes()["patched"]})
    assert code in (0, 1) and len(smtp_plain.sessions) == 1


def test_lone_surrogates_in_providers_notes_and_titles_are_survivable(tmp_path):
    cfg = _write(tmp_path)
    evil = _fakes(patched=lambda c: _sec(LONE, [LONE], LONE), expiry=lambda c: _sec("Stale", [LONE]))
    code, out, _ = _run(cfg, providers=evil)
    assert code == 0 and "\ud800" not in out


def test_a_lone_surrogate_in_a_config_string_is_a_clean_config_error(tmp_path):
    cfg = _write(tmp_path, extra='\n[grafana]\nurl = "https://g.example.com"\ntoken_env = "T"\n')
    cfg.write_text(cfg.read_text().replace('state_file = "state.json"', 'state_file = "st\\ud800.json"'))
    assert _run(cfg)[0] == 2


def test_non_numeric_times_are_counted_in_the_source_note(tmp_path, grafana, smtp_plain):
    ms = int(NOW.timestamp() * 1000)
    _Grafana.body = json.dumps([{"time": "12345", "alertName": "x", "newState": "Alerting"},
                                {"time": ms - 5, "alertName": "update y", "newState": "Alerting"}]).encode()
    cfg = _write(tmp_path, smtp_plain.server_address[1], grafana=grafana)
    _run(cfg, send=True, env={"DIGEST_GRAFANA_TOKEN": GRAFANA_TOKEN})
    assert "1 record(s) skipped" in smtp_plain.sessions[0]["data"]


def _marker(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    d = tmp_path / "weekly-digest-state"
    d.mkdir(mode=0o700)
    return cfg, d / "last-sent"


@pytest.mark.parametrize("kind", ["empty", "garbage", "partial", "directory", "symlink", "unreadable", "binary"])
def test_a_damaged_last_sent_marker_fails_closed(tmp_path, smtp_plain, kind):
    import os
    cfg, marker = _marker(tmp_path, smtp_plain)
    if kind == "empty":
        marker.write_text("")
    elif kind == "garbage":
        marker.write_text("2026-W47-corrupt\n")
    elif kind == "partial":
        marker.write_text("2026-W4")
    elif kind == "binary":
        marker.write_bytes(b"\xff\xfe\x00junk")
    elif kind == "directory":
        marker.mkdir()
    elif kind == "symlink":
        other = tmp_path / "other"
        other.write_text("2026-W01\n")
        marker.symlink_to(other)
    else:
        marker.write_text("2026-W01\n")
        marker.chmod(0)
        if os.access(marker, os.R_OK):
            pytest.skip("running as a user that ignores file modes")
    code, _, err = _run(cfg, send=True, providers=_fakes())
    assert code == 4 and "last-sent" in err and not smtp_plain.sessions
    assert not (marker.parent / "lock").exists()


def test_a_refusal_releases_the_lock_so_the_next_run_is_refused_for_the_right_reason(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    assert _send(cfg) == 0 and _send(cfg) == 4
    assert not (tmp_path / "weekly-digest-state" / "lock").exists()
    assert _send(cfg, force=True) == 0  # would be refused by a leaked lock


def test_force_overrides_a_damaged_marker_and_a_missing_marker_allows_the_first_send(tmp_path, smtp_plain):
    cfg, marker = _marker(tmp_path, smtp_plain)
    assert _run(cfg, send=True, providers=_fakes())[0] == 0  # missing marker: first send
    marker.write_text("garbage")
    assert wd.run(cfg, NOW, env={}, out=lambda m: None, err=lambda m: None, send=True, providers=_fakes(),
                  force=True) == 0
    assert marker.read_text().strip() == "2026-W47"


def test_wire_size_counts_dot_stuffing_and_the_terminator_exactly(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1])
    parsed = wd.parse_config(__import__("tomllib").loads(cfg.read_text()))
    body = "\n".join("." * 5 for _ in range(100)) + "\n"
    msg = wd.build_message(parsed, "subject", body, NOW)
    ew.smtp_deliver(parsed.email, {}, msg)
    (s,) = smtp_plain.sessions
    assert wd.wire_size(msg) == len(s["data"].encode("latin-1")) + len(b".\r\n")


def test_the_cap_holds_for_a_dot_heavy_body_at_the_boundary(tmp_path, smtp_plain):
    cfg = _write(tmp_path, smtp_plain.server_address[1],
                 digest="max_message_bytes = 4096\nmax_entries_per_section = 200")
    dots = _fakes(expiry=lambda c: _sec("Stale", ["." * 3 for _ in range(200)]))
    parsed = wd.parse_config(__import__("tomllib").loads(cfg.read_text()))
    assert _run(cfg, send=True, providers=dots)[0] == 0
    (s,) = smtp_plain.sessions
    assert len(s["data"].encode("latin-1")) + 3 <= parsed.max_message_bytes
