"""Guards for the credential expiry watch (issue #76, slice 1).

The decision engine runs against a fake clock. The TLS probe talks to a throwaway local
server with a certificate made by the openssl CLI at test time (openssl is required, not
skipped). The webhook shape is checked against what the n8n router's Normalize Alert node
accepts (see test_update_alerting.py).
"""
import datetime as dt
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import urllib.request

import pytest

from conftest import REPO_ROOT, import_module_from_path

ew = import_module_from_path("expiry_watch", REPO_ROOT / "scripts" / "expiry_watch.py")

UTC = dt.timezone.utc
START = dt.datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
EXPIRES = dt.date(2026, 3, 1)  # 59 days after START
RUNBOOK = "https://wiki.example.com/runbooks/rotate-key"


def _cfg(**watch):
    phone = ["discord", "pushover"]
    routes = {str(t): (phone if t <= 7 else ["discord"]) for t in watch.get("thresholds_days", [30, 14, 7])}
    routes.update({"daily": phone, "expired": phone})
    raw = {"watch": watch, "router": {"url": "https://n8n.example.com/webhook/grafana-alerts",
                                      "token_env": "EXPIRY_WATCH_TOKEN"}, "routes": routes}
    return ew.parse_config(raw)


def _item(expires=EXPIRES, name="deploy-key"):
    return ew.Item.build(name=name, kind="ssh-key", expires=expires, owner="ops@example.com", runbook=RUNBOOK)


def _at(days_before, expires=EXPIRES, hour=12):
    d = expires - dt.timedelta(days=days_before)
    return dt.datetime(d.year, d.month, d.day, hour, 0, tzinfo=UTC)


def _walk(cfg, item_for_day, days, state=None, expires=EXPIRES):
    """Run the engine once per day for each value in days; return [(days_left, stage), ...]."""
    fired = []
    state = state or {}
    for d in days:
        notices, state = ew.decide([item_for_day(d)], _at(d, expires), cfg, state)
        fired += [(n.days_left, n.stage) for n in notices]
    return fired, state


# --- the engine: thresholds, daily, expired --------------------------------------

def test_default_schedule_30_14_7_then_daily_then_expired():
    cfg = _cfg()
    assert cfg.thresholds == (30, 14, 7) and cfg.daily_below_days == 7
    fired, _ = _walk(cfg, lambda d: _item(), range(60, -3, -1))
    assert fired == [(30, "30"), (14, "14"), (7, "7"),
                     (6, "daily"), (5, "daily"), (4, "daily"), (3, "daily"), (2, "daily"), (1, "daily"),
                     (0, "expired")]


def test_each_threshold_fires_once_even_if_run_many_times_a_day():
    cfg = _cfg()
    state = {}
    stages = []
    for _ in range(5):
        notices, state = ew.decide([_item()], _at(14), cfg, state)
        stages += [n.stage for n in notices]
    assert stages == ["14"], "the 30 day threshold was crossed too, but only the lowest crossed one fires"
    notices, state = ew.decide([_item()], _at(14, hour=23), cfg, state)
    assert notices == []


def test_missed_days_fire_the_lowest_crossed_threshold_once():
    cfg = _cfg()
    notices, state = ew.decide([_item()], _at(10), cfg, {})
    assert [n.stage for n in notices] == ["14"]
    notices, state = ew.decide([_item()], _at(9), cfg, state)
    assert notices == []


def test_daily_runs_once_per_day_and_expired_fires_once():
    cfg = _cfg()
    _, state = ew.decide([_item()], _at(7), cfg, {})
    n1, state = ew.decide([_item()], _at(5, hour=1), cfg, state)
    n2, state = ew.decide([_item()], _at(5, hour=23), cfg, state)
    assert [n.stage for n in n1] == ["daily"] and n2 == []
    e1, state = ew.decide([_item()], _at(0), cfg, state)
    e2, state = ew.decide([_item()], _at(-3), cfg, state)
    assert [n.stage for n in e1] == ["expired"] and e2 == []


def test_thresholds_and_daily_rule_are_config_not_code():
    cfg = _cfg(thresholds_days=[60, 10], daily_below_days=3)
    fired, _ = _walk(cfg, lambda d: _item(), range(61, -1, -1))
    assert fired == [(60, "60"), (10, "10"), (3, "daily"), (2, "daily"), (1, "daily"), (0, "expired")]
    off = _cfg(daily_below_days=0)
    fired, _ = _walk(off, lambda d: _item(), range(60, -2, -1))
    assert [s for _, s in fired] == ["30", "14", "7", "expired"]


def test_first_sight_of_an_already_expired_item_fires_expired_once():
    cfg = _cfg()
    notices, state = ew.decide([_item()], _at(-20), cfg, {})
    assert [n.stage for n in notices] == ["expired"] and notices[0].days_left == -20
    assert ew.decide([_item()], _at(-19), cfg, state)[0] == []


def test_far_away_expiry_stays_silent_but_is_remembered():
    cfg = _cfg()
    notices, state = ew.decide([_item()], _at(300), cfg, {})
    assert notices == [] and "deploy-key" in state


# --- rotation resets state --------------------------------------------------------

def test_rotation_resets_state_so_new_thresholds_fire_again():
    cfg = _cfg()
    _, state = _walk(cfg, lambda d: _item(), range(31, 0, -1))
    assert state["deploy-key"]["threshold"] == 7
    new_exp = dt.date(2027, 3, 1)
    # rotated: the new expiry is far away, the old state must not linger
    notices, state = ew.decide([_item(new_exp)], _at(200, new_exp), cfg, state)
    assert notices == [] and state["deploy-key"]["threshold"] is None
    fired, _ = _walk(cfg, lambda d: _item(new_exp), range(31, 0, -1), state, new_exp)
    assert [s for _, s in fired][:3] == ["30", "14", "7"]


def test_rotation_after_expiry_clears_the_expired_flag():
    cfg = _cfg()
    _, state = ew.decide([_item()], _at(-1), cfg, {})
    assert state["deploy-key"]["expired"] is True
    new_exp = dt.date(2026, 6, 1)
    _, state = ew.decide([_item(new_exp)], START, cfg, state)
    assert state["deploy-key"]["expired"] is False


def test_a_removed_item_drops_its_state_and_state_is_not_mutated():
    cfg = _cfg()
    _, state = ew.decide([_item(), _item(name="other")], _at(10), cfg, {})
    frozen = json.loads(json.dumps(state))
    _, new = ew.decide([_item()], _at(9), cfg, state)
    assert set(new) == {"deploy-key"}
    assert state == frozen, "decide must not mutate the state it was given"


def test_the_clock_is_injected_and_uses_utc_dates():
    cfg = _cfg()
    late = dt.datetime(2026, 2, 28, 23, 30, tzinfo=dt.timezone(dt.timedelta(hours=-5)))  # Mar 1 04:30 UTC
    notices, _ = ew.decide([_item()], late, cfg, {})
    assert notices[0].stage == "expired" and notices[0].days_left == 0
    with pytest.raises(ValueError):
        ew.decide([_item()], dt.datetime(2026, 1, 1), cfg, {})  # naive time is refused


# --- notices become router payloads ----------------------------------------------

def _payload(days, stage_cfg=None):
    cfg = stage_cfg or _cfg()
    notices, _ = ew.decide([_item()], _at(days), cfg, {})
    assert len(notices) == 1
    return notices[0], ew.build_payload(notices[0], _at(days))


def test_payload_has_the_grafana_shape_and_labels():
    n, body = _payload(14)
    a = body["alerts"][0]
    assert body["status"] == "firing" and a["status"] == "firing" and len(body["alerts"]) == 1
    assert a["labels"]["expiry_watch"] == "true"
    assert a["labels"]["severity"] == "warning"
    assert "phone" not in a["labels"], "14 days routes to discord only"
    assert a["labels"]["alertname"].startswith("Expiry watch")
    assert len(a["fingerprint"]) == 32
    text = a["annotations"]["description"]
    for needle in ("deploy-key", "2026-03-01", "14 days", "ops@example.com", RUNBOOK):
        assert needle in text
    assert len(a["annotations"]["summary"]) <= 300 and len(text) <= 1000


def test_phone_label_only_for_thresholds_routed_to_pushover():
    assert "phone" not in _payload(30)[1]["alerts"][0]["labels"]
    assert _payload(7)[1]["alerts"][0]["labels"]["phone"] == "true"
    n, body = _payload(0)
    assert body["alerts"][0]["labels"]["phone"] == "true" and body["alerts"][0]["labels"]["severity"] == "critical"


def test_routing_is_config():
    cfg = ew.parse_config({"router": {"url": "https://n8n.example.com/h", "token_env": "T"},
                           "routes": {"30": ["pushover"], "14": ["discord"], "7": ["discord"],
                                      "daily": ["discord"], "expired": ["discord"]}})
    assert _payload(30, cfg)[1]["alerts"][0]["labels"]["phone"] == "true"
    assert "phone" not in _payload(7, cfg)[1]["alerts"][0]["labels"]


def test_router_normalizer_accepts_the_payload_unchanged():
    """The label names and lengths survive the router's own limits (labels 200, summary 300)."""
    _, body = _payload(7)
    a = body["alerts"][0]
    assert all(len(k) <= 100 and len(v) <= 200 for k, v in a["labels"].items())
    assert len(a["labels"]) <= 50 and isinstance(a["startsAt"], str) and not isinstance(a["labels"].get("alertname"), dict)
    assert dt.datetime.fromisoformat(a["startsAt"].replace("Z", "+00:00"))


def test_hostile_item_text_cannot_inject_control_characters_or_overflow():
    with pytest.raises(ew.ExpiryWatchError):
        ew.Item.build(name="a\nb", kind="k", expires=EXPIRES, owner="o", runbook=RUNBOOK)
    with pytest.raises(ew.ExpiryWatchError):
        ew.Item.build(name="x" * 101, kind="k", expires=EXPIRES, owner="o", runbook=RUNBOOK)
    with pytest.raises(ew.ExpiryWatchError):
        ew.Item.build(name="n", kind="k", expires=EXPIRES, owner="o", runbook="javascript:alert(1)")
    with pytest.raises(ew.ExpiryWatchError):
        ew.Item.build(name="n", kind="k", expires=EXPIRES, owner="", runbook=RUNBOOK)
    with pytest.raises(ew.ExpiryWatchError):
        ew.Item.build(name="n", kind="k", expires="2026-13-45", owner="o", runbook=RUNBOOK)


# --- config -----------------------------------------------------------------------

def test_example_config_parses_and_has_the_default_schedule():
    cfg = ew.load_config(REPO_ROOT / "docs" / "expiry-watch.example.toml")
    assert cfg.thresholds == (30, 14, 7) and cfg.daily_below_days == 7
    assert cfg.router.token_env.isidentifier()
    items = ew.RegistryProvider(dict(cfg.providers[0]), base_dir=REPO_ROOT / "docs").items()
    assert len(items) >= 3 and {"ssh-key", "pgp-key", "domain"} <= {i.kind for i in items}


@pytest.mark.parametrize("raw", [
    {"watch": {"thresholds_days": [7, 7]}},
    {"watch": {"thresholds_days": []}},
    {"watch": {"thresholds_days": [0]}},
    {"watch": {"thresholds_days": ["30"]}},
    {"watch": {"thresholds_days": [True]}},
    {"watch": {"daily_below_days": -1}},
    {"watch": {"surprise": 1}},
    {"routes": {"31": ["discord"]}},
    {"routes": {"7": ["carrier-pigeon"]}},
    {"routes": {"7": "discord"}},
    {"router": {"url": "http://n8n.example.com/h", "token_env": "T"}},
    {"router": {"url": "ftp://n8n.example.com/h", "token_env": "T"}},
    {"router": {"url": "https://n8n.example.com/h", "token_env": "has space"}},
    {"router": {"url": "https://n8n.example.com/h"}},
    {"unknown_section": {}},
])
def test_bad_config_is_rejected_with_a_clear_error(raw):
    base = {"router": {"url": "https://n8n.example.com/h", "token_env": "T"}}
    base.update(raw)
    with pytest.raises(ew.ExpiryWatchError):
        ew.parse_config(base)


def test_loopback_http_is_allowed_for_the_router_url():
    ew.parse_config({"router": {"url": "http://127.0.0.1:5678/h", "token_env": "T"}})


def test_config_file_with_duplicate_keys_or_huge_size_is_rejected(tmp_path):
    dup = tmp_path / "dup.toml"
    dup.write_text('[router]\nurl = "https://n8n.example.com/h"\nurl = "https://other.example.com/h"\n')
    with pytest.raises(ew.ExpiryWatchError, match="(?i)parse|duplicate|invalid"):
        ew.load_config(dup)
    huge = tmp_path / "huge.toml"
    huge.write_text("# " + "x" * (ew.MAX_FILE_BYTES + 10))
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
        ew.load_config(huge)


# --- registry provider -------------------------------------------------------------

REG_OK = """
[[item]]
name = "ops-ssh-key"
kind = "ssh-key"
expires = 2026-07-01
owner = "ops@example.com"
runbook = "https://wiki.example.com/runbooks/ssh"

[[item]]
name = "example.com"
kind = "domain"
expires = "2027-01-15"
owner = "dns@example.com"
runbook = "https://wiki.example.com/runbooks/domain"
"""


def _reg(tmp_path, text, name="registry.toml"):
    p = tmp_path / name
    p.write_text(text)
    return ew.RegistryProvider({"path": str(p)}, base_dir=tmp_path)


def test_registry_reads_items(tmp_path):
    items = _reg(tmp_path, REG_OK).items()
    assert [(i.name, i.kind, i.expires) for i in items] == [
        ("ops-ssh-key", "ssh-key", dt.date(2026, 7, 1)), ("example.com", "domain", dt.date(2027, 1, 15))]


@pytest.mark.parametrize("text,match", [
    ('[[item]]\nname = "a"\nname = "b"\n', "(?i)parse|duplicate|invalid"),
    ("this is not toml [[", "(?i)parse|invalid"),
    (REG_OK + REG_OK, "(?i)parse|duplicate|invalid|defined"),
    (REG_OK.replace("2026-07-01", "2026-13-01"), "(?i)parse|date|invalid"),
    (REG_OK.replace("2026-07-01", '"next tuesday"'), "(?i)date"),
    (REG_OK.replace("expires = 2026-07-01", "expires = 2026-07-01T00:00:00Z"), "(?i)date"),
    (REG_OK.replace('owner = "ops@example.com"\n', ""), "(?i)owner|missing"),
    (REG_OK.replace('kind = "ssh-key"', 'kind = "ssh-key"\nextra = 1'), "(?i)unknown|extra"),
    (REG_OK.replace('"example.com"', '"ops-ssh-key"'), "(?i)duplicate"),
    ("[[item]]\n" * 2 + 'name = "x"\n', "(?i)parse|missing|invalid|defined"),
    ('item = "scalar"\n', "(?i)item"),
    ("", "(?i)no items|item"),
])
def test_registry_errors_are_reported_not_swallowed(tmp_path, text, match):
    with pytest.raises(ew.ExpiryWatchError, match=match):
        _reg(tmp_path, text).items()


def test_registry_rejects_huge_files_too_many_items_and_non_regular_files(tmp_path):
    big = "# " + "x" * (ew.MAX_FILE_BYTES + 10)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
        _reg(tmp_path, big).items()
    many = "\n".join(f'[[item]]\nname = "i{n}"\nkind = "k"\nexpires = 2027-01-01\nowner = "o"\n'
                     f'runbook = "https://wiki.example.com/r"\n' for n in range(ew.MAX_ITEMS + 1))
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too many"):
        _reg(tmp_path, many).items()
    with pytest.raises(ew.ExpiryWatchError):
        ew.RegistryProvider({"path": str(tmp_path)}, base_dir=tmp_path).items()  # a directory
    fifo = tmp_path / "fifo.toml"
    os.mkfifo(fifo)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)regular"):
        ew.RegistryProvider({"path": str(fifo)}, base_dir=tmp_path).items()
    real = tmp_path / "real.toml"
    real.write_text(REG_OK)
    link = tmp_path / "link.toml"
    link.symlink_to(real)
    with pytest.raises(ew.ExpiryWatchError):
        ew.RegistryProvider({"path": str(link)}, base_dir=tmp_path).items()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)not found|cannot read"):
        ew.RegistryProvider({"path": str(tmp_path / "missing.toml")}, base_dir=tmp_path).items()


# --- DER date reader and TLS provider ------------------------------------------------

def test_der_reader_handles_utctime_and_generalizedtime_pivot():
    def seq(*parts):
        body = b"".join(parts)
        return b"\x30" + bytes([len(body)]) + body

    def cert(nb, na):
        validity = seq(nb, na)
        tbs = seq(b"\xa0\x03\x02\x01\x02", b"\x02\x01\x01", seq(), seq(), validity, seq(), seq())
        return seq(tbs, seq(), b"\x03\x01\x00")

    utc = lambda s: b"\x17" + bytes([len(s)]) + s.encode()
    gen = lambda s: b"\x18" + bytes([len(s)]) + s.encode()
    assert ew.der_not_after(cert(utc("250101000000Z"), utc("261231235959Z"))) == dt.datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
    assert ew.der_not_after(cert(utc("250101000000Z"), utc("491231235959Z"))).year == 2049
    assert ew.der_not_after(cert(utc("250101000000Z"), utc("500101000000Z"))).year == 1950  # RFC 5280 pivot
    assert ew.der_not_after(cert(gen("20250101000000Z"), gen("20510101000000Z"))).year == 2051
    for junk in (b"", b"\x00", b"\x30\x80", b"\x30\xff" + b"A" * 8, cert(utc("25010100Z"), utc("261231235959Z"))):
        with pytest.raises(ew.ExpiryWatchError):
            ew.der_not_after(junk)


def _make_cert(tmp_path, days):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    assert shutil.which("openssl"), "openssl is required for these tests (it must not be skipped or faked)"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", str(days), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    end = subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-enddate"], check=True,
                         capture_output=True, text=True).stdout.strip().split("=", 1)[1]
    expected = dt.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    return key, crt, expected


class _TlsServer:
    def __init__(self, key, crt):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.ctx, self.stop = ctx, threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2)
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    def close(self):
        self.stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.thread.join(5)
        self.sock.close()


@pytest.fixture
def tls_server(tmp_path):
    key, crt, expected = _make_cert(tmp_path, 40)
    srv = _TlsServer(key, crt)
    yield srv, crt, expected
    srv.close()


def _tls(port, **extra):
    cfg = {"host": "127.0.0.1", "port": port, "owner": "ops@example.com", "runbook": RUNBOOK, "timeout_seconds": 3}
    cfg.update(extra)
    return ew.TlsProvider(cfg)


def test_tls_probe_reads_the_expiry_from_the_peer_certificate(tls_server):
    srv, _, expected = tls_server
    (item,) = _tls(srv.port, verify=False).items()
    assert item.expires == expected.date() and item.kind == "tls-cert" and item.name == f"tls:127.0.0.1:{srv.port}"


def test_tls_probe_verifies_by_default_and_reports_the_failure(tls_server):
    srv, _, _ = tls_server
    with pytest.raises(ew.ExpiryWatchError, match="(?i)tls"):
        _tls(srv.port).items()  # self-signed: the default context refuses it


def test_tls_probe_can_verify_against_a_given_ca_file(tls_server):
    srv, crt, expected = tls_server
    (item,) = _tls(srv.port, ca_file=str(crt), server_name="localhost").items()
    assert item.expires == expected.date()


def test_tls_probe_timeouts_are_bounded_and_errors_reported():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)  # accepts at the kernel level but never answers the handshake
    try:
        import time
        t0 = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError, match="(?i)tls"):
            _tls(s.getsockname()[1], verify=False, timeout_seconds=1).items()
        assert time.monotonic() - t0 < 2.5
    finally:
        s.close()
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)tls"):
        _tls(port, verify=False).items()


@pytest.mark.parametrize("cfg", [
    {"host": "bad host", "port": 443}, {"host": "", "port": 443}, {"host": "example.com", "port": 0},
    {"host": "example.com", "port": 70000}, {"host": "example.com", "port": "443"},
    {"host": "example.com", "port": 443, "timeout_seconds": 0},
    {"host": "example.com", "port": 443, "timeout_seconds": 999},
    {"host": "example.com", "port": 443, "surprise": 1},
    {"host": "example.com", "port": 443, "verify": "no"},
])
def test_tls_config_is_validated(cfg):
    base = {"owner": "o", "runbook": RUNBOOK}
    base.update(cfg)
    with pytest.raises(ew.ExpiryWatchError):
        ew.TlsProvider(base)


def test_providers_are_plugins_behind_one_interface(tmp_path):
    class Static:
        def __init__(self, cfg):
            self.cfg = cfg

        def items(self):
            return [_item(name=self.cfg["name"])]

    ew.register_provider("static-test", Static)
    try:
        assert ew.PROVIDER_TYPES["static-test"] is Static
        with pytest.raises(ew.ExpiryWatchError):
            ew.register_provider("static-test", Static)  # no silent override
    finally:
        del ew.PROVIDER_TYPES["static-test"]
    assert set(ew.PROVIDER_TYPES) == {"registry", "tls"}


# --- state file ------------------------------------------------------------------------

def test_state_roundtrip_is_atomic_private_and_strict(tmp_path):
    p = tmp_path / "state.json"
    assert ew.load_state(p) == {}
    state = {"a": {"expires": "2026-03-01", "threshold": 14, "daily": None, "expired": False}}
    ew.save_state(p, state)
    assert ew.load_state(p) == state and (p.stat().st_mode & 0o777) == 0o600
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"], "no temp file left behind"
    for bad in ("{", "[]", '{"a": 1}', '{"a": {"expires": "nope", "threshold": null, "daily": null, "expired": false}}',
                '{"a": {"expires": "2026-03-01"}}'):
        p.write_text(bad)
        with pytest.raises(ew.ExpiryWatchError):
            ew.load_state(p)
    p.write_text("x" * (ew.MAX_FILE_BYTES + 1))
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
        ew.load_state(p)


# --- posting ------------------------------------------------------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    seen = []
    status = 200
    redirect_to = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append((self.path, dict(self.headers), body))
        if type(self).redirect_to and self.path == "/h":
            self.send_response(307)
            self.send_header("Location", type(self).redirect_to)
            self.end_headers()
            return
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b'{"status":"delivered"}')

    def log_message(self, *a):
        pass


@pytest.fixture
def router():
    _Recorder.seen, _Recorder.status, _Recorder.redirect_to = [], 200, None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    t.join(5)
    srv.server_close()


def test_post_sends_json_with_a_bearer_and_never_follows_redirects(router):
    srv, base = router
    ew.post_json(base + "/h", "tok-value", {"a": 1}, timeout=3)
    path, headers, body = _Recorder.seen[0]
    assert headers["Authorization"] == "Bearer tok-value" and headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"a": 1}
    _Recorder.redirect_to = base + "/elsewhere"
    with pytest.raises(ew.ExpiryWatchError, match="(?i)redirect|307"):
        ew.post_json(base + "/h", "tok-value", {"a": 1}, timeout=3)
    assert [p for p, _, _ in _Recorder.seen] == ["/h", "/h"], "the bearer must not be replayed to the redirect target"
    _Recorder.status = 502
    with pytest.raises(ew.ExpiryWatchError, match="502") as exc:
        ew.post_json(base + "/x", "tok-value", {}, timeout=3)
    assert "tok-value" not in str(exc.value)


def test_post_rejects_a_token_that_could_inject_headers():
    for bad in ("a\r\nX-Evil: 1", "has space", "", "x" * 600):
        with pytest.raises(ew.ExpiryWatchError):
            ew.post_json("https://n8n.example.com/h", bad, {}, timeout=3)


# --- the runner (cron entry point) -------------------------------------------------------

def _write_setup(tmp_path, router_url, expires="2026-03-01", routes=None):
    reg = tmp_path / "registry.toml"
    reg.write_text(f'[[item]]\nname = "deploy-key"\nkind = "ssh-key"\nexpires = {expires}\n'
                   f'owner = "ops@example.com"\nrunbook = "{RUNBOOK}"\n')
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'''[watch]
state_file = "state.json"

[router]
url = "{router_url}/h"
token_env = "EXPIRY_WATCH_TOKEN"
timeout_seconds = 3

[routes]
{routes or ""}

[[providers]]
type = "registry"
path = "registry.toml"
''')
    return cfg


def _run(cfg, now, env=None, **kw):
    out, err = [], []
    code = ew.run(cfg, now=now, env=env if env is not None else {"EXPIRY_WATCH_TOKEN": "secret-token-value"},
                  out=out.append, err=err.append, **kw)
    return code, "\n".join(out), "\n".join(err)


def test_run_posts_the_due_notice_once_and_never_prints_the_secret(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    code, out, err = _run(cfg, _at(14))
    assert code == 0 and len(_Recorder.seen) == 1
    sent = json.loads(_Recorder.seen[0][2])
    assert sent["alerts"][0]["labels"]["expiry_watch"] == "true"
    assert "secret-token-value" not in out + err
    code, out, _ = _run(cfg, _at(14, hour=20))
    assert code == 0 and len(_Recorder.seen) == 1, "the same threshold must not post twice"
    code, _, _ = _run(cfg, _at(7))
    assert code == 0 and len(_Recorder.seen) == 2


def test_run_keeps_the_notice_due_when_delivery_fails(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    _Recorder.status = 500
    code, out, err = _run(cfg, _at(14))
    assert code == 1 and "500" in err and "secret-token-value" not in out + err
    _Recorder.status = 200
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert code == 0 and len(_Recorder.seen) == 2, "a failed post is retried on the next run"
    code, _, _ = _run(cfg, _at(14, hour=19))
    assert len(_Recorder.seen) == 2


def test_run_dry_run_posts_nothing_and_saves_nothing(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    code, out, _ = _run(cfg, _at(14), env={}, dry_run=True)
    assert code == 0 and not _Recorder.seen and not (tmp_path / "state.json").exists()
    assert "deploy-key" in out and "14" in out


def test_run_needs_the_token_when_it_would_post(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    code, _, err = _run(cfg, _at(14), env={})
    assert code == 2 and "EXPIRY_WATCH_TOKEN" in err and not _Recorder.seen
    code, _, err = _run(cfg, _at(14), env={"EXPIRY_WATCH_TOKEN": "bad token"})
    assert code == 2 and "bad token" not in err


def test_run_reports_a_broken_provider_and_keeps_its_state(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    assert _run(cfg, _at(14))[0] == 0
    (tmp_path / "registry.toml").write_text("not toml [[")
    code, _, err = _run(cfg, _at(13))
    assert code == 1 and "registry" in err
    state = ew.load_state(tmp_path / "state.json")
    assert "deploy-key" in state, "a provider outage must not forget what was already notified"


def test_run_skips_channels_that_are_not_built_yet_and_says_so(tmp_path, router):
    srv, base = router
    cfg = _write_setup(tmp_path, base, routes='"14" = ["matrix", "email"]')
    code, out, err = _run(cfg, _at(14))
    assert code == 0 and not _Recorder.seen
    assert "matrix" in err and "not built" in err
    # nothing was delivered, so the notice must still be due (the state did not advance)
    state = ew.load_state(tmp_path / "state.json")
    assert state.get("deploy-key", {}).get("threshold") is None
    # the operator fixes the route: the same notice now goes out
    cfg.write_text(cfg.read_text().replace('"14" = ["matrix", "email"]', '"14" = ["discord"]'))
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert code == 0 and len(_Recorder.seen) == 1
    assert json.loads(_Recorder.seen[0][2])["alerts"][0]["labels"]["stage"] == "14"


def test_run_config_error_exit_code(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[watch]\nthresholds_days = [1, 1]\n")
    code, _, err = _run(bad, START)
    assert code == 2 and "thresholds" in err


def test_no_secret_value_in_the_shipped_files():
    for f in ("scripts/expiry_watch.py", "docs/expiry-watch.md", "docs/expiry-watch.example.toml",
              "docs/expiry-watch-registry.example.toml"):
        text = (REPO_ROOT / f).read_text(encoding="utf-8")
        assert chr(0x2014) not in text, f"{f}: no em dashes"
        assert "BEGIN PRIVATE KEY" not in text
