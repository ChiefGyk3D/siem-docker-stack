"""Slice 2 guards for the expiry watch (issue #97): the Grafana service account token provider and
the secret manager service token provider, against a fake vendor served by an in-process HTTP
server on loopback (the same approach as the router tests in test_expiry_watch.py).
"""
import datetime as dt
import http.server
import json
import threading
import time
import urllib.parse

import pytest

from test_expiry_watch import RUNBOOK, START, _at, _cfg, _run, _write_setup, ew

TOKEN = "vendor-ro-token-value"
BODY_SECRET = "dp.st.SECRET-KEY-VALUE-MUST-NEVER-APPEAR"
TODAY = dt.date(2026, 1, 1)


class FakeVendor:
    """Serves canned replies by path, records every request, and can hang or redirect."""

    def __init__(self):
        self.requests = []          # (path with query, headers dict)
        self.replies = {}           # path (no query) -> (status, body bytes, extra headers)
        self.release = threading.Event()
        self.hang = False
        vendor = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                vendor.requests.append((self.path, dict(self.headers)))
                if vendor.hang:
                    vendor.release.wait(8)
                    return
                status, body, headers = vendor.replies.get(urllib.parse.urlsplit(self.path).path,
                                                           (404, b"{}", {}))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def reply(self, path, payload, status=200, headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.replies[path] = (status, body, headers or {})

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.thread.join(5)
        self.server.server_close()


@pytest.fixture
def vendor():
    v = FakeVendor()
    yield v
    v.close()


@pytest.fixture
def other():
    v = FakeVendor()
    yield v
    v.close()


def _grafana(vendor, ids=(3,), **extra):
    cfg = {"url": vendor.base, "service_account_ids": list(ids), "token_env": "GRAFANA_RO_TOKEN",
           "owner": "ops@example.com", "runbook": RUNBOOK, "timeout_seconds": 3,
           "_env": {"GRAFANA_RO_TOKEN": TOKEN}}
    cfg.update(extra)
    prov = ew.GrafanaProvider(cfg)
    prov._today = lambda: TODAY
    return prov


def _doppler(vendor, **extra):
    cfg = {"api_url": vendor.base, "project": "example-app", "config": "prd", "token_env": "DOPPLER_RO_TOKEN",
           "owner": "ops@example.com", "runbook": RUNBOOK, "timeout_seconds": 3,
           "_env": {"DOPPLER_RO_TOKEN": TOKEN}}
    cfg.update(extra)
    prov = ew.DopplerProvider(cfg)
    prov._today = lambda: TODAY
    return prov


def _tok(name, expiration=None, expired=False, **extra):
    d = {"id": 1, "name": name, "role": "Viewer", "created": "2025-01-01T00:00:00Z", "expiration": expiration,
         "secondsUntilExpiration": 0, "hasExpired": expired}
    d.update(extra)
    return d


GRAFANA_PATH = "/api/serviceaccounts/3/tokens"
DOPPLER_PATH = "/v3/configs/config/tokens"


# --- parse_expiry ------------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("2026-12-01T00:00:00Z", dt.date(2026, 12, 1)),
    ("2026-12-01T00:00:00.000Z", dt.date(2026, 12, 1)),
    ("2026-12-01T00:00:00.123456789Z", dt.date(2026, 12, 1)),
    ("2026-12-01T23:30:00-05:00", dt.date(2026, 12, 2)),   # converted to UTC
    ("2026-12-01T00:30:00+01:00", dt.date(2026, 11, 30)),
    ("2026-12-01t10:00z", dt.date(2026, 12, 1)),
    ("2026-12-01 10:00:00Z", dt.date(2026, 12, 1)),
    ("2026-12-01", dt.date(2026, 12, 1)),
])
def test_parse_expiry_accepts_iso_8601_and_converts_to_a_utc_date(text, expected):
    assert ew.parse_expiry("t", text) == expected


@pytest.mark.parametrize("bad", [
    "tomorrow", "", "2026-13-45", "2026-02-30", "2026-12-01T00:00:00",           # no zone: not guessed
    "2026-12-01T25:00:00Z", "2026-12-01T00:00:60Z", "2026-12-01T00:00:00+25:00", "2026-12-01T00:00:00+01:75",
    "0001-01-01T00:00:00Z", "1999-12-31T00:00:00Z",                                # an implausible zero date
    "2026-12-01T00:00:00Z junk", " 2026-12-01", "20261201", "1796112000", "2026-12-01T00:00:00Z" + "0" * 60,
    "2026/12/01", "+2026-12-01", "２０２６-12-01",
    12345, 1.5, True, [], {}, object(),
])
def test_parse_expiry_refuses_anything_else_with_a_clear_error(bad):
    with pytest.raises(ew.ExpiryWatchError, match="(?i)expiry date|ISO"):
        ew.parse_expiry("t", bad)


# --- the Grafana provider -----------------------------------------------------------------------

def test_grafana_lists_tokens_keys_on_expiration_and_skips_tokens_that_never_expire(vendor):
    vendor.reply(GRAFANA_PATH, [
        _tok("ci", "2026-06-01T12:00:00Z"),
        _tok("forever", None),                                       # expiration null: no expiry
        _tok("old", "2025-12-01T00:00:00Z", expired=True),
    ])
    prov = _grafana(vendor, report_non_expiring=True)
    items = prov.items()
    assert [(i.name, i.expires, i.kind) for i in items] == [
        ("grafana-sa:3:ci", dt.date(2026, 6, 1), "grafana-sa-token"),
        ("grafana-sa:3:old", dt.date(2025, 12, 1), "grafana-sa-token")]
    assert prov.last_note and "1 token" in prov.last_note
    path, headers = vendor.requests[0]
    assert path == GRAFANA_PATH
    assert headers["Authorization"] == f"Bearer {TOKEN}" and headers["Accept"] == "application/json"
    assert _grafana(vendor).items() and _grafana(vendor).last_note is None, "the count is opt in"


def test_grafana_does_not_key_on_seconds_until_expiration(vendor):
    # 0 is ambiguous: here it sits on a token that is NOT expired and expires in the future
    vendor.reply(GRAFANA_PATH, [_tok("ci", "2027-06-01T00:00:00Z", expired=False, secondsUntilExpiration=0),
                                _tok("never", None, secondsUntilExpiration=0)])
    (item,) = _grafana(vendor).items()
    assert item.name == "grafana-sa:3:ci" and item.expires == dt.date(2027, 6, 1)
    notices, _ = ew.decide([item], START, _cfg(), {})
    assert notices == [], "a zero seconds field must not make the token look expired"


def test_grafana_has_expired_wins_over_a_date_that_looks_future(vendor):
    vendor.reply(GRAFANA_PATH, [_tok("skewed", "2026-06-01T00:00:00Z", expired=True)])
    (item,) = _grafana(vendor).items()
    assert item.expires == TODAY, "clamped to today so the engine reports it as expired"
    notices, _ = ew.decide([item], START, _cfg(), {})
    assert [n.stage for n in notices] == ["expired"]


def test_grafana_reads_several_service_accounts_and_names_them_apart(vendor):
    vendor.reply("/api/serviceaccounts/3/tokens", [_tok("ci", "2026-06-01T00:00:00Z")])
    vendor.reply("/api/serviceaccounts/9/tokens", [_tok("ci", "2026-07-01T00:00:00Z")])
    items = _grafana(vendor, ids=(3, 9)).items()
    assert [i.name for i in items] == ["grafana-sa:3:ci", "grafana-sa:9:ci"]


def test_grafana_a_base_path_is_kept(vendor):
    vendor.reply("/grafana" + GRAFANA_PATH, [])
    assert _grafana(vendor, url=vendor.base + "/grafana/").items() == []
    assert vendor.requests[0][0] == "/grafana" + GRAFANA_PATH


@pytest.mark.parametrize("payload", [
    {"tokens": []},                                   # an object, not a list
    "text", 7, None,
    [1], [[]], ["x"],                                 # elements that are not objects
    [{"expiration": "2026-06-01T00:00:00Z", "hasExpired": False}],            # no name
    [{"name": 5, "expiration": "2026-06-01T00:00:00Z", "hasExpired": False}],
    [{"name": "a", "expiration": "2026-06-01T00:00:00Z"}],                    # hasExpired missing
    [{"name": "a", "expiration": "2026-06-01T00:00:00Z", "hasExpired": "false"}],
    [{"name": "a", "expiration": "2026-06-01T00:00:00Z", "hasExpired": 0}],
    [{"name": "a", "expiration": None, "hasExpired": True}],                  # contradictory
    [_tok("dup", "2026-06-01T00:00:00Z"), _tok("dup", "2026-07-01T00:00:00Z")],  # duplicate names
    [_tok("a\nb", "2026-06-01T00:00:00Z")],                                   # control character
    [_tok("n" * 100, "2026-06-01T00:00:00Z")],                                # name too long once prefixed
    [_tok("a", "2026-06-01T00:00:00")],                                       # no zone
    [_tok("a", "not a date")],
    [_tok("a", 1796112000)],
    [_tok("a", {"when": "2026-06-01"})],
])
def test_grafana_hostile_or_wrong_shapes_are_errors_not_guesses(vendor, payload):
    vendor.reply(GRAFANA_PATH, payload)
    with pytest.raises(ew.ExpiryWatchError) as exc:
        _grafana(vendor).items()
    assert TOKEN not in str(exc.value)


def test_grafana_huge_arrays_are_refused(vendor):
    vendor.reply(GRAFANA_PATH, [_tok(f"t{n}", "2026-06-01T00:00:00Z") for n in range(ew.MAX_ITEMS + 1)])
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too many"):
        _grafana(vendor).items()
    # many service accounts together may not exceed the limit either
    half = [_tok(f"t{n}", "2026-06-01T00:00:00Z") for n in range(ew.MAX_ITEMS // 2 + 1)]
    vendor.reply("/api/serviceaccounts/3/tokens", half)
    vendor.reply("/api/serviceaccounts/9/tokens", half)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too many"):
        _grafana(vendor, ids=(3, 9)).items()


@pytest.mark.parametrize("body,match", [
    (b"not json", "(?i)not valid JSON"),
    (b"\xff\xfe", "(?i)not valid JSON"),
    (b'[{"name": "a", "name": "b"}]', "(?i)not valid JSON"),     # duplicate JSON keys
    (b"[NaN]", "(?i)not valid JSON"),
    (b"[Infinity]", "(?i)not valid JSON"),
    (b"[" * 200000 + b"]" * 200000, "(?i)not valid JSON"),       # nesting deeper than the parser allows
    (b"", "(?i)not valid JSON"),
])
def test_grafana_unparseable_bodies_are_errors(vendor, body, match):
    vendor.reply(GRAFANA_PATH, body)
    with pytest.raises(ew.ExpiryWatchError, match=match):
        _grafana(vendor).items()


def test_responses_over_the_size_cap_are_refused_with_or_without_a_length_header(vendor):
    big = b"[" + b" " * (ew.MAX_RESPONSE_BYTES + 10) + b"]"
    vendor.reply(GRAFANA_PATH, big)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
        _grafana(vendor).items()

    # a body that lies about its length by omitting it: the read itself is capped
    class Chunked(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(40):
                    self.wfile.write(b"%x\r\n" % 65536 + b" " * 65536 + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except OSError:
                pass

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Chunked)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fake = type("V", (), {"base": f"http://127.0.0.1:{srv.server_address[1]}"})
        with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
            _grafana(fake).items()
    finally:
        srv.shutdown()
        t.join(5)
        srv.server_close()


@pytest.mark.parametrize("status,match", [(401, "401"), (403, "403"), (404, "404"), (500, "500"), (503, "503")])
def test_http_errors_are_reported_and_never_carry_the_secret_or_the_body(vendor, status, match):
    vendor.reply(GRAFANA_PATH, ('{"message": "%s %s"}' % (TOKEN, BODY_SECRET)).encode(), status=status)
    with pytest.raises(ew.ExpiryWatchError, match=match) as exc:
        _grafana(vendor).items()
    assert TOKEN not in str(exc.value) and BODY_SECRET not in str(exc.value)
    if status in (401, 403):
        assert "permission" in str(exc.value)


def test_a_hanging_vendor_is_cut_off_at_the_deadline(vendor):
    vendor.hang = True
    t0 = time.monotonic()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out"):
        _grafana(vendor, timeout_seconds=1).items()
    assert time.monotonic() - t0 < 2.5


def test_a_closed_port_is_reported():
    s = __import__("socket").socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    fake = type("V", (), {"base": f"http://127.0.0.1:{port}"})
    with pytest.raises(ew.ExpiryWatchError, match="(?i)unreachable|timed out"):
        _grafana(fake).items()


def test_redirects_are_not_followed_and_the_token_is_never_replayed(vendor, other):
    other.reply(GRAFANA_PATH, [])
    vendor.reply(GRAFANA_PATH, b"", status=307, headers={"Location": other.base + GRAFANA_PATH})
    with pytest.raises(ew.ExpiryWatchError, match="(?i)redirect") as exc:
        _grafana(vendor).items()
    assert TOKEN not in str(exc.value)
    assert other.requests == [], "the bearer must not be sent to the redirect target"
    for code in (301, 302, 303, 308):
        vendor.reply(GRAFANA_PATH, b"", status=code, headers={"Location": other.base + "/x"})
        with pytest.raises(ew.ExpiryWatchError, match="(?i)redirect"):
            _grafana(vendor).items()
    assert other.requests == []


@pytest.mark.parametrize("cfg,match", [
    ({"url": "http://grafana.example.com"}, "(?i)https"),
    ({"url": "https://user:pw@grafana.example.com"}, "(?i)credentials"),
    ({"url": "https://grafana.example.com/?a=1"}, "(?i)query"),
    ({"url": "https://grafana.example.com/#x"}, "(?i)query|fragment"),
    ({"url": "https://grafana.example.com/\n"}, "(?i)link"),
    ({"url": 5}, "(?i)link"),
    ({"service_account_ids": []}, "(?i)service_account_ids"),
    ({"service_account_ids": [0]}, "(?i)service_account_ids"),
    ({"service_account_ids": [True]}, "(?i)service_account_ids"),
    ({"service_account_ids": ["3"]}, "(?i)service_account_ids"),
    ({"service_account_ids": [3, 3]}, "(?i)service_account_ids"),
    ({"service_account_ids": list(range(1, 52))}, "(?i)service_account_ids"),
    ({"service_account_ids": [2**31]}, "(?i)service_account_ids"),
    ({"service_account_ids": 3}, "(?i)service_account_ids"),
    ({"token_env": "has space"}, "(?i)token_env"),
    ({"token_env": "NOT_SET_ANYWHERE"}, "(?i)NOT_SET_ANYWHERE"),
    ({"token_env": None}, "(?i)token_env"),
    ({"_env": {"GRAFANA_RO_TOKEN": "bad token"}}, "(?i)GRAFANA_RO_TOKEN"),
    ({"_env": {"GRAFANA_RO_TOKEN": ""}}, "(?i)GRAFANA_RO_TOKEN"),
    ({"timeout_seconds": 0}, "(?i)timeout"),
    ({"timeout_seconds": 61}, "(?i)timeout"),
    ({"timeout_seconds": True}, "(?i)timeout"),
    ({"report_non_expiring": "yes"}, "(?i)report_non_expiring"),
    ({"owner": ""}, "(?i)owner"),
    ({"runbook": "javascript:alert(1)"}, "(?i)runbook"),
    ({"surprise": 1}, "(?i)unknown"),
    ({"token": "a-literal-secret"}, "(?i)unknown"),
])
def test_grafana_config_is_validated_and_never_echoes_a_secret(vendor, cfg, match):
    with pytest.raises(ew.ExpiryWatchError, match=match) as exc:
        _grafana(vendor, **cfg)
    for secret in (TOKEN, "bad token", "a-literal-secret"):
        assert secret not in str(exc.value)


def test_grafana_loopback_http_is_the_only_plain_http(vendor):
    _grafana(vendor)  # 127.0.0.1 over http is accepted (the fake server needs it)
    with pytest.raises(ew.ExpiryWatchError):
        _grafana(vendor, url="http://10.0.0.5:3000")


# --- the secret manager provider ----------------------------------------------------------------------

def _dp_tok(name, expires_at=None, slug="tok-slug", **extra):
    d = {"name": name, "slug": slug, "created_at": "2025-01-01T00:00:00.000Z", "config": "prd",
         "environment": "prd", "project": "example-app", "expires_at": expires_at, "key": BODY_SECRET}
    d.update(extra)
    return d


def test_doppler_lists_tokens_for_one_project_and_config_and_skips_non_expiring(vendor):
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-06-01T00:00:00.000Z", slug="a"),
                                           _dp_tok("forever", None, slug="b"),
                                           _dp_tok("", "2026-07-01T00:00:00.000Z", slug="by-slug")],
                                "success": True})
    prov = _doppler(vendor, report_non_expiring=True)
    items = prov.items()
    assert [(i.name, i.expires, i.kind) for i in items] == [
        ("doppler:example-app/prd:ci", dt.date(2026, 6, 1), "service-token"),
        ("doppler:example-app/prd:by-slug", dt.date(2026, 7, 1), "service-token")]
    assert "1 token" in prov.last_note
    path, headers = vendor.requests[0]
    parsed = urllib.parse.urlsplit(path)
    assert parsed.path == DOPPLER_PATH and dict(urllib.parse.parse_qsl(parsed.query)) == {
        "project": "example-app", "config": "prd"}
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert BODY_SECRET not in repr(items), "only name, slug and expires_at are read from a token"


@pytest.mark.parametrize("payload", [
    [], "x", 7, None, {"tokens": "x"}, {"tokens": {}}, {"success": True}, {"tokens": [1]}, {"tokens": [[]]},
    {"tokens": [{"slug": 5, "expires_at": "2026-06-01T00:00:00Z"}]},
    {"tokens": [{"name": "", "expires_at": "2026-06-01T00:00:00Z"}]},            # neither name nor slug
    {"tokens": [_dp_tok("a", "2026-06-01T00:00:00Z", slug="1"), _dp_tok("a", "2026-07-01T00:00:00Z", slug="2")]},
    {"tokens": [_dp_tok("a", "2026-06-01T00:00:00")]},                           # no zone
    {"tokens": [_dp_tok("a", "soon")]},
    {"tokens": [_dp_tok("a", 1796112000)]},
    {"tokens": [_dp_tok("a\x00b", "2026-06-01T00:00:00Z")]},
    {"tokens": [_dp_tok("x" * 100, "2026-06-01T00:00:00Z")]},
])
def test_doppler_hostile_or_wrong_shapes_are_errors_not_guesses(vendor, payload):
    vendor.reply(DOPPLER_PATH, payload)
    with pytest.raises(ew.ExpiryWatchError) as exc:
        _doppler(vendor).items()
    assert TOKEN not in str(exc.value) and BODY_SECRET not in str(exc.value)


def test_doppler_huge_arrays_are_refused(vendor):
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok(f"t{n}", "2026-06-01T00:00:00Z", slug=str(n))
                                           for n in range(ew.MAX_ITEMS + 1)]})
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too many"):
        _doppler(vendor).items()


def test_doppler_http_errors_redirects_timeouts_and_size_follow_the_same_rules(vendor, other):
    vendor.reply(DOPPLER_PATH, ('{"messages": ["%s"]}' % BODY_SECRET).encode(), status=403)
    with pytest.raises(ew.ExpiryWatchError, match="403") as exc:
        _doppler(vendor).items()
    assert BODY_SECRET not in str(exc.value) and TOKEN not in str(exc.value)
    vendor.reply(DOPPLER_PATH, b"", status=302, headers={"Location": other.base + DOPPLER_PATH})
    with pytest.raises(ew.ExpiryWatchError, match="(?i)redirect"):
        _doppler(vendor).items()
    assert other.requests == []
    vendor.reply(DOPPLER_PATH, b"{" + b" " * (ew.MAX_RESPONSE_BYTES + 10) + b"}")
    with pytest.raises(ew.ExpiryWatchError, match="(?i)too large"):
        _doppler(vendor).items()
    vendor.hang = True
    t0 = time.monotonic()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out"):
        _doppler(vendor, timeout_seconds=1).items()
    assert time.monotonic() - t0 < 2.5


@pytest.mark.parametrize("cfg,match", [
    ({"project": "a/b"}, "(?i)project"),
    ({"project": "a&config=other"}, "(?i)project"),            # query injection
    ({"project": "a b"}, "(?i)project"),
    ({"project": ""}, "(?i)project"),
    ({"project": None}, "(?i)project"),
    ({"config": "prd\n"}, "(?i)config"),
    ({"config": "x" * 101}, "(?i)config"),
    ({"config": 5}, "(?i)config"),
    ({"api_url": "http://api.doppler.com"}, "(?i)https"),
    ({"api_url": "https://api.doppler.com/?x=1"}, "(?i)query"),
    ({"token_env": "NOT_SET_ANYWHERE"}, "(?i)NOT_SET_ANYWHERE"),
    ({"surprise": 1}, "(?i)unknown"),
])
def test_doppler_config_is_validated(vendor, cfg, match):
    with pytest.raises(ew.ExpiryWatchError, match=match) as exc:
        _doppler(vendor, **cfg)
    assert TOKEN not in str(exc.value)


def test_doppler_defaults_to_the_vendor_url_over_https():
    prov = ew.DopplerProvider({"project": "p", "config": "c", "token_env": "T", "owner": "o", "runbook": RUNBOOK,
                               "_env": {"T": TOKEN}})
    assert prov.api_url == "https://api.doppler.com"


# --- the whole run: config file, notices, the vanished-token notice, no secret anywhere ----------------

def _setup(tmp_path, router_url, vendor_url, vendor_type="doppler_tokens"):
    cfg = _write_setup(tmp_path, router_url)
    if vendor_type == "doppler_tokens":
        block = (f'\n[[providers]]\ntype = "doppler_tokens"\napi_url = "{vendor_url}"\nproject = "example-app"\n'
                 'config = "prd"\ntoken_env = "DOPPLER_RO_TOKEN"\nowner = "ops@example.com"\n'
                 f'runbook = "{RUNBOOK}"\ntimeout_seconds = 3\n')
    else:
        block = (f'\n[[providers]]\ntype = "grafana_sa_tokens"\nurl = "{vendor_url}"\nservice_account_ids = [3]\n'
                 'token_env = "GRAFANA_RO_TOKEN"\nowner = "ops@example.com"\n'
                 f'runbook = "{RUNBOOK}"\ntimeout_seconds = 3\n')
    cfg.write_text(cfg.read_text() + block)
    return cfg


ENV = {"EXPIRY_WATCH_TOKEN": "secret-token-value", "DOPPLER_RO_TOKEN": TOKEN, "GRAFANA_RO_TOKEN": TOKEN}


@pytest.fixture
def router():
    from test_expiry_watch import _Recorder
    _Recorder.seen, _Recorder.status, _Recorder.redirect_to = [], 200, None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", _Recorder
    srv.shutdown()
    t.join(5)
    srv.server_close()


def _posted(rec):
    return [(json.loads(b)["alerts"][0]["labels"]["item"], json.loads(b)["alerts"][0]["labels"]["stage"])
            for _, _, b in rec.seen]


def test_a_vanished_secret_manager_token_is_reported_once_and_resets(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base)
    name = "doppler:example-app/prd:ci"
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
    code, out, err = _run(cfg, _at(30), env=ENV)  # the registry item (deploy-key) is at 30 days: one notice
    assert code == 0 and (name, "disappeared") not in _posted(rec)
    posted_before = len(rec.seen)
    vendor.reply(DOPPLER_PATH, {"tokens": []})  # the vendor deleted it between runs
    code, out, err = _run(cfg, _at(29), env=ENV)
    assert code == 0 and _posted(rec)[posted_before:] == [(name, "disappeared")]
    sent = json.loads(rec.seen[-1][2])["alerts"][0]
    assert "2026-03-10" in sent["annotations"]["description"] and sent["labels"]["stage"] == "disappeared"
    assert _run(cfg, _at(28), env=ENV)[0] == 0 and len(rec.seen) == posted_before + 1, "reported once"
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
    assert _run(cfg, _at(27), env=ENV)[0] == 0 and len(rec.seen) == posted_before + 1
    vendor.reply(DOPPLER_PATH, {"tokens": []})
    assert _run(cfg, _at(26), env=ENV)[0] == 0 and _posted(rec)[-1] == (name, "disappeared"), "and it can fire again"


def test_acknowledging_a_removed_vendor_token_keeps_it_silent(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base)
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
    assert _run(cfg, _at(100), env=ENV)[0] == 0
    cfg.write_text(cfg.read_text() + 'acknowledge_removed = ["doppler:example-app/prd:ci"]\n')
    vendor.reply(DOPPLER_PATH, {"tokens": []})
    assert _run(cfg, _at(99), env=ENV)[0] == 0 and not rec.seen


def test_a_vendor_outage_is_not_a_vanished_token(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base)
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
    assert _run(cfg, _at(100), env=ENV)[0] == 0
    vendor.reply(DOPPLER_PATH, b"", status=503)
    code, _, err = _run(cfg, _at(99), env=ENV)
    assert code == 1 and "503" in err and not rec.seen
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-10T00:00:00.000Z")]})
    assert _run(cfg, _at(98), env=ENV)[0] == 0 and not rec.seen


def test_the_secrets_are_never_printed_saved_or_sent_to_the_wrong_place(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base)
    vendor.reply(DOPPLER_PATH, {"tokens": [_dp_tok("ci", "2026-03-05T00:00:00.000Z")]})  # 4 days: due now
    code, out, err = _run(cfg, _at(4), env=ENV)
    assert code == 0
    blob = out + err + (tmp_path / "state.json").read_text()
    for secret in (TOKEN, BODY_SECRET, "secret-token-value"):
        assert secret not in blob
    # the vendor token went to the vendor only; the router secret to the router only
    assert all(h["Authorization"] == f"Bearer {TOKEN}" for _, h in vendor.requests)
    assert all(h["Authorization"] == "Bearer secret-token-value" for _, h, _ in rec.seen)
    assert all(TOKEN not in json.dumps(b.decode()) and BODY_SECRET not in b.decode() for _, _, b in rec.seen)


def test_a_missing_vendor_token_variable_is_a_config_error_naming_only_the_variable(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base)
    code, _, err = _run(cfg, _at(30), env={"EXPIRY_WATCH_TOKEN": "secret-token-value"})
    assert code == 2 and "DOPPLER_RO_TOKEN" in err and not rec.seen and not vendor.requests


def test_a_grafana_token_that_expired_is_reported_through_the_run(tmp_path, router, vendor):
    base, rec = router
    cfg = _setup(tmp_path, base, vendor.base, vendor_type="grafana_sa_tokens")
    vendor.reply(GRAFANA_PATH, [_tok("ci", "2026-02-27T00:00:00Z", expired=True), _tok("never", None)])
    code, out, err = _run(cfg, _at(1), env={**ENV}, )
    assert code == 0 and ("grafana-sa:3:ci", "expired") in _posted(rec)
    assert all("never" not in i for i, _ in _posted(rec))


def test_a_provider_without_a_key_still_gets_the_vanished_notice(tmp_path, router):
    """Any provider, not only the built in ones: a plug-in with no state_key is keyed by position."""
    base, rec = router
    cfg = _write_setup(tmp_path, base)
    cfg.write_text(cfg.read_text().replace('type = "registry"\npath = "registry.toml"', 'type = "plugin-test"'))
    live = {"names": ["a", "b"]}

    class Plugin:
        def __init__(self, config):
            pass

        def items(self):
            return [ew.Item.build(name=n, kind="k", expires="2026-09-01", owner="o@example.com", runbook=RUNBOOK)
                    for n in live["names"]]

    ew.register_provider("plugin-test", Plugin)
    try:
        assert _run(cfg, _at(100))[0] == 0 and not rec.seen
        live["names"] = ["a"]
        assert _run(cfg, _at(99))[0] == 0 and _posted(rec) == [("b", "disappeared")]
        assert _run(cfg, _at(98))[0] == 0 and len(rec.seen) == 1
    finally:
        del ew.PROVIDER_TYPES["plugin-test"]


def test_the_shipped_example_config_parses_with_the_new_providers():
    from conftest import REPO_ROOT
    cfg = ew.load_config(REPO_ROOT / "docs" / "expiry-watch.example.toml")
    kinds = {p["type"] for p in cfg.providers}
    assert {"registry", "tls", "grafana_sa_tokens", "doppler_tokens"} <= kinds
    env = {"EXPIRY_WATCH_GRAFANA_TOKEN": TOKEN, "EXPIRY_WATCH_DOPPLER_TOKEN": TOKEN}
    for table in cfg.providers:
        table = dict(table)
        if table["type"] in ("grafana_sa_tokens", "doppler_tokens"):
            table["_env"] = env
            table.pop("acknowledge_removed", None)
            table.pop("notify_disappeared", None)
            ew.PROVIDER_TYPES[table["type"]](table)  # builds: every field in the example is accepted


def test_a_slow_drip_response_cannot_outlast_the_overall_deadline():
    """Each byte arrives inside the socket timeout, so only the overall deadline can stop this."""
    done = threading.Event()

    class Drip(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "60")
            self.end_headers()
            try:
                for _ in range(60):
                    if done.wait(0.3):
                        return
                    self.wfile.write(b" ")
                    self.wfile.flush()
            except OSError:
                pass

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fake = type("V", (), {"base": f"http://127.0.0.1:{srv.server_address[1]}"})
        t0 = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out"):
            _grafana(fake, timeout_seconds=1).items()
        assert time.monotonic() - t0 < 2.5
    finally:
        done.set()
        srv.shutdown()
        t.join(5)
        srv.server_close()
