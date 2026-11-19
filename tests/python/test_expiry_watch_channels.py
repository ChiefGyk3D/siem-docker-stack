"""Guards for the expiry watch Matrix and email channels (issue #98, slice 3).

Everything runs against fakes on loopback: a Matrix homeserver that records requests and an SMTP
server (plain, STARTTLS and implicit TLS) that records sessions. No real homeserver or mail server
is ever contacted.
"""
import datetime as dt
import http.server
import json
import socketserver
import ssl
import threading

import pytest

from test_expiry_watch import RUNBOOK, UTC, _at, _make_cert, _Recorder, _write_setup, ew, router  # noqa: F401  one module object

MATRIX_TOKEN = "matrix-secret-token-value"
SMTP_PASSWORD = "smtp-secret-password-value"
ROOM = "!abcDEF123:example.com"


# --- fake Matrix homeserver -----------------------------------------------------------------

class _Matrix(http.server.BaseHTTPRequestHandler):
    seen = []
    status = 200
    redirect_to = None

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        if type(self).redirect_to:
            self.send_response(307)
            self.send_header("Location", type(self).redirect_to)
            self.end_headers()
            return
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b'{"event_id":"$abc"}')

    def log_message(self, *a):
        pass


@pytest.fixture
def matrix():
    _Matrix.seen, _Matrix.status, _Matrix.redirect_to = [], 200, None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Matrix)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    t.join(5)
    srv.server_close()


# --- fake SMTP server -----------------------------------------------------------------------

class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        sess = {"tls": False, "auth": None, "from": None, "rcpt": [], "data": None, "commands": []}
        srv.sessions.append(sess)
        conn = self.request
        if srv.implicit_ctx:
            conn = srv.implicit_ctx.wrap_socket(self.request, server_side=True)
            self.rfile, self.wfile = conn.makefile("rb"), conn.makefile("wb")
            sess["tls"] = True

        def send(line):
            self.wfile.write(line.encode() + b"\r\n")
            self.wfile.flush()

        send("220 fake ESMTP")
        try:
            while True:
                raw = self.rfile.readline(4096)
                if not raw:
                    return
                line = raw.decode("latin-1").rstrip("\r\n")
                verb = line.split(" ", 1)[0].upper()
                sess["commands"].append(verb)
                if verb in ("EHLO", "HELO"):
                    sess["helo"] = line.split(" ", 1)[1] if " " in line else ""
                    send("250-fake")
                    if srv.starttls_ctx and not sess["tls"]:
                        send("250-STARTTLS")
                    send("250 AUTH PLAIN LOGIN" if srv.offer_auth else "250 OK")
                elif verb == "STARTTLS":
                    send("220 go")
                    conn = srv.starttls_ctx.wrap_socket(conn, server_side=True)
                    self.rfile, self.wfile = conn.makefile("rb"), conn.makefile("wb")
                    sess["tls"] = True
                elif verb == "AUTH":
                    sess["auth"] = line
                    send("235 ok")
                elif verb == "MAIL":
                    sess["from"] = line
                    send("250 ok")
                elif verb == "RCPT":
                    sess["rcpt"].append(line)
                    send("250 ok")
                elif verb == "DATA":
                    send("354 go")
                    lines = []
                    while True:
                        row = self.rfile.readline(65536).decode("utf-8", "replace")
                        if row in (".\r\n", ""):
                            break
                        lines.append(row)
                    sess["data"] = "".join(lines)
                    send(srv.data_reply)
                elif verb == "QUIT":
                    send("221 bye")
                    return
                else:
                    send("250 ok")
        except (ssl.SSLError, OSError):
            return


class _SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start_smtp(starttls_ctx=None, implicit_ctx=None, offer_auth=True, data_reply="250 queued"):
    srv = _SmtpServer(("127.0.0.1", 0), _SmtpHandler)
    srv.sessions, srv.starttls_ctx, srv.implicit_ctx = [], starttls_ctx, implicit_ctx
    srv.offer_auth, srv.data_reply = offer_auth, data_reply
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


def _stop(srv, t):
    srv.shutdown()
    t.join(5)
    srv.server_close()


def _server_ctx(tmp_path):
    key, crt, _ = _make_cert(tmp_path, 30)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    return ctx, crt


@pytest.fixture
def smtp_plain():
    srv, t = _start_smtp()
    yield srv
    _stop(srv, t)


# --- helpers --------------------------------------------------------------------------------

def _item(name="deploy-key", **over):
    return ew.Item(**{"name": name, "kind": "ssh-key", "expires": dt.date(2026, 3, 1), "owner": "ops@example.com",
                      "runbook": RUNBOOK, **over})


def _notice(item=None, stage="14", days=14, channels=("matrix",)):
    return ew.Notice(item or _item(), stage, days, tuple(channels))


def _base(**extra):
    raw = {"router": {"url": "https://n8n.example.com/h", "token_env": "T"}}
    raw.update(extra)
    return raw


def _matrix_table(base="http://127.0.0.1:8008", **over):
    return {"homeserver": base, "room_id": ROOM, "token_env": "EXPIRY_WATCH_MATRIX_TOKEN", **over}


def _email_table(port=2525, **over):
    return {"host": "127.0.0.1", "port": port, "security": "starttls", "from": "expiry-watch@example.com",
            "to": ["ops@example.com"], **over}


# --- config ---------------------------------------------------------------------------------

def test_matrix_and_email_tables_are_optional_and_parse():
    cfg = ew.parse_config(_base())
    assert cfg.matrix is None and cfg.email is None
    cfg = ew.parse_config(_base(matrix=_matrix_table(), email=_email_table(),
                                routes={"14": ["matrix", "email"]}))
    assert cfg.matrix.room_id == ROOM and cfg.matrix.token_env == "EXPIRY_WATCH_MATRIX_TOKEN"
    assert cfg.email.security == "starttls" and cfg.email.to == ("ops@example.com",)


def test_a_route_to_a_channel_without_its_table_is_a_config_error():
    with pytest.raises(ew.ExpiryWatchError, match=r"(?i)matrix.*\[matrix\]"):
        ew.parse_config(_base(routes={"14": ["matrix"]}))
    with pytest.raises(ew.ExpiryWatchError, match=r"(?i)email.*\[email\]"):
        ew.parse_config(_base(routes={"expired": ["discord", "email"]}))


@pytest.mark.parametrize("over", [
    {"homeserver": "http://matrix.example.com"},               # plain http off loopback
    {"homeserver": "https://user:pw@matrix.example.com"},      # credentials in the link
    {"homeserver": "https://matrix.example.com/?x=1"},         # query
    {"room_id": "#alias:example.com"},                         # an alias, not an id
    {"room_id": "!room\r\n:example.com"},                      # control characters
    {"room_id": "!room/../x:example.com"},                     # path characters
    {"room_id": "!" + "a" * 300 + ":example.com"},              # too long
    {"token_env": "not a name"},                               # the secret itself pasted in
    {"timeout_seconds": 0},
    {"timeout_seconds": 600},
    {"surprise": 1},                                           # unknown key
])
def test_matrix_config_hostile_values_are_refused(over):
    with pytest.raises(ew.ExpiryWatchError):
        ew.parse_config(_base(matrix=_matrix_table(**over)))


@pytest.mark.parametrize("over", [
    {"from": "a@example.com\r\nBcc: x@example.com"},
    {"from": "Name <a@example.com>"},
    {"to": ["ok@example.com", "bad address@example.com"]},
    {"to": []},
    {"to": ["a@example.com"] * 5},
    {"to": "ops@example.com"},
    {"to": ["ops@example.com\nBcc: x@example.com"]},
    {"security": "maybe"},
    {"port": 0},
    {"port": 70000},
    {"host": "bad host"},
    {"host": "mail.example.com\r\nX: 1"},
    {"timeout_seconds": 0},
    {"helo_name": "a b"},
    {"username_env": "EW_USER"},                               # a username without a password
    {"password_env": "not a name"},
    {"security": "plaintext"},                                 # needs allow_plaintext
    {"security": "plaintext", "allow_plaintext": True, "username_env": "U", "password_env": "P"},  # creds in clear
    {"allow_plaintext": True},                                 # only meaningful with plaintext
    {"surprise": 1},
])
def test_email_config_hostile_values_are_refused(over):
    with pytest.raises(ew.ExpiryWatchError):
        ew.parse_config(_base(email=_email_table(**over)))


def test_email_plaintext_needs_the_explicit_opt_in_and_no_credentials():
    cfg = ew.parse_config(_base(email=_email_table(security="plaintext", allow_plaintext=True)))
    assert cfg.email.security == "plaintext"


# --- message text ---------------------------------------------------------------------------

def test_message_text_is_plain_and_clean_even_for_hostile_item_text():
    evil = _item(name="key\r\nBcc: attacker@example.com\x00\x1b[31m", owner="o\r\nX-Evil: 1", kind="k\nk")
    subject, body = ew.build_message(_notice(evil), dt.datetime(2026, 2, 15, tzinfo=UTC))
    assert "\r" not in subject and "\n" not in subject and len(subject) <= 200
    assert not any(ord(c) < 32 and c != "\n" for c in body) and "\x7f" not in body
    assert "\r" not in body
    assert "Expiry watch" in subject and "14 days left" in body and RUNBOOK in body


def test_message_for_a_disappeared_notice_says_so():
    n = _notice(stage="disappeared", days=-3)
    subject, body = ew.build_message(n, dt.datetime(2026, 3, 4, tzinfo=UTC))
    assert "no longer listed" in body and "expired 3 days ago" in body


# --- Matrix delivery ------------------------------------------------------------------------

def _mcfg(base, **over):
    return ew.parse_config(_base(matrix=_matrix_table(base, **over))).matrix


def test_matrix_send_puts_one_notice_with_a_bearer_and_a_stable_transaction_id(matrix):
    cfg = _mcfg(matrix)
    n, now = _notice(), _at(14)
    ew.matrix_send(cfg, MATRIX_TOKEN, n, now)
    ew.matrix_send(cfg, MATRIX_TOKEN, n, now)
    ew.matrix_send(cfg, MATRIX_TOKEN, _notice(stage="7", days=7), now)
    (m1, p1, h1, b1), (_, p2, _, _), (_, p3, _, _) = _Matrix.seen
    assert m1 == "PUT" and h1["Authorization"] == f"Bearer {MATRIX_TOKEN}"
    assert p1.startswith("/_matrix/client/v3/rooms/%21abcDEF123%3Aexample.com/send/m.room.message/")
    assert p1 == p2, "a retry of the same notice reuses the transaction id (the server drops the duplicate)"
    assert p1 != p3
    sent = json.loads(b1)
    assert sent["msgtype"] == "m.notice" and "deploy-key" in sent["body"] and set(sent) == {"msgtype", "body"}


def test_matrix_send_never_follows_a_redirect_and_never_echoes_the_token(matrix):
    cfg = _mcfg(matrix)
    _Matrix.redirect_to = matrix + "/elsewhere"
    with pytest.raises(ew.ExpiryWatchError, match="(?i)redirect|307") as exc:
        ew.matrix_send(cfg, MATRIX_TOKEN, _notice(), _at(14))
    assert len(_Matrix.seen) == 1 and MATRIX_TOKEN not in str(exc.value)
    _Matrix.redirect_to, _Matrix.status = None, 403
    with pytest.raises(ew.ExpiryWatchError, match="403") as exc:
        ew.matrix_send(cfg, MATRIX_TOKEN, _notice(), _at(14))
    assert MATRIX_TOKEN not in str(exc.value)


def test_matrix_send_refuses_a_token_that_could_inject_headers():
    cfg = _mcfg("http://127.0.0.1:1")
    for bad in ("a\r\nX-Evil: 1", "has space", "", "x" * 600):
        with pytest.raises(ew.ExpiryWatchError):
            ew.matrix_send(cfg, bad, _notice(), _at(14))


def test_matrix_unreachable_server_is_a_delivery_error_without_the_token():
    cfg = _mcfg("http://127.0.0.1:1", timeout_seconds=2)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)unreachable") as exc:
        ew.matrix_send(cfg, MATRIX_TOKEN, _notice(), _at(14))
    assert MATRIX_TOKEN not in str(exc.value)


def test_matrix_homeserver_path_prefix_is_kept(matrix):
    cfg = _mcfg(matrix + "/prefix/")
    ew.matrix_send(cfg, MATRIX_TOKEN, _notice(), _at(14))
    assert _Matrix.seen[0][1].startswith("/prefix/_matrix/client/v3/rooms/")


# --- email delivery -------------------------------------------------------------------------

def _ecfg(port, **over):
    return ew.parse_config(_base(email=_email_table(port, **over))).email


def test_email_plaintext_delivery_when_explicitly_allowed(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14), root=None)
    (s,) = smtp_plain.sessions
    assert s["tls"] is False and "AUTH" not in s["commands"]
    assert "<expiry-watch@example.com>" in s["from"] and "<ops@example.com>" in s["rcpt"][0]
    head, _, body = s["data"].partition("\r\n\r\n")
    assert "Subject: " in head and "From: expiry-watch@example.com" in head and "To: ops@example.com" in head
    assert "Date: " in head and "Message-ID: <" in head
    assert "deploy-key" in s["data"] and RUNBOOK in s["data"]
    assert s["helo"] == "localhost", "the machine's own host name must not be sent by default"


def test_email_header_injection_is_impossible(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    evil = _item(name="x\r\nBcc: attacker@example.com\r\n\r\nINJECTED BODY", owner="o\r\nX-Evil: 1")
    ew.email_send(cfg, {}, _notice(evil, channels=("email",)), _at(14), root=None)
    (s,) = smtp_plain.sessions
    head = s["data"].partition("\r\n\r\n")[0]
    assert "\nBcc:" not in head and "\nX-Evil:" not in head and len(s["rcpt"]) == 1


def test_email_starttls_with_a_trusted_certificate_authenticates_only_after_tls(tmp_path):
    ctx, crt = _server_ctx(tmp_path)
    srv, t = _start_smtp(starttls_ctx=ctx)
    try:
        (tmp_path / "ca.pem").write_bytes(crt.read_bytes())
        root = ew.Root(str(tmp_path))
        cfg = _ecfg(srv.server_address[1], ca_file="ca.pem", username_env="EW_USER", password_env="EW_PASS")
        env = {"EW_USER": "watcher", "EW_PASS": SMTP_PASSWORD}
        try:
            ew.email_send(cfg, env, _notice(channels=("email",)), _at(14), root=root)
        finally:
            root.close()
        (s,) = srv.sessions
        assert s["tls"] is True and s["commands"].index("STARTTLS") < s["commands"].index("AUTH")
        assert s["data"] is not None
    finally:
        _stop(srv, t)


def test_email_refuses_to_continue_when_starttls_is_not_offered(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], username_env="EW_USER", password_env="EW_PASS")
    with pytest.raises(ew.ExpiryWatchError) as exc:
        ew.email_send(cfg, {"EW_USER": "u", "EW_PASS": SMTP_PASSWORD}, _notice(channels=("email",)), _at(14),
                      root=None)
    (s,) = smtp_plain.sessions
    assert s["data"] is None and "AUTH" not in s["commands"] and "MAIL" not in s["commands"]
    assert SMTP_PASSWORD not in str(exc.value)


def test_email_refuses_an_untrusted_certificate(tmp_path):
    ctx, _ = _server_ctx(tmp_path)  # self-signed and not in any trust store
    srv, t = _start_smtp(starttls_ctx=ctx)
    try:
        cfg = _ecfg(srv.server_address[1], username_env="EW_USER", password_env="EW_PASS")
        with pytest.raises(ew.ExpiryWatchError, match="(?i)certificate|tls|ssl") as exc:
            ew.email_send(cfg, {"EW_USER": "u", "EW_PASS": SMTP_PASSWORD}, _notice(channels=("email",)),
                          _at(14), root=None)
        assert srv.sessions and all(s["data"] is None and "AUTH" not in s["commands"] for s in srv.sessions)
        assert SMTP_PASSWORD not in str(exc.value)
    finally:
        _stop(srv, t)


def test_email_implicit_tls(tmp_path):
    ctx, crt = _server_ctx(tmp_path)
    srv, t = _start_smtp(implicit_ctx=ctx)
    try:
        (tmp_path / "ca.pem").write_bytes(crt.read_bytes())
        root = ew.Root(str(tmp_path))
        cfg = _ecfg(srv.server_address[1], security="tls", ca_file="ca.pem")
        try:
            ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14), root=root)
        finally:
            root.close()
        assert srv.sessions[0]["tls"] is True and srv.sessions[0]["data"] is not None
    finally:
        _stop(srv, t)


def test_email_server_rejection_and_unreachable_are_delivery_errors(smtp_plain):
    smtp_plain.data_reply = "554 no"
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    with pytest.raises(ew.ExpiryWatchError, match="554"):
        ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14), root=None)
    dead = _ecfg(1, security="plaintext", allow_plaintext=True, timeout_seconds=2)
    with pytest.raises(ew.ExpiryWatchError, match="(?i)unreachable|failed"):
        ew.email_send(dead, {}, _notice(channels=("email",)), _at(14), root=None)


def test_email_credentials_missing_from_the_environment_is_a_config_error(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], username_env="EW_USER", password_env="EW_PASS")
    with pytest.raises(ew.ExpiryWatchError, match="EW_PASS"):
        ew.email_secrets(cfg, {"EW_USER": "u"})
    with pytest.raises(ew.ExpiryWatchError):
        ew.email_secrets(cfg, {"EW_USER": "u\r\nx", "EW_PASS": "p"})


# --- the runner -----------------------------------------------------------------------------

def _setup(tmp_path, base_router, matrix_url=None, smtp_port=None, routes='"14" = ["matrix"]'):
    cfg = _write_setup(tmp_path, base_router, routes=routes)
    extra = ""
    if matrix_url:
        extra += f'\n[matrix]\nhomeserver = "{matrix_url}"\nroom_id = "{ROOM}"\n' \
                 'token_env = "EXPIRY_WATCH_MATRIX_TOKEN"\ntimeout_seconds = 3\n'
    if smtp_port:
        extra += f'\n[email]\nhost = "127.0.0.1"\nport = {smtp_port}\nsecurity = "plaintext"\n' \
                 'allow_plaintext = true\nfrom = "expiry-watch@example.com"\nto = ["ops@example.com"]\n' \
                 'timeout_seconds = 3\n'
    # tables must come before [[providers]]: TOML scoping, so insert before it
    text = cfg.read_text()
    head, sep, tail = text.partition("[[providers]]")
    cfg.write_text(head + extra + "\n" + sep + tail)
    return cfg


def _run(cfg, now, env=None, **kw):
    out, err = [], []
    env = {"EXPIRY_WATCH_TOKEN": "secret-token-value", "EXPIRY_WATCH_MATRIX_TOKEN": MATRIX_TOKEN,
           **(env or {})}
    code = ew.run(cfg, now=now, env=env, out=out.append, err=err.append, **kw)
    return code, "\n".join(out), "\n".join(err)


def test_a_matrix_only_route_posts_nothing_to_the_router(tmp_path, matrix):
    _Recorder.seen[:] = []
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    code, out, err = _run(cfg, _at(14), env={"EXPIRY_WATCH_TOKEN": ""})  # no router secret is needed either
    assert code == 0, err
    assert len(_Matrix.seen) == 1 and not _Recorder.seen
    assert MATRIX_TOKEN not in out + err and "not built" not in err
    code, _, _ = _run(cfg, _at(14, hour=20))
    assert code == 0 and len(_Matrix.seen) == 1, "once per threshold"


def test_a_failed_matrix_delivery_keeps_the_notice_due(tmp_path, matrix):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    _Matrix.status = 500
    code, out, err = _run(cfg, _at(14))
    assert code == 1 and "matrix" in err.lower() and "500" in err and MATRIX_TOKEN not in out + err
    _Matrix.status = 200
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert code == 0 and len(_Matrix.seen) == 2
    code, _, _ = _run(cfg, _at(14, hour=19))
    assert len(_Matrix.seen) == 2


def test_router_and_matrix_together_one_failure_retries_the_notice(tmp_path, router, matrix):
    srv, base = router
    cfg = _setup(tmp_path, base, matrix_url=matrix, routes='"14" = ["discord", "matrix"]')
    _Matrix.status = 500
    code, _, _ = _run(cfg, _at(14))
    assert code == 1 and len(_Recorder.seen) == 1
    _Matrix.status = 200
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert code == 0 and len(_Matrix.seen) == 2, "the notice stays due until every channel took it"


def test_the_matrix_secret_is_required_only_when_a_matrix_notice_is_due(tmp_path, matrix):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    code, _, err = _run(cfg, _at(30))  # nothing is due at 30 days with this route? 30 is a threshold: stage 30
    # stage "30" routes to the default (discord): the router, not matrix, is needed, so only that secret matters
    assert "EXPIRY_WATCH_MATRIX_TOKEN" not in err
    code, _, err = _run(cfg, _at(14), env={"EXPIRY_WATCH_MATRIX_TOKEN": ""})
    assert code == 2 and "EXPIRY_WATCH_MATRIX_TOKEN" in err and not _Matrix.seen
    code, _, err = _run(cfg, _at(14), env={"EXPIRY_WATCH_MATRIX_TOKEN": "bad token"})
    assert code == 2 and "bad token" not in err


def test_dry_run_sends_nothing_over_matrix_or_email(tmp_path, matrix, smtp_plain):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix, smtp_port=smtp_plain.server_address[1],
                 routes='"14" = ["matrix", "email"]')
    code, out, _ = _run(cfg, _at(14), env={"EXPIRY_WATCH_MATRIX_TOKEN": ""}, dry_run=True)
    assert code == 0 and not _Matrix.seen and not smtp_plain.sessions
    assert "matrix" in out and "email" in out and not (tmp_path / "state.json").exists()


def test_an_email_only_route_delivers_by_smtp(tmp_path, smtp_plain):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=smtp_plain.server_address[1],
                 routes='"14" = ["email"]')
    code, out, err = _run(cfg, _at(14), env={"EXPIRY_WATCH_TOKEN": ""})
    assert code == 0, err
    assert len(smtp_plain.sessions) == 1 and "deploy-key" in smtp_plain.sessions[0]["data"]
    code, _, _ = _run(cfg, _at(14, hour=20))
    assert len(smtp_plain.sessions) == 1


def test_a_failed_email_keeps_the_notice_due(tmp_path, smtp_plain):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=smtp_plain.server_address[1],
                 routes='"14" = ["email"]')
    smtp_plain.data_reply = "451 try later"
    code, _, err = _run(cfg, _at(14))
    assert code == 1 and "email" in err.lower() and "451" in err
    smtp_plain.data_reply = "250 queued"
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert code == 0 and sum(1 for s in smtp_plain.sessions if s["data"] and "QUEUED" not in s["data"]) >= 1


def test_the_disappeared_notice_can_go_to_matrix(tmp_path, matrix):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix, routes='disappeared = ["matrix"]')
    assert _run(cfg, _at(59))[0] == 0
    (tmp_path / "registry.toml").write_text(
        f'[[item]]\nname = "other-key"\nkind = "ssh-key"\nexpires = 2027-01-01\nowner = "ops@example.com"\n'
        f'runbook = "{RUNBOOK}"\n')
    code, _, err = _run(cfg, _at(58))
    assert code == 0, err
    assert len(_Matrix.seen) == 1 and "no longer listed" in json.loads(_Matrix.seen[0][3])["body"]


def test_shipped_example_config_parses_with_the_channel_tables_and_has_no_secrets():
    from conftest import REPO_ROOT
    import tomllib
    text = (REPO_ROOT / "docs" / "expiry-watch.example.toml").read_text(encoding="utf-8")
    assert "NOT delivered yet" not in text
    cfg = ew.parse_config(tomllib.loads(text))
    assert cfg.matrix is not None and cfg.email is not None
    assert MATRIX_TOKEN not in text and SMTP_PASSWORD not in text
