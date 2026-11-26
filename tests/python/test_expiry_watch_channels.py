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
import time

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
    delay = 0.0

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        time.sleep(type(self).delay)
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
    _Matrix.seen, _Matrix.status, _Matrix.redirect_to, _Matrix.delay = [], 200, None, 0.0
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
            time.sleep(srv.reply_delay)
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
                    send(getattr(srv, "rcpt_reply", "250 ok"))
                elif verb == "DATA":
                    send("354 go")
                    lines = []
                    while True:
                        row = self.rfile.readline(65536).decode("utf-8", "replace")
                        if row in (".\r\n", ""):
                            break
                        lines.append(row)
                    sess["data"] = "".join(lines)
                    if srv.drop_after_data:  # queued, but the final reply never comes
                        return
                    if getattr(srv, "hang_after_data", 0):  # queued, then silence (the client times out)
                        time.sleep(srv.hang_after_data)
                        return
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


def _start_smtp(starttls_ctx=None, implicit_ctx=None, offer_auth=True, data_reply="250 queued", reply_delay=0.0):
    srv = _SmtpServer(("127.0.0.1", 0), _SmtpHandler)
    srv.sessions, srv.starttls_ctx, srv.implicit_ctx = [], starttls_ctx, implicit_ctx
    srv.offer_auth, srv.data_reply, srv.reply_delay = offer_auth, data_reply, reply_delay
    srv.drop_after_data = False
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


# --- review round 1: deadlines, budget, ca_file, transaction ids --------------------------------

def test_a_timed_out_email_never_authenticates_or_sends_afterwards():
    """Finding 1. Every reply is slower than nothing but faster than the per-call timeout, so only an
    overall deadline stops the delivery. After it raised, the worker must not go on to send."""
    srv, t = _start_smtp(reply_delay=0.6)
    try:
        cfg = _ecfg(srv.server_address[1], security="plaintext", allow_plaintext=True, timeout_seconds=1)
        started = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError):
            ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14), root=None)
        assert time.monotonic() - started < 3.5
        time.sleep(4)  # the old code finished the whole conversation in the background in about 3 seconds
        assert all(s["data"] is None for s in srv.sessions), "a message was delivered after the failure"
    finally:
        _stop(srv, t)


def test_a_slow_matrix_server_is_cut_off_at_the_deadline(matrix):
    """Finding 1, Matrix side (regression guard: the earlier code also stopped waiting)."""
    _Matrix.delay = 2.5
    cfg = _mcfg(matrix, timeout_seconds=1)
    started = time.monotonic()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out|deadline") as exc:
        ew.matrix_send(cfg, MATRIX_TOKEN, _notice(), _at(14))
    assert time.monotonic() - started < 2.4 and MATRIX_TOKEN not in str(exc.value)


def test_the_deadline_object_refuses_work_after_expiry_and_after_abort():
    dl = ew._Deadline(0.05)
    assert dl.left() > 0
    time.sleep(0.1)
    with pytest.raises(TimeoutError):
        dl.left()
    dl2 = ew._Deadline(30)
    dl2.abort()
    with pytest.raises(TimeoutError):
        dl2.left()


@pytest.mark.parametrize("bad", [0, -1, 3601, True, "10"])
def test_delivery_budget_is_validated(bad):
    with pytest.raises(ew.ExpiryWatchError, match="delivery_budget_seconds"):
        ew.parse_config(_base(watch={"delivery_budget_seconds": bad}))


def test_the_run_has_one_delivery_budget_and_leaves_the_rest_due(tmp_path, matrix):
    """Finding 2. Three due notices, each answered slower than the budget allows for all three."""
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    cfg.write_text(cfg.read_text().replace('state_file = "state.json"',
                                           'state_file = "state.json"\ndelivery_budget_seconds = 0.7'))
    reg = "".join(f'[[item]]\nname = "key-{i}"\nkind = "ssh-key"\nexpires = 2026-03-01\nowner = "ops@example.com"\n'
                  f'runbook = "{RUNBOOK}"\n' for i in range(3))
    (tmp_path / "registry.toml").write_text(reg)
    _Matrix.delay = 0.4
    started = time.monotonic()
    code, out, err = _run(cfg, _at(14))
    assert code == 1 and time.monotonic() - started < 1.4
    assert len(_Matrix.seen) <= 2, "the third delivery must not be tried once the budget is gone"
    assert "timed out" in err or "budget" in err
    # nothing is lost: with time to spare the next run delivers every notice that is still due
    cfg.write_text(cfg.read_text().replace("delivery_budget_seconds = 0.7", "delivery_budget_seconds = 30"))
    _Matrix.delay = 0.0
    before = len(_Matrix.seen)
    code, _, err = _run(cfg, _at(14, hour=18))
    assert code == 0, err
    names = {json.loads(b)["body"].split(":")[1].strip() for _, _, _, b in _Matrix.seen}
    assert {"key-0", "key-1", "key-2"} <= names and len(_Matrix.seen) > before


def test_ca_file_replaces_the_system_trust_store(tmp_path):
    """Finding 3. With ca_file only that CA is trusted, not that CA plus every public one."""
    _, crt = _server_ctx(tmp_path)
    (tmp_path / "ca.pem").write_bytes(crt.read_bytes())
    root = ew.Root(str(tmp_path))
    try:
        ctx = ew._smtp_context(_ecfg(2525, ca_file="ca.pem"), root)
    finally:
        root.close()
    assert len(ctx.get_ca_certs()) == 1
    assert ctx.check_hostname is True and ctx.verify_mode == ssl.CERT_REQUIRED


def test_a_ca_file_that_is_not_pem_is_a_config_error(tmp_path):
    (tmp_path / "ca.pem").write_text("not a certificate")
    root = ew.Root(str(tmp_path))
    try:
        with pytest.raises(ew.ExpiryWatchError, match="(?i)ca_file"):
            ew._smtp_context(_ecfg(2525, ca_file="ca.pem"), root)
    finally:
        root.close()


def test_matrix_transaction_id_names_the_logical_notice_not_the_attempt_day():
    """Finding 4. The same notice retried on a later day, when days_left has moved on, is the same
    transaction. Only the daily stage is a different event from one day to the next."""
    base = _notice(stage="14", days=14)
    assert ew.matrix_txn_id(base) == ew.matrix_txn_id(_notice(stage="14", days=13))
    assert ew.matrix_txn_id(_notice(stage="expired", days=-1)) == ew.matrix_txn_id(_notice(stage="expired", days=-2))
    assert ew.matrix_txn_id(_notice(stage="daily", days=5)) != ew.matrix_txn_id(_notice(stage="daily", days=4))
    assert ew.matrix_txn_id(_notice(stage="daily", days=5)) == ew.matrix_txn_id(_notice(stage="daily", days=5))
    assert ew.matrix_txn_id(base) != ew.matrix_txn_id(_notice(stage="7", days=7))
    other = _notice(_item(expires=dt.date(2026, 6, 1)), stage="14", days=14)
    assert ew.matrix_txn_id(base) != ew.matrix_txn_id(other)


def test_a_matrix_retry_across_midnight_reuses_the_transaction(matrix):
    cfg = _mcfg(matrix)
    ew.matrix_send(cfg, MATRIX_TOKEN, _notice(stage="14", days=14), _at(14, hour=23))
    ew.matrix_send(cfg, MATRIX_TOKEN, _notice(stage="14", days=13), _at(13, hour=1))
    assert _Matrix.seen[0][1] == _Matrix.seen[1][1]


# --- review round 2: router deadline, tight deadlines, notice generations ----------------------

class _Drip(http.server.BaseHTTPRequestHandler):
    """Answers 200, then keeps the body going one small chunk at a time for about 3 seconds."""
    seen = 0
    drip = True

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen += 1
        self.send_response(200)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for _ in range(20 if type(self).drip else 0):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.15)
        except OSError:
            pass

    def log_message(self, *a):
        pass


@pytest.fixture
def drip():
    _Drip.seen, _Drip.drip = 0, True
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Drip)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    t.join(5)
    srv.server_close()


def test_a_slow_drip_router_answer_is_cut_off_at_the_absolute_deadline(drip):
    started = time.monotonic()
    with pytest.raises(ew.ExpiryWatchError, match="(?i)timed out|deadline") as exc:
        ew.post_json(drip + "/h", "router-secret-value", {"a": 1}, timeout=0.5)
    assert time.monotonic() - started < 1.2, "every chunk arrives inside the socket timeout; only the deadline stops it"
    assert "router-secret-value" not in str(exc.value)


def test_the_run_budget_also_bounds_a_slow_drip_router(tmp_path, drip):
    cfg = _setup(tmp_path, drip, routes='"14" = ["discord"]')
    cfg.write_text(cfg.read_text().replace('state_file = "state.json"',
                                           'state_file = "state.json"\ndelivery_budget_seconds = 0.6'))
    reg = "".join(f'[[item]]\nname = "key-{i}"\nkind = "ssh-key"\nexpires = 2026-03-01\nowner = "ops@example.com"\n'
                  f'runbook = "{RUNBOOK}"\n' for i in range(2))
    (tmp_path / "registry.toml").write_text(reg)
    started = time.monotonic()
    code, _, err = _run(cfg, _at(14))
    assert code == 1 and time.monotonic() - started < 1.5 and _Drip.seen <= 1
    _Drip.drip = False  # the router recovers: both notices are still due
    cfg.write_text(cfg.read_text().replace("delivery_budget_seconds = 0.6", "delivery_budget_seconds = 30"))
    seen_before = _Drip.seen
    code, _, err = _run(cfg, _at(14, hour=18))
    assert code == 0, err
    assert _Drip.seen - seen_before == 2


def test_run_deadline_returns_at_the_deadline_even_when_the_worker_never_does():
    gate = threading.Event()
    try:
        started = time.monotonic()
        with pytest.raises(ew._Overrun):
            ew._run_deadline(ew._Deadline(0.05), gate.wait)
        assert time.monotonic() - started < 0.5
    finally:
        gate.set()


def test_an_smtp_transaction_of_individually_fast_replies_still_ends_at_the_deadline():
    """Every reply comes inside the socket timeout; their sum passes the deadline."""
    srv, t = _start_smtp(reply_delay=0.3)
    try:
        cfg = _ecfg(srv.server_address[1], security="plaintext", allow_plaintext=True, timeout_seconds=1)
        started = time.monotonic()
        with pytest.raises(ew.ExpiryWatchError):
            ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14), root=None)
        assert time.monotonic() - started < 1.5
        time.sleep(2.5)
        assert all(s["data"] is None for s in srv.sessions)
    finally:
        _stop(srv, t)


def test_matrix_transaction_id_changes_with_the_notice_generation():
    n = _notice(stage="disappeared", days=10)
    assert ew.matrix_txn_id(n, "aaaa") == ew.matrix_txn_id(n, "aaaa")
    assert ew.matrix_txn_id(n, "aaaa") != ew.matrix_txn_id(n, "bbbb")


def _replace_registry(tmp_path, name):
    (tmp_path / "registry.toml").write_text(
        f'[[item]]\nname = "{name}"\nkind = "ssh-key"\nexpires = 2026-03-01\nowner = "ops@example.com"\n'
        f'runbook = "{RUNBOOK}"\n')


def test_a_second_disappear_return_disappear_cycle_is_a_new_matrix_event(tmp_path, matrix):
    """Round 2 Low. Same item, same stage, same expiry date, two separate lifecycles."""
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix, routes='disappeared = ["matrix"]')
    assert _run(cfg, _at(59))[0] == 0
    _replace_registry(tmp_path, "other-key")
    assert _run(cfg, _at(58))[0] == 0 and len(_Matrix.seen) == 1
    _replace_registry(tmp_path, "deploy-key")
    assert _run(cfg, _at(57))[0] == 0
    _replace_registry(tmp_path, "other-key")
    assert _run(cfg, _at(56))[0] == 0
    # (other-key also vanishes when deploy-key comes back; only deploy-key's two notices matter here)
    mine = [path for _, path, _, body in _Matrix.seen if b"deploy-key" in body]
    assert len(mine) == 2 and mine[0] != mine[1], "the homeserver must see the second lifecycle as new"


def test_a_failed_matrix_notice_keeps_its_generation_for_the_retry_across_days(tmp_path, matrix):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix)
    _Matrix.status = 500
    assert _run(cfg, _at(14))[0] == 1
    assert "pending" in json.loads((tmp_path / "state.json").read_text())
    _Matrix.status = 200
    assert _run(cfg, _at(13))[0] == 0
    assert _Matrix.seen[0][1] == _Matrix.seen[1][1], "a retry is the same Matrix transaction"
    assert "pending" not in json.loads((tmp_path / "state.json").read_text()), "delivered: nothing to remember"


def test_the_pending_section_of_the_state_file_is_validated(tmp_path):
    good = {"version": 2, "items": {}, "seen": {}, "pending": {"deploy-key|14|2026-03-01": "0123456789abcdef" * 2}}
    path = tmp_path / "s.json"
    path.write_text(json.dumps(good))
    assert ew.load_memory(str(path), None, with_pending=True)[2] == good["pending"]
    for bad in ({"k": "short"}, {"k": 5}, {"k\n": "0123456789abcdef" * 2}, ["x"],
                {f"k{i}": "0123456789abcdef" * 2 for i in range(20000)}):
        path.write_text(json.dumps({**good, "pending": bad}))
        with pytest.raises(ew.ExpiryWatchError):
            ew.load_memory(str(path), None, with_pending=True)


# --- review round 3: pending survives a provider outage; stable Message-ID ---------------------

def _pending(tmp_path):
    return json.loads((tmp_path / "state.json").read_text()).get("pending", {})


def test_pending_generation_survives_a_run_where_the_provider_fails(tmp_path, matrix, smtp_plain):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix, smtp_port=smtp_plain.server_address[1],
                 routes='"14" = ["matrix", "email"]')
    good_registry = (tmp_path / "registry.toml").read_text()
    smtp_plain.data_reply = "451 try later"
    assert _run(cfg, _at(14))[0] == 1  # matrix took it, email did not
    first = dict(_pending(tmp_path))
    assert len(first) == 1 and len(_Matrix.seen) == 1
    (tmp_path / "registry.toml").write_text("not toml [[")  # the provider fails; no notice can be rebuilt
    code, _, err = _run(cfg, _at(14, hour=15))
    assert code == 1 and "registry" in err
    assert _pending(tmp_path) == first, "the generation must be carried through a provider outage"
    (tmp_path / "registry.toml").write_text(good_registry)
    smtp_plain.data_reply = "250 queued"
    assert _run(cfg, _at(13))[0] == 0
    assert len(_Matrix.seen) == 2 and _Matrix.seen[0][1] == _Matrix.seen[1][1]
    assert _pending(tmp_path) == {}, "forgotten only once the notice was fully delivered"


def test_pending_generation_is_dropped_when_the_notice_is_provably_no_longer_due(tmp_path, matrix, smtp_plain):
    cfg = _setup(tmp_path, "http://127.0.0.1:1", matrix_url=matrix, smtp_port=smtp_plain.server_address[1],
                 routes='"14" = ["matrix", "email"]')
    smtp_plain.data_reply = "451 try later"
    assert _run(cfg, _at(14))[0] == 1 and len(_pending(tmp_path)) == 1
    # the item is rotated to a far date while every provider is healthy: nothing is due, nothing is kept
    (tmp_path / "registry.toml").write_text(
        f'[[item]]\nname = "deploy-key"\nkind = "ssh-key"\nexpires = 2030-01-01\nowner = "ops@example.com"\n'
        f'runbook = "{RUNBOOK}"\n')
    assert _run(cfg, _at(13))[0] == 0
    assert _pending(tmp_path) == {}


def _message_id(data):
    for line in data.split("\r\n"):
        if line.lower().startswith("message-id:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("no Message-ID header")


def test_a_retry_after_an_ambiguous_smtp_acceptance_carries_the_same_message_id(tmp_path):
    """The server queues the message and then drops the connection without its final reply."""
    srv, t = _start_smtp()
    srv.drop_after_data = True
    try:
        cfg = _setup(tmp_path, "http://127.0.0.1:1", smtp_port=srv.server_address[1], routes='"14" = ["email"]')
        assert _run(cfg, _at(14))[0] == 1  # the client cannot know the mail was queued
        srv.drop_after_data = False
        assert _run(cfg, _at(13))[0] == 0
        copies = [s["data"] for s in srv.sessions if s["data"]]
        assert len(copies) == 2 and _message_id(copies[0]) == _message_id(copies[1])
        assert _pending(tmp_path) == {}
    finally:
        _stop(srv, t)


def test_message_id_is_stable_per_generation_and_new_for_a_new_one(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    n = _notice(channels=("email",))
    for gen in ("aaaa", "aaaa", "bbbb"):
        ew.email_send(cfg, {}, n, _at(14), root=None, generation=gen)
    ids = [_message_id(s["data"]) for s in smtp_plain.sessions]
    assert ids[0] == ids[1] != ids[2]
    assert ids[0].startswith("<") and ids[0].endswith("@example.com>")
