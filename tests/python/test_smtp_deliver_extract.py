"""The SMTP transport was extracted from email_send into smtp_deliver (issue #69) so the weekly
digest reuses the one hardened sender. These tests pin that email_send's behavior is unchanged:
the same session on the wire, and every transport guard now lives in smtp_deliver itself."""
import email.message

import pytest

from test_expiry_watch_channels import (SMTP_PASSWORD, _at, _ecfg, _notice, ew,
                                        smtp_plain)  # noqa: F401  fixtures


def test_email_send_delegates_to_smtp_deliver(smtp_plain, monkeypatch):
    seen = []
    monkeypatch.setattr(ew, "smtp_deliver", lambda cfg, env, msg, root=None, budget=None: seen.append(msg))
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    ew.email_send(cfg, {}, _notice(channels=("email",)), _at(14))
    (msg,) = seen
    assert msg["From"] == "expiry-watch@example.com" and msg["Auto-Submitted"] == "auto-generated"
    assert msg["Message-ID"].startswith("<") and "deploy-key" in msg["Subject"]
    assert not smtp_plain.sessions  # nothing on the wire: the delegate was replaced


def test_smtp_deliver_sends_a_prepared_message(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], security="plaintext", allow_plaintext=True)
    msg = email.message.EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg.sender, "ops@example.com", "hello"
    msg.set_content("body text")
    ew.smtp_deliver(cfg, {}, msg)
    (s,) = smtp_plain.sessions
    assert "body text" in s["data"] and s["helo"] == "localhost"


def test_smtp_deliver_still_refuses_without_starttls_and_never_logs_in(smtp_plain):
    cfg = _ecfg(smtp_plain.server_address[1], username_env="EW_USER", password_env="EW_PASS")
    msg = email.message.EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg.sender, "ops@example.com", "x"
    msg.set_content("b")
    with pytest.raises(ew.ExpiryWatchError):
        ew.smtp_deliver(cfg, {"EW_USER": "u", "EW_PASS": SMTP_PASSWORD}, msg)
    (s,) = smtp_plain.sessions
    assert s["data"] is None and "AUTH" not in s["commands"]
