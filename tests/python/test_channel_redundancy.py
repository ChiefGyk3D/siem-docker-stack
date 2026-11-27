"""Guards for the second P1 channel (issue #82, design docs/design/channel-redundancy.md).

A Grafana email contact point and a continue route send every P1 alert (severity=critical,
phone=true) to email as well as to the n8n router. Both files ship as .example, so nothing
is active until the owner copies them. These tests parse the files; Grafana never loads them
here and no email is sent.
"""
import re

import yaml

from conftest import REPO_ROOT
from test_update_alerting import ALERTING, ENV_EXAMPLE

CONTACT_FILE = ALERTING / "email-contact-point.yml.example"
POLICY_FILE = ALERTING / "email-notification-policy.yml.example"
DOC = REPO_ROOT / "docs" / "channel-redundancy.md"
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"

SMTP_KEYS = ["GF_SMTP_ENABLED", "GF_SMTP_HOST", "GF_SMTP_USER", "GF_SMTP_PASSWORD", "GF_SMTP_FROM_ADDRESS",
             "GF_SMTP_STARTTLS_POLICY", "P1_EMAIL_TO"]


def _contact():
    data = yaml.safe_load(CONTACT_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    assert len(data["contactPoints"]) == 1
    return data["contactPoints"][0]


def _policy():
    data = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    return data["policies"][0]


def test_the_files_ship_as_examples_and_are_not_loaded_by_grafana():
    for f in (CONTACT_FILE, POLICY_FILE):
        assert f.exists() and f.name.endswith(".yml.example")
    loaded = {p.name for p in ALERTING.iterdir() if p.suffix in {".yml", ".yaml"}}
    assert not any("email" in n for n in loaded), "an active file would change the live policy tree"


def test_the_email_contact_point_reads_addresses_only_from_the_environment():
    cp = _contact()
    assert cp["name"] == "email-p1"
    (rcv,) = cp["receivers"]
    assert rcv["type"] == "email"
    assert rcv["settings"]["addresses"] == "$P1_EMAIL_TO"
    assert rcv["settings"]["singleEmail"] is True
    assert rcv["disableResolveMessage"] is False


def test_no_secret_or_address_value_is_written_in_the_files():
    for f in (CONTACT_FILE, POLICY_FILE, DOC):
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"(?i)password\s*[:=]\s*[^\s$<`]", text), f.name
        for domain in re.findall(r"[\w.+-]+@([\w.-]+)", text):
            assert domain.endswith("example.com"), (f.name, domain)
        for host in re.findall(r"https?://([\w.-]+)", text):
            cited = f is DOC and host in {"documentation.mailgun.com", "grafana.com", "spec.matrix.org", "gyptazy.com"}
            assert host.endswith("example.com") or host == "localhost" or cited, (f.name, host)
    # every $VAR the contact file uses is a documented, empty key in .env.example
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    body = "\n".join(l for l in CONTACT_FILE.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
    used = re.findall(r"\$([A-Z0-9_]+)", body)
    assert used, "the contact point must reference the environment"
    for var in used:
        assert re.search(rf"(?m)^# {var}=\s*$", env), var


def test_the_provisioning_files_name_no_provider_or_host():
    for f in (CONTACT_FILE, POLICY_FILE):
        text = f.read_text(encoding="utf-8").lower()
        for bad in ("mailgun", "sendgrid", "ses.", "smtp.", "gmail", "postmark", "sparkpost", "mandrill"):
            assert bad not in text.replace("gf_smtp", ""), (f.name, bad)
        assert not re.search(r"https?://", text), f.name


def test_the_policy_sends_p1_to_email_with_a_continue_route_before_the_n8n_routes():
    root = _policy()
    assert root["receiver"] == "n8n-grafana-router"
    routes = root["routes"]
    email = [r for r in routes if r["receiver"] == "email-p1"]
    assert len(email) == 1
    r = email[0]
    assert r["continue"] is True, "without continue the n8n route would not see the P1"
    assert sorted(map(tuple, r["object_matchers"])) == [("phone", "=", "true"), ("severity", "=", "critical")]
    # the email route comes first, and a route to n8n still exists after it
    assert routes[0] is r
    assert any(x["receiver"] == "n8n-grafana-router" for x in routes[1:])


def test_the_heartbeat_and_non_p1_alerts_do_not_match_the_email_route():
    r = [x for x in _policy()["routes"] if x["receiver"] == "email-p1"][0]
    matchers = {m[0]: m[2] for m in r["object_matchers"]}

    def matches(labels):
        return all(labels.get(k) == v for k, v in matchers.items())

    assert matches({"severity": "critical", "phone": "true"})
    assert not matches({"severity": "info", "phone": "false", "heartbeat": "true"})
    assert not matches({"severity": "warning", "phone": "true"})
    assert not matches({"severity": "critical", "phone": "false"})


def test_the_policy_file_says_it_replaces_the_tree_and_names_its_contact_point_file():
    text = POLICY_FILE.read_text(encoding="utf-8")
    assert "replaces" in text and CONTACT_FILE.name in text


def test_env_example_has_the_smtp_keys_commented_and_empty():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for key in SMTP_KEYS:
        assert re.search(rf"(?m)^# {key}=\s*$", text), key
        assert not re.search(rf"(?m)^{key}=", text), f"{key} must stay off by default"
    assert "docs/channel-redundancy.md" in text


def test_compose_is_untouched_so_nothing_changes_until_the_owner_acts():
    assert "GF_SMTP" not in COMPOSE.read_text(encoding="utf-8")


def test_docs_cover_enable_rollback_and_unverified():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("severity=critical", "phone=true", "continue", "email-p1", "P1_EMAIL_TO", "GF_SMTP_PASSWORD",
                   "Doppler", "dev", "Live change", "Rollback", "Not verified", "Matrix", "n8n-grafana-router",
                   "example.com", "docs/design/channel-redundancy.md", "outside heartbeat observer"):
        assert needle in flat, needle
    assert "channel-redundancy.md" in (REPO_ROOT / "docs" / "heartbeat.md").read_text(encoding="utf-8")


# --- Matrix as a third path (issue #147) ---------------------------------------------------------
# Grafana cannot post to Matrix directly: the send endpoint needs a unique txnId per message and a
# webhook contact point sends a fixed URL. The contact point therefore posts to a small relay
# (design note in docs/channel-redundancy.md; no relay code ships here).
MATRIX_CONTACT_FILE = ALERTING / "matrix-contact-point.yml.example"
MATRIX_POLICY_FILE = ALERTING / "matrix-notification-policy.yml.example"
MATRIX_KEYS = ["P1_MATRIX_RELAY_URL", "P1_MATRIX_RELAY_TOKEN"]


def _matrix_contact():
    data = yaml.safe_load(MATRIX_CONTACT_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1 and len(data["contactPoints"]) == 1
    return data["contactPoints"][0]


def _matrix_policy():
    data = yaml.safe_load(MATRIX_POLICY_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    return data["policies"][0]


def test_matrix_files_ship_as_examples_and_are_not_loaded():
    for f in (MATRIX_CONTACT_FILE, MATRIX_POLICY_FILE):
        assert f.exists() and f.name.endswith(".yml.example")
    loaded = {p.name for p in ALERTING.iterdir() if p.suffix in {".yml", ".yaml"}}
    assert not any("matrix" in n for n in loaded)


def test_matrix_contact_point_is_a_webhook_to_a_relay_with_env_only_values():
    cp = _matrix_contact()
    assert cp["name"] == "matrix-p1"
    (rcv,) = cp["receivers"]
    assert rcv["type"] == "webhook"
    s = rcv["settings"]
    assert s["url"] == "$P1_MATRIX_RELAY_URL"
    assert s["httpMethod"] == "POST"
    assert s["authorization_scheme"] == "Bearer"
    assert s["authorization_credentials"] == "$P1_MATRIX_RELAY_TOKEN"
    assert rcv["disableResolveMessage"] is False
    # Grafana cannot supply a unique txnId, so it must not target the Matrix send endpoint itself
    assert "/_matrix/" not in str(rcv)


def test_matrix_files_hold_no_secret_host_or_room_value():
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    for f in (MATRIX_CONTACT_FILE, MATRIX_POLICY_FILE):
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"(?i)(syt_|access_token\s*[:=]\s*[^\s$<`])", text), f.name
        assert not re.search(r"![A-Za-z0-9]+:(?!example\.com)[\w.-]+", text), f.name
        for host in re.findall(r"https?://([\w.-]+)", text):
            assert host.endswith("example.com"), (f.name, host)
    body = "\n".join(l for l in MATRIX_CONTACT_FILE.read_text(encoding="utf-8").splitlines()
                     if not l.lstrip().startswith("#"))
    used = re.findall(r"\$([A-Z0-9_]+)", body)
    assert sorted(used) == sorted(MATRIX_KEYS)
    for var in used:
        assert re.search(rf"(?m)^# {var}=\s*$", env), var


def test_matrix_route_follows_the_email_route_with_continue_and_p1_matchers():
    root = _matrix_policy()
    assert root["receiver"] == "n8n-grafana-router"
    routes = root["routes"]
    (m,) = [r for r in routes if r["receiver"] == "matrix-p1"]
    assert m["continue"] is True
    assert sorted(map(tuple, m["object_matchers"])) == [("phone", "=", "true"), ("severity", "=", "critical")]
    order = [r["receiver"] for r in routes]
    assert order.index("email-p1") < order.index("matrix-p1") < order.index("n8n-grafana-router")
    (e,) = [r for r in routes if r["receiver"] == "email-p1"]
    assert e["continue"] is True


def test_matrix_route_excludes_heartbeat_and_non_p1():
    (m,) = [r for r in _matrix_policy()["routes"] if r["receiver"] == "matrix-p1"]
    want = {k: v for k, _, v in m["object_matchers"]}

    def hit(labels):
        return all(labels.get(k) == v for k, v in want.items())

    assert hit({"severity": "critical", "phone": "true"})
    assert not hit({"severity": "info", "phone": "false", "heartbeat": "true"})
    assert not hit({"severity": "warning", "phone": "true"})


def test_env_example_has_matrix_keys_commented_and_empty_and_compose_untouched():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for key in MATRIX_KEYS:
        assert re.search(rf"(?m)^# {key}=\s*$", text), key
        assert not re.search(rf"(?m)^{key}=", text), key
    assert "P1_MATRIX" not in COMPOSE.read_text(encoding="utf-8")


def test_docs_matrix_section_states_the_txnid_limit_and_relay_design():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("txnId", "retransmission", "relay", "matrix-p1", "P1_MATRIX_RELAY_TOKEN", "MATRIX_ACCESS_TOKEN",
                   "Doppler", "dev_network", "bot account", "Rollback", "VERIFIED", "INFERRED", "read 2026-11-19",
                   "spec.matrix.org", "webhook-notifier", "design note", "no relay code"):
        assert needle in flat, needle


# --- Matrix P2 route (issue #152) ----------------------------------------------------------------
# Owner decision 2026-11-20: the two "update pending over 24 hours" rules are P2 (severity=warning,
# phone=false). They alert Discord through the n8n router and, once the owner enables this inactive
# example, Matrix as well. They never reach the phone: the route matches phone=false only.
MATRIX_P2_POLICY_FILE = ALERTING / "matrix-p2-notification-policy.yml.example"
P2_UIDS = ("update-unifi-pending-24h", "update-pfsense-pending-24h")


def _matrix_p2_route():
    data = yaml.safe_load(MATRIX_P2_POLICY_FILE.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    root = data["policies"][0]
    assert root["receiver"] == "n8n-grafana-router"
    (m,) = [r for r in root["routes"] if r["receiver"] == "matrix-p1"]
    return root, m


def _hit(route, labels):
    want = {k: v for k, op, v in route["object_matchers"] if op == "="}
    assert len(want) == len(route["object_matchers"])
    return all(labels.get(k) == v for k, v in want.items())


def test_matrix_p2_policy_ships_as_an_inactive_example():
    assert MATRIX_P2_POLICY_FILE.exists() and MATRIX_P2_POLICY_FILE.name.endswith(".yml.example")
    loaded = {p.name for p in ALERTING.iterdir() if p.suffix in {".yml", ".yaml"}}
    assert not any("matrix" in n for n in loaded)


def test_matrix_p2_route_continues_and_never_matches_the_phone_tiers():
    root, m = _matrix_p2_route()
    assert m["continue"] is True, "without continue the n8n route would not see the P2 alert"
    assert ("phone", "=", "false") in [tuple(x) for x in m["object_matchers"]]
    assert ("severity", "=", "warning") in [tuple(x) for x in m["object_matchers"]]
    assert _hit(m, {"severity": "warning", "tier": "P2", "phone": "false"})
    assert not _hit(m, {"severity": "critical", "tier": "P1", "phone": "true"})
    assert not _hit(m, {"severity": "warning", "phone": "true"})
    assert not _hit(m, {"severity": "info", "tier": "none", "phone": "false", "heartbeat": "true"})
    assert not _hit(m, {"severity": "info", "tier": "P3", "phone": "false", "digest": "true"})
    # a route to n8n still follows, so Discord keeps receiving the alert
    order = [r["receiver"] for r in root["routes"]]
    assert order.index("matrix-p1") < len(order) - 1 and "n8n-grafana-router" in order[order.index("matrix-p1") + 1:]


def test_the_two_update_pending_24h_rules_match_the_matrix_p2_route():
    _, m = _matrix_p2_route()
    rules = {}
    for name in ("update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml"):
        data = yaml.safe_load((ALERTING / name).read_text(encoding="utf-8"))
        for g in data["groups"]:
            rules.update({r["uid"]: r for r in g["rules"]})
    for uid in P2_UIDS:
        assert _hit(m, rules[uid]["labels"]), uid
    # the 7 day escalations stay P1 on the phone and are not sent by the P2 route
    for uid in ("update-unifi-pending-7d", "update-pfsense-pending-7d"):
        assert not _hit(m, rules[uid]["labels"]), uid


def test_matrix_p2_policy_reuses_the_relay_contact_point_and_holds_no_secret():
    text = MATRIX_P2_POLICY_FILE.read_text(encoding="utf-8")
    assert "matrix-contact-point.yml.example" in text and "replaces" in text
    assert not re.search(r"https?://", text)
    assert not re.search(r"(?i)(syt_|access_token\s*[:=]\s*[^\s$<`])", text)


def test_docs_matrix_p2_section_covers_enable_and_rollback():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("matrix-p2-notification-policy.yml.example", "P2 route", "severity=warning", "phone=false",
                   "update-unifi-pending-24h", "update-pfsense-pending-24h", "never the phone", "Rollback (P2)",
                   "Enable the P2 route"):
        assert needle in flat, needle
