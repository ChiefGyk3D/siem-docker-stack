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
            assert host.endswith("example.com") or host == "localhost", (f.name, host)
    # every $VAR the contact file uses is a documented, empty key in .env.example
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    body = "\n".join(l for l in CONTACT_FILE.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
    used = re.findall(r"\$([A-Z0-9_]+)", body)
    assert used, "the contact point must reference the environment"
    for var in used:
        assert re.search(rf"(?m)^# {var}=\s*$", env), var


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
