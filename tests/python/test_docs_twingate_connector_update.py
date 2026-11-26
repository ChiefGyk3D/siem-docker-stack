"""Guard for docs/twingate-connector-update.md: the load-bearing warnings stay, and no secret or address appears."""

import re

import pytest

from conftest import REPO_ROOT

DOC = REPO_ROOT / "docs" / "twingate-connector-update.md"
ALERTING = REPO_ROOT / "docs" / "update-alerting.md"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
TOKEN = re.compile(r"\b(?:[A-Fa-f0-9]{32,}|eyJ[\w-]{10,}\.[\w-]{10,}|[A-Za-z0-9_-]{40,})\b")


def text():
    return DOC.read_text()


def flat():
    return " ".join(text().split())


def secret_findings(s):
    return [m.group(0) for rx in (IPV4, EMAIL, TOKEN) for m in rx.finditer(s)]


def test_doc_exists_and_is_collected():
    assert DOC.is_file()
    assert len(text()) > 500


def test_names_host_network_flag():
    assert "--network host" in text()


def test_warns_against_vendor_script():
    t = flat()
    assert "docker-upgrade.sh" in t
    assert "Do not use the vendor upgrade script on these hosts" in t
    assert "--sysctl net.ipv4.ping_group_range" in t


def test_pulled_image_is_not_running_image():
    assert "A pulled newer image does NOT mean the container is updated" in flat()


def test_no_ip_email_or_token():
    assert secret_findings(text()) == []


def test_alerting_doc_links_it():
    assert "twingate-connector-update.md" in ALERTING.read_text()


@pytest.mark.parametrize("bad", ["host 10.1.2.3 up", "mail me@example.com", "tok " + "a" * 40, "h " + "ab12" * 16])
def test_guard_bites(bad):
    assert secret_findings(bad)
