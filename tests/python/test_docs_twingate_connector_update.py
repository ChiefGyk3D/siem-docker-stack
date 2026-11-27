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


SCRIPT_DOC = REPO_ROOT / "docs" / "twingate-connector-update-script.md"
ROOT_FROM_CHECKOUT = re.compile(r"sudo\s+(?:\./)?scripts/twingate-connector-update\.sh")


def test_script_doc_never_shows_a_root_run_from_a_checkout():
    t = SCRIPT_DOC.read_text()
    assert "/usr/local/sbin/twingate-connector-update" in t  # collected something real
    assert not ROOT_FROM_CHECKOUT.search(t)
    assert "EVERY invocation from a path that fails it is refused" in " ".join(t.split())
    assert "only warns" not in t and "nothing runs as root" not in t
    assert "root-equivalent" in t and "unsupported for the install location" in " ".join(t.split())


def test_docs_describe_the_launcher_as_the_trust_root_and_not_a_self_check():
    t = " ".join(SCRIPT_DOC.read_text().split())
    r = " ".join(DOC.read_text().split())
    assert "twingate-connector-update-launcher.sh" in t and "twingate-connector-update-launcher.sh" in r
    assert "the launcher is the one trust root" in t
    assert "A shell file cannot check its own location" in t
    # the old claims that the updater validates itself must be gone
    for old in ("The check runs inside the script", "the script restarts itself", "re-executes itself"):
        assert old.lower() not in t.lower()
    assert "never opened again" in t
    assert "-m 0700 /usr/local/libexec/twingate-connector-update" in r


def test_every_documented_root_command_calls_the_installed_launcher():
    for doc in (SCRIPT_DOC, DOC):
        for line in doc.read_text().splitlines():
            if line.lstrip().startswith("sudo ") and "twingate-connector-update" in line and "install" not in line:
                assert "/usr/local/sbin/twingate-connector-update" in line, line


def test_script_doc_documents_cleanup_failure_and_the_launcher_exit_codes():
    t = " ".join(SCRIPT_DOC.read_text().split())
    assert "prints the path of the directory that was kept" in t
    assert "5 the run otherwise succeeded" in t
    assert "mount table" in t


@pytest.mark.parametrize("bad", ["sudo ./scripts/twingate-connector-update.sh --dry-run x",
                                 "sudo scripts/twingate-connector-update.sh --dry-run x"])
def test_checkout_guard_bites(bad):
    assert ROOT_FROM_CHECKOUT.search(bad)


def test_script_doc_describes_the_descriptor_checks_the_byte_count_and_inherited_descriptors():
    t = " ".join(SCRIPT_DOC.read_text().split())
    assert "opens the updater ONCE, FIRST, and then checks the open descriptor itself" in t
    assert "a FIFO, device or directory is refused" in t and "does not block on a FIFO" in t
    assert "COUNTED as they pass" in t and "drops NUL bytes and trailing newlines" in t
    assert "closes descriptors 4 to 9" in t and "any descriptor above 9" in t
    assert "a read-only mount is refused" in t
    assert "octal escapes" in t


def test_script_doc_lists_every_fixed_command_of_the_launcher():
    launcher = (REPO_ROOT / "scripts" / "twingate-connector-update-launcher.sh").read_text()
    names = re.findall(r"^[A-Z]+=/usr/bin/([a-z]+)$", launcher, re.M)
    assert len(names) >= 12, names  # loose collection: something was found
    t = " ".join(SCRIPT_DOC.read_text().split())
    start = t.index("The launcher runs every program it needs (")
    inventory = t[start:t.index(") by a fixed absolute path", start)]
    listed = re.findall(r"`([a-z]+)`", inventory)
    assert sorted(listed) == sorted(names), (listed, names)

