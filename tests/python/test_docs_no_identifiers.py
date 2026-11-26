"""Guard: the consistency docs carry placeholders only (issue #230).

No IPv4 address, email address or token-like string may appear in these docs. Collection is loose (the file
list is fixed and must exist); the assertions are strict, and a negative case proves each pattern bites.
The sample bad strings are assembled at run time so this file holds no such value itself.
"""

import re

import pytest

from conftest import REPO_ROOT

DOCS = [
    "docs/update-alerting.md",
    "docs/alert-taxonomy.md",
    "docs/detection-ownership.md",
    "docs/live-deploy-runbook.md",
]

# RFC 5737 documentation ranges are placeholders by definition and are allowed
IPV4 = re.compile(r"(?<![\w.])(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
# a long unbroken run of base64/hex-ish characters, or a well-known vendor prefix
TOKEN = re.compile(r"\b(?:gh[pousr]_|github_pat_|xox[bap]-|sk-|dp\.[a-z]+\.|AKIA)[A-Za-z0-9_-]{8,}"
                   r"|(?<![\w/.-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_]{40,}={0,2}(?![\w/.-])")


def findings(text):
    out = []
    for name, rx in (("ip", IPV4), ("email", EMAIL), ("token", TOKEN)):
        out += [(name, m.group(0)) for m in rx.finditer(text)]
    return out


@pytest.mark.parametrize("rel", DOCS)
def test_doc_has_no_ip_email_or_token(rel):
    path = REPO_ROOT / rel
    assert path.is_file(), rel
    assert findings(path.read_text(encoding="utf-8")) == [], rel


def test_guard_collected_something():
    assert len(DOCS) >= 4


@pytest.mark.parametrize("sample", [
    ".".join(["10", "0", "0", "5"]),
    "ops" + "@" + "example" + ".org",
    "ghp" + "_" + "A1b2C3d4E5f6G7h8",
    "A1" * 22,
])
def test_guard_bites(sample):
    assert findings("text " + sample + " text")


def test_documentation_range_and_paths_are_allowed():
    assert findings("host " + ".".join(["192", "0", "2", "10"]) + " and docker/grafana/provisioning/alerting/update-alert-rules-")== []
