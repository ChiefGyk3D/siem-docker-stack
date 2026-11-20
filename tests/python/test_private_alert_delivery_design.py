"""Guard for the private alert delivery design note (issue #155, epic #62).

Docs only. The note must exist, name every tier, state the minimal payload and
stay free of em dashes and real addresses.
"""
import re

from conftest import REPO_ROOT

DOC = REPO_ROOT / "docs" / "design" / "private-alert-delivery.md"


def _text():
    return DOC.read_text(encoding="utf-8")


def test_note_exists_and_names_every_tier():
    text = _text()
    for tier in ("P1", "P2", "P3"):
        assert tier in text, tier


def test_note_has_required_sections():
    text = _text()
    for heading in ("## Tier to channel table", "## Minimal payload",
                    "## Ticket link pattern", "## Per-platform setup",
                    "## Risks", "## Rollback", "## Owner decisions list",
                    "## Proposed follow-up issues"):
        assert heading in text, heading


def test_note_states_ticket_pattern():
    assert "TICKET_BASE_URL/<id>" in _text()


def test_no_em_dash_and_only_documentation_addresses():
    text = _text()
    assert "—" not in text
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith("192.0.2."), ip
