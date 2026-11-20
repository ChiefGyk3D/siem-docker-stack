"""Guards for the WAN failover design note (issue #68, epic #62).

The repo collects no pfSense gateway status metric, so this change is a design
note only. The tests keep it honest: the note must exist and carry its required
sections, must not invent a rule file or metric in the provisioned alerting
directory, and must stay free of real addresses and em dashes.
"""
import re

from conftest import REPO_ROOT

DOC = REPO_ROOT / "docs" / "design" / "wan-failover-alert.md"
ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"


def _text():
    return DOC.read_text(encoding="utf-8")


def test_note_exists_with_required_sections():
    text = _text()
    for heading in ("## What the repo collects", "## Input needed",
                    "## Rule once the data exists", "## Owner steps",
                    "## Rollback", "## Verified and inferred"):
        assert heading in text, heading


def test_note_names_sources_with_read_date():
    text = _text()
    assert "https://docs.netgate.com/pfsense/en/latest/monitoring/status/gateways.html" in text
    assert "https://github.com/influxdata/telegraf/blob/master/plugins/inputs/exec/README.md" in text
    assert "2026-11-19" in text


def test_note_states_p1_labels_and_error_state():
    text = _text()
    for needle in ("severity: critical", "tier: P1", "phone: \"true\"",
                   "execErrState: Alerting", "noDataState"):
        assert needle in text, needle


def test_no_em_dash_and_only_documentation_addresses():
    text = _text()
    assert "—" not in text
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith("192.0.2."), ip


def test_guard_no_gateway_rule_provisioned():
    # Guard only: when real gateway data exists, replace this note with rules.
    for path in ALERTING.iterdir():
        assert "gateway" not in path.read_text(encoding="utf-8").lower(), path
