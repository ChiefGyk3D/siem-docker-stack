#!/usr/bin/env python3
"""Validate custom Wazuh rule IDs across all rule XML files.

Checks:
  1. Every rule XML file parses (Wazuh files are XML fragments with multiple
     top-level <group> elements, so each file is wrapped in a dummy root).
  2. No duplicate rule IDs across files.
  3. All rule IDs fall inside the custom range 100000-120999
     (100000-120000 is the Wazuh-reserved custom rule space; this repo
     allocates per-integration blocks up to 120999).

Usage:
    python3 scripts/check-wazuh-rule-ids.py [wazuh_dir]

Exits non-zero with a description of each violation.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CUSTOM_ID_MIN = 100000
CUSTOM_ID_MAX = 120999


def parse_fragment(path: Path) -> ET.Element:
    """Parse a Wazuh XML fragment file by wrapping it in a dummy root."""
    content = path.read_text(encoding="utf-8")
    return ET.fromstring(f"<ossec_wrapper>{content}</ossec_wrapper>")


def main() -> int:
    wazuh_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("wazuh")
    rule_files = sorted(
        p for p in wazuh_dir.rglob("*.xml") if "rules" in p.name
    )
    if not rule_files:
        print(f"ERROR: no rule XML files found under {wazuh_dir}/")
        return 1

    errors = []
    seen = {}  # rule id -> first file seen in

    for path in rule_files:
        try:
            root = parse_fragment(path)
        except ET.ParseError as e:
            errors.append(f"{path}: XML parse error: {e}")
            continue

        rules = root.iter("rule")
        count = 0
        for rule in rules:
            count += 1
            raw_id = rule.get("id")
            if raw_id is None or not raw_id.isdigit():
                errors.append(f"{path}: rule with missing/non-numeric id: {raw_id!r}")
                continue
            rule_id = int(raw_id)
            if not CUSTOM_ID_MIN <= rule_id <= CUSTOM_ID_MAX:
                errors.append(
                    f"{path}: rule id {rule_id} outside custom range "
                    f"{CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}"
                )
            if rule_id in seen:
                errors.append(
                    f"{path}: duplicate rule id {rule_id} (first defined in {seen[rule_id]})"
                )
            else:
                seen[rule_id] = path
        print(f"  {path}: {count} rules")

    if errors:
        print(f"\nFAIL: {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"\nOK: {len(seen)} unique rule ids across {len(rule_files)} files, "
          f"all within {CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
