#!/usr/bin/env python3
"""Validate the JSON-compatible YAML security abuse-case matrix."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REQUIRED_CASE_PREFIXES = (
    "SEC-AMP-",
    "SEC-RPL-",
    "SEC-STG-",
    "SEC-TOK-",
    "SEC-SRC-",
    "SEC-PRV-",
)


def validate(root: Path) -> None:
    matrix_path = root / "security" / "abuse-cases.yaml"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    assert matrix["schema"] == "vot-security-abuse-cases-v1"
    assert matrix["default_telemetry_level"] == "pseudonymous"

    cases = matrix["cases"]
    identifiers = [case["id"] for case in cases]
    assert len(identifiers) == len(set(identifiers)), "duplicate abuse-case ID"
    for prefix in REQUIRED_CASE_PREFIXES:
        assert any(identifier.startswith(prefix) for identifier in identifiers), (
            f"missing required category {prefix}"
        )

    for case in cases:
        for field in ("title", "actor", "attack", "residual_risk", "gate"):
            assert isinstance(case[field], str) and case[field], f"{case['id']}: {field}"
        for field in ("assets", "controls", "tests", "telemetry"):
            assert isinstance(case[field], list), f"{case['id']}: {field}"
        assert case["assets"], f"{case['id']}: no assets"
        assert case["controls"], f"{case['id']}: no controls"
        assert case["tests"], f"{case['id']}: no tests"

    registry = (root / "spec" / "registries.md").read_text(encoding="utf-8")
    registered_events = set(
        re.findall(r"^\| `((?:vot|vcrc)\.[a-z0-9_.]+)` \|", registry, re.MULTILINE)
    )
    used_events = {
        event for case in cases for event in case["telemetry"]
    }
    assert used_events <= registered_events, (
        f"unregistered telemetry events: {sorted(used_events - registered_events)}"
    )

    security = (root / "spec" / "security.md").read_text(encoding="utf-8")
    telemetry = (root / "spec" / "telemetry.md").read_text(encoding="utf-8")
    assert "default level is `pseudonymous`" in telemetry
    assert "raw paths" in telemetry.lower()
    assert "capability tokens" in telemetry
    assert "payload bytes" in telemetry


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        validate(root)
    except (AssertionError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"security matrix validation failed: {error}", file=sys.stderr)
        return 1
    print("security matrix validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
