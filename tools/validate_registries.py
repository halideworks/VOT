#!/usr/bin/env python3
"""Check registry uniqueness, criticality, and Rust constant synchronization."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_-]+)` "
    r"\| (?P<handling>critical|optional) \|",
    re.MULTILINE,
)
SETTING_ROW = re.compile(r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_-]+)` \|.*\| (?P<handling>critical|optional) \|$", re.MULTILINE)
RUST_CONSTANT = re.compile(
    r"^\s*pub const (?P<name>[A-Z0-9_]+): u64 = (?P<value>0x[0-9a-f]+);$",
    re.MULTILINE,
)


def section(document: str, heading: str, next_heading: str) -> str:
    start = document.index(heading)
    end = document.index(next_heading, start)
    return document[start:end]


def validate(root: Path) -> None:
    registry_text = (root / "spec" / "registries.md").read_text(encoding="utf-8")
    frame_text = section(registry_text, "## 2. Frame types", "## 3. Settings")
    rows = [
        (int(match["value"], 16), match["name"], match["handling"])
        for match in ROW.finditer(frame_text)
    ]
    assert rows, "no frame registry rows parsed"

    values = [value for value, _, _ in rows]
    names = [name for _, name, _ in rows]
    assert len(values) == len(set(values)), "duplicate frame value"
    assert len(names) == len(set(names)), "duplicate frame name"
    for value, name, handling in rows:
        expected = "critical" if value & 1 else "optional"
        assert handling == expected, f"{name}: {handling}, expected {expected}"
        assert not (0x1F00 <= value <= 0x1FFE), f"{name}: grease collision"

    rust_text = (root / "crates" / "vot-codec" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    rust_rows = {
        match["name"]: int(match["value"], 16)
        for match in RUST_CONSTANT.finditer(rust_text)
    }
    registry_rows = {name: value for value, name, _ in rows}
    assert rust_rows == registry_rows, (
        f"Rust/registry mismatch: Rust-only={rust_rows.keys() - registry_rows.keys()}, "
        f"registry-only={registry_rows.keys() - rust_rows.keys()}"
    )

    setting_text = section(registry_text, "## 3. Settings", "## 4. Extension identifiers")
    setting_rows = [
        (int(match["value"], 16), match["name"], match["handling"])
        for match in SETTING_ROW.finditer(setting_text)
    ]
    assert setting_rows, "no settings registry rows parsed"
    assert len({value for value, _, _ in setting_rows}) == len(setting_rows)
    assert len({name for _, name, _ in setting_rows}) == len(setting_rows)
    for value, name, handling in setting_rows:
        expected = "critical" if value & 1 else "optional"
        assert handling == expected, f"setting {name}: {handling}, expected {expected}"

    grease_values = range(0x1F00, 0x1FFF, 2)
    assert all(value % 2 == 0 for value in grease_values)
    assert not set(values).intersection(grease_values)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        validate(root)
    except (AssertionError, OSError, ValueError) as error:
        print(f"registry validation failed: {error}", file=sys.stderr)
        return 1
    print("registry validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
