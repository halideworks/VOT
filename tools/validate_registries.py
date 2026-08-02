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


def rust_module(source: str, name: str) -> str:
    marker = f"pub mod {name} {{"
    start = source.index(marker) + len(marker)
    end = source.index("\n}", start)
    return source[start:end]


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
    frame_rust_rows = {
        match["name"]: int(match["value"], 16)
        for match in RUST_CONSTANT.finditer(rust_module(rust_text, "frame_type"))
    }
    registry_rows = {name: value for value, name, _ in rows}
    assert frame_rust_rows == registry_rows, (
        "Rust/frame registry mismatch: "
        f"Rust-only={frame_rust_rows.keys() - registry_rows.keys()}, "
        f"registry-only={registry_rows.keys() - frame_rust_rows.keys()}"
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

    setting_rust_rows = {
        match["name"]: int(match["value"], 16)
        for match in RUST_CONSTANT.finditer(rust_module(rust_text, "setting_id"))
    }
    setting_registry_rows = {name: value for value, name, _ in setting_rows}
    assert setting_rust_rows == setting_registry_rows, (
        "Rust/settings registry mismatch: "
        f"Rust-only={setting_rust_rows.keys() - setting_registry_rows.keys()}, "
        f"registry-only={setting_registry_rows.keys() - setting_rust_rows.keys()}"
    )

    # Encoding walks REGISTERED_SETTINGS, so a setting that reaches the
    # registry and the Rust constants but not that list is silently never
    # advertised. The list is checked against the constants rather than the
    # registry so the two mismatches are reported separately.
    listed = re.search(
        r"pub const REGISTERED_SETTINGS: \[u64; (?P<count>\d+)\] = \[(?P<body>[^\]]*)\];",
        rust_text,
    )
    assert listed, "REGISTERED_SETTINGS not found"
    listed_names = re.findall(r"setting_id::([A-Z0-9_]+)", listed["body"])
    assert len(listed_names) == int(listed["count"]), (
        f"REGISTERED_SETTINGS declares {listed['count']} entries "
        f"but lists {len(listed_names)}"
    )
    assert len(listed_names) == len(set(listed_names)), "duplicate in REGISTERED_SETTINGS"
    assert set(listed_names) == setting_rust_rows.keys(), (
        "REGISTERED_SETTINGS/setting_id mismatch: "
        f"listed-only={set(listed_names) - setting_rust_rows.keys()}, "
        f"constant-only={setting_rust_rows.keys() - set(listed_names)}"
    )

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
