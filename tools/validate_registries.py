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
BEHAVIOR_ROW = re.compile(
    r"^\| `(?P<name>[A-Z0-9_]+)` \|[^|]*\|[^|]*\| (?P<auth>yes|no|depends on phase) \|",
    re.MULTILINE,
)
RUST_CONSTANT = re.compile(
    r"^\s*pub const (?P<name>[A-Z0-9_]+): u64 = (?P<value>0x[0-9a-f]+);$",
    re.MULTILINE,
)
OPERATION_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| (?P<status>[a-z ]+) \|$",
    re.MULTILINE,
)
# Section 13 carries a unit column between the name and the status.
LIMIT_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| [^|]+ \| (?P<status>[a-z ]+) \|$",
    re.MULTILINE,
)


def section(document: str, heading: str, next_heading: str) -> str:
    start = document.index(heading)
    end = document.index(next_heading, start)
    return document[start:end]


def numbered_section(document: str, heading: str) -> str:
    """One section, whether or not another follows it.

    Slicing to the end of the document instead reads the next section's rows as
    this one's, which is what a table-line count then reports as a parse failure.
    """
    start = document.index(heading)
    body = document[start + len(heading) :]
    offset = body.find("\n## ")
    return heading + (body if offset < 0 else body[:offset])


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

    # Section 12 is the vocabulary a capability's operation set draws from, and
    # `is_registered_operation` is what decides whether a verifier knows a value.
    # A table row without a constant is an operation nothing can authorize; a
    # constant the list omits is one every verifier silently ignores.
    operation_text = numbered_section(registry_text, "## 12. Capability operations")
    operation_rows = {
        match["name"]: int(match["value"], 16)
        for match in OPERATION_ROW.finditer(operation_text)
    }
    assert operation_rows, "no capability operation rows parsed"
    table_lines = sum(
        1 for line in operation_text.splitlines() if line.startswith("| `0x")
    )
    assert len(operation_rows) == table_lines, (
        f"parsed {len(operation_rows)} of {table_lines} capability operation rows"
    )
    assert 0 not in operation_rows.values(), "0x0000 is reserved"
    # The name map collapses a duplicate name, which the row count above catches.
    # Two names sharing a value survives both, and is what makes an operation set
    # ambiguous on the wire.
    assert len(set(operation_rows.values())) == len(operation_rows), (
        "duplicate capability operation value"
    )
    operation_rust_rows = {
        match["name"]: int(match["value"], 16)
        for match in RUST_CONSTANT.finditer(rust_module(rust_text, "operation"))
    }
    assert operation_rust_rows == operation_rows, (
        "Rust/operation registry mismatch: "
        f"Rust-only={operation_rust_rows.keys() - operation_rows.keys()}, "
        f"registry-only={operation_rows.keys() - operation_rust_rows.keys()}"
    )
    listed_operations = re.search(
        r"pub const REGISTERED_OPERATIONS: \[u64; (?P<count>\d+)\] = \[(?P<body>[^\]]*)\];",
        rust_text,
    )
    assert listed_operations, "REGISTERED_OPERATIONS not found"
    listed_operation_names = re.findall(
        r"operation::([A-Z0-9_]+)", listed_operations["body"]
    )
    assert len(listed_operation_names) == int(listed_operations["count"]), (
        f"REGISTERED_OPERATIONS declares {listed_operations['count']} entries "
        f"but lists {len(listed_operation_names)}"
    )
    assert set(listed_operation_names) == operation_rust_rows.keys(), (
        "REGISTERED_OPERATIONS/operation mismatch: "
        f"listed-only={set(listed_operation_names) - operation_rust_rows.keys()}, "
        f"constant-only={operation_rust_rows.keys() - set(listed_operation_names)}"
    )

    # Section 13 is the same shape as section 12 and needs the same two checks,
    # because a limit is what a verifier refuses a capability over.
    limit_text = numbered_section(registry_text, "## 13. Capability resource limits")
    limit_rows = {
        match["name"]: int(match["value"], 16)
        for match in LIMIT_ROW.finditer(limit_text)
    }
    assert limit_rows, "no capability limit rows parsed"
    table_lines = sum(1 for line in limit_text.splitlines() if line.startswith("| `0x"))
    assert len(limit_rows) == table_lines, (
        f"parsed {len(limit_rows)} of {table_lines} capability limit rows"
    )
    assert 0 not in limit_rows.values(), "0x0000 is reserved"
    assert len(set(limit_rows.values())) == len(limit_rows), (
        "duplicate capability limit value"
    )
    limit_rust_rows = {
        match["name"]: int(match["value"], 16)
        for match in RUST_CONSTANT.finditer(rust_module(rust_text, "resource_limit"))
    }
    assert limit_rust_rows == limit_rows, (
        "Rust/limit registry mismatch: "
        f"Rust-only={limit_rust_rows.keys() - limit_rows.keys()}, "
        f"registry-only={limit_rows.keys() - limit_rust_rows.keys()}"
    )
    listed_limits = re.search(
        r"pub const REGISTERED_LIMITS: \[u64; (?P<count>\d+)\] = \[(?P<body>[^\]]*)\];",
        rust_text,
    )
    assert listed_limits, "REGISTERED_LIMITS not found"
    listed_limit_names = re.findall(r"resource_limit::([A-Z0-9_]+)", listed_limits["body"])
    assert len(listed_limit_names) == int(listed_limits["count"]), (
        f"REGISTERED_LIMITS declares {listed_limits['count']} entries "
        f"but lists {len(listed_limit_names)}"
    )
    assert set(listed_limit_names) == limit_rust_rows.keys(), (
        "REGISTERED_LIMITS/resource_limit mismatch: "
        f"listed-only={set(listed_limit_names) - limit_rust_rows.keys()}, "
        f"constant-only={limit_rust_rows.keys() - set(listed_limit_names)}"
    )

    # The Auth column of wire.md section 5 is enforced by
    # `requires_authentication`. Nothing else compares the two, so the column
    # and the gate could drift silently.
    wire_text = (root / "spec" / "wire.md").read_text(encoding="utf-8")
    behavior_text = section(
        wire_text, "## 5. Frame behavior registry", "## 6. State and assurance"
    )
    behavior_rows = {
        match["name"]: match["auth"] for match in BEHAVIOR_ROW.finditer(behavior_text)
    }
    assert behavior_rows, "no frame behavior rows parsed"
    # Every table line parsed, so a row the regex silently skips cannot make
    # this check weaker than it reads.
    table_lines = sum(1 for line in behavior_text.splitlines() if line.startswith("| `"))
    assert len(behavior_rows) == table_lines, (
        f"parsed {len(behavior_rows)} of {table_lines} frame behavior rows"
    )
    assert behavior_rows.keys() == registry_rows.keys(), (
        "frame registry/behavior mismatch: "
        f"registry-only={registry_rows.keys() - behavior_rows.keys()}, "
        f"behavior-only={behavior_rows.keys() - registry_rows.keys()}"
    )
    exempt = re.search(
        r"pub const fn requires_authentication\(frame_type: u64\) -> bool \{"
        r".*?!matches!\((?P<body>.*?)\)\n\}",
        rust_text,
        re.DOTALL,
    )
    assert exempt, "requires_authentication not found"
    exempt_names = set(re.findall(r"ty::([A-Z0-9_]+)", exempt["body"]))
    for name, auth in behavior_rows.items():
        # A phase-dependent frame is never refused: a peer has to be able to
        # report a fault before it authenticates.
        expected_exempt = auth in ("no", "depends on phase")
        assert (name in exempt_names) == expected_exempt, (
            f"{name}: wire.md says auth {auth!r}, "
            f"requires_authentication says {name not in exempt_names}"
        )
    unknown = exempt_names - behavior_rows.keys()
    assert not unknown, f"requires_authentication exempts unlisted frames: {unknown}"

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
