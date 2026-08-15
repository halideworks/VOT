#!/usr/bin/env python3
"""Check registry uniqueness, criticality, and Rust constant synchronization.

The identifier tables live in spec/registries.yaml. spec/registries.md is the
human view of those tables. vot-codec holds the Rust constants. A row that
exists in only one of them is a failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__:
    from .registries import check_registries, load_registries
else:
    from registries import check_registries, load_registries


def validate(root: Path) -> None:
    document = load_registries(root / "spec" / "registries.yaml")
    markdown = (root / "spec" / "registries.md").read_text(encoding="utf-8")
    rust = (root / "crates" / "vot-codec" / "src" / "lib.rs").read_text(encoding="utf-8")
    generated = (root / "crates" / "vot-codec" / "src" / "generated.rs").read_text(
        encoding="utf-8"
    )
    wire = (root / "spec" / "wire.md").read_text(encoding="utf-8")
    failures = check_registries(document, markdown, rust, wire, generated)
    if failures:
        raise AssertionError("; ".join(failures))


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
