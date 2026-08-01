#!/usr/bin/env python3
"""Fail when the Rust commit Event enum and TLA action map drift."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    rust = (ROOT / "crates/vot-commit-model/src/lib.rs").read_text(encoding="utf-8")
    tla = (ROOT / "models/tla/Commit.tla").read_text(encoding="utf-8")

    body = re.search(r"pub enum Event \{(?P<body>.*?)^\}", rust, re.MULTILINE | re.DOTALL)
    assert body, "Rust Event enum not found"
    events = set(re.findall(r"^\s+([A-Z][A-Za-z0-9]+),$", body["body"], re.MULTILINE))

    mappings = dict(
        re.findall(r"^\\\* RUST_EVENT ([A-Z][A-Za-z0-9]+) -> ([A-Z][A-Za-z0-9]+)$", tla, re.MULTILINE)
    )
    assert set(mappings) == events, (
        f"commit model event drift: Rust-only={sorted(events - set(mappings))}, "
        f"TLA-map-only={sorted(set(mappings) - events)}"
    )
    actions = set(re.findall(r"^([A-Z][A-Za-z0-9]+)\([^=\n]*\) ==", tla, re.MULTILINE))
    missing = set(mappings.values()) - actions
    assert not missing, f"mapped TLA actions are undefined: {sorted(missing)}"
    print("commit Rust/TLA event synchronization: PASS")


if __name__ == "__main__":
    main()
