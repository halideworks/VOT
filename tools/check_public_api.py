#!/usr/bin/env python3
"""Compare each crate's importable public surface against a committed snapshot.

Renders rustdoc JSON with the pinned nightly toolchain and walks the module
tree from the crate root, recording every importable path with its item kind:
public modules, their public items, and `pub use` re-exports (globs expanded
when the target is in this crate). A module split that keeps its facade
re-exports produces an identical snapshot; a dropped, renamed, or moved
public item does not.

The snapshot pins paths and kinds. Signatures, trait impls, and methods are
not recorded here; those ride the workspace compile and test gates.

Usage:
    check_public_api.py            # compare every crate, exit 1 on any diff
    check_public_api.py --update   # regenerate every snapshot
    check_public_api.py --crate vot-codec [--update]
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
from pathlib import Path

NIGHTLY = "nightly-2026-07-15"
REPO = Path(__file__).resolve().parent.parent
SNAPSHOTS = REPO / "test-vectors" / "public-api"

# Feature-gated public surface is part of the API; crates whose gates add
# public items are rendered with those features on.
FEATURES: dict[str, list[str]] = {
    "vot-cli": ["wire"],
    "vot-transport-quiche": ["live"],
    "vot-transport-msquic": ["live"],
}


def workspace_crates() -> list[str]:
    return sorted(path.name for path in (REPO / "crates").iterdir() if path.is_dir())


def render(crate: str) -> Path:
    cargo = os.environ.get("VOT_CARGO", "cargo")
    command = [cargo, f"+{NIGHTLY}", "rustdoc", "-p", crate, "--lib", "--locked"]
    for feature in FEATURES.get(crate, []):
        command += ["--features", feature]
    command += ["--", "-Zunstable-options", "--output-format", "json"]
    subprocess.run(command, cwd=REPO, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    return target / "doc" / f"{crate.replace('-', '_')}.json"


def item_kind(item: dict) -> str:
    inner = item.get("inner")
    if isinstance(inner, dict) and inner:
        return next(iter(inner))
    return str(inner)


def surface(document: dict) -> list[str]:
    index: dict[str, dict] = {str(key): value for key, value in document["index"].items()}
    lines: set[str] = set()
    visited: set[tuple[str, str]] = set()

    def walk(module_id: str, prefix: str) -> None:
        module = index[module_id]
        for child_id in module["inner"]["module"]["items"]:
            emit(str(child_id), prefix)

    def emit(child_id: str, prefix: str) -> None:
        if (child_id, prefix) in visited:
            return
        visited.add((child_id, prefix))
        item = index.get(child_id)
        if item is None:
            return
        kind = item_kind(item)
        if kind == "use":
            reexport(item["inner"]["use"], prefix)
            return
        if item.get("visibility") != "public":
            return
        name = item.get("name")
        if name is None:
            return
        path = f"{prefix}::{name}"
        lines.add(f"{kind} {path}")
        if kind == "module":
            walk(child_id, path)

    def reexport(use: dict, prefix: str) -> None:
        target_id = use.get("id")
        target = index.get(str(target_id)) if target_id is not None else None
        if use.get("is_glob"):
            if target is not None and item_kind(target) == "module":
                walk(str(target_id), prefix)
            else:
                lines.add(f"glob {prefix}::* <- {use['source']}")
            return
        name = use["name"]
        if target is None:
            lines.add(f"use {prefix}::{name} <- {use['source']}")
            return
        lines.add(f"{item_kind(target)} {prefix}::{name}")
        if item_kind(target) == "module":
            walk(str(target_id), f"{prefix}::{name}")

    root = str(document["root"])
    crate_name = index[root]["name"]
    walk(root, crate_name)
    return sorted(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--crate", action="append")
    arguments = parser.parse_args()
    crates = arguments.crate or workspace_crates()

    failed = []
    for crate in crates:
        lines = surface(json.loads(render(crate).read_text()))
        snapshot = SNAPSHOTS / f"{crate}.txt"
        if arguments.update:
            SNAPSHOTS.mkdir(parents=True, exist_ok=True)
            snapshot.write_text("\n".join(lines) + "\n")
            print(f"wrote {snapshot.relative_to(REPO)} ({len(lines)} items)")
            continue
        expected = snapshot.read_text().splitlines() if snapshot.exists() else []
        if lines != expected:
            failed.append(crate)
            for line in difflib.unified_diff(
                expected, lines, f"{crate} (snapshot)", f"{crate} (built)", lineterm=""
            ):
                print(line)
    if failed:
        print(f"public API drifted: {', '.join(failed)}")
        return 1
    if not arguments.update:
        print(f"public API unchanged across {len(crates)} crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
