#!/usr/bin/env python3
"""Reject host dependencies outside the thin WASM facade boundary."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .check_sdk_dependencies import ALLOWED_PACKAGES as SDK_PACKAGES
else:
    from check_sdk_dependencies import ALLOWED_PACKAGES as SDK_PACKAGES

REPO = Path(__file__).resolve().parent.parent

ALLOWED_PACKAGES = SDK_PACKAGES | {
    "bumpalo",
    "once_cell",
    "rustversion",
    "vot-wasm",
    "wasm-bindgen",
    "wasm-bindgen-macro",
    "wasm-bindgen-macro-support",
    "wasm-bindgen-shared",
}


def unexpected_packages(packages: set[str]) -> list[str]:
    return sorted(packages - ALLOWED_PACKAGES)


def dependency_packages() -> set[str]:
    cargo = os.environ.get("VOT_CARGO", "cargo")
    result = subprocess.run(
        [
            cargo,
            "tree",
            "-p",
            "vot-wasm",
            "--no-default-features",
            "--edges",
            "normal",
            "--target",
            "wasm32-unknown-unknown",
            "--locked",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.split()[0] for line in result.stdout.splitlines() if line.strip()}


def main() -> int:
    unexpected = unexpected_packages(dependency_packages())
    if unexpected:
        print(
            "vot-wasm dependency boundary includes unreviewed packages: "
            + ", ".join(unexpected),
            file=sys.stderr,
        )
        return 1
    print("vot-wasm dependency boundary is host-neutral")
    return 0


if __name__ == "__main__":
    sys.exit(main())
