#!/usr/bin/env python3
"""Reject dependencies outside the stable pure SDK boundary."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "crates" / "vot-sdk" / "Cargo.toml"

ALLOWED_PACKAGES = frozenset(
    {
        "arrayref",
        "arrayvec",
        "blake3",
        "block-buffer",
        "cfg-if",
        "const-oid",
        "constant_time_eq",
        "cpufeatures",
        "crypto-common",
        "curve25519-dalek",
        "curve25519-dalek-derive",
        "digest",
        "ed25519",
        "ed25519-dalek",
        "fiat-crypto",
        "generic-array",
        "hybrid-array",
        "libc",
        "proc-macro2",
        "quote",
        "sha2",
        "signature",
        "subtle",
        "syn",
        "tinyvec",
        "tinyvec_macros",
        "typenum",
        "unicode-ident",
        "unicode-normalization",
        "vot-cbor",
        "vot-codec",
        "vot-commit-model",
        "vot-coverage",
        "vot-fec",
        "vot-manifest",
        "vot-object",
        "vot-package",
        "vot-proof-blake3",
        "vot-proof-catalog",
        "vot-proof-sha256",
        "vot-proof-store",
        "vot-receipt",
        "vot-resume-core",
        "vot-sdk",
        "vot-verified-range",
        "vot-verifier",
        "zeroize",
    }
)


def unexpected_packages(packages: set[str]) -> list[str]:
    return sorted(packages - ALLOWED_PACKAGES)


def dependency_packages() -> set[str]:
    cargo = os.environ.get("VOT_CARGO", "cargo")
    result = subprocess.run(
        [
            cargo,
            "tree",
            "-p",
            "vot-sdk",
            "--no-default-features",
            "--edges",
            "normal",
            "--target",
            "all",
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
    manifest = tomllib.loads(MANIFEST.read_text())
    if manifest.get("features", {}).get("default") != []:
        print("vot-sdk default features must be empty", file=sys.stderr)
        return 1
    unexpected = unexpected_packages(dependency_packages())
    if unexpected:
        print(
            "vot-sdk dependency boundary includes unreviewed packages: "
            + ", ".join(unexpected),
            file=sys.stderr,
        )
        return 1
    print("vot-sdk dependency boundary is pure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
