#!/usr/bin/env python3
"""Cross-document acceptance checks for the VOT v0.3 W0 specification gate."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REQUIRED_FILES = (
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "PATENTS.md",
    "PRIOR_ART.md",
    "CONTRIBUTING.md",
    "DEPENDENCIES.md",
    "REPRODUCIBILITY.md",
    "Cargo.toml",
    "Cargo.lock",
    "spec/architecture.md",
    "spec/object.md",
    "spec/proofs.md",
    "spec/commit.md",
    "spec/wire.md",
    "spec/registries.md",
    "spec/registries.yaml",
    "spec/security.md",
    "spec/telemetry.md",
    "spec/manifest.cddl",
    "spec/proof-bundle.cddl",
    "spec/receipt.cddl",
    "security/abuse-cases.yaml",
    "test-vectors/wire/frame-envelope.json",
)

REQUIRED_FRAMES = {
    "HELLO",
    "SETTINGS",
    "SETTINGS_ACK",
    "AUTH_CONTEXT",
    "SESSION_OPEN",
    "SESSION_ACCEPT",
    "SESSION_REJECT",
    "PACKAGE_DESCRIPTOR",
    "MANIFEST_REQUEST",
    "MANIFEST_PAGE",
    "PROGRESSIVE_PAGE",
    "SEAL",
    "HAVE",
    "RANGE_REQUEST",
    "PROOF_BUNDLE",
    "DATA_RECORD",
    "RANGE_CANCEL",
    "CAPACITY",
    "TRANSIT_VERIFIED",
    "CHUNK_DURABLE",
    "CHUNK_AT_REST_VERIFIED",
    "PUBLISH_RECEIPT",
    "DATAGRAM_CREDIT",
    "CODING_EPOCH_OPEN",
    "GEN_STATE",
    "GEN_DONE",
    "CODING_EPOCH_CLOSE",
    "PING",
    "GOAWAY",
    "ERROR",
    "SOURCE_SCORE_HINT",
    "JOB_PRIORITY_UPDATE",
}


def read(root: Path, relative: str) -> str:
    path = root / relative
    assert path.is_file(), f"missing {relative}"
    text = path.read_text(encoding="utf-8")
    assert text.strip(), f"empty {relative}"
    return text


def validate_cddl(text: str, name: str) -> None:
    stack: list[str] = []
    pairs = {"}": "{", "]": "[", ")": "("}
    for line in text.splitlines():
        code = line.split(";", 1)[0]
        in_string = False
        escaped = False
        for character in code:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character in "{[(":
                stack.append(character)
            elif character in "}])":
                assert stack and stack.pop() == pairs[character], (
                    f"unbalanced {character} in {name}"
                )
    assert not stack, f"unclosed delimiter in {name}: {stack}"


def validate(root: Path) -> None:
    documents = {relative: read(root, relative) for relative in REQUIRED_FILES}

    architecture = documents["spec/architecture.md"]
    assert len(re.findall(r"^\| R[1-8]:", architecture, re.MULTILINE)) == 8
    assert "Fast | `TRANSIT_VERIFIED`" in architecture
    assert "Balanced | `DURABLE`" in architecture
    assert "Strict | `AT_REST_VERIFIED`" in architecture
    assert "no automatic reset" in architecture

    adr_dir = root / "adr"
    adrs = sorted(adr_dir.glob("[0-9][0-9][0-9][0-9]-*.md"))
    assert [path.name[:4] for path in adrs] == [
        f"{number:04d}" for number in range(1, len(adrs) + 1)
    ]
    for path in adrs:
        assert "Status: Accepted" in path.read_text(encoding="utf-8"), path.name

    registries = json.loads(documents["spec/registries.yaml"])
    allocated_frames = {row["name"] for row in registries["frames"]}
    assert allocated_frames == REQUIRED_FRAMES, (
        f"frame registry mismatch: missing={sorted(REQUIRED_FRAMES - allocated_frames)}, "
        f"extra={sorted(allocated_frames - REQUIRED_FRAMES)}"
    )
    schemes = {row["name"]: row for row in registries["receipt_schemes"]}
    assert schemes["ED25519"]["authenticator_length"] == "64 bytes"
    assert schemes["HMAC_SHA256"]["authenticator_length"] == "32 bytes"

    proofs = documents["spec/proofs.md"]
    for phrase in (
        "group log `6`",
        "u64 little-endian object byte_length",
        "BEP 52 order",
        "SHA-256(\"\")",
        "reordered, or trailing hashes invalidate the proof",
    ):
        assert phrase in proofs, f"proof freeze missing: {phrase}"

    commit = documents["spec/commit.md"]
    for phrase in (
        "Published(profile=Fast)     => TransitVerified",
        "Published(profile=Balanced) => Durable",
        "Published(profile=Strict)   => AtRestVerified",
        "Poisoned                    => never Published",
        "StaleIncarnation            => never Current",
    ):
        assert phrase in commit, f"commit invariant missing: {phrase}"

    for relative in ("spec/manifest.cddl", "spec/proof-bundle.cddl", "spec/receipt.cddl"):
        validate_cddl(documents[relative], relative)

    telemetry = documents["spec/telemetry.md"].lower()
    assert "default level is `pseudonymous`" in telemetry
    assert "raw paths or capability tokens" in telemetry

    license_text = documents["LICENSE"]
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in license_text and "Version 3, 19 November 2007" in license_text
    assert "proprietary source" in documents["CONTRIBUTING.md"].lower()
    assert "not legal advice" in documents["PATENTS.md"].lower()
    assert "not legal advice" in documents["PRIOR_ART.md"].lower()

    cargo_lock = documents["Cargo.lock"]
    assert "version = 4" in cargo_lock and 'name = "vot-codec"' in cargo_lock


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        validate(root)
    except (AssertionError, OSError, ValueError) as error:
        print(f"Wave 0 validation failed: {error}", file=sys.stderr)
        return 1
    print("Wave 0 document validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
