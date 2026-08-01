#!/usr/bin/env python3
"""Independent standard-library verifier for the Wave 4 package vector."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from verify_wave1_vectors import blake3_hash, sha_root

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "test-vectors/xfer/bundle"
DOMAIN = b"VOT package v0\0"


def take(data: bytes, cursor: int, length: int) -> tuple[bytes, int]:
    end = cursor + length
    assert end <= len(data)
    return data[cursor:end], end


def verify() -> None:
    manifest = (BUNDLE / "manifest.vot").read_bytes()
    assert manifest[:8] == b"VOTPKG0\n"
    declared_root = manifest[8:40]
    declared_length, entries = struct.unpack(">QQ", manifest[40:56])
    assert entries > 0
    cursor = 56
    transcript = bytearray(DOMAIN)
    logical_length = 0

    for _ in range(entries):
        encoded_length = struct.unpack(">I", manifest[cursor:cursor + 4])[0]
        cursor += 4
        path, cursor = take(manifest, cursor, encoded_length)
        length = struct.unpack(">Q", manifest[cursor:cursor + 8])[0]
        cursor += 8
        logical_root, cursor = take(manifest, cursor, 32)
        kind = manifest[cursor]
        cursor += 1

        transcript.extend(struct.pack(">I", encoded_length))
        transcript.extend(path)
        transcript.extend(struct.pack(">H", 2))
        transcript.extend(struct.pack(">Q", length))
        transcript.extend(logical_root)
        logical_length += length

        if kind == 0:
            object_root = logical_root
            object_length = length
            offset = 0
        elif kind == 1:
            object_root, cursor = take(manifest, cursor, 32)
            object_length, offset = struct.unpack(">QQ", manifest[cursor:cursor + 16])
            cursor += 16
        else:
            raise AssertionError("unknown storage kind")

        object_bytes = (BUNDLE / "objects" / f"{object_root.hex()}.obj").read_bytes()
        assert len(object_bytes) == object_length
        assert sha_root(object_bytes) == object_root
        logical = object_bytes[offset:offset + length]
        assert len(logical) == length
        assert sha_root(logical) == logical_root

    assert cursor == len(manifest)
    assert logical_length == declared_length
    assert blake3_hash(bytes(transcript)) == declared_root
    receipt = json.loads((BUNDLE / "receipt.json").read_text())
    assert receipt == {
        "assurance": "PUBLISHED",
        "suite": 1,
        "root": declared_root.hex(),
        "length": declared_length,
        "entries": entries,
    }
    print("PASS independent_root_recomputation_matches_receipt")


if __name__ == "__main__":
    verify()
