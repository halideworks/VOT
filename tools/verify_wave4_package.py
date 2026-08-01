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


def decode_head(data: bytes, cursor: int) -> tuple[int, int, int]:
    first = data[cursor]
    cursor += 1
    major = first >> 5
    additional = first & 0x1F
    if additional <= 23:
        return major, additional, cursor
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths[additional]
    raw, cursor = take(data, cursor, width)
    value = int.from_bytes(raw, "big")
    assert value >= (24, 0x100, 0x1_0000, 0x1_0000_0000)[width.bit_length() - 1]
    return major, value, cursor


def decode_cbor(data: bytes, cursor: int = 0) -> tuple[object, int]:
    if data[cursor] == 0xF6:
        return None, cursor + 1
    major, value, cursor = decode_head(data, cursor)
    if major == 0:
        return value, cursor
    if major in (2, 3):
        raw, cursor = take(data, cursor, value)
        return (raw if major == 2 else raw.decode("utf-8")), cursor
    if major == 4:
        values = []
        for _ in range(value):
            item, cursor = decode_cbor(data, cursor)
            values.append(item)
        return values, cursor
    if major == 5:
        values = {}
        previous = -1
        for _ in range(value):
            key, cursor = decode_cbor(data, cursor)
            assert isinstance(key, int) and key > previous
            previous = key
            item, cursor = decode_cbor(data, cursor)
            values[key] = item
        return values, cursor
    raise AssertionError("unsupported CBOR value")


def canonical_path(path: list[object]) -> bytes:
    assert path and len(path) <= 256
    encoded = bytearray(struct.pack(">H", len(path)))
    for component in path:
        assert isinstance(component, str)
        raw = component.encode("utf-8")
        assert 0 < len(raw) <= 255
        encoded.extend(struct.pack(">H", len(raw)))
        encoded.extend(raw)
    return bytes(encoded)


def verify() -> None:
    manifest_dir = BUNDLE / "manifest"
    seal_bytes = (manifest_dir / "seal.cbor").read_bytes()
    seal, cursor = decode_cbor(seal_bytes)
    assert cursor == len(seal_bytes) and isinstance(seal, dict)
    manifest_id = seal[1]
    page_count = seal[2]
    final_digest = seal[3]
    subject = seal[4]
    assert subject[0] == 1 and subject[1] == 1
    declared_root = subject[2]
    declared_length = subject[3]
    commitments = seal[5]
    assert page_count == len(commitments) > 0

    transcript = bytearray(DOMAIN)
    logical_length = 0
    entries = 0
    previous_digest = bytes(32)

    for page_index, commitment in enumerate(commitments):
        assert commitment[0] == page_index and commitment[2] == []
        encoded = (manifest_dir / f"{page_index:016}.cbor").read_bytes()
        digest = blake3_hash(encoded)
        assert commitment[1] == digest
        page, cursor = decode_cbor(encoded)
        assert cursor == len(encoded) and isinstance(page, dict)
        assert page[0] == 0
        assert page[1] == manifest_id
        assert page[2] == page_index
        assert page[3] in (None, page_count)
        assert page[4] == previous_digest
        assert page[5] == 0
        previous_digest = digest

        for entry in page[6]:
            assert entry[1] == 0
            path = canonical_path(entry[0])
            length = entry[2]
            storage = entry[3]
            entries += 1
            transcript.extend(struct.pack(">I", len(path)))
            transcript.extend(path)
            transcript.extend(struct.pack(">H", 2))
            transcript.extend(struct.pack(">Q", length))

            if storage[0] == 0:
                logical = storage[1]
                object_id = logical
                offset = 0
            else:
                assert storage[0] == 1
                object_id = storage[1]
                offset = storage[2]
                assert storage[3] == length
                logical = storage[4]
            assert logical[0] == 2 and logical[2] == length
            logical_root = logical[1]
            transcript.extend(logical_root)
            logical_length += length

            assert object_id[0] == 2
            object_root = object_id[1]
            object_length = object_id[2]
            object_bytes = (
                BUNDLE / "objects" / f"{object_root.hex()}.obj"
            ).read_bytes()
            assert len(object_bytes) == object_length
            assert sha_root(object_bytes) == object_root
            logical_bytes = object_bytes[offset:offset + length]
            assert len(logical_bytes) == length
            assert sha_root(logical_bytes) == logical_root

    assert previous_digest == final_digest
    assert entries > 0
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
