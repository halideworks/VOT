#!/usr/bin/env python3
"""Independent validator for the normative VOT frame-envelope vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

MAX_VARINT = (1 << 62) - 1
HARD_MAX = 16 * 1024 * 1024
DEFAULT_UNKNOWN_MAX = 1024 * 1024

FRAME_LIMITS = {
    0x01: 4 * 1024,
    0x03: 16 * 1024,
    0x05: 0,
    0x07: 64 * 1024,
    0x09: 64 * 1024,
    0x0B: 64 * 1024,
    0x0D: 64 * 1024,
    0x21: 1024 * 1024,
    0x23: 64 * 1024,
    0x25: 1024 * 1024,
    0x27: 1024 * 1024,
    0x29: 256 * 1024,
    0x2B: 4 * 1024 * 1024,
    0x2D: 1024 * 1024,
    0x2F: HARD_MAX,
    0x31: 256 * 1024,
    0x33: 64 * 1024,
    0x40: 4 * 1024,
    0x43: 64 * 1024,
    0x45: 64 * 1024,
    0x47: 64 * 1024,
    0x49: 64 * 1024,
    0x60: 4 * 1024,
    0x62: 64 * 1024,
    0x64: 64 * 1024,
    0x66: 64 * 1024,
    0x68: 64 * 1024,
    0x80: 0,
    0x83: 4 * 1024,
    0x85: 64 * 1024,
    0x86: 64 * 1024,
    0x89: 64 * 1024,
}


class VectorError(Exception):
    def __init__(self, code: str, **details: int) -> None:
        super().__init__(code)
        self.code = code
        self.details = details


def encode_varint(value: int) -> bytes:
    if not 0 <= value <= MAX_VARINT:
        raise ValueError(value)
    if value < 1 << 6:
        return value.to_bytes(1, "big")
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise VectorError("INCOMPLETE")
    width = 1 << (data[offset] >> 6)
    if len(data) - offset < width:
        raise VectorError("INCOMPLETE")
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, offset + width


def is_grease(frame_type: int) -> bool:
    return 0x1F00 <= frame_type <= 0x1FFE and frame_type % 2 == 0


def decode_frames(data: bytes) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data):
        frame_type, offset = decode_varint(data, offset)
        length, offset = decode_varint(data, offset)
        registered_limit = FRAME_LIMITS.get(frame_type)
        limit = min(
            registered_limit if registered_limit is not None else DEFAULT_UNKNOWN_MAX,
            HARD_MAX,
        )
        if length > limit:
            raise VectorError(
                "FRAME_TOO_LARGE", type=frame_type, length=length, limit=limit
            )
        if registered_limit is None and frame_type % 2 == 1:
            raise VectorError("UNKNOWN_CRITICAL_FRAME", type=frame_type)
        end = offset + length
        if end > len(data):
            raise VectorError("INCOMPLETE")
        payload = data[offset:end]
        offset = end
        if registered_limit is not None and not is_grease(frame_type):
            frames.append(
                {"kind": "known", "type": frame_type, "payload_hex": payload.hex()}
            )
        else:
            frames.append(
                {
                    "kind": "skipped_optional",
                    "type": frame_type,
                    "payload_length": length,
                }
            )
    return frames


def validate(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["hard_max_frame_payload"] == HARD_MAX
    assert document["default_max_unknown_payload"] == DEFAULT_UNKNOWN_MAX

    for vector in document["varints"]:
        encoded = bytes.fromhex(vector["canonical_hex"])
        assert encode_varint(vector["value"]) == encoded, vector
        decoded, offset = decode_varint(encoded, 0)
        assert decoded == vector["value"] and offset == len(encoded), vector

    for vector in document["frames"]:
        expected = vector["expected"]
        try:
            frames = decode_frames(bytes.fromhex(vector["hex"]))
        except VectorError as error:
            assert expected["result"] == "error", vector["name"]
            assert expected["error"] == error.code, vector["name"]
            for key, value in error.details.items():
                assert expected[key] == value, vector["name"]
        else:
            assert expected["result"] == "ok", vector["name"]
            assert expected["frames"] == frames, vector["name"]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "test-vectors" / "wire" / "frame-envelope.json"
    try:
        validate(path)
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"wire vector validation failed: {error}", file=sys.stderr)
        return 1
    print("wire vector validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
