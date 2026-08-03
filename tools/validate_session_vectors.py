#!/usr/bin/env python3
"""Independent validator for the session authentication vectors.

Reimplements spec/session.cddl and spec/wire.md section 1.1 from the
specification text rather than from the Rust crate, so agreement between the
two is evidence and not a tautology.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

MIN_NONCE = 16
MAX_NONCE = 64
MAX_FORMATS = 16
MAX_CAPABILITY = 49_152
MAX_SCOPE = 4_096
MAX_DETAIL = 1_024
MAX_FORMAT = 65_535
FRAME_LIMIT = 64 * 1024

FRAME_TYPES = {
    "auth_context": 0x07,
    "session_open": 0x09,
    "session_accept": 0x0B,
    "session_reject": 0x0D,
}
REJECT_REASONS = {0x0201, 0x0202, 0x0203}


class VectorError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def encode_varint(value: int) -> bytes:
    if value < 1 << 6:
        return value.to_bytes(1, "big")
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise VectorError("MALFORMED_FRAME")
    width = 1 << (data[offset] >> 6)
    if len(data) - offset < width:
        raise VectorError("MALFORMED_FRAME")
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, offset + width


def cbor_head(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value < 1 << 8:
        return bytes([prefix | 24, value])
    if value < 1 << 16:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value < 1 << 32:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def read_head(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise VectorError("MALFORMED_FRAME")
    first = data[offset]
    major = first >> 5
    additional = first & 0x1F
    offset += 1
    if additional < 24:
        return major, additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or len(data) - offset < width:
        raise VectorError("MALFORMED_FRAME")
    value = int.from_bytes(data[offset : offset + width], "big")
    offset += width
    # RFC 8949 core deterministic encoding: the shortest head that fits.
    minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
    if value < minimum:
        raise VectorError("MALFORMED_FRAME")
    return major, value, offset


def read_uint(data: bytes, offset: int) -> tuple[int, int]:
    major, value, offset = read_head(data, offset)
    if major != 0:
        raise VectorError("MALFORMED_FRAME")
    return value, offset


def read_key(data: bytes, offset: int, expected: int) -> int:
    value, offset = read_uint(data, offset)
    if value != expected:
        raise VectorError("MALFORMED_FRAME")
    return offset


def read_string(data: bytes, offset: int, major: int, maximum: int) -> tuple[bytes, int]:
    actual, length, offset = read_head(data, offset)
    if actual != major:
        raise VectorError("MALFORMED_FRAME")
    if length > maximum:
        raise VectorError("FRAME_TOO_LARGE")
    if len(data) - offset < length:
        raise VectorError("MALFORMED_FRAME")
    return data[offset : offset + length], offset + length


def read_map(data: bytes, offset: int, expected: int) -> int:
    major, value, offset = read_head(data, offset)
    if major != 5 or value != expected:
        raise VectorError("MALFORMED_FRAME")
    return offset


def encode_auth_context(case: dict[str, Any]) -> bytes:
    nonce = bytes.fromhex(case["nonce_hex"])
    formats = case["formats"]
    check_auth_context(nonce, case["binding"], formats)
    body = cbor_head(5, 4)
    body += cbor_head(0, 0) + cbor_head(0, 0)
    body += cbor_head(0, 1) + cbor_head(2, len(nonce)) + nonce
    body += cbor_head(0, 2) + cbor_head(0, case["binding"])
    body += cbor_head(0, 3) + cbor_head(4, len(formats))
    for value in formats:
        body += cbor_head(0, value)
    return body


def check_auth_context(nonce: bytes, binding: int, formats: list[int]) -> None:
    if not MIN_NONCE <= len(nonce) <= MAX_NONCE:
        raise VectorError("INVALID_VALUE")
    if binding not in (0, 1):
        raise VectorError("INVALID_VALUE")
    if len(formats) > MAX_FORMATS:
        raise VectorError("FRAME_TOO_LARGE")
    if any(value < 1 or value > MAX_FORMAT for value in formats):
        raise VectorError("INVALID_VALUE")
    if any(a >= b for a, b in zip(formats, formats[1:])):
        raise VectorError("INVALID_VALUE")


def decode_auth_context(payload: bytes) -> dict[str, Any]:
    offset = read_map(payload, 0, 4)
    offset = read_key(payload, offset, 0)
    version, offset = read_uint(payload, offset)
    if version != 0:
        raise VectorError("INVALID_VALUE")
    offset = read_key(payload, offset, 1)
    nonce, offset = read_string(payload, offset, 2, MAX_NONCE)
    offset = read_key(payload, offset, 2)
    binding, offset = read_uint(payload, offset)
    offset = read_key(payload, offset, 3)
    major, count, offset = read_head(payload, offset)
    if major != 4:
        raise VectorError("MALFORMED_FRAME")
    if count > MAX_FORMATS:
        raise VectorError("FRAME_TOO_LARGE")
    formats = []
    for _ in range(count):
        value, offset = read_uint(payload, offset)
        formats.append(value)
    finish(payload, offset)
    check_auth_context(nonce, binding, formats)
    return {"nonce": nonce, "binding": binding, "formats": formats}


def encode_session_open(case: dict[str, Any]) -> bytes:
    session_id = bytes.fromhex(case["session_id_hex"])
    capability = bytes.fromhex(case["capability_hex"])
    scope = bytes.fromhex(case["requested_scope_hex"])
    proof = bytes.fromhex(case["binding_proof_hex"])
    check_session_open(session_id, case["capability_format"], capability, scope, proof)
    body = cbor_head(5, 6)
    body += cbor_head(0, 0) + cbor_head(0, 0)
    body += cbor_head(0, 1) + cbor_head(2, len(session_id)) + session_id
    body += cbor_head(0, 2) + cbor_head(0, case["capability_format"])
    body += cbor_head(0, 3) + cbor_head(2, len(capability)) + capability
    body += cbor_head(0, 4) + cbor_head(2, len(scope)) + scope
    body += cbor_head(0, 5) + cbor_head(2, len(proof)) + proof
    return body


def check_session_open(
    session_id: bytes,
    capability_format: int,
    capability: bytes,
    scope: bytes,
    proof: bytes,
) -> None:
    if len(session_id) != 16:
        raise VectorError("MALFORMED_FRAME")
    if capability_format < 1 or capability_format > MAX_FORMAT:
        raise VectorError("INVALID_VALUE")
    if len(capability) > MAX_CAPABILITY or len(scope) > MAX_SCOPE or len(proof) > MAX_SCOPE:
        raise VectorError("FRAME_TOO_LARGE")


def decode_session_open(payload: bytes) -> dict[str, Any]:
    offset = read_map(payload, 0, 6)
    offset = read_key(payload, offset, 0)
    version, offset = read_uint(payload, offset)
    if version != 0:
        raise VectorError("INVALID_VALUE")
    offset = read_key(payload, offset, 1)
    session_id, offset = read_string(payload, offset, 2, 16)
    offset = read_key(payload, offset, 2)
    capability_format, offset = read_uint(payload, offset)
    offset = read_key(payload, offset, 3)
    capability, offset = read_string(payload, offset, 2, MAX_CAPABILITY)
    offset = read_key(payload, offset, 4)
    scope, offset = read_string(payload, offset, 2, MAX_SCOPE)
    offset = read_key(payload, offset, 5)
    proof, offset = read_string(payload, offset, 2, MAX_SCOPE)
    finish(payload, offset)
    check_session_open(session_id, capability_format, capability, scope, proof)
    return {
        "session_id": session_id,
        "capability_format": capability_format,
        "capability": capability,
        "requested_scope": scope,
        "binding_proof": proof,
    }


def encode_session_accept(case: dict[str, Any]) -> bytes:
    session_id = bytes.fromhex(case["session_id_hex"])
    scope = bytes.fromhex(case["granted_scope_hex"])
    if len(session_id) != 16:
        raise VectorError("MALFORMED_FRAME")
    if len(scope) > MAX_SCOPE:
        raise VectorError("FRAME_TOO_LARGE")
    body = cbor_head(5, 3)
    body += cbor_head(0, 0) + cbor_head(0, 0)
    body += cbor_head(0, 1) + cbor_head(2, len(session_id)) + session_id
    body += cbor_head(0, 2) + cbor_head(2, len(scope)) + scope
    return body


def decode_session_accept(payload: bytes) -> dict[str, Any]:
    offset = read_map(payload, 0, 3)
    offset = read_key(payload, offset, 0)
    version, offset = read_uint(payload, offset)
    if version != 0:
        raise VectorError("INVALID_VALUE")
    offset = read_key(payload, offset, 1)
    session_id, offset = read_string(payload, offset, 2, 16)
    offset = read_key(payload, offset, 2)
    scope, offset = read_string(payload, offset, 2, MAX_SCOPE)
    finish(payload, offset)
    return {"session_id": session_id, "granted_scope": scope}


def encode_session_reject(case: dict[str, Any]) -> bytes:
    session_id = bytes.fromhex(case["session_id_hex"])
    detail = case["detail"].encode("utf-8")
    check_session_reject(session_id, case["reason"], detail)
    body = cbor_head(5, 4)
    body += cbor_head(0, 0) + cbor_head(0, 0)
    body += cbor_head(0, 1) + cbor_head(2, len(session_id)) + session_id
    body += cbor_head(0, 2) + cbor_head(0, case["reason"])
    body += cbor_head(0, 3) + cbor_head(3, len(detail)) + detail
    return body


def check_session_reject(session_id: bytes, reason: int, detail: bytes) -> None:
    if len(session_id) != 16:
        raise VectorError("MALFORMED_FRAME")
    if reason not in REJECT_REASONS or len(detail) > MAX_DETAIL:
        raise VectorError("INVALID_VALUE")


def decode_session_reject(payload: bytes) -> dict[str, Any]:
    offset = read_map(payload, 0, 4)
    offset = read_key(payload, offset, 0)
    version, offset = read_uint(payload, offset)
    if version != 0:
        raise VectorError("INVALID_VALUE")
    offset = read_key(payload, offset, 1)
    session_id, offset = read_string(payload, offset, 2, 16)
    offset = read_key(payload, offset, 2)
    reason, offset = read_uint(payload, offset)
    offset = read_key(payload, offset, 3)
    detail, offset = read_string(payload, offset, 3, MAX_DETAIL)
    finish(payload, offset)
    detail.decode("utf-8")
    check_session_reject(session_id, reason, detail)
    return {"session_id": session_id, "reason": reason, "detail": detail}


def finish(payload: bytes, offset: int) -> None:
    if offset != len(payload):
        raise VectorError("MALFORMED_FRAME")


ENCODERS = {
    "auth_context": encode_auth_context,
    "session_open": encode_session_open,
    "session_accept": encode_session_accept,
    "session_reject": encode_session_reject,
}
DECODERS = {
    "auth_context": decode_auth_context,
    "session_open": decode_session_open,
    "session_accept": decode_session_accept,
    "session_reject": decode_session_reject,
}


def frame(kind: str, payload: bytes) -> bytes:
    if len(payload) > FRAME_LIMIT:
        raise VectorError("FRAME_TOO_LARGE")
    return encode_varint(FRAME_TYPES[kind]) + encode_varint(len(payload)) + payload


def split_frame(data: bytes) -> tuple[str, bytes]:
    frame_type, offset = decode_varint(data, 0)
    length, offset = decode_varint(data, offset)
    names = {value: name for name, value in FRAME_TYPES.items()}
    if frame_type not in names:
        raise VectorError("WRONG_FRAME_TYPE")
    if length > FRAME_LIMIT:
        raise VectorError("FRAME_TOO_LARGE")
    if len(data) - offset != length:
        raise VectorError("MALFORMED_FRAME")
    return names[frame_type], data[offset:]


def canonical_line(kind: str, decoded: dict[str, Any], encoded: bytes) -> str:
    parts = ["ok", kind]
    if kind == "auth_context":
        parts.append(decoded["nonce"].hex())
        parts.append(str(decoded["binding"]))
        parts.extend(str(value) for value in decoded["formats"])
    elif kind == "session_open":
        parts.append(decoded["session_id"].hex())
        parts.append(str(decoded["capability_format"]))
        parts.append(decoded["capability"].hex())
        parts.append(decoded["requested_scope"].hex())
        parts.append(decoded["binding_proof"].hex())
    elif kind == "session_accept":
        parts.append(decoded["session_id"].hex())
        parts.append(decoded["granted_scope"].hex())
    else:
        parts.append(decoded["session_id"].hex())
        parts.append(str(decoded["reason"]))
        parts.append(decoded["detail"].hex())
    parts.append(f"re={encoded.hex()}")
    return "|".join(parts)


def validate(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    assert document["format"] == "vot-session-authentication-v1"
    requests: list[str] = []
    expectations: list[str] = []

    for case in document["canonical"]:
        kind = case["frame"]
        payload = ENCODERS[kind](case)
        encoded = frame(kind, payload)
        assert encoded.hex() == case["hex"], (
            f"{case['name']}: python={encoded.hex()[:64]} fixture={case['hex'][:64]}"
        )
        # Decoded from the fixture rather than from what was just encoded, so a
        # shared mistake in one direction cannot hide.
        name, body = split_frame(bytes.fromhex(case["hex"]))
        assert name == kind, f"{case['name']}: frame type {name}"
        decoded = DECODERS[kind](body)
        requests.append("session " + case["hex"])
        expectations.append(canonical_line(kind, decoded, encoded))

    for case in document["rejected"]:
        data = bytes.fromhex(case["hex"])
        try:
            name, body = split_frame(data)
            DECODERS[name](body)
        except VectorError as error:
            actual = error.code
        except (UnicodeDecodeError, ValueError):
            actual = "MALFORMED_FRAME"
        else:
            raise AssertionError(f"{case['name']}: accepted, expected {case['error']}")
        assert actual == case["error"], (
            f"{case['name']}: python={actual} expected={case['error']}"
        )
        requests.append("session " + case["hex"])
        expectations.append(f"err|{case['error']}")
    return requests, expectations


def oracle_lines(root: Path, requests: list[str]) -> list[str]:
    cargo = shlex.split(os.environ.get("VOT_CARGO", "cargo"))
    command = [*cargo, "run", "--quiet", "--bin", "vot-codec-oracle"]
    result = subprocess.run(
        command,
        cwd=root,
        input="\n".join(requests) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "test-vectors" / "wire" / "session-authentication.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        requests, expectations = validate(document)
        for request, expected, actual in zip(
            requests, expectations, oracle_lines(root, requests), strict=True
        ):
            if actual != expected:
                raise AssertionError(
                    f"{request[:48]}: python={expected[:96]} rust={actual[:96]}"
                )
    except (
        AssertionError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"session vector validation failed: {error}", file=sys.stderr)
        return 1
    print(f"session vector validation: PASS ({len(requests)} cases cross-checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
