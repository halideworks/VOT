#!/usr/bin/env python3
"""Independent validator for the HELLO and SETTINGS negotiation vectors.

Reimplements spec/wire.md section 1 from the specification text rather than
from the Rust crate, so agreement between the two is evidence and not a
tautology.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_VARINT = (1 << 62) - 1
DRAFT_REVISION = 5
MAX_EXTENSIONS_PER_HELLO = 256
MAX_SETTINGS_PER_FRAME = 128


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
        raise VectorError("MALFORMED_FRAME")
    width = 1 << (data[offset] >> 6)
    if len(data) - offset < width:
        raise VectorError("MALFORMED_FRAME")
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, offset + width


def encode_hello(revision: int, role: int, extensions: list[int]) -> bytes:
    out = encode_varint(revision) + encode_varint(role) + encode_varint(len(extensions))
    for extension in sorted(extensions):
        out += encode_varint(extension)
    return out


def decode_hello(payload: bytes) -> dict[str, Any]:
    revision, offset = decode_varint(payload, 0)
    if revision != DRAFT_REVISION:
        raise VectorError("UNSUPPORTED_VERSION", draft_revision=revision)
    role, offset = decode_varint(payload, offset)
    if role not in (0, 1):
        raise VectorError("MALFORMED_FRAME")
    count, offset = decode_varint(payload, offset)
    if count > MAX_EXTENSIONS_PER_HELLO:
        raise VectorError("RESOURCE_LIMIT", extension_count=count)
    extensions: list[int] = []
    for _ in range(count):
        extension, offset = decode_varint(payload, offset)
        if extension in extensions:
            raise VectorError("MALFORMED_FRAME")
        extensions.append(extension)
    if offset != len(payload):
        raise VectorError("MALFORMED_FRAME")
    return {
        "result": "ok",
        "draft_revision": revision,
        "endpoint_role": role,
        "extensions": sorted(extensions),
    }


def encode_settings(pairs: list[tuple[int, int]]) -> bytes:
    out = b""
    for identifier, value in pairs:
        out += encode_varint(identifier) + encode_varint(value)
    return out


def decode_settings(payload: bytes, registry: dict[int, dict[str, int]]) -> dict[str, Any]:
    settings = {str(identifier): entry["default"] for identifier, entry in registry.items()}
    seen: set[int] = set()
    offset = 0
    while offset < len(payload):
        if len(seen) == MAX_SETTINGS_PER_FRAME:
            raise VectorError("RESOURCE_LIMIT")
        identifier, offset = decode_varint(payload, offset)
        value, offset = decode_varint(payload, offset)
        if identifier in seen:
            raise VectorError("DUPLICATE_SETTING", setting=identifier)
        seen.add(identifier)
        entry = registry.get(identifier)
        if entry is None:
            # spec/wire.md section 1: an unknown critical setting terminates
            # negotiation, an unknown optional one is ignored. Criticality is
            # the least-significant bit, the same convention frames use.
            if identifier % 2 == 1:
                raise VectorError("INVALID_SETTING", setting=identifier)
            continue
        if not entry["min"] <= value <= entry["max"]:
            raise VectorError("INVALID_SETTING", setting=identifier, value=value)
        settings[str(identifier)] = value
    return {"result": "ok", "settings": settings}


def check(vector: dict[str, Any], decode) -> None:
    expected = vector["expected"]
    payload = bytes.fromhex(vector.get("canonical_hex", vector.get("hex", "")))
    try:
        actual = decode(payload)
    except VectorError as error:
        assert expected["result"] == "error", vector["name"]
        assert expected["error"] == error.code, (vector["name"], error.code)
        for key, value in error.details.items():
            assert expected.get(key) == value, (vector["name"], key)
    else:
        assert expected["result"] == "ok", vector["name"]
        for key, value in expected.items():
            if key == "result":
                continue
            assert actual[key] == value, (vector["name"], key, actual[key], value)


def validate(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["format"] == "vot-wire-negotiation-v1"
    assert document["draft_revision"] == DRAFT_REVISION
    assert document["alpn"] == "vot-draft-05"
    assert document["max_extensions_per_hello"] == MAX_EXTENSIONS_PER_HELLO
    assert document["max_settings_per_frame"] == MAX_SETTINGS_PER_FRAME

    registry = {entry["id"]: entry for entry in document["settings_registry"]}
    assert registry, "no settings registry entries"
    for entry in registry.values():
        assert entry["min"] <= entry["default"] <= entry["max"], entry["name"]
        assert entry["min"] < entry["max"], entry["name"]
        # spec/wire.md section 2 puts criticality in the least-significant bit,
        # and the settings registry uses the same convention: a peer that does
        # not know an odd identifier must stop rather than carry on.
        assert entry["id"] <= MAX_VARINT, entry["name"]

    canonical_hello = 0
    for vector in document["hello"]:
        check(vector, decode_hello)
        if "canonical_hex" in vector:
            expected = vector["expected"]
            encoded = encode_hello(
                expected["draft_revision"],
                expected["endpoint_role"],
                expected["extensions"],
            )
            assert encoded.hex() == vector["canonical_hex"], vector["name"]
            canonical_hello += 1
    assert canonical_hello >= 4, "too few canonical HELLO cases to be worth anything"

    canonical_settings = 0
    for vector in document["settings"]:
        check(vector, lambda payload: decode_settings(payload, registry))
        if "canonical_hex" in vector:
            pairs = [
                (identifier, vector["expected"]["settings"][str(identifier)])
                for identifier in sorted(registry)
            ]
            assert encode_settings(pairs).hex() == vector["canonical_hex"], vector["name"]
            canonical_settings += 1
    assert canonical_settings >= 3, "too few canonical SETTINGS cases to be worth anything"

    # A vector set that only proves what an encoder produces would not catch a
    # decoder that accepts what it should refuse.
    errors = [
        vector
        for group in ("hello", "settings")
        for vector in document[group]
        if vector["expected"]["result"] == "error"
    ]
    assert len(errors) >= 10, "too few rejection cases"


def oracle_command() -> list[str]:
    if executable := os.environ.get("VOT_CODEC_ORACLE"):
        return [executable]
    cargo = shlex.split(os.environ.get("VOT_CARGO", "cargo"))
    return cargo + ["run", "-q", "-p", "vot-codec", "--bin", "vot-codec-oracle"]


def oracle_lines(root: Path, requests: list[str]) -> list[str]:
    completed = subprocess.run(
        oracle_command(),
        cwd=root,
        input="".join(f"{request}\n" for request in requests),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr or f"oracle exited {completed.returncode}")
    lines = completed.stdout.splitlines()
    if len(lines) != len(requests):
        raise AssertionError(f"oracle returned {len(lines)} lines for {len(requests)} requests")
    return lines


def expected_hello_line(vector: dict[str, Any]) -> str:
    expected = vector["expected"]
    if expected["result"] == "error":
        return f"err|{expected['error']}"
    fields = [str(expected["draft_revision"]), str(expected["endpoint_role"])]
    fields += [str(extension) for extension in expected["extensions"]]
    canonical = encode_hello(
        expected["draft_revision"], expected["endpoint_role"], expected["extensions"]
    ).hex()
    return "ok|" + "|".join(fields) + f"|re={canonical}"


def expected_settings_line(vector: dict[str, Any], registry: dict[int, Any]) -> str:
    expected = vector["expected"]
    if expected["result"] == "error":
        return f"err|{expected['error']}"
    values = [
        (identifier, expected["settings"][str(identifier)]) for identifier in sorted(registry)
    ]
    fields = [f"{identifier}={value}" for identifier, value in values]
    canonical = encode_settings(values).hex()
    return "ok|" + "|".join(fields) + f"|re={canonical}"


def cross_check(root: Path, document: dict[str, Any]) -> int:
    """Compares this implementation against the Rust one, case by case.

    Agreement on the canonical bytes is the point: a decoder that reads a
    payload correctly and an encoder that writes different bytes for it would
    pass a decode-only comparison.
    """
    registry = {entry["id"]: entry for entry in document["settings_registry"]}
    requests: list[str] = []
    expectations: list[str] = []
    for vector in document["hello"]:
        requests.append("hello " + vector.get("canonical_hex", vector.get("hex", "")))
        expectations.append(expected_hello_line(vector))
    for vector in document["settings"]:
        requests.append("settings " + vector.get("canonical_hex", vector.get("hex", "")))
        expectations.append(expected_settings_line(vector, registry))

    for request, expected, actual in zip(
        requests, expectations, oracle_lines(root, requests), strict=True
    ):
        if actual != expected:
            raise AssertionError(f"{request}: python={expected} rust={actual}")
    return len(requests)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "test-vectors" / "wire" / "negotiation.json"
    try:
        validate(path)
        document = json.loads(path.read_text(encoding="utf-8"))
        cases = cross_check(root, document)
    except (AssertionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"negotiation vector validation failed: {error}", file=sys.stderr)
        return 1
    print(f"negotiation vector validation: PASS ({cases} cases cross-checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
