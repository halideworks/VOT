#!/usr/bin/env python3
"""Independent validator for the ed25519-cbor-tls-exporter-v1 vectors.

Reimplements spec/capability.cddl, the rules spec/security.md section 5 puts on a
capability, and the possession transcript in spec/registries.md section 11 from
the specification text rather than from the Rust crate. Every case is then put
through the Rust oracle and the two answers are compared.
"""

from __future__ import annotations

import json
import os
import shlex
import struct
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

KEY_ID = (1, 64)
IDENTITY = (1, 128)
OPERATIONS = (1, 16)
LIMITS = 16
RANGES = 64
SIGNED = 49_152
SCOPE = 4_096
SUITES = (1, 2)
CAPABILITY_DOMAIN = b"VOT capability v0\0"
PROOF_DOMAIN = b"VOT capability pop v1\0"
PROOF_FORMAT = 2
CHANNEL_BINDING_BYTES = 32
EXPORTER_LABEL = "EXPORTER-VOT-Channel-Binding"


class Refused(Exception):
    """A rule the capability broke, named as the vectors name it."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Reader:
    """Deterministic CBOR, the subset spec/capability.cddl uses."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise Refused("TRUNCATED")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def head(self) -> tuple[int, int]:
        first = self.take(1)[0]
        major = first >> 5
        additional = first & 0x1F
        if additional < 24:
            return major, additional
        if additional == 24:
            value = self.take(1)[0]
            floor = 24
        elif additional == 25:
            value = int.from_bytes(self.take(2), "big")
            floor = 0x100
        elif additional == 26:
            value = int.from_bytes(self.take(4), "big")
            floor = 0x1_0000
        elif additional == 27:
            value = int.from_bytes(self.take(8), "big")
            floor = 0x1_0000_0000
        else:
            raise Refused("MALFORMED")
        if value < floor:
            raise Refused("NON_CANONICAL")
        return major, value

    def typed(self, expected: int) -> int:
        major, value = self.head()
        if major != expected:
            raise Refused("MALFORMED")
        return value

    def uint(self) -> int:
        return self.typed(0)

    def key(self, expected: int) -> None:
        if self.uint() != expected:
            raise Refused("MALFORMED")

    def bstr(self, maximum: int) -> bytes:
        length = self.typed(2)
        if length > maximum:
            raise Refused("MALFORMED")
        return self.take(length)

    def fixed(self, size: int) -> bytes:
        value = self.bstr(size)
        if len(value) != size:
            raise Refused("MALFORMED")
        return value

    def tstr(self, maximum: int) -> str:
        length = self.typed(3)
        if length > maximum:
            raise Refused("MALFORMED")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refused("NOT_UTF8") from error

    def array(self, maximum: int) -> int:
        length = self.typed(4)
        if length > maximum:
            raise Refused("MALFORMED")
        return length

    def exact_array(self, expected: int) -> None:
        if self.typed(4) != expected:
            raise Refused("MALFORMED")

    def map(self, maximum: int) -> int:
        length = self.typed(5)
        if length > maximum:
            raise Refused("MALFORMED")
        return length

    def exact_map(self, expected: int) -> None:
        if self.typed(5) != expected:
            raise Refused("MALFORMED")

    def is_null(self) -> bool:
        return self.offset < len(self.data) and self.data[self.offset] == 0xF6

    def null(self) -> None:
        if self.take(1)[0] != 0xF6:
            raise Refused("MALFORMED")

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise Refused("TRAILING")


def check_identity(value: str) -> str:
    low, high = IDENTITY
    if not low <= len(value.encode("utf-8")) <= high:
        raise Refused("INVALID_IDENTITY")
    # Control characters, which is the Unicode Cc category and what Rust's
    # `char::is_control` answers. `str.isprintable` is not the same rule: it also
    # refuses a non-breaking space, and an implementation using it would reject an
    # identity this format allows.
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise Refused("INVALID_IDENTITY")
    return value


def read_scope(reader: Reader) -> dict[str, Any]:
    reader.exact_map(4)
    reader.key(0)
    suite = reader.uint()
    if not SUITES[0] <= suite <= SUITES[1]:
        raise Refused("INVALID_SUITE")
    reader.key(1)
    root = reader.fixed(32)
    reader.key(2)
    length = None if reader.is_null() else reader.uint()
    if length is None:
        reader.null()
    reader.key(3)
    count = reader.array(RANGES)
    ranges = []
    previous_end = 0
    for index in range(count):
        reader.exact_array(2)
        offset = reader.uint()
        span = reader.uint()
        if span == 0:
            raise Refused("INVALID_RANGE")
        end = offset + span
        if end > 1 << 64:
            raise Refused("INVALID_RANGE")
        # Strictly separated, not merely disjoint: two adjacent ranges are one
        # range written twice, and the format refuses the second way of saying it.
        if index > 0 and offset <= previous_end:
            raise Refused("INVALID_RANGE")
        if length is not None and end > length:
            raise Refused("INVALID_RANGE")
        previous_end = end
        ranges.append((offset, span))
    return {"suite": suite, "root": root, "length": length, "ranges": ranges}


def read_capability(data: bytes) -> dict[str, Any]:
    reader = Reader(data)
    reader.exact_map(11)
    reader.key(0)
    if reader.uint() != 0:
        raise Refused("UNSUPPORTED_VERSION")
    reader.key(1)
    issuer = check_identity(reader.tstr(IDENTITY[1]))
    reader.key(2)
    audience = check_identity(reader.tstr(IDENTITY[1]))
    reader.key(3)
    holder_key = reader.fixed(32)
    reader.key(4)
    count = reader.array(OPERATIONS[1])
    operations = [reader.uint() for _ in range(count)]
    if not OPERATIONS[0] <= len(operations) <= OPERATIONS[1]:
        raise Refused("INVALID_OPERATIONS")
    if (
        operations[0] == 0
        or any(operations[i] >= operations[i + 1] for i in range(len(operations) - 1))
        or any(value > 0xFFFF for value in operations)
    ):
        raise Refused("INVALID_OPERATIONS")
    reader.key(5)
    scope = read_scope(reader)
    reader.key(6)
    count = reader.map(LIMITS)
    limits = []
    for _ in range(count):
        identifier = reader.uint()
        limits.append((identifier, reader.uint()))
    if limits and (
        limits[0][0] == 0
        or any(limits[i][0] >= limits[i + 1][0] for i in range(len(limits) - 1))
        or any(identifier > 0xFFFF for identifier, _ in limits)
    ):
        raise Refused("INVALID_LIMITS")
    reader.key(7)
    not_before = reader.uint()
    reader.key(8)
    expiry = reader.uint()
    if expiry <= not_before:
        raise Refused("INVALID_VALIDITY")
    reader.key(9)
    token_id = reader.fixed(16)
    reader.key(10)
    if reader.uint() != 0:
        raise Refused("UNSUPPORTED_DELEGATION")
    reader.finish()
    return {
        "issuer": issuer,
        "audience": audience,
        "holder_key": holder_key,
        "operations": operations,
        "scope": scope,
        "limits": limits,
        "not_before": not_before,
        "expiry": expiry,
        "token_id": token_id,
    }


def read_signed(data: bytes) -> dict[str, Any]:
    if len(data) > SIGNED:
        raise Refused("TOO_LARGE")
    reader = Reader(data)
    reader.exact_map(4)
    reader.key(0)
    if reader.uint() != 0:
        raise Refused("UNSUPPORTED_VERSION")
    reader.key(1)
    key_id = reader.bstr(KEY_ID[1])
    if not KEY_ID[0] <= len(key_id) <= KEY_ID[1]:
        raise Refused("INVALID_KEY_ID")
    reader.key(2)
    capability = reader.bstr(SIGNED)
    reader.key(3)
    signature = reader.fixed(64)
    reader.finish()
    return {"key_id": key_id, "capability": capability, "signature": signature}


def scope_fields(scope: dict[str, Any]) -> str:
    ranges = "+".join(f"{offset}:{span}" for offset, span in scope["ranges"])
    length = "null" if scope["length"] is None else str(scope["length"])
    return f"{scope['suite']},{scope['root'][:4].hex()},{length},{ranges}"


def answer(kind: str, data: bytes) -> str:
    """The line the oracle should print for this case."""
    if kind == "signed":
        value = read_signed(data)
        return (
            f"ok|signed|{value['key_id'].hex()}|{len(value['capability'])}"
            f"|{value['signature'][:4].hex()}"
        )
    if kind == "capability":
        value = read_capability(data)
        operations = "+".join(str(operation) for operation in value["operations"])
        line = (
            f"ok|capability|{value['issuer']}|{value['audience']}"
            f"|{value['holder_key'][:4].hex()}|{operations}"
            f"|{value['not_before']}|{value['expiry']}|{value['token_id'][:4].hex()}"
            f"|{scope_fields(value['scope'])}"
        )
        for identifier, limit in value["limits"]:
            line += f"|l{identifier}={limit}"
        return line
    if kind == "scope":
        if len(data) > SCOPE:
            raise Refused("TOO_LARGE")
        reader = Reader(data)
        scope = read_scope(reader)
        reader.finish()
        return f"ok|scope|{scope_fields(scope)}"
    raise AssertionError(f"unknown case kind {kind}")


def oracle_lines(root: Path, requests: list[str]) -> list[str]:
    cargo = shlex.split(os.environ.get("VOT_CARGO", "cargo"))
    command = [*cargo, "run", "--quiet", "-p", "vot-capability", "--bin", "vot-capability-oracle"]
    result = subprocess.run(
        command,
        cwd=root,
        input="\n".join(requests) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def capability_signing_input(
    capability_format: int, key_id: bytes, capability: bytes
) -> bytes:
    assert 0 <= capability_format <= 0xFFFF
    assert KEY_ID[0] <= len(key_id) <= KEY_ID[1]
    return b"".join(
        (
            CAPABILITY_DOMAIN,
            struct.pack(">H", capability_format),
            bytes([len(key_id)]),
            key_id,
            capability,
        )
    )


def validate_capability_signatures(root: Path, document: dict[str, Any]) -> int:
    metadata = document["capability_signature"]
    assert bytes.fromhex(metadata["domain_separator_hex"]) == CAPABILITY_DOMAIN
    seed = metadata["test_signing_seed_hex"]
    public_key = metadata["issuer_public_key_hex"]
    assert len(bytes.fromhex(seed)) == 32
    assert len(bytes.fromhex(public_key)) == 32

    requests = []
    expected = []
    first = None
    for case in document["cases"]:
        if case["kind"] != "signed" or case["result"] != "ok":
            continue
        signed = read_signed(bytes.fromhex(case["bytes"]))
        transcript = capability_signing_input(
            document["capability_format"], signed["key_id"], signed["capability"]
        )
        signature = signed["signature"].hex()
        requests.append(f"ed25519-sign {seed} {transcript.hex()}")
        expected.append(f"ok|signature|{public_key}|{signature}")
        if first is None:
            first = (signed, signature)

    assert first is not None, "no accepted signed capability case"
    signed, signature = first
    retired = capability_signing_input(1, signed["key_id"], signed["capability"])
    requests.append(f"ed25519-verify {public_key} {retired.hex()} {signature}")
    expected.append("err|SIGNATURE")
    actual = oracle_lines(root, requests)
    assert actual == expected, f"capability signature oracle={actual} expected={expected}"
    return len(requests)


def possession_transcript(values: dict[str, Any]) -> bytes:
    domain = bytes.fromhex(values["domain_separator_hex"])
    token_id = bytes.fromhex(values["token_id_hex"])
    session_id = bytes.fromhex(values["session_id_hex"])
    nonce = bytes.fromhex(values["nonce_hex"])
    channel_binding = bytes.fromhex(values["channel_binding_hex"])
    capability_format = values["capability_format"]
    assert 0 <= capability_format <= 0xFFFF
    assert len(token_id) == 16
    assert len(session_id) == 16
    assert 16 <= len(nonce) <= 64
    assert len(channel_binding) == CHANNEL_BINDING_BYTES
    return b"".join(
        (
            domain,
            struct.pack(">H", capability_format),
            token_id,
            session_id,
            struct.pack(">H", len(nonce)),
            nonce,
            channel_binding,
        )
    )


def validate_possession(root: Path) -> int:
    path = root / "test-vectors" / "capability" / "possession-transcript.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["format"] == "vot-capability-possession-transcript-v1"
    assert document["capability_format"] == PROOF_FORMAT
    assert bytes.fromhex(document["domain_separator_hex"]) == PROOF_DOMAIN
    assert document["exporter"] == {
        "label": EXPORTER_LABEL,
        "context": None,
        "output_bytes": CHANNEL_BINDING_BYTES,
    }
    public_key = document["holder_public_key_hex"]
    assert len(bytes.fromhex(public_key)) == 32
    assert len(bytes.fromhex(document["test_signing_seed_hex"])) == 32

    case = {
        **document["case"],
        "capability_format": document["capability_format"],
        "domain_separator_hex": document["domain_separator_hex"],
    }
    transcript = possession_transcript(case)
    assert transcript.hex() == case["transcript_hex"]
    signature = case["signature_hex"]
    assert len(bytes.fromhex(signature)) == 64

    requests = [f"possession {public_key} {transcript.hex()} {signature}"]
    expected = ["ok|possession"]
    names = []
    for rejected in document["rejected"]:
        names.append(rejected["name"])
        altered = dict(case)
        altered[rejected["field"]] = rejected["value"]
        requests.append(
            f"possession {public_key} {possession_transcript(altered).hex()} {signature}"
        )
        expected.append("err|SIGNATURE")
    assert len(names) == len(set(names)), "duplicate possession refusal case"
    assert len(names) >= 6, "too few possession refusal cases to be evidence"
    actual = oracle_lines(root, requests)
    assert actual == expected, f"possession oracle={actual} expected={expected}"
    return len(requests)


def validate(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    assert document["format"] == "vot-capability-vectors-v1"
    assert document["capability_format"] == PROOF_FORMAT
    cases = document["cases"]
    assert cases, "no cases"
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names)), "duplicate case name"

    requests: list[str] = []
    expectations: list[str] = []
    for case in cases:
        data = bytes.fromhex(case["bytes"])
        requests.append(f"{case['kind']} {case['bytes']}")
        try:
            line = answer(case["kind"], data)
            outcome = "ok"
        except Refused as refused:
            line = f"err|{refused.code}"
            outcome = "err"
        assert outcome == case["result"], (
            f"{case['name']}: python says {outcome}, the vector says {case['result']}"
        )
        if outcome == "err":
            assert line == f"err|{case['error']}", (
                f"{case['name']}: python says {line}, the vector says err|{case['error']}"
            )
        expectations.append(line)

    # A file of nothing but accepted cases proves only that the decoder decodes.
    assert sum(1 for case in cases if case["result"] == "err") >= 5, (
        "too few refusal cases to be evidence"
    )
    return requests, expectations


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "test-vectors" / "capability" / "capability.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        requests, expectations = validate(document)
        for request, expected, actual in zip(
            requests, expectations, oracle_lines(root, requests), strict=True
        ):
            if actual != expected:
                raise AssertionError(
                    f"{request[:40]}: python={expected[:96]} rust={actual[:96]}"
                )
        signature_cases = validate_capability_signatures(root, document)
        possession_cases = validate_possession(root)
    except (
        AssertionError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"capability vector validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "capability vector validation: PASS "
        f"({len(document['cases'])} encoding cases, "
        f"{signature_cases} capability signature cases, and "
        f"{possession_cases} possession cases cross-checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
