#!/usr/bin/env python3
"""Independent deterministic manifest and pack vector checks."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

from verify_wave1_vectors import blake3_hash, sha_root

ROOT = Path(__file__).resolve().parents[1]


def head(major: int, value: int) -> bytes:
    prefix = major << 5
    if value <= 23:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFF_FFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def uint(value: int) -> bytes:
    return head(0, value)


def byte_string(value: bytes) -> bytes:
    return head(2, len(value)) + value


def text(value: str) -> bytes:
    encoded = value.encode()
    return head(3, len(encoded)) + encoded


def array(*values: bytes) -> bytes:
    return head(4, len(values)) + b"".join(values)


def mapping(*pairs: tuple[int, bytes]) -> bytes:
    assert list(pairs) == sorted(pairs)
    return head(5, len(pairs)) + b"".join(uint(key) + value for key, value in pairs)


def encode_manifest(vector: dict) -> bytes:
    entries = []
    for entry in vector["entries"]:
        path = array(*(text(component) for component in entry["path"]))
        if entry["kind"] == "directory":
            entries.append(mapping((0, path), (1, uint(1))))
            continue
        object_id = array(
            uint(entry["suite"]),
            byte_string(bytes.fromhex(entry["root"])),
            uint(entry["length"]),
        )
        storage = array(uint(0), object_id)
        entries.append(mapping((0, path), (1, uint(0)), (2, uint(entry["length"])), (3, storage)))
    return mapping(
        (0, uint(0)),
        (1, byte_string(bytes.fromhex(vector["manifest_id"]))),
        (2, uint(vector["index"])),
        (3, uint(vector["total"])),
        (4, byte_string(bytes.fromhex(vector["previous_digest"]))),
        (5, uint(0)),
        (6, array(*entries)),
    )


def portable_key(value: str) -> str:
    forbidden = "\0/\\<>:\"|?*"
    format_controls = {
        "\u200c", "\u200d", "\u202a", "\u202b", "\u202c", "\u202d",
        "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
    }
    if (
        not value
        or value in {".", ".."}
        or any(character in value for character in forbidden)
        or any(ord(character) <= 0x1F or character in format_controls for character in value)
    ):
        raise ValueError(value)
    if value.endswith((".", " ")):
        raise ValueError(value)
    if unicodedata.normalize("NFKC", value) in {".", ".."}:
        raise ValueError(value)
    folded = "".join(
        "i" if character in {"I", "i", "\u0130", "\u0131"} else character.lower()
        for character in unicodedata.normalize("NFC", value)
    )
    folded = unicodedata.normalize("NFC", folded)
    stem = folded.split(".", 1)[0]
    if stem in {"con", "prn", "aux", "nul"}:
        raise ValueError(value)
    if len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789\u00b9\u00b2\u00b3":
        raise ValueError(value)
    return folded


def raw_valid(component: bytes) -> bool:
    """Whether the raw-POSIX profile carries this component.

    spec/object.md section 6. Written out rather than expressed as "holds a
    NUL or a slash", which is what this file used to assert and which agrees
    with any implementation that forgot the rest of the rule.
    """
    return (
        len(component) > 0
        and len(component) <= 255
        and component not in {b".", b".."}
        and b"\0" not in component
        and b"/" not in component
        and b"\\" not in component
    )


def verify_manifest() -> None:
    vector = json.loads((ROOT / "test-vectors/manifest/page.json").read_text())
    encoded = encode_manifest(vector)
    assert encoded.hex() == vector["encoded"]
    assert blake3_hash(encoded).hex() == vector["digest"]

    corpus = json.loads((ROOT / "test-vectors/manifest/path-collisions.json").read_text())
    for left, right in corpus["portable_collisions"]:
        assert portable_key(left) == portable_key(right)
    for value in corpus["portable_invalid"]:
        try:
            portable_key(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid portable path accepted: {value!r}")
    for encoded_hex in corpus["raw_posix_invalid_hex"]:
        value = bytes.fromhex(encoded_hex)
        assert not raw_valid(value), f"invalid raw component accepted: {value!r}"
    # The valid half is what keeps the invalid half meaningful: a rule that
    # rejected everything would satisfy the loop above on its own.
    for encoded_hex in corpus["raw_posix_valid_hex"]:
        value = bytes.fromhex(encoded_hex)
        assert raw_valid(value), f"valid raw component rejected: {value!r}"
    for encoded_hex in corpus["portable_invalid_utf8_hex"]:
        try:
            bytes.fromhex(encoded_hex).decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            raise AssertionError(f"invalid UTF-8 accepted: {encoded_hex}")


def verify_pack() -> None:
    vector = json.loads((ROOT / "test-vectors/pack/pack.json").read_text())
    data = bytes.fromhex(vector["bytes"])
    assert sha_root(data).hex() == vector["root"]
    assert len(data) <= 134_217_728
    paths = []
    for entry in vector["entries"]:
        paths.append(portable_key(entry["path"]))
        start = entry["offset"]
        end = start + entry["length"]
        assert start % 8 == 0
        assert data[start:end].hex() == entry["plaintext"]
        assert sha_root(data[start:end]).hex() == entry["logical_root"]
    assert paths == sorted(paths) and len(paths) == len(set(paths))

    corrupted = bytearray(data)
    corrupted[0] ^= 1
    first = vector["entries"][0]
    assert hashlib.sha256(corrupted[: first["length"]]).hexdigest() != first["logical_root"]


def main() -> None:
    verify_manifest()
    verify_pack()
    print("Wave 1 manifest and pack vector validation: PASS")


if __name__ == "__main__":
    main()
