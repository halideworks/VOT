#!/usr/bin/env python3
"""Independent generator and validator for static proof catalog vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from functools import lru_cache
from pathlib import Path

from verify_wave1_vectors import (
    GROUP,
    ZERO_PIECE,
    blake3_hash,
    group_cv,
    parent_output,
    piece_hash,
    proof_window,
    reduce_hashes,
    sha_parent,
    sha_root,
    split_count,
)

ROOT = Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "test-vectors/static-proof-catalog"
VECTOR_FILE = VECTOR_DIR / "vectors.json"

MAGIC = b"VOTPCAT\0"
VERSION = 0
HEADER_LENGTH = 128
ENTRY_LENGTH = 16
PROFILE = 1
RANGE_LENGTH = 4_194_304
MAX_PROOF_LENGTH = 8_192
MAX_OBJECT_LENGTH = (1 << 63) - 1
MAX_RECORDS = 1 << 41
MAX_INDEX_LENGTH = 1 << 45
MAX_PROOF_BLOB_LENGTH = 1 << 54
MAX_CATALOG_LENGTH = HEADER_LENGTH + MAX_INDEX_LENGTH + MAX_PROOF_BLOB_LENGTH
U64_MAX = (1 << 64) - 1

HEADER = struct.Struct(">8sHHIHHI32sQQQQQQQ16s")
ENTRY = struct.Struct(">QII")
assert HEADER.size == HEADER_LENGTH
assert ENTRY.size == ENTRY_LENGTH

MALFORMED = "MALFORMED_CATALOG"
UNSUPPORTED = "UNSUPPORTED_CATALOG"
IDENTITY = "IDENTITY_MISMATCH"
PROOF_INVALID = "PROOF_INVALID"
UNAVAILABLE = "CATALOG_UNAVAILABLE"


class CatalogFailure(Exception):
    def __init__(self, outcome: str):
        super().__init__(outcome)
        self.outcome = outcome


def checked_add(left: int, right: int) -> int:
    result = left + right
    if left < 0 or right < 0 or result > U64_MAX:
        raise OverflowError
    return result


def checked_mul(left: int, right: int) -> int:
    result = left * right
    if left < 0 or right < 0 or result > U64_MAX:
        raise OverflowError
    return result


def geometry(length: int) -> tuple[int, int]:
    if length < 0 or length > MAX_OBJECT_LENGTH:
        raise ValueError
    count = length // RANGE_LENGTH + int(length % RANGE_LENGTH != 0)
    index_length = checked_mul(count, ENTRY_LENGTH)
    if count > MAX_RECORDS or index_length > MAX_INDEX_LENGTH:
        raise ValueError
    return count, index_length


def pattern(length: int) -> bytes:
    return bytes((index * 17) % 251 for index in range(length))


def blake_prover(data: bytes):
    groups = (len(data) + GROUP - 1) // GROUP
    leaves = [group_cv(data, index) for index in range(groups)]

    @lru_cache(maxsize=None)
    def node(start: int, count: int) -> bytes:
        if count == 1:
            return leaves[start]
        left_count = split_count(count)
        return parent_output(
            node(start, left_count), node(start + left_count, count - left_count)
        ).chaining_value()

    def prove(offset: int, length: int) -> bytes:
        first = offset // GROUP
        end = (offset + length + GROUP - 1) // GROUP
        proof = bytearray()

        def intersects(start: int, count: int) -> bool:
            return start < end and first < start + count

        def visit(start: int, count: int) -> None:
            if count == 1:
                return
            left_count = split_count(count)
            right_start = start + left_count
            proof.extend(node(start, left_count))
            proof.extend(node(right_start, count - left_count))
            if intersects(start, left_count):
                visit(start, left_count)
            if intersects(right_start, count - left_count):
                visit(right_start, count - left_count)

        if groups > 1:
            visit(0, groups)
        return bytes(proof)

    return prove, leaves


def sha_prover(data: bytes):
    count = (len(data) + GROUP - 1) // GROUP
    width = 1 << (count - 1).bit_length()
    leaves = [piece_hash(data[index : index + GROUP]) for index in range(0, len(data), GROUP)]
    leaves.extend([ZERO_PIECE] * (width - count))

    @lru_cache(maxsize=None)
    def node(start: int, count_: int) -> bytes:
        return reduce_hashes(leaves[start : start + count_])

    def prove(offset: int, length: int) -> bytes:
        if count == 1:
            return b""
        first = offset // GROUP
        end = (offset + length + GROUP - 1) // GROUP
        start, window = proof_window(first, end, width)
        proof = bytearray()
        for index in range(start, start + window):
            if not first <= index < end and index < count:
                proof.extend(leaves[index])
        while window < width:
            sibling = ((start // window) ^ 1) * window
            if sibling < count:
                proof.extend(node(sibling, window))
            start = min(start, sibling)
            window *= 2
        return bytes(proof)

    return prove, leaves, count


def verify_blake_leaves(
    root: bytes,
    first: int,
    end: int,
    proof: bytes,
    leaves: list[bytes],
    data: bytes,
) -> None:
    groups = len(leaves)
    if groups == 1:
        assert not proof
        assert blake3_hash(data) == root
        return
    cursor = 0

    def read_parent() -> tuple[bytes, bytes]:
        nonlocal cursor
        assert cursor + 64 <= len(proof)
        left, right = proof[cursor : cursor + 32], proof[cursor + 32 : cursor + 64]
        cursor += 64
        return left, right

    def intersects(start: int, count: int) -> bool:
        return start < end and first < start + count

    def verify_child(start: int, count: int, expected: bytes) -> None:
        if not intersects(start, count):
            return
        if count == 1:
            actual = leaves[start]
        else:
            left_count = split_count(count)
            left, right = read_parent()
            verify_child(start, left_count, left)
            verify_child(start + left_count, count - left_count, right)
            actual = parent_output(left, right).chaining_value()
        assert actual == expected

    left_count = split_count(groups)
    left, right = read_parent()
    verify_child(0, left_count, left)
    verify_child(left_count, groups - left_count, right)
    assert cursor == len(proof)
    assert parent_output(left, right).root_hash() == root


def verify_sha_leaves(
    root: bytes,
    first: int,
    end: int,
    proof: bytes,
    leaves: list[bytes],
    count: int,
    data: bytes,
) -> None:
    if count == 1:
        assert not proof
        assert sha_root(data) == root
        return
    width = len(leaves)
    start, window = proof_window(first, end, width)
    cursor = 0

    def read_hash() -> bytes:
        nonlocal cursor
        assert cursor + 32 <= len(proof)
        value = proof[cursor : cursor + 32]
        cursor += 32
        return value

    nodes = []
    for index in range(start, start + window):
        if first <= index < end:
            nodes.append(leaves[index])
        elif index < count:
            nodes.append(read_hash())
        else:
            nodes.append(ZERO_PIECE)
    value = reduce_hashes(nodes)
    while window < width:
        sibling = ((start // window) ^ 1) * window
        sibling_hash = read_hash() if sibling < count else reduce_hashes(leaves[sibling : sibling + window])
        value = sha_parent(sibling_hash, value) if sibling < start else sha_parent(value, sibling_hash)
        start = min(start, sibling)
        window *= 2
    assert cursor == len(proof)
    assert value == root


def build_catalog(suite: int, data: bytes):
    count, index_length = geometry(len(data))
    if suite == 1:
        root = blake3_hash(data)
        material = blake_prover(data) if data else None
        prove = material[0] if material else None
        context = (suite, root, material[1] if material else [], 0, data)
    elif suite == 2:
        root = sha_root(data)
        material = sha_prover(data) if data else None
        prove = material[0] if material else None
        context = (
            suite,
            root,
            material[1] if material else [],
            material[2] if material else 0,
            data,
        )
    else:
        raise ValueError("unknown suite")

    proofs: list[bytes] = []
    records: list[dict[str, object]] = []
    relative = 0
    for ordinal in range(count):
        offset = ordinal * RANGE_LENGTH
        length = min(RANGE_LENGTH, len(data) - offset)
        assert prove is not None
        proof = prove(offset, length)
        assert len(proof) <= MAX_PROOF_LENGTH and len(proof) % 32 == 0
        proofs.append(proof)
        records.append(
            {
                "ordinal": ordinal,
                "index_absolute_offset": HEADER_LENGTH + ordinal * ENTRY_LENGTH,
                "data_offset": offset,
                "data_length": length,
                "proof_relative_offset": relative,
                "proof_length": len(proof),
                "cold_proof_hex": proof.hex(),
            }
        )
        relative += len(proof)

    proof_blob = b"".join(proofs)
    proof_offset = HEADER_LENGTH + index_length
    catalog_length = proof_offset + len(proof_blob)
    assert len(proof_blob) <= MAX_PROOF_BLOB_LENGTH
    assert catalog_length <= MAX_CATALOG_LENGTH
    header = HEADER.pack(
        MAGIC, VERSION, HEADER_LENGTH, 0, suite, PROFILE, 0, root, len(data), count,
        HEADER_LENGTH, index_length, proof_offset, len(proof_blob), catalog_length,
        bytes(16),
    )
    index = b"".join(
        ENTRY.pack(record["proof_relative_offset"], record["proof_length"], 0)
        for record in records
    )
    return header + index + proof_blob, root, records, context


def fail(outcome: str) -> None:
    raise CatalogFailure(outcome)


def verify_record(
    suite: int,
    root: bytes,
    object_length: int,
    ordinal: int,
    proof: bytes,
    context,
) -> None:
    context_suite, context_root, leaves, context_count, data = context
    if context_suite != suite or context_root != root:
        fail(PROOF_INVALID)
    data_offset = checked_mul(ordinal, RANGE_LENGTH)
    data_length = min(RANGE_LENGTH, object_length - data_offset)
    first = data_offset // GROUP
    end = (checked_add(data_offset, data_length) + GROUP - 1) // GROUP
    try:
        if suite == 1:
            verify_blake_leaves(root, first, end, proof, leaves, data)
        else:
            verify_sha_leaves(root, first, end, proof, leaves, context_count, data)
    except AssertionError:
        fail(PROOF_INVALID)


def parse_and_verify(blob: bytes, expected: tuple[int, bytes, int], context) -> None:
    if len(blob) < HEADER_LENGTH:
        fail(UNAVAILABLE)
    fields = HEADER.unpack(blob[:HEADER_LENGTH])
    (
        magic, version, header_length, flags, suite, profile, reserved, root,
        object_length, count, index_offset, index_length, proof_offset, proof_length,
        catalog_length, tail_reserved,
    ) = fields
    if magic != MAGIC or header_length != HEADER_LENGTH or flags != 0:
        fail(MALFORMED)
    if version != VERSION or suite not in (1, 2) or profile != PROFILE:
        fail(UNSUPPORTED)
    if reserved != 0 or tail_reserved != bytes(16) or object_length > MAX_OBJECT_LENGTH:
        fail(MALFORMED)
    if (suite, root, object_length) != expected:
        fail(IDENTITY)
    try:
        derived_count, derived_index_length = geometry(object_length)
        derived_proof_offset = checked_add(HEADER_LENGTH, derived_index_length)
        derived_catalog_length = checked_add(proof_offset, proof_length)
    except (OverflowError, ValueError):
        fail(MALFORMED)
    if (
        count != derived_count or index_offset != HEADER_LENGTH
        or index_length != derived_index_length or proof_offset != derived_proof_offset
        or proof_length > MAX_PROOF_BLOB_LENGTH
        or catalog_length != derived_catalog_length or catalog_length > MAX_CATALOG_LENGTH
    ):
        fail(MALFORMED)
    if len(blob) < catalog_length:
        fail(UNAVAILABLE)
    if len(blob) != catalog_length:
        fail(MALFORMED)

    entries: list[tuple[int, int]] = []
    expected_relative = 0
    for ordinal in range(count):
        start = index_offset + ordinal * ENTRY_LENGTH
        relative, length, entry_reserved = ENTRY.unpack(blob[start : start + ENTRY_LENGTH])
        if entry_reserved != 0 or length > MAX_PROOF_LENGTH or length % 32 != 0:
            fail(MALFORMED)
        if relative != expected_relative:
            fail(MALFORMED)
        try:
            end = checked_add(relative, length)
        except OverflowError:
            fail(MALFORMED)
        if end > proof_length:
            fail(MALFORMED)
        entries.append((relative, length))
        expected_relative = end
    if expected_relative != proof_length:
        fail(MALFORMED)

    for ordinal, (relative, length) in enumerate(entries):
        start = proof_offset + relative
        proof = blob[start : start + length]
        try:
            verify_record(suite, root, object_length, ordinal, proof, context)
        except (OverflowError, ValueError):
            fail(MALFORMED)


def parse_and_verify_selected(
    read_at,
    storage_length: int,
    expected: tuple[int, bytes, int],
    ordinal: int,
    context,
) -> None:
    header_bytes = read_at(0, HEADER_LENGTH)
    if len(header_bytes) != HEADER_LENGTH:
        fail(UNAVAILABLE)
    (
        magic, version, header_length, flags, suite, profile, reserved, root,
        object_length, count, index_offset, index_length, proof_offset, proof_length,
        catalog_length, tail_reserved,
    ) = HEADER.unpack(header_bytes)
    if magic != MAGIC or header_length != HEADER_LENGTH or flags != 0:
        fail(MALFORMED)
    if version != VERSION or suite not in (1, 2) or profile != PROFILE:
        fail(UNSUPPORTED)
    if reserved != 0 or tail_reserved != bytes(16) or object_length > MAX_OBJECT_LENGTH:
        fail(MALFORMED)

    # Object identity is authoritative and must be authenticated before the
    # catalog controls any subsequent read address.
    if (suite, root, object_length) != expected:
        fail(IDENTITY)
    try:
        derived_count, derived_index_length = geometry(object_length)
        derived_proof_offset = checked_add(HEADER_LENGTH, derived_index_length)
        derived_catalog_length = checked_add(proof_offset, proof_length)
    except (OverflowError, ValueError):
        fail(MALFORMED)
    if (
        count != derived_count or index_offset != HEADER_LENGTH
        or index_length != derived_index_length or proof_offset != derived_proof_offset
        or proof_length > MAX_PROOF_BLOB_LENGTH
        or catalog_length != derived_catalog_length or catalog_length > MAX_CATALOG_LENGTH
    ):
        fail(MALFORMED)
    if storage_length < catalog_length:
        fail(UNAVAILABLE)
    if storage_length != catalog_length or ordinal < 0 or ordinal >= count:
        fail(MALFORMED)

    try:
        entry_start = checked_add(index_offset, checked_mul(ordinal, ENTRY_LENGTH))
        entry_end = checked_add(entry_start, ENTRY_LENGTH)
    except OverflowError:
        fail(MALFORMED)
    if entry_end > proof_offset:
        fail(MALFORMED)
    entry_bytes = read_at(entry_start, ENTRY_LENGTH)
    if len(entry_bytes) != ENTRY_LENGTH:
        fail(UNAVAILABLE)
    relative, length, entry_reserved = ENTRY.unpack(entry_bytes)
    if entry_reserved != 0 or length > MAX_PROOF_LENGTH or length % 32 != 0:
        fail(MALFORMED)
    try:
        relative_end = checked_add(relative, length)
        proof_start = checked_add(proof_offset, relative)
        proof_end = checked_add(proof_start, length)
    except OverflowError:
        fail(MALFORMED)
    if relative_end > proof_length or proof_end > catalog_length:
        fail(MALFORMED)
    proof = read_at(proof_start, length)
    if len(proof) != length:
        fail(UNAVAILABLE)
    try:
        verify_record(suite, root, object_length, ordinal, proof, context)
    except (OverflowError, ValueError):
        fail(MALFORMED)


def apply_negative(base: bytes, vector: dict[str, object], records: list[dict[str, object]]) -> bytes:
    changed = bytearray(base)
    for patch in vector.get("patches", []):
        offset = patch["offset"]
        replacement = bytes.fromhex(patch["replace_hex"])
        changed[offset : offset + len(replacement)] = replacement
    fields = {"proof_offset": (0, 8), "proof_length": (8, 4)}
    for mutation in vector.get("index_mutations", []):
        field_offset, length = fields[mutation["field"]]
        offset = HEADER_LENGTH + mutation["record"] * ENTRY_LENGTH + field_offset
        current = int.from_bytes(changed[offset : offset + length], "big")
        value = mutation.get("set", current + mutation.get("add", 0))
        changed[offset : offset + length] = value.to_bytes(length, "big")
    if "swap_proofs" in vector:
        left, right = vector["swap_proofs"]
        left_record, right_record = records[left], records[right]
        assert left_record["proof_length"] == right_record["proof_length"]
        blob_offset = HEADER_LENGTH + len(records) * ENTRY_LENGTH
        left_start = blob_offset + left_record["proof_relative_offset"]
        right_start = blob_offset + right_record["proof_relative_offset"]
        length = left_record["proof_length"]
        left_bytes = changed[left_start : left_start + length]
        changed[left_start : left_start + length] = changed[right_start : right_start + length]
        changed[right_start : right_start + length] = left_bytes
    for patch in vector.get("proof_patches", []):
        record = records[patch["record"]]
        blob_offset = HEADER_LENGTH + len(records) * ENTRY_LENGTH
        offset = blob_offset + record["proof_relative_offset"] + patch["offset"]
        changed[offset] ^= patch["xor"]
    if "append_hex" in vector:
        changed.extend(bytes.fromhex(vector["append_hex"]))
    if "truncate_tail" in vector:
        del changed[-vector["truncate_tail"] :]
    if "truncate_to" in vector:
        del changed[vector["truncate_to"] :]
    return bytes(changed)


def expected_case(case: dict[str, object], *, write: bool):
    data = pattern(case["object_length"])
    catalog, root, records, context = build_catalog(case["suite_id"], data)
    if write:
        (VECTOR_DIR / case["file"]).write_bytes(catalog)
        case["root_hex"] = root.hex()
        case["catalog_length"] = len(catalog)
        case["catalog_sha256"] = hashlib.sha256(catalog).hexdigest()
        case["records"] = records
    else:
        assert case["root_hex"] == root.hex()
        assert case["catalog_length"] == len(catalog)
        assert case["catalog_sha256"] == hashlib.sha256(catalog).hexdigest()
        assert case["records"] == records
    fixture = (VECTOR_DIR / case["file"]).read_bytes()
    assert fixture == catalog
    return fixture, root, records, data, context


def validate_arithmetic(vectors: list[dict[str, object]], *, write: bool) -> None:
    for vector in vectors:
        try:
            if vector["operation"] == "geometry":
                count, index_length = geometry(vector["object_length"])
                result: object = {"record_count": count, "index_length": index_length}
            elif vector["operation"] == "multiply":
                result = checked_mul(vector["left"], vector["right"])
            elif vector["operation"] == "add":
                result = checked_add(vector["left"], vector["right"])
            else:
                raise AssertionError("unknown arithmetic operation")
            outcome = "ok"
        except ValueError:
            result, outcome = None, "out_of_range"
        except OverflowError:
            result, outcome = None, "overflow"
        if write:
            vector["expected"] = outcome
            if result is None:
                vector.pop("result", None)
            else:
                vector["result"] = result
        else:
            assert vector["expected"] == outcome
            assert vector.get("result") == result


def with_single_record_proof(base: bytes, length: int) -> bytes:
    fields = list(HEADER.unpack(base[:HEADER_LENGTH]))
    assert fields[9] == 1
    fields[13] = length
    fields[14] = checked_add(fields[12], length)
    return HEADER.pack(*fields) + ENTRY.pack(0, length, 0) + bytes(length)


def validate_random_access(vectors: list[dict[str, object]], positive) -> None:
    for vector in vectors:
        case, fixture, root, records, _, context = positive[vector["base"]]
        ordinal = vector["record"]
        if "proof_length" in vector:
            fixture = with_single_record_proof(fixture, vector["proof_length"])
        if "index_mutations" in vector:
            fixture = apply_negative(fixture, vector, records)
        expected_root = root
        if "identity_root_xor" in vector:
            expected_root = bytes([root[0] ^ vector["identity_root_xor"]]) + root[1:]
        reads: list[tuple[int, int]] = []

        def read_at(offset: int, length: int) -> bytes:
            reads.append((offset, length))
            return fixture[offset : offset + length]

        outcome = "ok"
        try:
            parse_and_verify_selected(
                read_at,
                len(fixture),
                (case["suite_id"], expected_root, case["object_length"]),
                ordinal,
                context,
            )
        except CatalogFailure as failure:
            outcome = failure.outcome
        assert outcome == vector["expected"], (vector["name"], outcome, vector["expected"])
        assert reads[0] == (0, HEADER_LENGTH)
        if outcome == IDENTITY:
            assert reads == [(0, HEADER_LENGTH)]
        if vector.get("require_sparse"):
            selected_index = HEADER_LENGTH + ordinal * ENTRY_LENGTH
            neighbor_indexes = {
                HEADER_LENGTH + neighbor * ENTRY_LENGTH
                for neighbor in range(len(records))
                if neighbor != ordinal
            }
            assert (selected_index, ENTRY_LENGTH) in reads
            assert not any(offset in neighbor_indexes for offset, _ in reads)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="refresh committed fixtures")
    args = parser.parse_args()
    vectors = json.loads(VECTOR_FILE.read_text())
    assert vectors["format"] == "vot-static-proof-catalog-v0"
    assert bytes.fromhex(vectors["magic_hex"]) == MAGIC
    assert vectors["version"] == VERSION
    assert vectors["header_length"] == HEADER_LENGTH
    assert vectors["index_entry_length"] == ENTRY_LENGTH
    assert vectors["profile"] == {
        "id": PROFILE,
        "group_length": GROUP,
        "range_length": RANGE_LENGTH,
        "max_proof_length": MAX_PROOF_LENGTH,
    }

    positive = {}
    for case in vectors["positive"]:
        fixture, root, records, data, context = expected_case(case, write=args.write)
        parse_and_verify(fixture, (case["suite_id"], root, case["object_length"]), context)
        positive[case["name"]] = (case, fixture, root, records, data, context)

    for vector in vectors["negative"]:
        case, fixture, root, records, data, context = positive[vector["base"]]
        changed = apply_negative(fixture, vector, records)
        changed_data = bytearray(data)
        for patch in vector.get("payload_patches", []):
            changed_data[patch["offset"]] ^= patch["xor"]
        if vector.get("payload_patches"):
            _, _, _, changed_context = build_catalog(case["suite_id"], bytes(changed_data))
        else:
            changed_context = context
        try:
            parse_and_verify(
                changed,
                (case["suite_id"], root, case["object_length"]),
                changed_context,
            )
        except CatalogFailure as failure:
            assert failure.outcome == vector["expected"], (
                vector["name"], failure.outcome, vector["expected"]
            )
        else:
            raise AssertionError(f"negative vector accepted: {vector['name']}")

    validate_random_access(vectors["random_access"], positive)
    validate_arithmetic(vectors["arithmetic"], write=args.write)
    if args.write:
        VECTOR_FILE.write_text(json.dumps(vectors, indent=2) + "\n")
    print(
        "static proof catalog vectors: PASS "
        f"({len(vectors['positive'])} positive, {len(vectors['negative'])} negative, "
        f"{len(vectors['random_access'])} random-access)"
    )


if __name__ == "__main__":
    main()
