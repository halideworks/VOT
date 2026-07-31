#!/usr/bin/env python3
"""Independent standard-library verifier for VOT Wave 1 proof vectors."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUP = 65_536
LEAF = 16_384
MASK32 = 0xFFFF_FFFF

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]
PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT_FLAG = 8


def rotr(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK32


def mix(state: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    state[a] = (state[a] + state[b] + x) & MASK32
    state[d] = rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & MASK32
    state[d] = rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = rotr(state[b] ^ state[c], 7)


def compress(cv: list[int], block: list[int], counter: int, block_len: int, flags: int) -> list[int]:
    state = cv[:] + IV[:4] + [counter & MASK32, counter >> 32, block_len, flags]
    message = block[:]
    for _ in range(7):
        mix(state, 0, 4, 8, 12, message[0], message[1])
        mix(state, 1, 5, 9, 13, message[2], message[3])
        mix(state, 2, 6, 10, 14, message[4], message[5])
        mix(state, 3, 7, 11, 15, message[6], message[7])
        mix(state, 0, 5, 10, 15, message[8], message[9])
        mix(state, 1, 6, 11, 12, message[10], message[11])
        mix(state, 2, 7, 8, 13, message[12], message[13])
        mix(state, 3, 4, 9, 14, message[14], message[15])
        message = [message[index] for index in PERMUTATION]
    return [state[i] ^ state[i + 8] for i in range(8)] + [state[i + 8] ^ cv[i] for i in range(8)]


class Output:
    def __init__(self, cv: list[int], block: list[int], counter: int, block_len: int, flags: int):
        self.input_cv = cv
        self.block = block
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> bytes:
        words = compress(self.input_cv, self.block, self.counter, self.block_len, self.flags)[:8]
        return struct.pack("<8I", *words)

    def root_hash(self) -> bytes:
        words = compress(self.input_cv, self.block, self.counter, self.block_len, self.flags | ROOT_FLAG)[:8]
        return struct.pack("<8I", *words)


def words(block: bytes) -> list[int]:
    return list(struct.unpack("<16I", block.ljust(64, b"\0")))


def chunk_output(chunk: bytes, counter: int) -> Output:
    blocks = [chunk[index : index + 64] for index in range(0, len(chunk), 64)] or [b""]
    cv = IV[:]
    output = None
    for index, block in enumerate(blocks):
        flags = (CHUNK_START if index == 0 else 0) | (CHUNK_END if index + 1 == len(blocks) else 0)
        output = Output(cv, words(block), counter, len(block), flags)
        if index + 1 != len(blocks):
            cv = list(struct.unpack("<8I", output.chaining_value()))
    assert output is not None
    return output


def parent_output(left: bytes, right: bytes) -> Output:
    return Output(IV[:], list(struct.unpack("<16I", left + right)), 0, 64, PARENT)


def split_count(count: int) -> int:
    return 1 << ((count - 1).bit_length() - 1)


def subtree_cv(data: bytes, starting_chunk: int) -> bytes:
    count = max(1, (len(data) + 1023) // 1024)
    if count == 1:
        return chunk_output(data, starting_chunk).chaining_value()
    left_count = split_count(count)
    boundary = left_count * 1024
    left = subtree_cv(data[:boundary], starting_chunk)
    right = subtree_cv(data[boundary:], starting_chunk + left_count)
    return parent_output(left, right).chaining_value()


def blake3_hash(data: bytes) -> bytes:
    count = max(1, (len(data) + 1023) // 1024)
    if count == 1:
        return chunk_output(data, 0).root_hash()
    left_count = split_count(count)
    boundary = left_count * 1024
    left = subtree_cv(data[:boundary], 0)
    right = subtree_cv(data[boundary:], left_count)
    return parent_output(left, right).root_hash()


def group_cv(data: bytes, index: int) -> bytes:
    start = index * GROUP
    return subtree_cv(data[start : start + GROUP], index * 64)


def blake_node_cv(data: bytes, start: int, count: int) -> bytes:
    if count == 1:
        return group_cv(data, start)
    left_count = split_count(count)
    return parent_output(
        blake_node_cv(data, start, left_count),
        blake_node_cv(data, start + left_count, count - left_count),
    ).chaining_value()


def blake_outboard(data: bytes) -> bytes:
    result = bytearray(struct.pack("<Q", len(data)))
    groups = max(1, (len(data) + GROUP - 1) // GROUP)

    def visit(start: int, count: int) -> None:
        if count == 1:
            return
        left_count = split_count(count)
        result.extend(blake_node_cv(data, start, left_count))
        result.extend(blake_node_cv(data, start + left_count, count - left_count))
        visit(start, left_count)
        visit(start + left_count, count - left_count)

    visit(0, groups)
    return bytes(result)


def verify_blake_range(root: bytes, object_data: bytes, covered_offset: int, covered_data: bytes, proof: bytes) -> None:
    groups = max(1, (len(object_data) + GROUP - 1) // GROUP)
    first = covered_offset // GROUP
    end = (covered_offset + len(covered_data) + GROUP - 1) // GROUP
    if groups == 1:
        assert not proof and blake3_hash(covered_data) == root
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
            relative = start * GROUP - covered_offset
            actual = subtree_cv(covered_data[relative : relative + GROUP], start * 64)
        else:
            left_count = split_count(count)
            left, right = read_parent()
            verify_child(start, left_count, left)
            verify_child(start + left_count, count - left_count, right)
            actual = parent_output(left, right).chaining_value()
        assert actual == expected

    root_left_count = split_count(groups)
    left, right = read_parent()
    verify_child(0, root_left_count, left)
    verify_child(root_left_count, groups - root_left_count, right)
    assert cursor == len(proof)
    assert parent_output(left, right).root_hash() == root


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha_parent(left: bytes, right: bytes) -> bytes:
    return sha(left + right)


def reduce_hashes(nodes: list[bytes]) -> bytes:
    while len(nodes) > 1:
        nodes = [sha_parent(nodes[index], nodes[index + 1]) for index in range(0, len(nodes), 2)]
    return nodes[0]


def sha_root(data: bytes) -> bytes:
    if not data:
        return sha(data)
    leaves = [sha(data[index : index + LEAF]) for index in range(0, len(data), LEAF)]
    leaves += [bytes(32)] * ((1 << (len(leaves) - 1).bit_length()) - len(leaves))
    return reduce_hashes(leaves)


def piece_hash(data: bytes) -> bytes:
    leaves = [sha(data[index : index + LEAF]) for index in range(0, len(data), LEAF)]
    leaves += [bytes(32)] * (4 - len(leaves))
    return reduce_hashes(leaves)


ZERO_PIECE = reduce_hashes([bytes(32)] * 4)


def zero_subtree(width: int) -> bytes:
    value = ZERO_PIECE
    while width > 1:
        value = sha_parent(value, value)
        width //= 2
    return value


def proof_window(first: int, end: int, tree_width: int) -> tuple[int, int]:
    width = 1 << ((end - first - 1).bit_length())
    if tree_width > 1:
        width = max(width, 2)
    while True:
        start = first // width * width
        if end <= start + width:
            return start, width
        width *= 2


def verify_sha_range(root: bytes, object_length: int, covered_offset: int, data: bytes, proof: bytes) -> None:
    piece_count = (object_length + GROUP - 1) // GROUP
    first = covered_offset // GROUP
    end = (covered_offset + len(data) + GROUP - 1) // GROUP
    covered = ([sha_root(data)] if piece_count == 1 else
                [piece_hash(data[index : index + GROUP]) for index in range(0, len(data), GROUP)])
    if piece_count == 1:
        assert not proof and covered == [root]
        return
    tree_width = 1 << (piece_count - 1).bit_length()
    start, width = proof_window(first, end, tree_width)
    cursor = 0

    def read_hash() -> bytes:
        nonlocal cursor
        assert cursor + 32 <= len(proof)
        value = proof[cursor : cursor + 32]
        cursor += 32
        return value

    nodes = []
    for index in range(start, start + width):
        if first <= index < end:
            nodes.append(covered[index - first])
        elif index < piece_count:
            nodes.append(read_hash())
        else:
            nodes.append(ZERO_PIECE)
    value = reduce_hashes(nodes)
    while width < tree_width:
        sibling_start = ((start // width) ^ 1) * width
        sibling = read_hash() if sibling_start < piece_count else zero_subtree(width)
        value = sha_parent(sibling, value) if sibling_start < start else sha_parent(value, sibling)
        start = min(start, sibling_start)
        width *= 2
    assert cursor == len(proof)
    assert value == root


def pattern(length: int, multiplier: int) -> bytes:
    return bytes((index * multiplier) % 251 for index in range(length))


def verify_blake_vectors() -> None:
    vectors = json.loads((ROOT / "test-vectors/blake3-bao64/vectors.json").read_text())
    assert blake3_hash(b"").hex() == vectors["empty_root"]
    assert blake_outboard(b"").hex() == vectors["empty_outboard"]
    for case in vectors["cases"]:
        data = pattern(case["object_length"], 31)
        root = bytes.fromhex(case["root"])
        assert blake3_hash(data) == root
        assert blake_outboard(data).hex() == case["outboard"]
        start = case["covered_offset"]
        covered = data[start : start + case["covered_length"]]
        proof = bytes.fromhex(case["proof"])
        verify_blake_range(root, data, start, covered, proof)
        corrupted = bytearray(covered)
        corrupted[0] ^= 1
        try:
            verify_blake_range(root, data, start, bytes(corrupted), proof)
        except AssertionError:
            pass
        else:
            raise AssertionError("corrupt BLAKE3 data accepted")


def verify_sha_vectors() -> None:
    vectors = json.loads((ROOT / "test-vectors/sha256-bep52-64k/vectors.json").read_text())
    assert sha_root(b"").hex() == vectors["empty_root"]
    for case in vectors["cases"]:
        data = pattern(case["object_length"], 17)
        root = bytes.fromhex(case["root"])
        assert sha_root(data) == root
        pieces = (sha_root(data) if len(data) <= GROUP else
                  b"".join(piece_hash(data[index : index + GROUP]) for index in range(0, len(data), GROUP)))
        assert pieces.hex() == case["piece_layer"]
        start = case["covered_offset"]
        covered = data[start : start + case["covered_length"]]
        proof = bytes.fromhex(case["proof"])
        verify_sha_range(root, len(data), start, covered, proof)
        corrupted = bytearray(covered)
        corrupted[-1] ^= 1
        try:
            verify_sha_range(root, len(data), start, bytes(corrupted), proof)
        except AssertionError:
            pass
        else:
            raise AssertionError("corrupt SHA-256 data accepted")


def main() -> None:
    verify_blake_vectors()
    verify_sha_vectors()
    print("Wave 1 proof vector validation: PASS")


if __name__ == "__main__":
    main()
