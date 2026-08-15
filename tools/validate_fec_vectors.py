#!/usr/bin/env python3
"""Independent generator and validator for datagram FEC erasure code vectors.

Implements spec/fec.md from the text alone: GF(2^8) with the 0x11D polynomial,
the Cauchy generator matrix, systematic encoding, and erasure decoding by
Gaussian elimination. `--write` regenerates test-vectors/fec/vectors.json;
without it the file on disk must match this implementation exactly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILE = ROOT / "test-vectors/fec/vectors.json"

FORMAT = "vot-datagram-fec-v0"
POLYNOMIAL = 0x11D
GENERATOR = 0x02
MAX_SOURCE = 64
MAX_REPAIR = 16
MAX_SYMBOL_LENGTH = 65535
PATTERN = "byte[i]=(i*17+esi*7+3)%251"


def build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for power in range(255):
        exp[power] = value
        log[value] = power
        value <<= 1
        if value & 0x100:
            value ^= POLYNOMIAL
    assert value == 1, "0x11D with generator 2 must have order 255"
    for power in range(255, 512):
        exp[power] = exp[power - 255]
    return exp, log


EXP, LOG = build_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("no inverse of zero in GF(2^8)")
    return EXP[255 - LOG[a]]


def gf_div(a: int, b: int) -> int:
    return gf_mul(a, gf_inv(b))


def cauchy_row(source_count: int, repair_index: int) -> list[int]:
    """Row `repair_index` of the generator: entries 1/(x_i + y_j)."""
    x = source_count + repair_index
    return [gf_inv(x ^ y) for y in range(source_count)]


def check_geometry(source_count: int, repair_count: int, symbol_length: int) -> None:
    if not 1 <= source_count <= MAX_SOURCE:
        raise ValueError("source_count out of range")
    if not 0 <= repair_count <= MAX_REPAIR:
        raise ValueError("repair_count out of range")
    if not 1 <= symbol_length <= MAX_SYMBOL_LENGTH:
        raise ValueError("symbol_length out of range")


def encode(source: list[bytes], repair_count: int) -> list[bytes]:
    k = len(source)
    length = len(source[0])
    check_geometry(k, repair_count, length)
    assert all(len(s) == length for s in source)
    repair = []
    for i in range(repair_count):
        row = cauchy_row(k, i)
        out = bytearray(length)
        for coefficient, symbol in zip(row, source):
            if coefficient == 0:
                continue
            for pos in range(length):
                out[pos] ^= gf_mul(coefficient, symbol[pos])
        repair.append(bytes(out))
    return repair


def decode(
    source_count: int,
    repair_count: int,
    symbol_length: int,
    received: dict[int, bytes],
) -> list[bytes] | None:
    """Reconstruct all source symbols from any `source_count` received ESIs.

    Returns None when fewer than `source_count` distinct symbols are present.
    Received symbols are keyed by encoding symbol identifier: 0..k-1 are source,
    k..k+r-1 are repair.
    """
    check_geometry(source_count, repair_count, symbol_length)
    k = source_count
    for esi, symbol in received.items():
        if not 0 <= esi < k + repair_count:
            raise ValueError("esi out of range")
        if len(symbol) != symbol_length:
            raise ValueError("symbol length mismatch")
    if len(received) < k:
        return None
    # Use source symbols first, then the lowest repair ESIs, exactly k rows.
    chosen = sorted(esi for esi in received if esi < k)
    chosen += sorted(esi for esi in received if esi >= k)[: k - len(chosen)]
    rows = []
    for esi in chosen:
        if esi < k:
            row = [1 if j == esi else 0 for j in range(k)]
        else:
            row = cauchy_row(k, esi - k)
        rows.append(row + list(received[esi]))
    # Gauss-Jordan over GF(2^8) on the augmented [k x (k + symbol_length)] system.
    for col in range(k):
        pivot = next(r for r in range(col, k) if rows[r][col] != 0)
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inv = gf_inv(rows[col][col])
        rows[col] = [gf_mul(inv, v) for v in rows[col]]
        for r in range(k):
            if r != col and rows[r][col] != 0:
                factor = rows[r][col]
                rows[r] = [a ^ gf_mul(factor, b) for a, b in zip(rows[r], rows[col])]
    return [bytes(rows[i][k:]) for i in range(k)]


def pattern_symbol(esi: int, length: int) -> bytes:
    return bytes((i * 17 + esi * 7 + 3) % 251 for i in range(length))


CASES = [
    # name, k, r, symbol_length, erased ESIs for the decode case
    ("k1_r1_len1", 1, 1, 1, [0]),
    ("k1_r0_len3", 1, 0, 3, []),
    ("k2_r2_len4", 2, 2, 4, [0, 1]),
    ("k3_r2_len5", 3, 2, 5, [1, 3]),
    ("k4_r1_len8", 4, 1, 8, [2]),
    ("k8_r4_len16", 8, 4, 16, [0, 3, 5, 7]),
    ("k64_r16_len4", 64, 16, 4, list(range(0, 64, 4))),
    ("k64_r16_len4_all_repair", 64, 16, 4, list(range(48, 64))),
    ("k64_r16_len4_no_erasure", 64, 16, 4, []),
]

INSUFFICIENT = [
    # name, k, r, symbol_length, erased ESIs (one more than r)
    ("k1_r1_len1_two_lost", 1, 1, 1, [0, 1]),
    ("k2_r2_len4_three_lost", 2, 2, 4, [0, 1, 3]),
    ("k64_r16_len4_seventeen_lost", 64, 16, 4, list(range(17))),
]

INVALID_GEOMETRY = [
    ("zero_source", 0, 1, 1),
    ("source_over_cap", 65, 0, 1),
    ("repair_over_cap", 1, 17, 1),
    ("zero_symbol_length", 1, 1, 0),
    ("symbol_length_over_cap", 1, 1, 65536),
]


def field_vectors() -> dict:
    return {
        "polynomial": POLYNOMIAL,
        "generator": GENERATOR,
        "exp_first_16": EXP[:16],
        "exp_254": EXP[254],
        "log_first_16": LOG[:16],
        "products": [
            {"a": a, "b": b, "product": gf_mul(a, b)}
            for a, b in [(0, 0), (1, 255), (2, 128), (0x53, 0xCA), (255, 255), (0x80, 0x80)]
        ],
        "inverses": [{"a": a, "inverse": gf_inv(a)} for a in [1, 2, 3, 0x1D, 0x80, 0xFF]],
    }


def matrix_vectors() -> list[dict]:
    out = []
    for k, r in [(1, 1), (2, 2), (4, 3), (64, 16)]:
        rows = [cauchy_row(k, i) for i in range(r)]
        flat = bytes(v for row in rows for v in row)
        out.append(
            {
                "source_count": k,
                "repair_count": r,
                "first_row": rows[0],
                "matrix_sha256": hashlib.sha256(flat).hexdigest(),
            }
        )
    return out


def build_vectors() -> dict:
    encode_cases = []
    for name, k, r, length, erased in CASES:
        source = [pattern_symbol(esi, length) for esi in range(k)]
        repair = encode(source, r)
        symbols = source + repair
        received = {esi: sym for esi, sym in enumerate(symbols) if esi not in erased}
        decoded = decode(k, r, length, received)
        assert decoded is not None and decoded == source, name
        encode_cases.append(
            {
                "name": name,
                "source_count": k,
                "repair_count": r,
                "symbol_length": length,
                "repair_hex": [s.hex() for s in repair],
                "repair_sha256": hashlib.sha256(b"".join(repair)).hexdigest(),
                "erased": erased,
                "decoded_sha256": hashlib.sha256(b"".join(decoded)).hexdigest(),
            }
        )
    insufficient = []
    for name, k, r, length, erased in INSUFFICIENT:
        source = [pattern_symbol(esi, length) for esi in range(k)]
        symbols = source + encode(source, r)
        received = {esi: sym for esi, sym in enumerate(symbols) if esi not in erased}
        assert decode(k, r, length, received) is None, name
        insufficient.append(
            {
                "name": name,
                "source_count": k,
                "repair_count": r,
                "symbol_length": length,
                "erased": erased,
                "outcome": "INSUFFICIENT_SYMBOLS",
            }
        )
    invalid = []
    for name, k, r, length in INVALID_GEOMETRY:
        try:
            check_geometry(k, r, length)
        except ValueError:
            invalid.append(
                {
                    "name": name,
                    "source_count": k,
                    "repair_count": r,
                    "symbol_length": length,
                    "outcome": "INVALID_GEOMETRY",
                }
            )
        else:
            raise AssertionError(name)
    return {
        "format": FORMAT,
        "limits": {
            "max_source_count": MAX_SOURCE,
            "max_repair_count": MAX_REPAIR,
            "max_symbol_length": MAX_SYMBOL_LENGTH,
        },
        "pattern": PATTERN,
        "field": field_vectors(),
        "matrices": matrix_vectors(),
        "encode": encode_cases,
        "insufficient": insufficient,
        "invalid_geometry": invalid,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate the vector file")
    args = parser.parse_args()
    vectors = build_vectors()
    text = json.dumps(vectors, indent=2) + "\n"
    if args.write:
        VECTOR_FILE.parent.mkdir(parents=True, exist_ok=True)
        VECTOR_FILE.write_text(text)
        print(f"wrote {VECTOR_FILE}")
        return 0
    if not VECTOR_FILE.exists():
        print(f"missing {VECTOR_FILE}", file=sys.stderr)
        return 1
    if VECTOR_FILE.read_text() != text:
        print("vectors.json does not match the reference implementation", file=sys.stderr)
        return 1
    print(f"ok: {len(vectors['encode'])} encode, {len(vectors['insufficient'])} insufficient, {len(vectors['invalid_geometry'])} invalid geometry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
