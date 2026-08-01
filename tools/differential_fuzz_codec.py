#!/usr/bin/env python3
"""Compare the Rust frame codec with the independent Python decoder."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

from validate_wire_vectors import FRAME_LIMITS, VectorError, decode_frames, encode_varint

ROOT = Path(__file__).resolve().parents[1]
CASES = 10_000


def xorshift(state: int) -> int:
    state ^= state << 13
    state ^= state >> 7
    state ^= state << 17
    return state & ((1 << 64) - 1)


def corpus() -> list[bytes]:
    cases: list[bytes] = []
    state = 0x243F_6A88_85A3_08D3
    while len(cases) < CASES:
        state = xorshift(state)
        length = state % 513
        value = bytearray()
        for _ in range(length):
            state = xorshift(state)
            value.append(state & 0xFF)
        cases.append(bytes(value))

        if len(cases) < CASES:
            frame_type = tuple(FRAME_LIMITS)[state % len(FRAME_LIMITS)]
            payload_length = (state >> 16) % 65
            payload = bytes((state + index) & 0xFF for index in range(payload_length))
            encoded = encode_varint(frame_type) + encode_varint(payload_length) + payload
            cases.append(encoded)
            if encoded and len(cases) < CASES:
                cases.append(encoded[:-1])

        if len(cases) < CASES:
            frame_type = 0x90
            cases.append(encode_varint(frame_type) + encode_varint(1024 * 1024 + 1))
    return cases[:CASES]


def python_result(data: bytes) -> str:
    try:
        frames = decode_frames(data)
    except VectorError as error:
        return f"err|{error.code}"
    fields = ["ok"]
    for frame in frames:
        if frame["kind"] == "known":
            fields.append(f"k,{frame['type']},{frame['payload_hex']}")
        else:
            fields.append(f"o,{frame['type']},{frame['payload_length']}")
    return "|".join(fields)


def oracle_command() -> list[str]:
    if executable := os.environ.get("VOT_CODEC_ORACLE"):
        return [executable]
    cargo = shlex.split(os.environ.get("VOT_CARGO", "cargo"))
    return cargo + ["run", "-q", "-p", "vot-codec", "--bin", "vot-codec-oracle"]


def main() -> int:
    cases = corpus()
    completed = subprocess.run(
        oracle_command(),
        cwd=ROOT,
        input="".join(f"{case.hex()}\n" for case in cases),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr or f"oracle exited {completed.returncode}")
    actual = completed.stdout.splitlines()
    if len(actual) != len(cases):
        raise AssertionError(f"oracle returned {len(actual)} lines for {len(cases)} cases")
    for index, (data, rust) in enumerate(zip(cases, actual, strict=True)):
        expected = python_result(data)
        if rust != expected:
            raise AssertionError(
                f"case {index} differs: input={data.hex()} python={expected} rust={rust}"
            )
    print(f"Rust/Python frame differential: PASS ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
