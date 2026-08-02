"""Validate benchmark result JSON Lines against the public schema, no dependencies.

The runner already refuses to build a result from a missing measurement. This
checks the other end: that what was written out is exactly what the published
schema allows, so an archived result file can be trusted without rerunning it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "bench/public_result_schema.json"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"benchmark result validation: {message}")


def check_integer(value: Any, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{name} must be an integer")
    if value < minimum:
        fail(f"{name} must be >= {minimum}")
    return value


def check_object(row: dict[str, Any], schema: dict[str, Any], index: int) -> None:
    properties = schema["properties"]
    required = set(schema["required"])
    present = set(row)
    missing = required - present
    if missing:
        fail(f"row {index} is missing {sorted(missing)}")
    unknown = present - set(properties)
    if unknown:
        fail(f"row {index} has unknown fields {sorted(unknown)}")

    for name, value in row.items():
        rule = properties[name]
        kinds = rule.get("type")
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if kinds is None:
            continue
        if value is None:
            if "null" not in kinds:
                fail(f"row {index} field {name} may not be null")
            continue
        if "integer" in kinds:
            check_integer(value, f"row {index} field {name}", rule.get("minimum", 0))
            if "const" in rule and value != rule["const"]:
                fail(f"row {index} field {name} must be {rule['const']}")
        elif "string" in kinds:
            if not isinstance(value, str):
                fail(f"row {index} field {name} must be a string")
            if len(value) < rule.get("minLength", 0):
                fail(f"row {index} field {name} is too short")
            if "enum" in rule and value not in rule["enum"]:
                fail(f"row {index} field {name} must be one of {rule['enum']}")
            pattern = rule.get("pattern")
            # fullmatch, not search: `$` also matches before a trailing newline,
            # so a search would accept "abc1234\n" for an anchored pattern.
            if pattern is not None and re.fullmatch(pattern, value) is None:
                fail(f"row {index} field {name} does not match {pattern}")
        elif "object" in kinds:
            if not isinstance(value, dict):
                fail(f"row {index} field {name} must be an object")
            check_object(value, rule, index)


def check_invariants(row: dict[str, Any], index: int) -> None:
    if row["bytes_sent"] < row["verified_bytes"]:
        fail(f"row {index} verified more bytes than it sent")
    if row["elapsed_ns"] < 1:
        fail(f"row {index} reports no elapsed time")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: validate_benchmark_results.py <results.jsonl>")
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        schema = json.load(handle)

    rows = 0
    with Path(argv[1]).open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                fail(f"row {index} is not JSON: {error}")
            if not isinstance(row, dict):
                fail(f"row {index} is not an object")
            check_object(row, schema, index)
            check_invariants(row, index)
            rows += 1
    if rows == 0:
        fail("no results to validate")
    print(f"benchmark result validation: PASS ({rows} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
