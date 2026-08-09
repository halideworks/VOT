#!/usr/bin/env python3
"""Check the Rust commit relation against an independent one, exhaustively.

`validate_commit_model_sync.py` checks that the Rust `Event` variants and the
TLA action names line up. That is a vocabulary check: it passes whether or not
the two agree about what any event does. This one reimplements the relation
from spec/commit.md and compares it against every row the Rust model can
produce, which is every reachable machine crossed with every event.

The Rust rows come from `vot-commit-transitions`. Set `VOT_CARGO` to pick the
toolchain, as the other cross-checking validators do.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from commit_relation import TERMINAL, step  # noqa: E402


def relation(row):
    """The shared relation, applied to one emitted row."""
    return step(
        row["profile"],
        row["state"],
        row["event"],
        row["recovery_state"],
        row["performed"],
        row["current"],
    )


# What a whole corpus contains. Every one of these was absent from a corpus
# that a mutant shrank while the comparison still passed.
MINIMUM_ROWS = 9000
REQUIRED_ARMS = {
    "a stale machine": lambda row: not row["current"],
    "a terminal state": lambda row: row["state"] in TERMINAL,
    "a rejected publication": lambda row: row["error"] == "MissingPredecessor",
    "a recovery with nothing saved": lambda row: row["state"] == "RecoveryRequired"
    and row["recovery_state"] is None,
    "an accepted publication": lambda row: row["observation"] == "Published",
    "a poisoning": lambda row: row["next_state"] == "Poisoned" and not row["error"],
    "an abort": lambda row: row["next_state"] == "Aborted" and not row["error"],
    "a recovery": lambda row: row["event"] == "Recover" and not row["error"],
}


def corpus_shortfall(rows):
    """What a whole corpus would have that this one does not."""
    missing = [name for name, holds in REQUIRED_ARMS.items() if not any(map(holds, rows))]
    reported = [f"no row shows {name}" for name in missing]
    if len(rows) < MINIMUM_ROWS:
        reported.append(f"{len(rows)} rows, fewer than the {MINIMUM_ROWS} expected")
    events = {row["event"] for row in rows}
    profiles = {row["profile"] for row in rows}
    if len(events) != 15:
        reported.append(f"{len(events)} distinct events, not 15")
    if len(profiles) != 3:
        reported.append(f"{len(profiles)} distinct profiles, not 3")
    return reported


def rust_rows():
    cargo = shlex.split(os.environ.get("VOT_CARGO", "cargo"))
    command = [
        *cargo,
        "run",
        "--quiet",
        "-p",
        "vot-commit-model",
        "--bin",
        "vot-commit-transitions",
    ]
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)["rows"]


def main() -> int:
    try:
        rows = rust_rows()
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"commit relation cross-check failed to run: {error}", file=sys.stderr)
        return 1

    # A floor, because "the rows agreed" says nothing about how much of the
    # relation was there to agree about. A model change that shrinks the
    # corpus would otherwise certify a fraction of it as complete: dropping
    # one recorded assurance took it from 9720 rows to 7290 and still passed.
    shortfall = corpus_shortfall(rows)
    if shortfall:
        for line in shortfall:
            print(f"  {line}", file=sys.stderr)
        print("commit relation cross-check: the corpus is not whole", file=sys.stderr)
        return 1

    disagreements = []
    rejections = 0
    for row in rows:
        expected = relation(row)
        actual = (
            row["error"],
            row["next_state"],
            row["next_recovery_state"],
            row["observation"],
            row["next_performed"],
        )
        if row["error"] is not None:
            rejections += 1
            # A rejection that changed anything is the defect this catches
            # whichever implementation it lands in.
            if (row["next_state"], row["next_recovery_state"], row["next_performed"]) != (
                row["state"],
                row["recovery_state"],
                row["performed"],
            ):
                disagreements.append((row, "rejected but changed the machine", actual))
                continue
        if expected != actual:
            disagreements.append((row, expected, actual))

    if disagreements:
        for row, expected, actual in disagreements[:10]:
            print(
                f"  {row['profile']} {row['state']} + {row['event']}: "
                f"expected {expected}, Rust said {actual}",
                file=sys.stderr,
            )
        print(
            f"commit relation cross-check: FAIL ({len(disagreements)} of {len(rows)})",
            file=sys.stderr,
        )
        return 1

    print(
        f"commit relation cross-check: PASS "
        f"({len(rows)} transitions, {rejections} of them rejected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
