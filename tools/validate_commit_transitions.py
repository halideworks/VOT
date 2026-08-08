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

TERMINAL = {"Published", "Poisoned", "Aborted"}
# The assurance a profile must have performed before it can publish, and the
# only state it may link a namespace from.
REQUIRED = {"Fast": "TransitVerified", "Balanced": "Durable", "Strict": "AtRestVerified"}
POISONING = {"DataFlushFailed", "JournalFlushFailed", "AtRestVerificationFailed"}
RECOVERING = {"NamespaceLinkAmbiguous", "NamespaceFlushFailed", "Crash"}
ABORTABLE = {
    "New",
    "Admitted",
    "TransitVerified",
    "DataFlushed",
    "Durable",
    "AtRestVerified",
}
ADVANCES = {
    ("New", "Admit"): ("Admitted", "Admitted"),
    ("Admitted", "TransitVerified"): ("TransitVerified", "TransitVerified"),
    ("TransitVerified", "DataFlushSucceeded"): ("DataFlushed", None),
    ("DataFlushed", "JournalFlushSucceeded"): ("Durable", "Durable"),
    ("Durable", "AtRestVerified"): ("AtRestVerified", "AtRestVerified"),
    ("NamespaceLinked", "NamespaceDurable"): ("Published", "Published"),
}


def relation(row):
    """What this implementation says the machine in `row` does with its event.

    Returns (error, next_state, next_recovery_state, observation). A rejection
    leaves the machine exactly as it was, which is the property the whole
    comparison exists to hold both implementations to.
    """
    state = row["state"]
    event = row["event"]
    recovery = row["recovery_state"]
    unchanged = (state, recovery, None)

    if not row["current"]:
        return ("StaleIncarnation", *unchanged)
    if state in TERMINAL:
        return ("Terminal", *unchanged)

    if event == "Recover":
        if state != "RecoveryRequired" or recovery is None:
            return ("InvalidTransition", *unchanged)
        return (None, recovery, None, None)
    if event in POISONING:
        return (None, "Poisoned", recovery, None)
    if event in RECOVERING:
        if state == "RecoveryRequired":
            return ("InvalidTransition", *unchanged)
        return (None, "RecoveryRequired", state, None)
    if event == "Abort":
        if state not in ABORTABLE:
            return ("InvalidTransition", *unchanged)
        return (None, "Aborted", recovery, None)
    if event == "NamespaceLinked":
        if state != REQUIRED[row["profile"]]:
            return ("InvalidTransition", *unchanged)
        return (None, "NamespaceLinked", recovery, None)

    advance = ADVANCES.get((state, event))
    if advance is None:
        return ("InvalidTransition", *unchanged)
    next_state, observation = advance
    if observation == "Published" and REQUIRED[row["profile"]] not in row["performed"]:
        return ("MissingPredecessor", *unchanged)
    return (None, next_state, recovery, observation)


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

    if not rows:
        print("commit relation cross-check: no rows", file=sys.stderr)
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
        )
        if row["error"] is not None:
            rejections += 1
            # A rejection that changed anything is the defect this catches
            # whichever implementation it lands in.
            if (row["next_state"], row["next_recovery_state"]) != (
                row["state"],
                row["recovery_state"],
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
