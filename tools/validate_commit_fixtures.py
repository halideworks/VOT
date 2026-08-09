#!/usr/bin/env python3
"""Execute the public commit transition fixtures independently.

Walks each fixture's events through `commit_relation`, the same relation
`validate_commit_transitions.py` compares the Rust model against. This file
used to carry its own copy, and the copy had drifted: it had no `Abort`
branch, so a legal abort read as an invalid transition, which no fixture
happened to exercise.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from commit_relation import REQUIRED, step  # noqa: E402


def execute(fixture):
    state = "New"
    recovery_state = None
    performed = []
    error = None
    for event in fixture["events"]:
        error, state, recovery_state, _, performed = step(
            fixture["profile"], state, event, recovery_state, performed
        )
        if error:
            break
    assert state == fixture["state"], fixture["name"]
    assert error == fixture.get("error"), fixture["name"]
    if "receipts" in fixture:
        assert performed == fixture["receipts"], fixture["name"]
    if state == "Published":
        assert REQUIRED[fixture["profile"]] in performed


def main():
    document = json.loads((ROOT / "test-vectors/commit/transitions.json").read_text())
    for fixture in document["fixtures"]:
        execute(fixture)
    print("commit transition fixtures: PASS")


if __name__ == "__main__":
    main()
