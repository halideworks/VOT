#!/usr/bin/env python3
"""Execute the public commit transition fixtures independently."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TERMINAL = {"Published", "Poisoned", "Aborted"}
REQUIRED = {"Fast": "TransitVerified", "Balanced": "Durable", "Strict": "AtRestVerified"}


def execute(fixture):
    state = "New"
    performed = []
    error = None
    for event in fixture["events"]:
        if state in TERMINAL:
            error = "Terminal"
            break
        transition = {
            ("New", "Admit"): ("Admitted", "Admitted"),
            ("Admitted", "TransitVerified"): ("TransitVerified", "TransitVerified"),
            ("TransitVerified", "DataFlushSucceeded"): ("DataFlushed", None),
            ("DataFlushed", "JournalFlushSucceeded"): ("Durable", "Durable"),
            ("Durable", "AtRestVerified"): ("AtRestVerified", "AtRestVerified"),
            ("NamespaceLinked", "NamespaceDurable"): ("Published", "Published"),
        }.get((state, event))
        if event in {"DataFlushFailed", "JournalFlushFailed", "AtRestVerificationFailed"}:
            transition = ("Poisoned", None)
        elif event in {"NamespaceLinkAmbiguous", "NamespaceFlushFailed", "Crash"}:
            transition = ("RecoveryRequired", None)
        elif event == "NamespaceLinked" and state == REQUIRED[fixture["profile"]]:
            transition = ("NamespaceLinked", None)
        if transition is None:
            error = "InvalidTransition"
            break
        state, receipt = transition
        if receipt:
            performed.append(receipt)
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
