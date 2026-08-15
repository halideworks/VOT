#!/usr/bin/env python3
"""Fail when the TLA commit actions stop implementing the relation table.

`validate_commit_transitions.py` already compares every Rust row to the
Python relation. This file used to check only that Rust `Event` names had
matching `RUST_EVENT` comments. That passed whether or not TLA took the
same step. The committed table is now the Python relation; this checker
requires the TLA actions to take those same steps.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__:
    from .commit_relation import RELATION_PATH, load_relation
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from commit_relation import RELATION_PATH, load_relation

ROOT = Path(__file__).resolve().parents[1]


def rust_events(rust: str) -> set[str]:
    body = re.search(r"pub enum Event \{(?P<body>.*?)^\}", rust, re.MULTILINE | re.DOTALL)
    if body is None:
        raise AssertionError("Rust Event enum not found")
    return set(re.findall(r"^\s+([A-Z][A-Za-z0-9]+),$", body["body"], re.MULTILINE))


def tla_event_map(tla: str) -> dict[str, str]:
    return dict(
        re.findall(
            r"^\\\* RUST_EVENT ([A-Z][A-Za-z0-9]+) -> ([A-Z][A-Za-z0-9]+)$",
            tla,
            re.MULTILINE,
        )
    )


def tla_actions(tla: str) -> set[str]:
    return set(re.findall(r"^([A-Z][A-Za-z0-9]+)\([^=\n]*\) ==", tla, re.MULTILINE))


def tla_steps(tla: str) -> set[tuple[str, str, str]]:
    """Every `Step(i, FROM, TO, ASSURANCE)` triple in the model."""
    return set(
        re.findall(
            r'Step\(\s*i\s*,\s*"([A-Z_]+)"\s*,\s*"([A-Z_]+)"\s*,\s*"([A-Z_]+)"\s*\)',
            tla,
        )
    )


def tla_required(tla: str) -> dict[str, str]:
    body = re.search(r"Required\(p\) ==(?P<body>.*?)(?=^[A-Za-z])", tla, re.MULTILINE | re.DOTALL)
    if body is None:
        raise AssertionError("TLA Required(p) not found")
    return dict(
        re.findall(r'p = "([A-Za-z]+)" -> "([A-Z_]+)"', body["body"])
    )


def action_body(tla: str, name: str) -> str:
    match = re.search(
        rf"^{name}\([^=\n]*\) ==(?P<body>.*?)(?=^[A-Za-z])",
        tla,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"TLA action {name} not found")
    return match["body"]


def next_flush_failure_from(tla: str) -> set[str]:
    return set(re.findall(r'FlushFailure\(\s*i\s*,\s*"([A-Z_]+)"\s*\)', tla))


def table_events(relation: dict) -> set[str]:
    events = {row["event"] for row in relation["advances"]}
    events.update(relation["poisoning"])
    events.update(relation["recovering"])
    events.add("NamespaceLinked")
    events.add("Recover")
    events.add("Abort")
    return events


def check_relation(relation: dict, rust: str, tla: str) -> list[str]:
    """What the sources disagree about. Empty means they implement one table."""
    failures: list[str] = []
    events = rust_events(rust)
    expected = table_events(relation)
    if events != expected:
        failures.append(
            f"Rust Event vs table: Rust-only={sorted(events - expected)}, "
            f"table-only={sorted(expected - events)}"
        )

    mappings = tla_event_map(tla)
    table_map = relation["tla_events"]
    if mappings != table_map:
        failures.append(
            f"RUST_EVENT map vs table: file-only={sorted(set(mappings) - set(table_map))}, "
            f"table-only={sorted(set(table_map) - set(mappings))}"
        )
        extra = {key: mappings[key] for key in mappings.keys() & table_map.keys() if mappings[key] != table_map[key]}
        if extra:
            failures.append(f"RUST_EVENT targets differ: {extra}")

    actions = tla_actions(tla)
    missing_actions = set(table_map.values()) - actions
    if missing_actions:
        failures.append(f"mapped TLA actions are undefined: {sorted(missing_actions)}")

    states = relation["tla_states"]
    assurances = relation["tla_assurances"]
    steps = tla_steps(tla)
    for row in relation["advances"]:
        if row["observation"] is None:
            continue
        # Publish is written out so it can name the predecessor set. The
        # dedicated Publish checks below cover that action.
        if table_map[row["event"]] == "Publish":
            continue
        expected_step = (
            states[row["state"]],
            states[row["next"]],
            assurances[row["observation"]],
        )
        if expected_step not in steps:
            failures.append(
                f"TLA has no Step{expected_step} for {row['state']}+{row['event']}"
            )

    flush = next(row for row in relation["advances"] if row["observation"] is None)
    flush_body = action_body(tla, table_map[flush["event"]])
    if f'state[i] = "{states[flush["state"]]}"' not in flush_body:
        failures.append(
            f"{table_map[flush['event']]} does not require {states[flush['state']]}"
        )
    if f'![i] = "{states[flush["next"]]}"' not in flush_body:
        failures.append(
            f"{table_map[flush['event']]} does not step to {states[flush['next']]}"
        )
    if "performed'" in flush_body:
        failures.append(f"{table_map[flush['event']]} records an observation")

    link_body = action_body(tla, table_map["NamespaceLinked"])
    if "state[i] = Required(profile)" not in link_body:
        failures.append("LinkNamespace does not require the profile predecessor")
    if f'![i] = "{states["NamespaceLinked"]}"' not in link_body:
        failures.append("LinkNamespace does not step to NAMESPACE_LINKED")

    publish_body = action_body(tla, table_map["NamespaceDurable"])
    if f'state[i] = "{states["NamespaceLinked"]}"' not in publish_body:
        failures.append("Publish does not require NAMESPACE_LINKED")
    if "Required(profile) \\in performed[i]" not in publish_body:
        failures.append("Publish does not require the profile predecessor")
    if f'![i] = "{states["Published"]}"' not in publish_body:
        failures.append("Publish does not step to PUBLISHED")

    abort_body = action_body(tla, table_map["Abort"])
    if 'state[i] \\notin Terminal \\cup {"RECOVERY_REQUIRED", "NAMESPACE_LINKED"}' not in abort_body:
        failures.append("Abort is not confined to the abortable states")

    recover_body = action_body(tla, "EnterRecovery")
    if 'state[i] \\notin Terminal \\cup {"RECOVERY_REQUIRED"}' not in recover_body:
        failures.append("EnterRecovery is not excluded from terminal and recovery")

    required = tla_required(tla)
    expected_required = {
        profile: assurances[level] for profile, level in relation["required"].items()
    }
    if required != expected_required:
        failures.append(f"TLA Required vs table: {required} != {expected_required}")

    flush_from = next_flush_failure_from(tla)
    expected_flush_from = {states[name] for name in relation["tla_flush_failure_from"]}
    if flush_from != expected_flush_from:
        failures.append(
            f"FlushFailure Next from-states {sorted(flush_from)} != "
            f"{sorted(expected_flush_from)}"
        )
    return failures


def main() -> None:
    relation = load_relation(RELATION_PATH)
    rust = (ROOT / "crates/vot-commit-model/src/lib.rs").read_text(encoding="utf-8")
    tla = (ROOT / "models/tla/Commit.tla").read_text(encoding="utf-8")
    failures = check_relation(relation, rust, tla)
    assert not failures, "commit TLA does not implement the relation table:\n" + "\n".join(
        failures
    )
    print("commit relation table / TLA refinement: PASS")


if __name__ == "__main__":
    main()
