#!/usr/bin/env python3
"""The TLA sync checker rejects a relation the table does not authorize."""

from __future__ import annotations

import unittest
from pathlib import Path

if __package__:
    from .commit_relation import RELATION_PATH, load_relation
    from .validate_commit_model_sync import check_relation, rust_events, tla_steps
else:
    from commit_relation import RELATION_PATH, load_relation
    from validate_commit_model_sync import check_relation, rust_events, tla_steps

ROOT = Path(__file__).resolve().parents[1]


def sources() -> tuple[dict, str, str]:
    relation = load_relation(RELATION_PATH)
    rust = (ROOT / "crates/vot-commit-model/src/lib.rs").read_text(encoding="utf-8")
    tla = (ROOT / "models/tla/Commit.tla").read_text(encoding="utf-8")
    return relation, rust, tla


class RelationTableSync(unittest.TestCase):
    def test_committed_sources_agree(self) -> None:
        relation, rust, tla = sources()
        self.assertEqual(check_relation(relation, rust, tla), [])

    def test_rust_events_are_the_table_events(self) -> None:
        relation, rust, _tla = sources()
        self.assertIn("Abort", rust_events(rust))
        self.assertTrue(any(row["event"] == "Admit" for row in relation["advances"]))

    def test_swapped_step_is_rejected(self) -> None:
        relation, rust, tla = sources()
        mutated = tla.replace(
            'Step(i, "NEW", "ADMITTED", "ADMITTED")',
            'Step(i, "NEW", "PUBLISHED", "PUBLISHED")',
            1,
        )
        self.assertNotEqual(tla_steps(tla), tla_steps(mutated))
        failures = check_relation(relation, rust, mutated)
        self.assertTrue(
            any("NEW" in item and "Admit" in item for item in failures),
            failures,
        )

    def test_dropped_flush_failure_from_state_is_rejected(self) -> None:
        relation, rust, tla = sources()
        mutated = tla.replace('FlushFailure(i, "DURABLE")', "FALSE", 1)
        failures = check_relation(relation, rust, mutated)
        self.assertTrue(any("FlushFailure" in item for item in failures), failures)

    def test_publish_without_predecessor_guard_is_rejected(self) -> None:
        relation, rust, tla = sources()
        mutated = tla.replace(
            "/\\ Required(profile) \\in performed[i]\n",
            "",
            1,
        )
        failures = check_relation(relation, rust, mutated)
        self.assertTrue(
            any("Publish does not require the profile predecessor" in item for item in failures),
            failures,
        )


if __name__ == "__main__":
    unittest.main()
