# Commit TLA implements the relation table

Criterion: `models/tla/Commit.tla` takes the same advances, predecessor
guards, abort/recovery exclusions, and `FlushFailure` from-states as
`models/commit/relation.json`. A TLA action that only shares an Event name
with Rust is not enough.

Passing evidence: `tools/test_commit_model_sync.py` loads the committed
sources and requires `check_relation` to return no failures. It then applies
three mutants of the TLA text.

Mutants: rewrite `Step(i, "NEW", "ADMITTED", "ADMITTED")` to publish from
`NEW`, which `test_swapped_step_is_rejected` fails. Drop
`FlushFailure(i, "DURABLE")` from `Next`, which
`test_dropped_flush_failure_from_state_is_rejected` fails. Delete
`Required(profile) \in performed[i]` from `Publish`, which
`test_publish_without_predecessor_guard_is_rejected` fails.
