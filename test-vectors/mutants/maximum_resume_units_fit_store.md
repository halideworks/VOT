# Maximum resume units fit the store

Criterion: every accepted collection of object unit counts can be fully
checkpointed in the bounded resume store.

Passing evidence: resume_store_handles_million_small_file_workload reserves
one million one-unit objects plus a 100-unit object in one compacted range
snapshot, appends a checkpoint, reopens the log, and proves the data remains
below the 64 MiB bound. The exact 8,388,595-unit per-object boundary is also
checked by store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic.

Mutants: remove range encoding, replay only the last append record, omit the
bounded snapshot check, or replace validate_reserved_capacity with Ok(()).

Mutation status: the final isolated `cargo mutants --package vot-resume
--jobs 1` run under Rust 1.88 and cargo-mutants 26.0.0 tested 254 mutants:
243 caught, 0 missed, 11 unviable, and 0 timeouts. The run covered VOTRES02,
range encoding, append replay, and the bounded unit iterator checks.
