# Batch outcomes name ownership

Criterion: a reliable batch that stops reports `Rejected`, `Partial`,
or `Ambiguous`. Zero records taken is `Rejected`, never `Partial`.
`Ambiguous` has no taken count.

Passing evidence: `rejected_partial_and_ambiguous_are_distinct` maps
`stopped(0)` to `Rejected` and `stopped(3)` to `Partial { admitted: 3 }`.
`taken()` is `Some(0)`, `Some(3)`, and `None`.
`a_batch_that_stops_part_way_reports_what_the_backend_took` fails the
third record as `stopped(2, Backend)` and the first record as
`Rejected`.

Mutants: make `stopped` always `Rejected`, which the part-way test
fails. Make `taken` return `Some(0)` for `Ambiguous`, which
`rejected_partial_and_ambiguous_are_distinct` fails.

Local `cargo mutants --package vot-transport-api`: 84 caught, 18
unviable, 0 missed.
