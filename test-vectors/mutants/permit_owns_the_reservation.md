# Permit owns the reservation

Criterion: a `Ledger` reservation is held only by `Permit` values. Dropping a
permit returns its amount once. Splitting moves amount between permits and
does not change `used`. A rejected acquire leaves the counters unchanged.

Passing evidence: `drop_returns_the_reservation`, `split_conserves_the_reservation`,
`rejected_acquire_leaves_the_ledger`, and `panic_unwind_releases` in
`crates/vot-transport-api/src/permit.rs`.

Mutants: skip the `used` subtract in `Drop`, which
`drop_returns_the_reservation` fails. Skip subtracting `take` from the parent
in `split`, which `split_conserves_the_reservation` fails after the child is
dropped (`used` stays 6). Accept an acquire past the limit, which
`rejected_acquire_leaves_the_ledger` fails. Change `next > limit` to
`next >= limit`, which `acquire_may_fill_the_limit` fails on `acquire(10)`.
Replace `is_poisoned` with `false`, which `over_release_poisons` fails after
a drop that subtracts more than `used`.
