# Range is constructed

Criterion: a `Range` is a nonzero length whose end fits in `u64`.
Fields are private. `AuthorizedRequest::ReadRanges` can only name one.

Passing evidence: `a_range_is_a_nonzero_length_that_fits` accepts
`(7, 3)` and `(u64::MAX - 1, 1)`, rejects length 0 and
`offset == u64::MAX` with length 1. The compile-fail doctest refuses
a struct literal.

Mutants: skip the length-zero check, which `Range::new(0, 0)` fails.
Skip the overflow check, which `Range::new(u64::MAX, 1)` fails.

Local `cargo mutants --package vot-capability --in-diff`: 16 caught, 1
unviable, 0 missed.
