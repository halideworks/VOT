# Verifier finish checks expected identity

Criterion: `StreamVerifier::finish` returns a `VerifiedObject` only when the
accepted suite, byte length, and computed root match the expected object.
A caller cannot construct that witness.

Passing evidence: `finish_returns_a_witness_only_for_the_expected_identity`
and `an_empty_stream_finishes_against_the_empty_object`.

Mutants: drop the suite, length, or root comparison, which the matching
mismatch case fails. Change `!=` to `==` on any of those three checks,
which the matching success or mismatch row fails.

Local `cargo mutants --package vot-verifier --in-diff`: 7 caught, 3
unviable, 0 missed.
