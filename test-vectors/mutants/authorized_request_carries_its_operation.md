# Authorized request carries its operation

Criterion: a grant takes `AuthorizedRequest`. `ReadRanges` always names
a range. `Publish` and `ReadManifest` have no range field. An unknown
identifier cannot be a request.

Passing evidence: `token_scope_rejected` denies a `ReadRanges` past the
scope and accepts one inside it. `an_unknown_operation_in_a_valid_capability_grants_nothing`
still grants only `Publish`. Compile-fail doctests reject a raw
identifier field and a `ReadRanges` with no range.

Mutants: skip the range check on `ReadRanges`, which
`token_scope_rejected` fails on length 65_537. Make `operation()` always
`Publish`, which the `ReadManifest` denial fails because the capability
does not name that operation.

Local `cargo mutants --package vot-capability`: 128 caught, 13
unviable, 0 missed.
