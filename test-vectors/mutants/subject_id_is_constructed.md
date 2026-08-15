# Subject identity is constructed

Criterion: a `SubjectId` is a registered suite, a 32-byte root, and a
representable length. Suite zero is only a store marker. A wire
`ObjectId` converts only when `validate` accepts it.

Passing evidence: `a_subject_is_a_registered_suite_and_a_representable_length`
accepts suites 1 and 2, rejects 0 and 3 and a length past `i64::MAX`,
round-trips a valid `ObjectId`, and refuses to convert a marker.

Mutants: skip `ObjectId::validate` in `TryFrom`, which the suite-0
conversion fails. Make `is_marker` always false, which the marker
assertion fails.

Local `cargo mutants --package vot-transport-api`: 93 caught, 21
unviable, 0 missed.
