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

`decode_subject` treats suite 0 and length 0 as a marker and every
neighbor as corrupt or a real object. Hand-applied mutants in
`a_marker_decodes_and_its_neighbors_do_not`: `&&` to `||` accepts
suite 0 length 1 as a marker; `suite == 0` to `!=` and
`length == 0` to `!=` both fail to decode the marker.

Local `cargo mutants --package vot-transport-api`: 93 caught, 21
unviable, 0 missed.
