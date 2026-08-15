# Package path is constructed

Criterion: a `PackagePath` exists only after `PackagePath::new` (or
`portable` / `raw`) accepts the components under one profile. Empty
paths, mixed component kinds, and raw `.` / `..` cannot be represented.

Passing evidence: `a_raw_path_cannot_leave_its_destination` and
`a_path_key_joins_components_and_prefixes_nothing` construct through
`PackagePath::new`. Decode constructs through `new`.

Mutants: drop the empty-path check in `validate_components`, which
`a_path_key_joins_components_and_prefixes_nothing` fails. Drop the
`b".."` refusal in `valid_raw_component`, which
`a_raw_path_cannot_leave_its_destination` fails. Drop the
`path.profile != profile` check in `canonical_path_key`, which
`an_index_finds_every_path_it_holds_and_nothing_it_does_not` fails
when a raw path is pushed under the portable profile.
