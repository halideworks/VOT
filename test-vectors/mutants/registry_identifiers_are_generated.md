# Registry identifiers are generated

Criterion: setting, operation, limit, and extension identifiers in
`vot-codec` are generated from `spec/registries.yaml`. Editing the
generated file without regenerating fails.

Passing evidence: `validate_registries.py` accepts the committed
`generated.rs`. `test_committed_sources_agree` is the same check.

Mutants: rename `IDLE_TIMEOUT_MS` in `generated.rs`, which
`test_stale_generated_file_is_rejected` fails. Change `PUBLISH` to
`0x0004` in the generated file, which
`test_swapped_operation_value_is_rejected` fails.
