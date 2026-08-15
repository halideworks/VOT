# Error codes are generated

Criterion: every error-code identifier in `vot-codec` is generated from
`spec/registries.yaml`. The Rust module is the complete table, not a
subset. Editing the generated file without regenerating fails.

Passing evidence: `validate_registries.py` accepts the committed
`generated.rs`. `test_committed_sources_agree` is the same check.

Mutants: drop `RISK_BUDGET_EXHAUSTED` from the YAML document, which
`test_dropped_error_is_rejected` fails. Change `MALFORMED_FRAME` to
`0x0103` in the generated file, which
`test_swapped_error_value_is_rejected` fails.
