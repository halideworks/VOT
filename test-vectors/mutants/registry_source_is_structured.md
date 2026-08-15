# Registry source is structured

Criterion: identifier tables live in `spec/registries.yaml`. The Markdown
view and the `vot-codec` constants must match it.

Passing evidence: `validate_registries.py` accepts the committed tree.
`test_committed_sources_agree` is the same check.

Mutants: drop `HELLO` from the YAML, which `test_dropped_frame_is_rejected`
fails. Change `PUBLISH` to `0x0004` in Rust, which
`test_swapped_operation_value_is_rejected` fails. Remove the Markdown
`PUBLISH` row, which `test_markdown_missing_a_row_is_rejected` fails.
Mark `CAPACITY` critical, which `test_handling_parity_is_rejected` fails.
