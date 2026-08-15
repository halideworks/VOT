# Frame behavior is generated

Criterion: each frame's payload limit, auth requirement, and extension
live in `spec/registries.yaml`. `frame_registry!` is generated from
those rows.

Passing evidence: `validate_registries.py` accepts the committed
`generated_frames.rs`. `test_committed_sources_agree` is the same check.

Mutants: change `HELLO` from `auth: exempt` to `auth: required` in
`generated_frames.rs`, which `test_stale_generated_frames_are_rejected`
fails.
