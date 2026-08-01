# VOT

Verified Object Transport is a protocol and implementation for transferring
immutable objects and publishing them with explicit receiver assurance.

The project is in early development. The v0.3 specifications are in `spec/`.
Implementation order and acceptance gates are defined in
`VOT_v0.3_Agent_Backlog.yaml`.

## Validation

```sh
python3 tools/validate_registries.py
python3 tools/validate_wire_vectors.py
python3 tools/validate_security_matrix.py
python3 tools/validate_wave0.py
python3 tools/verify_wave1_vectors.py
python3 tools/verify_manifest_pack_vectors.py
python3 tools/validate_commit_fixtures.py
python3 tools/validate_commit_model_sync.py
python3 tools/differential_fuzz_codec.py
cargo test --workspace --locked
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

## License

The Rust implementation and project files are licensed under
AGPL-3.0-only. The protocol specifications, test vectors, and formal models in
`spec/`, `test-vectors/`, and `models/` are licensed under Apache-2.0. See
`LICENSE`, `LICENSE-APACHE`, and the license marker in each permissive directory.
