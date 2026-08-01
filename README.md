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
python3 tools/verify_wave4_package.py
python3 tools/validate_commit_fixtures.py
python3 tools/validate_commit_model_sync.py
python3 tools/differential_fuzz_codec.py
cargo test --workspace --locked
cargo test -p vot-resume --test e_resume --locked
cargo test -p vot-transport-tcp --locked
cargo test -p vot-commit-platform --locked
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

## Package transfer

Build a deterministic transfer bundle:

```sh
cargo run -p vot-cli -- send SOURCE_DIRECTORY BUNDLE_DIRECTORY
```

Verify and publish a bundle, then write an authenticated receipt:

```sh
cargo run -p vot-cli -- receive BUNDLE_DIRECTORY DESTINATION_DIRECTORY RECEIPT.cbor HMAC_KEY_HEX 2026-07-31T20:00:00Z
```

The HMAC key must be at least 32 bytes. The receiver refuses to replace an
existing destination or receipt.

## License

The Rust implementation and project files are licensed under
AGPL-3.0-only. The protocol specifications, test vectors, and formal models in
`spec/`, `test-vectors/`, and `models/` are licensed under Apache-2.0. See
`LICENSE`, `LICENSE-APACHE`, and the license marker in each permissive directory.
