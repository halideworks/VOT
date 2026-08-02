# VOT

Verified Object Transport is a protocol and implementation for transferring
immutable objects and publishing them with explicit receiver assurance.

The project is in early development. The v0.3 specifications are in `spec/`.
Implementation order and acceptance gates are defined in
`VOT_v0.3_Agent_Backlog.yaml`.

## Validation

```sh
python3 tools/validate_benchmark_contract.py
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
cargo test -p vot-platform-fs --locked
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

## Package transfer

Build a deterministic transfer bundle:

```sh
cargo run -p vot-cli -- send SOURCE_DIRECTORY BUNDLE_DIRECTORY
```

An explicit logical-object suite can be selected with:

```sh
cargo run -p vot-cli -- send SUITE SOURCE_DIRECTORY BUNDLE_DIRECTORY
```

SUITE is `blake3` or `sha256`; the default is `sha256`.

Verify and publish a bundle, then write an authenticated receipt:

```sh
cargo run -p vot-cli -- receive BUNDLE_DIRECTORY DESTINATION_DIRECTORY RECEIPT.cbor KEY_SOURCE 2026-07-31T20:00:00Z
```

The receiver refuses to replace an existing destination or receipt.

Check a receipt without the bundle:

```sh
cargo run -p vot-cli -- verify-receipt RECEIPT.cbor KEY_SOURCE
```

`cargo run -p vot-cli -- help` prints the same reference as below.

### Keys

KEY_SOURCE says where to read the key from: `env:NAME`, `-` for standard input,
or a file path. What it reads decides the kind of key:

| Contents | Meaning |
| --- | --- |
| `ed25519-secret:HEX` | signs; 64 hex characters. `receive` only |
| `ed25519-public:HEX` | checks a signature; 64 hex characters |
| `hex:HEX` | shared secret, 32 to 64 bytes |
| `raw:TEXT` | shared secret as text |
| anything else | shared secret as raw bytes, 32 to 64 bytes |

An Ed25519 key is labelled because a secret and a public key are both 32 bytes,
and using one as the other would either leak the secret or produce receipts
nobody can check.

A receipt signed with `ed25519-secret` can be checked by anyone holding only the
matching `ed25519-public` key, and `verify-receipt` reports
`THIRD-PARTY-VERIFIABLE`. A shared secret cannot: whoever can check it can also
forge it, so those report `SHARED-SECRET`.

An auditor holding only the public key can run `verify-receipt`, but not
`receive`, which has to sign. The one exception is finishing a publication that
was interrupted after its receipt was already signed.

## License

The Rust implementation and project files are licensed under
AGPL-3.0-only. The protocol specifications, test vectors, and formal models in
`spec/`, `test-vectors/`, and `models/` are licensed under Apache-2.0. See
`LICENSE`, `LICENSE-APACHE`, and the license marker in each permissive directory.
