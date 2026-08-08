# VOT

Verified Object Transfer: a protocol and Rust implementation for transferring
immutable objects with cryptographic receiver assurance.

Status: early development. Specifications are in `spec/`.

## Quick start

```sh
cargo test --workspace --locked
```

## Commands

Build and run with `cargo run -p vot-cli -- <command>`.

### Local: build and verify a bundle

```sh
# Build a deterministic transfer bundle from a directory.
vot send [SUITE] SOURCE_DIR BUNDLE_DIR
# Prints: ROOT LENGTH

# Verify, publish, and write a receipt.
vot receive BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE OBSERVED_AT
# Prints: ROOT LENGTH PUBLISHED

# Check a receipt without the bundle.
vot verify-receipt RECEIPT.cbor KEY_SOURCE
# Prints: ROOT LENGTH ASSURANCE (THIRD-PARTY-VERIFIABLE or SHARED-SECRET)
```

SUITE is `blake3` or `sha256` (default: `sha256`).

OBSERVED_AT is an RFC 3339 timestamp.

### Wire: serve and fetch over QUIC

Wire commands need the `wire` feature (builds BoringSSL via cmake):

```sh
# Serve a bundle. Supports concurrent sessions.
vot serve BUNDLE_DIR LISTEN_ADDR [CERT.pem KEY.pem]

# Fetch a bundle from a server.
vot fetch CONNECT_ADDR BUNDLE_DIR [PACKAGE_ROOT]

# Fetch and receive in one step.
vot pull CONNECT_ADDR BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE \
  OBSERVED_AT [PACKAGE_ROOT]

# Run a rendezvous service (ADR-0033).
vot rendezvous LISTEN_ADDR
```

The channel is not authenticated. The server presents a throwaway certificate
and the client does not verify it. What an attacker cannot do is serve different
bytes: every range proves to its object root, every root is named by the
manifest, and the manifest proves to the seal. An optional PACKAGE_ROOT pins
which package the fetcher will accept.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VOT_CONGESTION` | `bbr2` | Congestion controller (`bbr2` or `cubic`) |
| `VOT_FETCH_RAILS` | `min(4, cores)` | Concurrent fetch sessions (multi-rail) |
| `VOT_DATAGRAM_BYTES` | auto (PMTU) | Max datagram size override |
| `VOT_RENDEZVOUS` | unset | Rendezvous service address for serve registration |
| `VOT_FETCH_PROVERS` | unset | Proving thread count for fetch |

## Keys

KEY_SOURCE is `env:NAME`, `-` (stdin), or a file path.

| Contents | Meaning |
| --- | --- |
| `ed25519-secret:HEX` | Signs receipts. 64 hex chars. `receive` and `pull` only. |
| `ed25519-public:HEX` | Verifies a signature. 64 hex chars. |
| `hex:HEX` | Shared secret. 32-64 bytes. |
| `raw:TEXT` | Shared secret as text. |
| anything else | Shared secret as raw bytes. 32-64 bytes. |

Ed25519 receipts are third-party verifiable: anyone with the public key can
check them. Shared-secret receipts cannot be verified without the ability to
forge them.

## Platform support

Linux, macOS, and Windows. Platform-specific code is isolated in
`vot-platform-fs`, `vot-platform-net`, and `vot-platform-proc`.

## Documentation

- [Validation](docs/validation.md) - every check and how to run it
- [Sessions and negotiation](docs/session.md) - handshake, readiness, lane identity
- [Specifications](spec/) - protocol specs (wire, security, proofs, registries)
- [Architecture](spec/architecture.md) - crate layering and invariants
- [ADRs](adr/) - decision records with reasoning

## Tooling

- `vot-bench-driver` - benchmark carrier (simulator, quiche, msquic)
- `vot-transport-sim` - deterministic network simulator
- `fuzz/` - libFuzzer targets for codec and manifest
- `tools/` - Python validators for conformance vectors
- `test-vectors/` - committed test vectors and mutation test records

## License

Rust implementation and project files: AGPL-3.0-only.
Specifications, test vectors, and formal models: Apache-2.0.
See `LICENSE`, `LICENSE-APACHE`, and permissive-directory markers.
