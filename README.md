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

# Fetch a bundle from a server. The root is what says which package to accept.
vot fetch CONNECT_ADDR BUNDLE_DIR PACKAGE_ROOT

# Fetch and receive in one step.
vot pull CONNECT_ADDR BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE \
  OBSERVED_AT PACKAGE_ROOT

# Run a rendezvous service (ADR-0033).
vot rendezvous LISTEN_ADDR
```

A fetch may name the package root where an address goes, which removes the
port-forward on an unmanaged network. Both ends point `VOT_RENDEZVOUS` at the
same service: the serve registers under a hash of the root, the fetch resolves
it, and each end punches the other's NAT. Symmetric and carrier-grade NAT
defeat the punch by construction, and the fetch says so rather than hanging.

```sh
export VOT_RENDEZVOUS=rendezvous.example:9999
vot serve BUNDLE_DIR 0.0.0.0:0            # registers under the bundle's root
vot fetch ROOT BUNDLE_DIR                 # resolves that root, no address
```

The channel is not authenticated. The server presents a throwaway certificate
and the client does not verify it. What an attacker cannot do is serve different
bytes: every range proves to its object root, every root is named by the
manifest, and the manifest proves to the seal.

That argument holds for the package the fetch named, and says nothing about
which package it got. So a fetch at an address requires the `PACKAGE_ROOT`,
and `vot serve` prints the whole fetch command for the bundle it is serving,
so the end holding the bundle hands over one line. A root in the address
position pins itself. `VOT_FETCH_UNPINNED=1` fetches from a server whose
package cannot be known in advance.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VOT_CONGESTION` | `bbr2` | Congestion controller (`bbr2` or `cubic`) |
| `VOT_FETCH_RAILS` | `min(4, cores)` | Concurrent fetch sessions (multi-rail) |
| `VOT_DATAGRAM_BYTES` | auto (PMTU) | Max datagram size override |
| `VOT_RENDEZVOUS` | unset | Rendezvous service, `ADDR:PORT` or `NAME:PORT`. A serve registers there; a fetch given a root instead of an address resolves there. No default: both ends name the same one. |
| `VOT_FETCH_PROVERS` | unset | Proving thread count for fetch |
| `VOT_FETCH_UNPINNED` | unset | Set to fetch at an address without a `PACKAGE_ROOT`, accepting whichever package the server serves |

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
