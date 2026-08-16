# VOT

Verified Object Transfer: a protocol and Rust implementation for transferring
immutable objects with cryptographic receiver assurance.

Status: early development. Specifications are in `spec/`.

## Quick start

```sh
cargo test --workspace --locked
```

## Library entry points

- `vot-sdk` is the pure Rust facade for verified coverage, package ingest,
  proof catalogs, and receipts. It has no native filesystem or network
  dependency.
- `vot-wasm` exposes the pure facade through generated WebAssembly bindings.
- `vot-sdk-file` adds native file staging and publication on Linux, macOS, and
  Windows. It never overwrites an existing destination and reports an
  unsupported assurance requirement instead of silently downgrading it.

Applications can use the pure facade directly and add the native adapter only
where filesystem publication is required.

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

# Run a relay, for two ends that cannot punch (ADR-0034).
vot relay LISTEN_ADDR
```

A relay forwards ciphertext between two endpoints. It observes addresses and
byte counts, not package roots or plaintext. Slots are keyed by a root hash and
bounded by operator-configured lifetimes and byte limits.

With `VOT_RENDEZVOUS`, the serve registers a package-root hash, the fetch
resolves it, and both peers attempt NAT traversal. Symmetric and carrier-grade
NAT may require a relay.

```sh
export VOT_RENDEZVOUS=rendezvous.example:9999
vot serve BUNDLE_DIR 0.0.0.0:0            # registers under the bundle's root
vot fetch ROOT BUNDLE_DIR                 # resolves that root, no address
```

Transport certificates are ephemeral and are not verified. Content is instead
authenticated against the requested package root: ranges prove to object
roots, and the manifest proves those roots to the package seal. Address-based
fetches therefore require `PACKAGE_ROOT`. Set `VOT_FETCH_UNPINNED=1` only when
the remote package is intentionally accepted without a trusted root.

### Who may fetch

A serve answers anyone by default. Give it an issuer key and it requires a
capability: a signed token naming one package, one holder key, and a validity
window. ADR-0036.

Every key below is a `KEY_SOURCE`, so it names where to read a key from and
not the key itself: `env:NAME`, `-` for stdin, or a file path. What it reads
is the labelled key, `ed25519-secret:HEX` or `ed25519-public:HEX`.

```sh
# The recipient makes a key and sends you the public half.
vot capability keygen                      # prints the secret, then the public

# You mint a token for your package under your own issuer key.
export ISSUER_SECRET=ed25519-secret:...    # your key, however you store it
export HOLDER_PUBLIC=ed25519-public:...    # theirs
vot capability issue env:ISSUER_SECRET you.example them.example \
  env:HOLDER_PUBLIC PACKAGE_ROOT 86400 token.cbor

# Your serve requires one.
export ISSUER_PUBLIC=ed25519-public:...    # the public half of yours
export VOT_SERVE_ISSUER=env:ISSUER_PUBLIC
export VOT_SERVE_ISSUER_NAME=you.example
export VOT_SERVE_AUDIENCE=them.example
vot serve BUNDLE_DIR 0.0.0.0:9000

# Their fetch presents it.
export HOLDER_SECRET=ed25519-secret:...
export VOT_FETCH_CAPABILITY=token.cbor
export VOT_FETCH_HOLDER_KEY=env:HOLDER_SECRET
vot fetch ADDR BUNDLE_DIR PACKAGE_ROOT
```

Authentication completes before transfer. Token validation failures use the
same refusal to avoid exposing token state.

The capability proof binds the holder key to the session challenge and TLS
exporter. Authentication fails closed when the carrier cannot provide that
binding. The exporter does not authenticate the server; the package root
authenticates received content. See ADR-0037.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VOT_CONGESTION` | `bbr2` | Congestion controller (`bbr2` or `cubic`) |
| `VOT_FETCH_RAILS` | `min(4, cores)` | Concurrent fetch sessions (multi-rail) |
| `VOT_DATAGRAM_BYTES` | auto (PMTU) | Max datagram size override |
| `VOT_DATAGRAM_FEC` | unset | Set to `1` at both ends to offer the experimental datagram FEC extension; group-aligned answers then travel as coded symbols and the reliable path carries the rest |
| `VOT_RENDEZVOUS` | unset | Rendezvous service, `ADDR:PORT` or `NAME:PORT`. A serve registers there; a fetch given a root instead of an address resolves there. No default: both ends name the same one. |
| `VOT_FETCH_PROVERS` | unset | Proving thread count for fetch |
| `VOT_FETCH_UNPINNED` | unset | Set to fetch at an address without a `PACKAGE_ROOT`, accepting whichever package the server serves |
| `VOT_SERVE_ISSUER` | unset | Issuer public key a serve accepts capabilities from, as a `KEY_SOURCE`. With the two below, the serve requires one |
| `VOT_SERVE_ISSUER_NAME` | unset | The issuer name that key signs under |
| `VOT_SERVE_AUDIENCE` | unset | The deployment a capability must name |
| `VOT_FETCH_CAPABILITY` | unset | Path to the token a fetch presents |
| `VOT_FETCH_HOLDER_KEY` | unset | The holder secret that token names, as a `KEY_SOURCE` |
| `VOT_RELAY_SLOTS` | 8 | Slots a relay opens at once |
| `VOT_RELAY_TTL_MS` | 600000 | How long one slot lives |
| `VOT_RELAY_BYTES` | 8589934592 | Bytes one slot forwards before it closes |

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
