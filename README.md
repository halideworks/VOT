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

# Run a relay, for two ends that cannot punch (ADR-0034).
vot relay LISTEN_ADDR
```

A relay forwards datagrams between the two ends of a slot and reads none of
them: it sees ciphertext, two addresses, and byte counts. A slot is a port, so
a relayed datagram is exactly the size of a direct one and nothing is wrapped.
Both ends reach it outbound, which is why it works where a punch does not.
Slots are keyed by the same hash of the root the rendezvous pairs on, so a
relay never learns a root either, and each carries a lifetime and a byte
ceiling its operator sets.

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

A fetch without a token is refused on the challenge rather than after a
transfer, and the refusal says the same thing whatever was wrong with the
token, because the difference between an expired one and a forged one is an
oracle.

What the token decides is that whoever opened the session holds the key it
names. It does not decide that the peer at the far end of the QUIC connection
is that holder: the proof is over a nonce, so an interposer can forward it.
Binding to the channel needs a keying-material exporter quiche does not
expose. An interposer still cannot give you different bytes.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VOT_CONGESTION` | `bbr2` | Congestion controller (`bbr2` or `cubic`) |
| `VOT_FETCH_RAILS` | `min(4, cores)` | Concurrent fetch sessions (multi-rail) |
| `VOT_DATAGRAM_BYTES` | auto (PMTU) | Max datagram size override |
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
