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

Both ends ask the kernel for a 16 MiB UDP receive buffer and an 8 MiB send
buffer. On Linux without `CAP_NET_ADMIN` the kernel clamps those to
`net.core.rmem_max` and `net.core.wmem_max`, 208 KiB on a stock system, which
dropped around a tenth of the packets at 12 to 15 Gbit/s over loopback. macOS
refuses a request above `kern.ipc.maxsockbuf` (about 7.4 MB by default) outright
and the socket keeps its much smaller default. The CLI prints one warning line
to stderr naming the knob when it got less than it asked for; raise it (64 MiB
is ample) to clear the warning.

A serve behind Linux's default `fq_codel` root qdisc loses packets on long paths for
a different reason: CoDel drops on queue sojourn time against a 5 ms target, and a
sender whose round trip is 100 ms keeps its queue above that permanently, so on one
measured 107 ms path 6.5% of the serve's packets were dropped by its own qdisc as
whole segmentation bursts. Raising the qdisc's limit does nothing; replacing it
(`tc qdisc replace dev eth0 root pfifo limit 100000`) took that to 0.001% and cut
the serve's CPU by a quarter, while the wall moved only 6% because eight rails are
not loss bound there.

A virtio guest with a single transmit queue commonly boots with
`tx-udp-segmentation` off, and then the serve's UDP_SEGMENT writes are taken apart
by the guest kernel and reach the queue as one 1.5 KB descriptor per packet, about
150,000 a second. That caps the serve near 1.6 Gbit/s at every rail count with no
drop counter moving and no thread busy, which is 98% of what plain UDP gets on the
same box and 17% of eight TCP streams at 3 ms, TCP keeping its own segmentation
offload. `ethtool -K eth0 tx-udp-segmentation on` (check with `ethtool -k eth0 |
grep tx-udp-segmentation`) put 30 KB in each descriptor and took the same binary to
6.1 Gbit/s at four rails and 6.0 at eight at 3 ms, 71% and 69% of eight TCP
streams, and to 3.9 at 83 ms, 189% of TCP. With it on, the fetch host's single
receive queue is the next limit: one core saturates in softirq near 380,000 packets
a second and the eighth rail adds loss rather than rate, so multiple receive queues
(RSS) or receive-side UDP GRO on the fetch host is the lever. VOT prints no warning
for this, because unlike the buffer clamp nothing socket-local reveals it.

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
| `VOT_INITIAL_CWND` | controller default | Initial congestion window in 1200-byte packets (10 to 7100, so up to ~8.5 MB of first-flight window). Set on the serve to skip most of slow start on a path the operator knows; size it near the path's bandwidth-delay product. The seed acts while the connection starts up and decays as the path's datagram size settles, so a generous value costs a burst, not the connection |
| `VOT_PREFIX_DUP` | 200 | Datagrams each end sends twice at the start of a connection, up to 4096, where `0` sends each once. The serial prefix is sparse, so a loss in it waits on a recovery round trip nothing else can shorten; the copies cost about 240 KB once per connection and removed the multi-second first-byte tail at 5% loss |
| `VOT_FETCH_RAILS` | `clamp(2 * cores, 1, 8)` | Concurrent fetch sessions (multi-rail) |
| `VOT_DATAGRAM_BYTES` | auto (PMTU) | Max datagram size override |
| `VOT_DATAGRAM_FEC` | `auto` | Negotiates datagram FEC but codes only once the smoothed measured loss reaches 10%, and stops again below 6.25%; `off` disables negotiation and `on` forces coding. The reliable path carries clean traffic. |
| `VOT_RENDEZVOUS` | unset | Rendezvous service, `ADDR:PORT` or `NAME:PORT`. A serve registers there; a fetch given a root instead of an address resolves there. No default: both ends name the same one. |
| `VOT_FETCH_PROVERS` | unset | Total proving thread ceiling for a fetch, divided evenly across its rails with at least one per rail |
| `VOT_FETCH_STATS` | unset | Set to `1` for a fetch to write one line to stderr when it finishes: the bytes it placed itself, total milliseconds, milliseconds to first verified payload, and what the datagram FEC path offered, decoded, abandoned, and refused |
| `VOT_FETCH_UNPINNED` | unset | Set to fetch at an address without a `PACKAGE_ROOT`, accepting whichever package the server serves |
| `VOT_FETCH_SERVE_IDENTITY` | unset | Pins the serve's identity: the 64 hex characters of the certificate digest `vot serve` prints. The fetch drops any connection whose certificate differs, before it sends anything |
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
