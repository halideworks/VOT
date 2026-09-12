# VOT

**Verified Object Transfer** is a protocol and Rust toolkit for moving large
files and directory trees with cryptographic proof of what arrived. It verifies
ranges as they arrive, resumes interrupted transfers, and distinguishes received
bytes from durable storage and final publication.

Use VOT to build transfer tools, media pipelines, or storage services that need
verifiable completion. Content identities and proofs are independent of the
transport, so applications can use the same verification model across network
and storage adapters.

**Prerelease.** APIs and formats may change. The CLI transfers immutable
packages today. Growing-file capture foundations are available in the SDK;
watch-folder uploads and mounted remote filesystems are not implemented.

## What it provides

- BLAKE3 and SHA-256 object identities, range proofs, and deterministic packages.
- QUIC transfers with resume, concurrent sessions, optional capability-based
  access, rendezvous, and relay support.
- Explicit storage assurance and receipts, including Ed25519 signatures that
  third parties can verify. Unsupported guarantees fail instead of downgrading.
- Streaming file preparation and bounded disk capture buffers, without staging
  entire payloads in RAM. Resource limits still depend on the chosen adapter.

Linux, macOS, and Windows are supported, with provider-specific storage limits.
The `receive-push` listener currently requires Unix; the dialing `push` command
supports all three platforms. See [mounted-share support](docs/mounted-shares.md)
and [capture status](docs/capture.md).

## Build and try it

Use Rust 1.97 or newer; CI uses 1.97.1. Run from the repository root:

```sh
cargo test --workspace --locked
cargo run -p vot-cli -- send ./source ./bundle
```

`send` creates a deterministic bundle and prints its package root and length.
To transfer it over QUIC:

```sh
cargo build -p vot-cli --release --features wire --locked
./target/release/vot-cli serve ./bundle 0.0.0.0:9000
# On the receiving machine, using the package root printed by send:
./target/release/vot-cli fetch HOST:9000 ./received-bundle PACKAGE_ROOT
```

The `wire` build needs a C/C++ toolchain, CMake and libclang; native macOS and
Windows builds also need NASM. On Windows, the executable is `vot-cli.exe`.

Obtain the package root through a trusted channel: it identifies the content
fetch will accept. Server identity pinning and access controls are configured
separately. See the [CLI reference](docs/cli.md) for publication, receipts,
authentication, push, and network tuning.

## Embed it

| Crate | Purpose |
| --- | --- |
| `vot-sdk` | Pure Rust facade for object preparation, proofs, verified coverage, packages, and receipts; no native filesystem or network dependency. |
| `vot-sdk-file` | Native staging, recovery, and publication, plus mutable disk capture. |
| `vot-wasm` | WebAssembly bindings for the pure SDK. |

The workspace crates are not published to crates.io yet. Use this checkout as a
path dependency and build API docs with `cargo doc -p vot-sdk -p vot-sdk-file --no-deps`.

## Developer resources

- [Architecture and invariants](spec/architecture.md)
- [CLI reference](docs/cli.md) and [sessions](docs/session.md)
- [Capture integration and remaining work](docs/capture.md)
- [Validation commands](docs/validation.md)
- [Protocol specifications](spec/) and [architecture decisions](adr/)
- [Benchmarks and platform measurements](bench/results/)

## License

Rust implementation and project files: [AGPL-3.0-only](LICENSE).
Specifications, test vectors, and formal models: [Apache-2.0](LICENSE-APACHE).
See the license markers in each permissive directory.
