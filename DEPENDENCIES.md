# Dependency Policy

VOT keeps the correctness core small and auditable.

- Rust dependencies are declared with exact compatible intent and committed in
  `Cargo.lock` for applications, tests, fuzzers, and tools.
- New runtime dependencies require an ownership, maintenance, license, advisory,
  unsafe-code, transitive-size, and reproducibility review.
- Cryptographic and proof implementations come from primary maintained projects
  or are implemented from public specifications with independent vectors.
- Git and CI dependencies are pinned to a reviewed release or immutable commit.
- `cargo deny` policy rejects unknown licenses, known advisories without an
  explicit time-bounded exception, and unknown git sources.
- An SBOM is generated for release artifacts. Dependency source and checksums are
  retained with reproducible result bundles.
- Automated updates run tests and vector comparisons; they never auto-merge an
  identity-, wire-, storage-, or cryptography-visible change.

Current minimum Rust version is 1.88. The optional AWS S3 backend requires the
patched SDK release below, whose dependency graph requires Rust 1.88. Raising the
minimum further requires an ADR or release-policy update and CI coverage.

Wave 1 runtime dependencies:

- `blake3` 1.8.5 provides the maintained BLAKE3 compression and hashing implementation.
- `sha2` 0.10.9 provides the maintained RustCrypto SHA-256 implementation.
- `unicode-normalization` 0.1.25 provides NFC normalization for portable path collision checks.

All three are registry dependencies locked by checksum. Their licenses are accepted by `deny.toml`, and their APIs are wrapped by VOT conformance tests and independent vectors.

Wave 2 runtime dependencies:

- `aligned-vec` 0.6.4 provides aligned buffers for direct read-back.
- `rustix` 1.1.4 provides the safe Linux `O_DIRECT` descriptor API.
- `hmac` 0.12.1 provides RustCrypto HMAC-SHA-256 receipt authentication.

The optional `s3-live` feature uses `aws-sdk-s3` 1.120.0, `base64` 0.22.1,
and `tokio`. Version 1.120.0 is the first SDK release in this line that pulls
the patched `lru` release and current TLS/runtime dependencies; it requires the
project Rust 1.88 minimum. The larger SDK dependency graph is isolated behind
the feature and exercised against MinIO in CI. The MinIO server and client
images are pinned by digest.

Wave 3 adds no new third-party runtime packages. The deterministic simulator
reuses the workspace `blake3` package for canonical trace digests. The frame and
manifest fuzz drivers depend only on their corresponding workspace crates.

Wave 5 runtime dependencies:

- `fs4` 1.1.0 provides safe, cross-platform exclusive file locking for
  serialized resume-store transactions. Only its synchronous feature is
  enabled. The crate is maintained, supports Rust 1.75 and later with that
  feature, uses `rustix` instead of direct libc calls on Unix, and is licensed
  under Apache-2.0 or MIT.

Test-only dependencies:

- `cap` 0.1.2 wraps the system allocator in the million-entry manifest and fuzz
  processes. It enforces a hard allocation ceiling without adding unsafe code to
  VOT.
