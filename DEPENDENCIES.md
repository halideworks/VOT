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

Current minimum Rust version is 1.85 for Rust 2024 edition support. Raising it
requires an ADR or release-policy update and CI coverage.

Wave 1 runtime dependencies:

- `blake3` 1.8.5 provides the maintained BLAKE3 compression and hashing implementation.
- `sha2` 0.10.9 provides the maintained RustCrypto SHA-256 implementation.
- `unicode-normalization` 0.1.25 provides NFC normalization for portable path collision checks.

All three are registry dependencies locked by checksum. Their licenses are accepted by `deny.toml`, and their APIs are wrapped by VOT conformance tests and independent vectors.
