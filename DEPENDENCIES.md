# Dependency Policy

VOT keeps the correctness core small and auditable.

- Runtime dependencies are pinned in `Cargo.lock`. New ones require a review
  covering ownership, maintenance, license, advisory history, unsafe-code
  surface, transitive size, and reproducibility impact.
- Cryptographic implementations come from maintained projects or are written
  from public specifications with independent vectors.
- `cargo deny` rejects unknown licenses, known advisories, and unknown git
  sources.
- SBOM is generated for release artifacts.
- Automated update PRs run tests and vector comparisons. They never auto-merge
  identity-, wire-, storage-, or cryptography-visible changes.

Minimum Rust version: 1.88.

## Runtime dependencies

| Crate | Version | Purpose |
| --- | --- | --- |
| `blake3` | 1.8.5 | BLAKE3 hashing |
| `sha2` | 0.11.0 | SHA-256 (RustCrypto) |
| `ed25519-dalek` | 2.2.0 | Ed25519 signing and verification |
| `rustls` | 0.23.43 | TLS for TCP carrier |
| `base64` | 0.23.0 | Signed-note format in `vot-log` |
| `unicode-normalization` | 0.1.24 | NFC for portable path collision checks |
| `aligned-vec` | 0.6.4 | Aligned buffers for direct I/O |
| `rustix` | 1.1.4 | Safe Linux `O_DIRECT` |
| `fs4` | 1.1.0 | Cross-platform file locking for resume store |
| `libc` | 0.2.189 | Don't-fragment socket options, process metrics |

### Optional (`s3-live` feature)

| Crate | Version | Purpose |
| --- | --- | --- |
| `aws-sdk-s3` | 1.122.0 | S3-compatible multipart upload |
| `tokio` | (via SDK) | Async runtime |

### Unsafe in dependencies

`curve2551919-dalek` (via `ed25519-dalek`) contains unsafe in its backends.
This does not relax the workspace lint (which governs VOT's own crates only)
but is part of the audited surface. Accepted because a receipt that cannot be
verified without the ability to forge it is not evidence (ADR-0017).

## Test-only dependencies

| Crate | Version | Purpose |
| --- | --- | --- |
| `cap` | 0.1.2 | Allocation ceiling in million-entry tests |
| `libfuzzer-sys` | 0.4.13 | Fuzz entry points (separate workspace) |

## CI actions

All pinned to released tags: `actions/checkout` 4.3.1,
`actions/setup-python` 6.2.0, `actions/upload-artifact` 4.6.2,
`actions/cache` 6.1.0.
