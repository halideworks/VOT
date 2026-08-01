# ADR-0015: Raise the MSRV for the patched optional S3 backend

- Status: Accepted
- Date: 2026-08-01

## Context

The optional `s3-live` feature pulled `aws-sdk-s3` 1.96.0. Its locked
dependency graph included `lru` 0.12.5, `rustls-webpki` 0.101.7, and `time`
0.3.45, which are covered by current RustSec advisories. The first AWS S3
release in this compatibility line that moves to patched `lru` and current
TLS/runtime dependencies is 1.120.0, whose declared MSRV is Rust 1.88.

The pinned cargo-deny 0.18.3 and cargo-audit 0.21.2 releases also cannot parse
the current RustSec database after CVSS 4.0 advisories were added.

## Decision

Raise the workspace MSRV and CI toolchain to Rust 1.88. Pin the optional S3
backend to `aws-sdk-s3` 1.120.0, cargo-deny to 0.20.2, and cargo-audit to
0.22.1. CI runs cargo-deny policy/advisory checks and cargo-audit against the
committed lockfile; no advisory is ignored.

The S3 dependency remains feature-gated. This decision changes the minimum
toolchain for the whole workspace so every supported build has the same
security policy and dependency resolution.

## Consequences

Rust 1.85 is no longer a supported build toolchain. Historical mutation and
benchmark evidence produced under 1.85 remains valid as historical evidence,
but new CI evidence uses the declared 1.88 MSRV.
