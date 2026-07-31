# ADR-0010: Package metadata uses deterministic CBOR, bounded pages, and packs

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A04 manifests and packs

## Context

Package identity must be independently reproducible across platforms and remain
bounded for a million small files. Paths, flexible map encodings, and ad hoc
small-file aggregation otherwise create collisions and identity ambiguity.

## Decision

VOT uses RFC 8949 core deterministic CBOR and CDDL schemas. Manifest pages are
at most 1 MiB, entries are ordered by canonical package path, and progressive
pages form an authenticated chain finalized by `SEAL`. Non-deterministic CBOR is
rejected wherever bytes are hashed or signed.

Paths are component arrays under portable or raw-POSIX profiles and are
preflighted for traversal, platform validity, and collisions before filesystem
mutation.

Small-file pack candidates default to at most 256 KiB, ordered by canonical path,
with 8-byte zero alignment, a 64 MiB target, 128 MiB maximum, and no file
straddling. Per-record zstd is optional, identity remains plaintext, there is no
cross-record dictionary, and bounded decompression applies.

## Consequences

- Independent encoders can reproduce manifest and package bytes.
- Indexed lookup can avoid holding a million entries in memory.
- Pack padding participates in pack identity but not logical-file hashes.
- Wire-visible schema changes require ADRs and vectors.

## Rejected alternatives

- Native filesystem path strings as package identity.
- Indefinite-length or non-deterministic CBOR.
- Packs that split logical files.
- Compression before object identity or an implicit cross-record dictionary.
