# ADR-0038: static proof catalogs are an optional storage profile

Status: Accepted

## Context

VOT peers compute range proofs when they answer requests. Immutable range-readable
storage can return object bytes but cannot execute the suite-specific proof
algorithm. Such storage needs precomputed proof records that a receiver can fetch
without first downloading an object-wide index.

The catalog is supporting material. Making it part of object or package identity
would give the same bytes different identities depending on storage arrangement.
A catalog digest would also create a second trust anchor beside the VOT object
root.

The profile must handle hostile lengths and offsets before allocation. It must
give BLAKE3 and SHA-256 equal status, preserve their existing proof bytes, and
leave the native VOT wire protocol unchanged.

## Decision

**Version zero defines an optional normative storage profile with a fixed header,
a directly addressable fixed-width index, and concatenated canonical proof
bytes. The caller-supplied VOT object identity remains authoritative.**

- The header is 128 bytes and every integer is unsigned big-endian.
- Profile 1 divides a non-empty object into consecutive 4 MiB ranges. Position
  determines data offset and length, so the index stores only proof offset and
  proof length.
- Index entries are 16 bytes. Entry `i` begins at `128 + i * 16`, allowing one
  entry to be read without reading earlier entries.
- Proof offsets are relative to one contiguous proof blob. A complete decoder
  rejects gaps, overlap, reordering, trailing proof bytes, and nonzero reserved
  fields.
- Each proof is the existing canonical suite proof for its derived data range.
  Version zero permits at most 8 KiB per proof and requires a multiple of 32
  bytes.
- The header carries suite, root, and length, but they are descriptive until
  they exactly match the object identity supplied by the caller. Verification
  always reconstructs that caller-supplied root.
- Empty objects have no records, index, or proof bytes. Their catalog is exactly
  the header.
- Unknown versions, profiles, flags, and reserved fields are rejected. A new
  interpretation requires a new version.

The byte layout and arithmetic rules are frozen in
`spec/static-proof-catalog.md` and its conformance vectors. No wire identifier,
frame, setting, negotiation, or error code is allocated.

## Consequences

- A client reads one bounded header, calculates one index-entry address, fetches
  one bounded proof, reads the corresponding object range, and verifies useful
  data without downloading the complete catalog.
- Catalog corruption can make a range unavailable or invalid. It cannot make
  incorrect object bytes verify.
- Catalog presence and representation do not change object, package, manifest,
  seal, or receipt identity.
- The fixed 4 MiB profile contains 64 verification groups and stays inside the
  existing requested-range bound.
- Version zero fixes an interoperable persistent representation. Its Rust
  encoder and hostile-input parser are separate implementation work.
- Building catalogs without object-size-proportional memory remains separate
  spillable-proof work. Temporary-storage policy does not appear in the format.
