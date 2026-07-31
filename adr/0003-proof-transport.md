# ADR-0003: V1 uses two proof suites and in-band range-proof bundles

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A02 BLAKE3 proof; A03 SHA-256 proof
- Applies to: object identity and proof transport

## Context

Receivers need to authenticate useful ranges without downloading unrelated
object bytes. Requiring a complete proof index before transferring data delays
first verification, creates a large bootstrap object, and raises the recursive
question of how that index authenticates itself. The SHA-256 profile must also
interoperate with BEP 52 tree geometry instead of defining a third tree.

## Decision

VOT v1 defines exactly two suites:

- `0x0001`, `blake3-bao64`: identity is BLAKE3 root and exact byte length;
  verification groups are 64 KiB Bao/BLAKE3 chunk groups; relay sidecars use the
  canonical pre-order outboard representation.
- `0x0002`, `sha256-bep52-64k`: identity is the BEP 52-compatible SHA-256 file
  root and exact byte length; base leaves are 16 KiB; verification pieces are
  64 KiB; construction, padding, piece roots, request geometry, and proof order
  follow BEP 52.

V1 proof transport is an in-band range-proof bundle. The sender or relay returns
the requested bytes with the suite-specific authentication material needed to
verify them against the advertised root. Contiguous ranges use multiproofs or a
streaming encoding where the suite profile permits it.

A full outboard or piece-layer object is not a mandatory prefetch. Relays may
maintain canonical local sidecars. A future negotiated extension may advertise
a separately cacheable verification index, but it cannot change v1 identity or
make the bootstrap mandatory.

Progressive ingest authenticates manifest pages containing verification-group
commitments. The final `SEAL` commits the ordered page chain to the canonical
suite root. Reordered, replayed, missing, truncated, or source-mutated page
sequences cannot seal.

Dual-suite equivalence is established only after one trusted verifier reads the
entire byte string and computes both exact-length identities. The signed record
maps immutable identities; it does not merge them. Stores should alias both to a
single extent when policy permits.

## Consequences

- Proof bundles can be processed as data arrives and are independently bounded.
- Suite profiles need byte-for-byte vectors before object implementation is
  considered conforming.
- The BEP 52 suite reuses its specified geometry and padding even where another
  shape might be locally convenient.
- Range requests and responses always carry exact object length and suite
  identity context.

## Rejected alternatives

- **Mandatory full proof-index prefetch:** delays useful verification and creates
  bootstrap recursion.
- **A bespoke SHA-256 Merkle layout:** defeats BEP 52 compatibility.
- **Treating equal content under two suites as one identity:** loses algorithm
  separation and exact verification context.
- **Equivalence inferred from matching ranges:** does not prove complete-byte
  equality.

## Required verification

- Golden vectors for empty, one-byte, boundary, odd-tree, sparse, and large
  logical-length cases.
- Independent verifier agreement for both suites.
- Rejection of wrong length, wrong root, reordered or missing proof nodes, and
  corrupted data.
- Arbitrary 64 KiB verification without unrelated object bytes.
- Progressive reorder, replay, truncation, and mutation rejection.
