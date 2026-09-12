# ADR-0058: Retained range authentication

- Status: Accepted for immutable owned range bytes.
- Date: 2026-09-12
- Applies to: `vot-verified-range`, `vot-sdk`, and both proof suites.

## Decision

Add `RetainedRange` to authenticate unchanged receiver bytes against later
canonical object checkpoints. It owns a previously verified byte allocation and
private verification-group commitments. `verify_for` consumes a new proof and
returns the existing `VerifiedSlice` witness borrowing the exact retained
subrange. It neither reads nor hashes the payload during this operation.

`VerifiedRange::retain` moves the existing allocation into the owner.
`VerifiedSlice::retain` copies borrowed bytes into a new allocation first.
Retention computes the commitments once, in addition to the original range
verification. Subsequent proofs use those commitments. The SDK exposes the same
operation and accepts the returned witness through existing `ObjectCoverage`.
The SDK can also take ownership of a retained transport range without copying.

There is no detached hash-to-byte storage token, mutable storage callback, new
dependency, wire encoding, identity format, or change to assurance transitions.

## Authentication and geometry

Both suites share their existing proof decoders between ordinary byte
verification and cached-commitment verification. BLAKE3 still applies positioned
group chaining values and root mode. SHA-256 still applies its canonical piece
tree, padding, and proof window. Both paths reject trailing proof material.
The low-level commitment functions authenticate supplied hashes only; they
cannot establish that any caller possesses corresponding bytes.

The owned range enforces the additional byte-binding rules:

- The target identity is valid and uses the original suite.
- The requested cover stays within both the target object and retained bytes.
- Its start is group-aligned. Its end is a group boundary or the retained
  range's original end. Only the target's last group may be short.
- A shortened cached group cannot acquire a different claimed byte length.
- A small target uses a separately cached standalone first-group root and an
  empty proof. BLAKE3 non-root values and short SHA-256 padded piece hashes
  cannot replace standalone roots.

A full first group can authenticate after growth or become a standalone object
after truncation. A changed partial tail requires fresh bytes. A changed group
inside a larger retained allocation does not prevent independently proving
unchanged subranges. Failure changes neither the owner nor its original witness.

## Storage and resource boundary

The byte allocation is private and immutable. A returned witness borrows it and
cannot outlive it in safe Rust. Previous bytes remain available even when the
producer or a separate input buffer changes.

`ObjectCoverage` remains bookkeeping, not an owner of stored bytes. A caller
must keep the retained owners alive or complete a destination write before
recording coverage, and preserve that storage for as long as it claims the
bytes. This increment does not persist coverage, implement a mutable receiver,
or establish durability, at-rest verification, or publication.

Each retained allocation has the existing verified-range bound of 8 MiB plus
one 64 KiB edge group. Callers still own the aggregate retention budget. A
subrange witness retains its borrow of the whole allocation; this API does not
split or evict parts of an allocation. Retention's extra initial hashing and RAM
cost are explicit tradeoffs. No transfer throughput improvement is claimed.

## Shared SHA-256 verifier allocation fix

Two requested groups straddling a large power-of-two boundary can imply a much
larger proof window. The decoder previously allocated that window before
discovering missing proof hashes. It now checks that the proof supplies every
real uncovered window hash before allocation; implicit padding needs no supplied
hash. Window storage is bounded by the supplied commitments and proof input.
This check applies to ordinary byte verification and retained verification.

## Validation and next boundary

Tests compare retained subranges against byte verification for both suites,
including nonzero retained offsets, tree boundaries, short tails, small/large
transitions, changed groups, forged lengths, cross-suite claims, stale or malformed
proofs, and byte allocation identity. Compile-fail checks reject mutation and
witnesses that outlive their owner.

The SDK integration test changes one group of a three-group-plus-tail object,
receives that 64 KiB group, and authenticates the other 131,089 bytes from the
retained owner. It reconstructs and freshly hashes the result, requires complete
coverage under the new identity, and rejects the original identity's witness.

The next boundary is owned disk staging with authenticated retained-coverage
metadata, followed by the invalidation journal and crash/failure injection
through real storage providers. Source lifecycle, capture orchestration,
filesystem watchers, and VOTPort integration remain outside this increment.

## Reproduction

```sh
cargo +1.97.1 test --locked -p vot-proof-blake3 -p vot-proof-sha256 -p vot-verified-range -p vot-sdk
```

Mutation results are recorded in
`test-vectors/mutants/adr_0058_retained_ranges.md`.
