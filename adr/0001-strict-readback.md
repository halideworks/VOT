# ADR-0001: Strict verification uses an independent read path

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A05 commit model; A06 POSIX provider
- Applies to: Strict commit providers

## Context

A durability barrier proves that a provider accepted a write according to its
contract. A buffered reread may still be satisfied from the write-side page
cache and therefore does not demonstrate that the backing representation can be
read independently. Advisory cache eviction has the same problem.

VOT receipts must describe work actually performed. Treating a buffered reread
as at-rest verification would overstate assurance and would make the defining
commit invariant depend on cache behavior.

## Decision

Strict at-rest verification MUST use one of:

1. a durability barrier followed by aligned direct or unbuffered reading through
   a separately opened descriptor or handle;
2. an independently generated backend checksum whose documented semantics meet
   the provider conformance profile; or
3. another provider integrity mechanism approved by a conformance profile.

For the Linux POSIX provider, the implementation flushes the object, separates
or closes the buffered writer, opens a read descriptor with `O_DIRECT`, obeys
the filesystem and device alignment constraints, reads the complete protected
extent, and verifies it against the object identity. `POSIX_FADV_DONTNEED` and a
buffered read are non-conforming.

If no conforming mechanism is available, Strict is `UNSUPPORTED`. The receiver
MUST NOT fall back to Balanced or Fast unless a new request explicitly selects
that profile.

Any write or flush error poisons the current incarnation. Retrying the flush
cannot rehabilitate it. Recovery must revalidate or reconstruct affected ranges
under a current incarnation.

The Strict POSIX publication sequence is:

1. create unique temporary object and journal incarnation;
2. reserve bounded staging capacity;
3. write and transit-verify ranges;
4. flush the data file;
5. flush the durable journal transition;
6. independently verify at-rest bytes;
7. flush the at-rest verification transition;
8. atomically publish without overwriting an unrelated object;
9. flush the parent directory; and
10. emit the publication receipt.

## Consequences

- Strict may be unavailable on a filesystem, device, operating system, or object
  store even when weaker profiles work.
- Direct I/O needs platform-specific alignment discovery and tail handling.
- Fault tests must corrupt the backing representation after the write and before
  read-back. The Strict path must detect the fault, while a deliberately
  buffered control is expected not to.
- Strict performance is measured separately from the Balanced overhead gate.

## Rejected alternatives

- **Buffered reread after `fsync`:** not independent of the write-side page
  cache.
- **`POSIX_FADV_DONTNEED` followed by buffered reread:** advisory and therefore
  not a correctness primitive.
- **Silent downgrade:** violates receipt and capability invariants.
- **Retrying a failed flush in the same incarnation:** can conceal an unknown
  writeback state.

## Required verification

- Direct-reader alignment and partial-tail tests.
- Unsupported-backend tests.
- Write, flush, rename, and directory-flush fault injection.
- Device-corruption test that distinguishes Strict from the buffered control.
- Recovery test proving a poisoned incarnation never reaches `PUBLISHED`.
