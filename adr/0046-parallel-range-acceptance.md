# ADR-0046: Parallel range acceptance

- Status: Accepted
- Date: 2026-08-31
- Decision owners: A00 architecture; A05 commit model; A06 POSIX provider;
  A12 performance
- Applies to: `crates/vot-sdk-file` (`NativeFile::accept`), `crates/vot-commit-posix`
  (`PosixCommit::write_verified_at`, the failure state machine), `crates/vot-sdk`
  (`ObjectCoverage`), and `crates/vot-coverage` (reservation alongside the
  existing booking). No change to `crates/vot-verified-range`, the proof
  crates, any spec file, or any wire identifier.

## Context

Verification is already parallel. `vot_verified_range::verify_range` is a free
function over `(ObjectId, covered_offset, data, proof)`; it dispatches to
`vot_proof_blake3::verify` or `vot_proof_sha256::verify`, both stateless
functions against the announced root. Each bao proof is self-contained, so
proofs for disjoint ranges of the same object share no mutable state and can be
checked on as many threads as a consumer cares to spend. Nothing in this ADR
changes that path.

Acceptance is not. `NativeFile::accept` takes `&mut self` and chains three
steps: `ObjectCoverage::check` books the range against coverage,
`write_backend` performs the positional write, and the booking commits only
after the write succeeds. `PosixCommit::write_verified_at` also takes
`&mut self`, and the exclusivity it demands is not for the write itself, which
is a positional write at a caller-supplied offset, but for the failure path:
`fail` drives the poison state machine, and a poisoned commit must refuse every
later write. One receiver object therefore accepts one range at a time no
matter how many were verified in parallel.

The consumer this is written for is a receive portal that keeps eight 8 MiB
proven ranges in flight per session over HTTP. Its worker owns the
`NativeFile` and today runs verify and accept back to back on one thread, and
its own documentation records the observed result: the serial verify-accept
loop, not its database, is what leaves the NIC idle on a fast path. That
consumer has a zero-cost move available without any VOT change: hoist the pure
`verify_range` calls onto its request handlers and funnel only the verified
slices through the worker. This ADR is the second step, letting the write and
commit of disjoint verified ranges proceed concurrently too, so the funnel
stops being a funnel.

The range-size ceilings are out of scope and unchanged:
`MAX_PROOF_RANGE_BYTES` in `vot-verified-range` (8 MiB plus one 64 KiB edge
group) and `MAX_REQUESTED_RANGE` in `vot-codec` stay as they are. Parallel
acceptance multiplies ranges in flight; it does not widen any single range.

## Decision

**`NativeFile::accept` takes `&self`. Coverage bookkeeping and the commit
state machine move behind one internal lock; the positional write happens
outside it on a shared file handle. Disjoint verified ranges then write and
commit concurrently, and every existing refusal keeps its place.**

1. **The lock covers bookkeeping, not bytes, and bookkeeping gains
   reservation.** Today's `Booking` reserves nothing: `Coverage::check`
   consults only committed extents, dropping a booking changes nothing, and
   the booking exclusively borrows the coverage, so it cannot exist across an
   unlock and two sequential checks of the same uncommitted range would both
   come back `New`. `Coverage` therefore gains a reserved-extents set beside
   the committed one. `accept(&self)` takes the lock and reserves the range,
   refusing overlap with committed or reserved extents and classifying a
   committed range as `Replay` exactly as today; releases the lock across the
   positional write; and reacquires it to move the reservation to committed
   on success or release it on failure. The reservation is a value, not a
   borrow, so it lives across the unlocked write.

2. **The write splits into a lock-free byte write and a locked state step.**
   `write_verified_at` cannot mechanically become `&self`: its failure path
   drives `fail`, which mutates the state machine (`Machine::apply` is
   `&mut self`) and appends to the trace. The split: the staging `File`
   lives outside the lock, shared, and the byte write is a bare
   `FileExt::write_all_at` against it, positional writes at disjoint offsets
   not observing one another; the machine, trace, and coverage live inside
   the one lock. A successful write reacquires the lock, re-checks that the
   commit was not poisoned while it was writing, and only then commits the
   reservation. A failed write reacquires the lock and drives `fail` there.

3. **Poison folds into the same lock.** A failed write takes the lock, drives
   `fail`, and marks the commit poisoned; every subsequent `accept`, `seal`,
   or `publish` observes the poisoned state under the lock and refuses with
   the same errors as today, and the commit-time re-check in item 2 means a
   range whose bytes landed while another thread poisoned the commit is
   released, never committed. The one-way character of the state machine is
   unchanged: a poisoned commit stays poisoned.

4. **Lifecycle operations serialize against acceptance.** `seal`, `publish`,
   and cancellation take the same lock and observe either a committed reservation
   or a released one, never a half-written range that coverage counts as
   done. `progress()` keeps its meaning: bytes it reports are written and
   committed.

5. **Sizes.** `vot-sdk-file` M, `vot-commit-posix` M with the poison
   transition being the part that deserves the care, `vot-sdk`'s
   `ObjectCoverage` wrapper S, `vot-coverage` M for the reserved-extents set
   and its release and commit paths. `vot-verified-range`, `vot-verifier`,
   and both proof crates: untouched.

## Consequences

- A consumer with K verified ranges in hand spends K threads writing them and
  pays one short critical section per range for bookkeeping. The NIC-idle gap
  the portal measured becomes a scheduling question on the consumer's side,
  not a VOT API limit.
- `&self` acceptance composes with the existing one-object-one-worker designs
  unchanged: code that holds `&mut NativeFile` today compiles and behaves as
  before, since `&mut` implies `&`.
- The failure semantics tighten from accidental to stated: today the poison
  machine is exercised only serially; after this it carries an explicit
  concurrent contract and the tests to hold it.
- No wire, spec, identity, or registry impact. Memory impact is bounded by
  the ranges a consumer chooses to keep in flight, which is the same bound as
  before; CPU moves from one core to as many as the consumer offers; storage
  and amplification are unchanged.

## Rejected alternatives

- **Consumer-side sharding only, one `NativeFile` per worker.** An object has
  one staging file and one journal; sharding the object across receivers
  either multiplies staging files that must later be stitched, which invents
  a second commit model, or serializes at the file anyway.
- **A lock-free coverage structure.** Coverage check and commit are short and
  amortized against an 8 MiB write and a proof verification; a mutex is not
  measurable next to them. Lock-free bookkeeping buys complexity where no
  contention evidence exists.
- **Making `verify_range` part of acceptance so the whole path parallelizes
  inside VOT.** Verification is already pure and parallel; binding it to
  acceptance would only take scheduling freedom away from consumers that
  verify on their own thread pools.
- **Doing nothing and letting consumers parallelize verify only.** That is
  the free first step and consumers should take it, but on fast paths the
  positional writes then queue behind one `&mut` acceptor, and the write is
  where the remaining wall time lives.

## Required verification

- K threads accepting K disjoint verified ranges of one object: every range
  accepted exactly once, `progress()` monotone, published object bytes equal
  to the source, for both suites.
- The same run with one duplicated range: exactly one `Accepted`, the rest
  `Replay`, no double write observable in the published bytes.
- A write forced to fail mid-run under concurrency: the commit is poisoned,
  every in-flight and subsequent `accept` refuses with today's error, the
  reservation of the failed range is released, and no partial range is counted
  by coverage.
- `seal` and `publish` racing active accepts: publication observes only
  committed coverage; a publish that wins refuses later accepts with the
  state-conflict error.
- Mutation gate per CONTRIBUTING: for the lock-order and poison transitions,
  a deliberate mutant that commits a reservation despite a failed write, and one
  that skips the poisoned check in `accept`, each killed by a test, recorded
  in `test-vectors/mutants/`.
