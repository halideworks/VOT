# ADR-0029: verified ranges flow to a sink, and the receiver keeps extents

Status: Accepted

Amends the receive contract ADR-0025 built on. The range path stays the unit
of parallel verification; what changes is what the receiver retains after a
range's proof has held.

## Context

`ReliableReceiver`'s range path stores every accepted range's bytes in
`RangeState { segments: BTreeMap<u64, Vec<u8>>, bytes }` and releases them
only when `finish_ranges` finds the object complete. Peak receiver memory
therefore tracks object size: the 1 GiB case in
`bench/workloads/ram-to-ram.json` would hold a gigabyte, and the driver's
rule that peak memory describes transport and verification rather than the
fixture (ADR-0025) cannot hold on this path as built. The finding is from
2026-08-04, while scoping PERF-001 multi-worker.

The retention buys nothing. A range is root-verified against the subject the
moment it is accepted: `check_range_proof` runs before any state changes, and
the witness flow (`verify_typed_bundle`) cannot construct a `VerifiedRange`
without the proof holding. Nothing ever reads the stored bytes back. The only
consumer of a stored segment is the duplicate check that compares a replayed
range against it, and `finish_ranges` drops the whole map on the floor.
Keeping the bytes is about having somewhere to put them, not about assurance.

The sequential path already has the right shape: it stages per record, holds
only the verifier's streaming state, and its peak is the receive window. The
range path is the one VOT's core purpose rides on, a verified receive that
scales, so it should be at least as honest.

## Decision

**The receiver hands each verified range to a sink and keeps only the
verified extent set.** `vot-scheduler` gains a `RangeSink` trait:

```rust
pub trait RangeSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), SinkError>;
}
```

`write_at` takes `&self` because writes of proven ranges commute: any two
accepted writes are either disjoint or byte-identical, so a sink may be
shared and may be written in any order or twice. A sink is registered per
subject at `begin_ranges`, because the sink is where that object's bytes go,
and the receiver owns it for the subject's lifetime.

**`RangeState` keeps a coalescing extent map, not segments.** Offsets map to
run ends, neighbours merge on insert, and the completeness rule is unchanged:
disjoint whole-unit extents inside `[0, length)` totalling `length` bytes can
only be the whole object. Memory is proportional to fragmentation, not to
bytes received.

**Admission writes, then books.** The proof has already held before
`insert_checked_range` runs, as it always has. The sink write happens next,
and only a write that returns `Ok` books its extent and releases its staging.
A sink failure refuses the range, and the range stays retryable.

**Replay is coverage, not byte equality.** A range wholly inside the covered
extents is a replay and returns `Ok` without writing. A range straddling
covered and uncovered bytes is an overlap and stays `LengthMismatch`, as
today. The current byte-for-byte comparison against the stored segment is
removed, and nothing is lost: the proof binds the bytes to the subject root
at that offset, so two different byte strings for the same range cannot both
hold, and a same-offset forgery still fails as `ProofInvalid`, one step
earlier, in the proof check itself.

**Fragmentation is bounded.** The extent map refuses an insert that would
exceed a configured fragment count, the same posture as
`PendingBundlesExhausted`. Real arrival is near-in-order per rail, so live
fragmentation is on the order of the rail count; the bound exists so an
adversarial interleave, alternating units to keep runs from merging, prices
its attack at extent entries rather than being free. A generous default
costs kilobytes where the segments map costs the object.

**Staging describes what the receiver holds.** A range's bytes are reserved
for exactly the span the receiver holds them, which is now admission only.
`VERIFIER_RESERVATION` stays held per subject until `finish_ranges`, as
today. `peak_staging` on the range path becomes the receive window plus
in-flight admissions, which is the claim the driver's rule needs it to make.

The sequential path does not change.

## Consequences

`begin_ranges` takes the sink, so both driver range paths and the session's
`deliver` thread one through. No caller reads bytes back from the receiver
today, so nothing loses a capability. The bench driver registers a
discarding sink, which is what its measurement already meant: the numbers
describe transport and verification, and the object was always dropped.
Tests that want the assembled object use a memory-backed sink.

Multi-worker benchmarking at 1 GiB becomes honest, which is what unblocks
the workstream the finding came from.

v1 wrote inside the admission lock, so rails serialized on the sink. With
the discarding sink that cost nothing and the wire numbers stood. The move
this paragraph anticipated happened the same day (PR 100): a rail places
its bytes through `VerifiedRange::write_to` before taking the lock and
admits a `WrittenRange` under it, sound because proven writes commute and
the witness can only be built by writing. Two conditions carry it, and a
future caller inherits both: the witness proves a write to *a* sink, not
to the subject's registered one, so handing rails the same sink is the
caller's discipline; and `finish_ranges` means every byte was proven and
handed over, not that every write returned, so a caller joins its writers
before treating the sink as final. The A/B is in the perf log: +4% at
W=4 loopback role, inside spread, the critical section smaller either way.

`finish_ranges` remains the verification claim and nothing more. Whether the
sink's bytes are durable, flushed, or committed is its owner's contract; the
`vot-commit-*` crates exist for callers that need one.

`vot-scheduler` is a required mutation package, so the extent map and the
new admission order come back at zero missed mutants like everything around
them.
