# A stream is read as frames and no more

Criterion: a carrier that delivers bytes yields exactly the frames that were
sent, whether one arrives split across many reads or many arrive in one; a frame
a receiver will skip is discarded by its declared length and never held; and what
is held for frames still arriving is bounded across every stream at once rather
than per stream.

This is `spec/wire.md` section 7 applied. Frame boundaries are independent of the
carrier's, so reassembly is the receiver's, and reassembly a peer can grow is a
way to spend an endpoint's memory without sending a valid frame.

Passing evidence:

- `a_frame_split_across_reads_arrives_once_and_whole` splits one frame at every
  byte position and requires the whole frame from each, then requires three
  frames from one read in order.
- `one_byte_at_a_time_still_yields_the_frame` is the same rule where even the
  envelope is split, which is the case the buffer has to handle without a bound
  of its own to grow.
- `a_frame_larger_than_the_stream_carries_is_refused_before_it_is_held` is the
  case the codec alone does not cover: a registered limit larger than the lane
  carries would let a frame decode, reach the adapter, be refused there, and be
  retried for ever at the head of the queue.
- `the_control_bound_is_the_one_this_endpoint_advertised` holds a stream to what
  was advertised rather than to the ceiling the crate was compiled with, and
  holds a lane to the record bound rather than to the control one.
- `a_peer_cannot_hold_more_than_the_budget_across_streams` is the bound no
  per-stream limit can see: a peer that opens many streams and leaves a nearly
  complete frame on each.
- `held_bytes_are_charged_and_returned` includes the stream reset part-way
  through a frame. Bytes left charged accumulate across resets until streams that
  have done nothing wrong are refused.

Two rules had been shipping unmeasured. The reassembly lived inside the MsQuic
live module, where cargo-mutants generates no mutants and only the live tests
could reach it. Moving it to `vot-transport-framing` measured it for the first
time, and seven mutants survived.

Five were the countdown for a skipped frame's payload. `spec/wire.md` step 6
requires a receiver to stream-discard exactly the declared length, and nothing
checked "exactly": the count could drift in either direction, or be skipped
entirely, and every test still passed.
`a_discarded_frame_is_counted_down_exactly_across_reads` spans three reads, and
the frame after the discarded one has to arrive whole, which is what says the
countdown ended on the right byte.

The sixth was a frame weighing exactly what a stream may hold, which was never
carried. Refusing it would close a session over a frame the advertisement
allowed. `a_frame_at_exactly_the_reassembly_bound_is_carried` finds the payload
that reaches the bound rather than writing one down, because the header width
depends on the payload it describes.

Mutants: drop a skipped frame's remaining payload by the wrong count; treat the
countdown as finished while bytes remain; refuse a frame at exactly the bound;
hold a skipped frame's payload instead of discarding it; charge a stream's held
bytes and never return them.

Observed failure:

```text
assertion `left == right` failed
  left: Ok([])
 right: Ok([[2, 8, 90, 90, 90, 90, 90, 90, 90, 90]])
assertion `left == right` failed
  left: Err(FrameFault { error: RecordTooLarge, close: 259 })
 right: Ok([[2, 8, 5, ...]])
```

The required `vot-transport-framing` mutation run reports 61 mutants, 55 caught,
6 unviable, and 0 missed. `vot-transport-msquic` keeps 38 mutants and no
survivor, and its 58 live tests pass in debug, in release, and under
AddressSanitizer with LeakSanitizer, which is what says the extraction changed
the carrier's behaviour in no way.

The owned-frame handoff rerun selected all 60 mutants in
`vot-transport-framing`: 52 were caught, 8 were unviable, and none survived.
The framing suite and the 86-test live quiche suite both passed with completed
reassembly buffers moved into transport payloads instead of copied into them.
