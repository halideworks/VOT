# ADR-0042: Coverage-first datagram FEC beats the loss floor

- Status: Accepted
- Date: 2026-08-21
- Decision owners: A00 architecture; A10 transport
- Applies to: the serve's coded answer path, the fetch's coded receive path,
  `FecPolicy`, and the repair-count profile; `spec/fec.md` is unchanged

## Context

Reliable transfer under random loss pays a floor far above the lost bytes.
Measured on the emulated 200 ms path (256 MB, seeded window, 5% loss both
ways): a range settles at p50 421 ms clean against p50 976 ms and p99
2,215 ms under loss, because a 4.26 MB cover is ~3,160 packets and completes
at its slowest straggler, which recovers through one to four retransmission
round trips. The request window paces on settlement, so wall time is window
over settlement latency: the measured 2.7x latency inflation is the measured
2.2x wall cost. The floor is controller-independent (cubic and bbr2 sit in
the same band once the window seed is scaled, PR 345), and every cheap
counter measured dead on the fixed transport: a deeper request pipeline is
worse because it inflates the recovery round trip itself, duplicating the
small serial-spine packets moves tails but not the median, and the FEC
extension as currently driven codes too little to matter.

Note, 2026-08-25: the deeper-pipeline half of that sentence is superseded.
It was measured at four outstanding covers against the receive window this
stack shipped then, where the credit already bound and depth only lengthened
the recovery round trip. With the receive-window ceiling raised beside it,
eight covers measured faster under loss, not slower: one rail on an emulated
80 ms path at 3% each way went 58.5 to 103.2 MB/s reliably and 67.5 to 105.3
with coding forced, and the coded share rose from 82% of offered generations
to essentially all of them. What the original result still says is that
depth alone, without the window, buys nothing.

Why FEC underdelivers today is an implementation shape, not the wire
protocol. The serve opens one coding epoch per `FEC_PIECE_BYTES` piece
(~1.1 MB, 17 generations) and holds at most `MAX_CODING_EPOCHS = 8` slots,
so even `VOT_DATAGRAM_FEC=1` coded only 818-1,045 of 4,096 generations of a
256 MB object (20-25%), and the automatic policy engages only after 1,024
packets show 5% corrected loss, which on a five-second transfer leaves most
ranges issued before the trigger trips (377-552 generations coded). Of the
generations that were coded, about a fifth lost more symbols than their
repair covered and fell back to exactly the retransmission rounds the code
exists to remove.

`spec/fec.md` sections 9 through 12 already permit what the floor needs: an
epoch binds one epoch identifier to one object and one contiguous byte
range of any length, `repair_count` may be up to 16 of `k = 64`, and a
generation that decodes never touches the reliable path. Nothing in the
spec ties an epoch to a piece; the piece binding lives in
`answer_range`/`answer_coded` and the receiver's bundle mapping.

## Decision

On a path where coding is engaged, the coded path becomes the primary loss
answer, sized so that no byte of a covered range waits on a retransmission
round trip in expectation.

1. **One epoch per requested cover.** The serve answers a `RANGE_REQUEST`
   whose path is engaged with a single coding epoch spanning the whole
   requested range, not an epoch per piece. Pieces remain the receiver's
   bundle unit: the fetch maps an epoch's generations onto piece bundles by
   offset, as the geometry already determines. Eight epoch slots then hold
   eight covers (~34 MB) rather than eight pieces (~9 MB). That was deeper
   than the request pipeline that feeds them at four outstanding covers; at
   the eight this stack now ships the two are equal, 8 x 4,259,840 bytes
   either way (2026-08-25).

2. **Repair sized from measured loss plus margin, up to the spec's 16.**
   The repair count becomes `clamp(ceil(3 * observed_loss * (k + r)) + 1,
   2, 16)` per epoch at open time, from the same rolling sample
   `FecPolicy` keeps. At 5% observed loss this yields r in the 12..16
   band, where the probability that a 64-source generation loses past its
   repair is below one in ten thousand, so the expected retransmission
   rounds per cover approach zero. The current `FEC_REPAIR_SYMBOLS = 8`
   sender cap rises to the spec's 16; overhead follows loss and is paid
   only on engaged paths.

3. **Engagement is immediate when the operator declares the path, and
   first-sample-fast otherwise.** `VOT_DATAGRAM_FEC=1` remains "code
   everything now". The automatic policy stops waiting for a full 1,024
   packet sample before its first decision: the first sample closes at 256
   packets (a cover's worth), and a trip applies to every range issued
   after it, so a five-second lossy transfer is mostly covered rather than
   mostly missed. The off-hysteresis is unchanged.

4. **Over-lost generations are repaired with symbols, not round trips,
   while their epoch lives.** The receiver already reports
   `missing_sources` in `GEN_STATE`. A sender holding an epoch open
   answers a generation whose received count cannot reach `k` from what
   remains in flight by sending further symbols for that generation (source
   retransmits or unsent repair ESIs), which is spec-legal today: symbols
   are sender-chosen and only duplicates drop. Reliable repair remains the
   backstop at epoch close, as section 12 says, but it stops being the
   first resort.

The target, which the netem rig can hold this to: range settlement under
5% loss within 1.3x of clean at p99, and wall within 1.2x of clean, where
today's floor is 2.2x.

## Consequences

- The serve's coded answer path and the fetch's epoch-to-bundle mapping
  change shape; the wire format, frame constraints, and error table do
  not. Both ends must land together behind the existing negotiation, which
  the extension's version already gates.
- Coded overhead on an engaged path rises to roughly loss times three plus
  a symbol per generation, and is zero on clean paths under the automatic
  policy. The 08-17 result that coding loses on clean paths is respected:
  nothing engages without loss or an operator's word.
- `max_decode_work` and the credit table become the real budgets on the
  receiver under whole-cover epochs; the pending-bundle and orphan bounds
  in `fetch/plan.rs` are re-derived for eight cover-sized epochs, the way
  PR 298 re-derived them for pieces.
- The `GEN_STATE`-driven symbol repair gives the sender a second consumer
  of `missing_sources`; the advisory frame's loss becomes performance, not
  correctness, exactly as the spec already treats it.
- The 15-slot result ([[fec-epoch-slot-sweep]]) was measured under
  per-piece epochs and does not carry over; the slot count is re-measured
  under cover-sized epochs before it moves.

## Rejected alternatives

- **Deeper request pipelining:** measured worse (6.70 s median against
  3.89 at 16 covers), because more in flight inflates the recovery round
  trip it is trying to hide.
- **Duplicate transmission of data packets:** the spine variant measured
  flat, and duplicating bulk data is overhead at all loss rates for
  protection only at the burst tail.
- **A rateless or larger-field code:** the shipped GF(2^8) Vandermonde
  geometry at `r = 16` already makes generation failure negligible at the
  loss rates this targets; changing the code is cost without a measured
  need (ADR-0039 stands).
- **Retransmission-scheduling surgery in the carrier:** the recovery
  rounds are QUIC's own loss-detection economics; making them cheaper is
  upstream work with a fraction of the payoff of not needing them.

## Required verification

- Coded share of an engaged 256 MB transfer at 5% loss exceeds 90% of
  generations under the automatic policy, measured by `fec_coded` against
  the object's generation count.
- Range-settlement p99 under 5% loss within 1.3x of clean; wall within
  1.2x, on the netem rig at 200 ms, three interleaved reps a cell.
- Generation failure (decoded below `k` before close) under 1 in 1,000 at
  5% loss with the loss-sized repair.
- The clean-path automatic arm still offers zero coded generations and
  costs within noise of reliable.
- Credit conformance: no symbol or open exceeds the receiver's advertised
  caps under the deeper epochs, held by the existing wire tests.
- The 4 GiB and 12 GiB coded cells that previously failed or stalled
  complete at both 8 and whatever slot count the re-measure selects.

## Measured outcome (2026-08-22)

The four decisions merged as PRs 346, 351, 352, and 353-355; the
verification then found and removed two delivery defects under the
decisions rather than in them: quiche's 1,024-slot inbound datagram
queue silently discarding symbols below every counter this stack owns
(PR 356 sizes it to the credit's event bound), and the targeted-repair
gate omitting this ADR's own "from what remains in flight" term, so it
answered nearly every generation while the over-lost ones starved on
the outbound budget (PR 357). PR 358 moved the engagement thresholds to
4%/2.5%, a margin under the loss rates the policy serves, after the 5%
threshold on a 5% path measured as a per-window coin flip.

Against the verification list, on the netem rig at 200 ms:

- Generation failure, credit conformance, and the clean automatic arm
  all hold: decode is 100% of coded, abandoned and refused are zero,
  receiver symbol drops are zero in every post-fix run, and the clean
  arm offers nothing and sits at reliable's wall.
- The 4 GiB coded cells that previously failed complete: at 5% loss,
  forced 18.75 s and defaults 19.54 s, full byte count, zero abandoned.
  The defaults arm offers 91% of generations at that size.
- Coded settlement at 256 MB: p50 303 ms against reliable-clean's 417,
  so a forced-coded clean transfer now completes faster than reliable
  (2.11-2.18 s against 2.21). The p99 under loss was last attributed
  while the drop defects stood; the coded arm's 5% data phase is not
  fully explained post-fix.
- The 90% automatic share holds at 4 GiB but not at 256 MB, and the
  reason is structural, not a tuning miss: issuance outruns the
  verdict, so most covers of a short transfer are answered before any
  sample can close. Deepening the request window makes this worse, not
  better (a parked W=8 branch front-loads issuance further and the
  codable tail shrinks; its 12-20% win exists only under forced
  coding).

Wall at 5% loss, 256 MB, defaults: median 1.9x of clean, best runs
1.6x, against this ADR's 1.2x. The remaining gap is not in the coded
path: it is the serial prefix under loss, whose first byte ran
1.5-6.7 s against 1.03 clean in the closing sweep with walls tracking
it nearly one for one. The lever there is prefix loss-robustness, not
prefix length: duplication of early packets removed the multi-second
first-byte tail in a probe, and the levers that shorten the prefix
(0-RTT sequencing, manifest in the announcement) shorten both arms and
barely move the ratio. That work changes the wire and needs its own
ADR; no lever inside this one's scope reaches 1.2x.
