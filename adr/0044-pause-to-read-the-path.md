# ADR-0044: The automatic FEC policy pauses to read the path

- Status: Accepted
- Date: 2026-08-23
- Decision owners: A00 architecture; A10 transport
- Applies to: `FecPolicy` in `crates/vot-cli/src/serve/connection.rs`;
  no wire frame, spec section, or negotiation state changes, and
  `VOT_DATAGRAM_FEC=1` still bypasses the policy entirely

## Context

The automatic policy engages coding when measured loss crosses 4%. On a
real intercontinental path with no loss of its own it engages anyway and
costs **30% of a 12 GiB transfer** (97.5 s against 74.6 s with coding
off), because bbr2 probes for bandwidth by pushing a bottleneck until it
sheds a burst, backing off, and pushing again. Each probe cycle reads to
this policy as a lossy path: a verdict probe counted **75 transitions in
one clean transfer**, 38 engagements and 37 disengagements, while the
windows underneath alternated between nothing and 7-14%.

The obvious repair is to tell self-induced loss from the path's own.
Five ways of doing that were built and falsified on real paths:

| discriminator | why it died |
|---|---|
| queueing delay above `min_rtt` | real clean 1.190, real lossy 1.135; the clean path is *more* inflated and the populations overlap. The netem cells where it separated had no bottleneck to queue at |
| loss differential across the engagement boundary | 18.80% coded against 18.56% uncoded, identical |
| spurious-loss fraction | zero declarations in 1.2M packets on this stack |
| `startup_exit` gate | 38 engagements per transfer, not one |
| whether decoding needed repair symbols (receiver side, a wire change) | in the cells where coding costs 13.7% and 30%, nearly every generation loses a source and consumes repair, so it reads "coding is earning its keep" |

They died of one thing, not five. **Every observable available while
coding runs is downstream of coding's own traffic.** The clearest
measurement of it: the reliable arm of a real clean transfer sustains
2.29% loss and the coded arm of the same path sustains 6.5%. Coding
manufactures the evidence that justifies coding.

Aspera does not have this problem because FASP's rate controller targets
a small queuing delay and backs off as delay rises, so it never fills
the bottleneck and any loss it sees is the path's by construction. VOT
cannot borrow the signal, which measured dead here, but it can borrow
the epistemology: that controller is continuously running a control
experiment on itself.

## Decision

The policy stops adding to the path for a moment and reads it.

1. **A bounded pause.** After a run of coded windows the policy stops
   coding for `PROBE_PAUSE_WINDOWS` (six) closed loss windows, averages
   the loss rate over that pause alone, and either carries on or stops
   coding. The first pause comes eight coded windows in and the interval
   doubles to a cap of sixty-four each time a look says carry on, so a
   settled answer is not re-asked at the same rate.

2. **The bar is the engagement rate, both ways.** A look asks whether
   this path would engage coding on its own merits, measured honestly,
   so both edges sit at 4%. They are not offset: a gap wide enough to
   matter would sit on top of the five percent paths this serves and
   make *their* verdict the coin flip, which is the defect PR 358 fixed.

3. **One look arms it.** The two errors are not the same size. A look
   that wrongly says quiet corrects itself within a few windows, because
   coding stops and unaided evidence then arrives every window. A look
   that wrongly says carry on costs the 30%, and on a path whose
   engagement flaps it may be the last look for a long time, since the
   count toward the next one only advances while coding. A two-look rule
   was tried and deadlocked on exactly that.

4. **Nothing else changes.** ADR-0042's first-sample engagement stands:
   a burst still engages coding at once, and the pause only audits it
   afterwards. The loss thresholds, the smoothing, the repair sizing, and
   PR 360's decode discriminator are untouched.

## Consequences

- Measured on the real Ashburn to Singapore path at 12 GiB, three
  interleaved reps an arm: the clean path's penalty falls from **+29.4%
  to +12.7%** against not coding, and the 5% loss path is **3.7% faster
  than main and 6.6% faster than not coding**. Coding a little less
  avoids some overhead while still taking the benefit.
- The pause costs coding time on paths that deserve it. Six windows in
  sixty-four is about 9% of a transfer uncoded at the cap, so on a path
  where coding wins 6% the probe costs under a percent of the wall.
  The measured lossy cell came out ahead regardless.
- The residual clean-path cost is audit latency: coding runs until the
  first look completes, eight coded windows in. Shortening that trades
  against the cost on lossy paths and is a tuning question with numbers
  attached rather than a defect.
- Small transfers are untouched: at the steady window size the first
  look is about 65,000 packets in, so anything shorter behaves exactly
  as it does today.
- A policy that deliberately stops doing the thing it is for, to check
  whether it should be doing it, is a behavior worth naming. It is why
  this is an ADR and not a constant.
- **A look's opening windows are not fully unaided, and the bias is
  toward carrying on.** A pause switches the denominator the instant it
  starts, because new range answers go reliable, but the numerator keeps
  arriving from the coded flight for about a round trip, which is the
  same detection lag `FIRST_FEC_SAMPLE_PACKETS` documents. At this ADR's
  reference path a window is roughly 80 ms against a 218 ms round trip,
  so the first windows of each six-window pause carry losses coding
  caused, and `unaided_loss` reads high. Every number above was measured
  with that bias present, so the design is validated in spite of it and
  the obvious refinement, dropping a settling prefix from each look, can
  only move the clean-path result further in the direction it already
  went. It is deliberately not in this change: it alters the measurement
  the numbers above describe, so it earns its own rig run rather than
  riding on this one's evidence.

## Rejected alternatives

- **The five in-band discriminators above**, each with its measured
  obituary. The class is closed: no statistic computed while coding runs
  escapes the feedback.
- **An unbounded self-experiment**, which fails open where every verdict
  here fails closed. The bound is what makes this safe: the cost ceiling
  is arithmetic and stated above.
- **Reversing ADR-0042's first-sample engagement** so the path is
  listened to before any coding. Built and measured: 27-64% coded on the
  clean path, no better than main, because the listening window lands
  inside the ramp. It also moved twelve tests and gave up fast
  engagement for nothing.
- **Replacing the congestion controller with delay-targeted pacing**,
  which is what Aspera does. Upstream carrier work, derated before, and
  far larger than auditing a policy.

## Required verification

- Real path, 12 GiB, three interleaved reps an arm, clean and 5% loss,
  three arms from two serves. Clean: the probe beats main by a wide
  margin and closes at least half the gap to coding off. Lossy: the
  probe is no slower than main and still beats coding off.
- The look fires on a flapping engagement, which is the shape it exists
  for, pinned by a table test rather than left to the rig.
- Both edges of the look pinned from both sides, and the counter-reset
  path clears the probe's state with the rest.

## Amendment, 2026-08-25: the bar is the measured crossover

Decision 2 puts the pause bar at the engagement rate and says nothing
about what that rate should be. It was 4%, set by PR 358 as a margin
under the 5% paths ADR-0042 served, and two campaigns since have
measured where coding actually starts paying. It is not 4%.

On the netem rig at 12 GiB, 107 ms, 2 Gbit/s, eight rails and unpaced
bbr2, forced coding overtakes the reliable path at **10.05% loss each
way**, per rep 10.07, 10.08 and 10.11, over 54 runs on merged main at PR
383. An earlier sweep of the same shape on a second box of the same type
put it at 9.77%. It is a knee, not a slope: the reliable arm is flat at
57.0 to 57.9 s from 5 to 9 percent and then goes 68.2, 85.7 and 135.1 s
at 10, 11 and 12, while the forced arm runs 67.3 to 68.9 s across the
whole sweep.

At a 4% bar the policy engages in every cell from 5% up, at a smoothed
4.1 to 6.8% within 0.8 to 2.2 s, and stays engaged for 83 to 89% of its
windows. That puts automatic 15.2%, 17.4% and 18.2% behind the reliable
path at 5, 7 and 9 percent loss, and 1.8%, 17.3% and 32.4% ahead of it
at 10, 11 and 12. The three cells the bar decides wrongly are the three
where not coding wins.

Four rates move, together:

| what | was | is |
|---|---|---|
| engage | `smoothed_loss * 25 >= RATE_ONE`, 2,622 units, 4.00% | `smoothed_loss * 10 >= RATE_ONE`, 6,554 units, 10.00% |
| stay engaged | `smoothed_loss * 40 >= RATE_ONE`, 1,639 units, 2.50% | `smoothed_loss * 16 >= RATE_ONE`, 4,096 units, 6.25% |
| pause bar | `PROBE_BAR = RATE_ONE / 25`, 2,621 units, 4.00% | `PROBE_BAR = RATE_ONE / 10`, 6,553 units, 10.00% |
| seed ceiling | `SEED_CEILING = RATE_ONE / 10`, 6,553 units, 10.00% | `SEED_CEILING = RATE_ONE / 4`, 16,384 units, 25.00% |

The first three move together or not at all, for decision 2's reason: a
pause bar left at 4% while engagement went to 10% would let any path
between the two engage once on a burst and then be ratified forever by
looks reading against the lower bar. The off-hysteresis keeps the five
eighths of the engagement rate it has always stood at.

The seed ceiling moves for an arithmetic reason. `RATE_ONE / 10` is
6,553 and `6553 * 10` is 65,530, one unit under `RATE_ONE`, so a first
window seeded at the ceiling would fail the new engagement test by that
unit and ADR-0042's decision 3, first-sample-fast engagement, would be
dead on every path at or above the bar. A quarter keeps the same 2.5x
relation to the bar that a tenth had to 4%. The cost is that a freak
first window can now seed 25% and engage a clean path once; the pause
audits that eight coded windows later, which is what already happens
today in the 3% cell for 0.7% of the wall.

Why 10.00 and not the crossover itself. The crossover cell reads a
smoothed 10.28% and an unaided 10.28%, the 9% cell reads 9.06 and 9.48,
and the 11% cell reads 11.19 and 11.49, so a bar at 10.00 has 0.5 to 0.9
points of clearance below it and 1.2 to 1.5 above. Per look rather than
per window it classifies 9, 11 and 12 percent correctly in every run and
splits the 10% cell one to two. Erring low is deliberate: engaging one
point early costs the 1.8% the 10% cell costs, and engaging one point
late costs the reliable path's 85.7 s at 11% against coding's 68.9.

What it buys, per cell, against the same rig: 13 to 15 percent back at
5, 7 and 9 percent loss, at most 1.8% given up in the crossover cell,
and no change at 11 and 12, which are the cells coding exists for. It
also takes the automatic arm's processor cost at 5, 7 and 9 percent from
100 to 104 core-seconds down to the reliable arm's 57 to 67, and its
peak resident set from 560 to 590 MiB back to about 440.

Nothing else changes. The hold, the pause cadence, the smoothing, the
window sizes and the repair sizing are all untouched. One consequence
of the new bar is worth naming: the repair count saturates at the
spec's 16 from 6.25%, which is now below the rate that keeps coding on,
so every engaged path sizes repair at the ceiling. That makes the
sizing branch that prefers the unaided rate over the smoothed one
dormant at these bars, since both inputs saturate on any path that is
coding; it is kept because it becomes live again under a lower bar or a
larger `MAX_REPAIR_SYMBOLS`, and the quantity it selects is pinned by a
test rather than by a repair count that can no longer tell them apart.

### The counter-evidence

- This ADR's own acceptance table has the real Ashburn to Singapore pair
  at 218 ms and 5% armed loss with automatic winning, 98.6 s against
  105.5 with coding off. A 10% bar forfeits that win if it is real. That
  pair's serve had USO off, so part of its loss was the sender's own,
  which is the case the pause exists for rather than the case the bar
  decides, and none of its numbers predate PRs 378 to 383.
- The emulated rig's loss is exogenous dice with no bottleneck behind
  it, so none of it is the sender's own probing. netem also drops whole
  UDP_SEGMENT super-skbs, about 21 consecutive packets at 5% and about 3
  at 12%, and a generation of 64 source symbols answers those two very
  differently. The reliable arm's cliff between 10 and 12 percent is a
  property of that rig's queue and controller; it moved by a third
  between two boxes of the same type in two campaigns a day apart.
- The one real-path point agrees with the direction. On a real ~0.85
  Gbit/s policer at about 100 ms with about 6% loss, 8 GiB, the shipped
  policy costs 11.4% against reliable (111.5 s against 100.1) while
  coding 53% of the object, and by its own unaided measurement during
  these pauses it reads 4.7 to 6.7%. Its loss is largely the sender's
  own probing, and pacing removes most of it and quiets the policy at
  the same time, so it constrains the bar from below and settles nothing
  above.

The campaign that would settle it is a real pair with armed loss swept
through 5, 7, 9, 11 and 13 percent at 12 GiB with the policy's trace
beside every run, plus this ADR's tbf congestion cell re-run on merged
main to confirm a 10% bar does not break the case the pause was built
for. It should help there, with one qualification: the false engagement
the pause fixes crosses the old bar at a smoothed 4 to 5%, which a 10%
bar refuses outright, but that is the smoothed crossing only. On the
real policer path all eight connections engaged on their first window,
seeded at exactly the old ceiling within 0.9 s, and under a 25% ceiling
that first window seeds higher and engages just the same. On that path
shape the new bar changes only how quickly the off-hysteresis and the
pause let the engagement go, not whether it happens.

### Verification of the amendment

- The four rates pinned as percentages by a table test, both edges of
  engagement and of the off-hysteresis pinned one unit either side, and
  the seed ceiling pinned above the engagement rate so that decision 3
  keeps working.
- The emulated rig re-run against the merge base, automatic arm only,
  three interleaved reps at 5, 7, 10 and 12 percent loss each way and a
  clean cell: automatic sits on the reliable path at 5 and 7, within 3%
  of either arm at 10, is unchanged at 12, and never engages on the
  clean cell.
