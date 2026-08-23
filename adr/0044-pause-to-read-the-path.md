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
