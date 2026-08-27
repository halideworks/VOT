# ADR-0028: a pinned quiche carries the ack-latency loss floor

Status: Accepted

Amends the dependency posture ADR-0027 described: quiche's virtues there
included "no pinned git revision", and this decision trades that virtue,
temporarily and with an exit condition, for the last gigabit on the wire.

## Context

PERF-002's loss forensics (2026-08-05, `docs/perf-engineering.md`) proved
the wire loses nothing: packet captures at the receiver's NIC match the
sender's transmissions exactly, the receiver processes in order, the ACK
ranges are contiguous, and every drop counter on both hosts and the path
reads zero. Yet the sender declared 25-30k packets lost per gigabyte at
W=6, a third of them later disproved by the very acks that were always
coming, and CUBIC's answer to that fiction was an ~8 Gbit/s equilibrium
against the path's 9.45 TCP ceiling.

The mechanism is arithmetic, not noise. quiche processes acknowledgements
in batches on the pump's pass, samples RTT only from the freshest packet
of each batch, and floors its loss delay at max(9/8 x RTT, 1ms). The full
feedback loop, receiver ack cadence plus wire plus the sender's own drain
pass, is structurally 1.5-3ms on this path. Every ack processing therefore
finds in-flight packets older than the loss delay whose acknowledgements
could not have been processed yet. Loopback's sub-millisecond loop never
poses the question, which is why identical code carries 14-15 Gbit/s there.

quiche's shipped remedies cannot answer this. The relaxed loss threshold
config exists but is unimplemented for the cubic recovery path (the source
says TODO), and the built-in adaptation caps at a packet threshold of 20
and a time threshold of 5/4, both under the observed staleness.

## Decision

Carry `quiche = { git = "halideworks/quiche", rev = 0d2f354 }`, which is
the 0.24.9 tag plus one change: an `enable_ack_latency_loss_floor` config
flag, off by default, that floors the loss delay at the slowest
send-to-processed-ack loop observed in the last 512ms and applies the
packet reordering threshold only to packets older than that loop. Both
recovery implementations carry it, both are tested, and the pump enables
it unconditionally: the floor is transport correctness on fast paths, not
a workload knob, so no `VOT_BENCH_*` variable controls it.

The same change is submitted upstream to cloudflare/quiche. The pin
dissolves when a quiche release ships the flag; the fork tracks nothing
else and takes no other divergence.

## Consequences

- Five W=6 1GB wire runs on the pinned build: 8.49/8.50/8.83/8.86/8.99
  receiver clock, median 8.83 against 7.9-8.0 stock the same day.
  Declared losses fell to 1.3-2.3k per run, disproofs to 100-200, and
  packets sent to within ~6% of the object's minimum.
- The dependency virtue ADR-0027 claimed is dented: quiche is now a
  pinned git revision until upstream takes the change. The fork carries
  exactly one commit atop a release tag so an upgrade is a rebase or a
  deletion, never a merge.
- CI fetches the fork from GitHub. A build without network access to it
  cannot resolve the workspace, the same exposure MsQuic's pinned rev
  already carries.
- The remaining ~0.6 Gbit/s to TCP parity is not a loss detection story:
  residual declarations only fire past a 6ms effective threshold, which
  is stall territory, and closing that gap is future pump work, not
  threshold work.

## Amendment, 2026-08-26: unpaced bbr2 leaves DRAIN and probes past inflight_hi

The fork takes a second change to the recovery path, at
`ce7e5b71f3198125ab92a1626390bbe3a2c7faa0`. `BBRv2::new` now receives the
recovery config's `pacing` flag and stores it in `Params`. When pacing is
true the controller is the pinned fork unchanged. When it is false, which
is this product's shipping default, two of the controller's phases behave
differently.

DRAIN's exit test asks bytes in flight to fall to one bandwidth delay
product, and its only actuator with a pacer is `drain_pacing_gain`. With
no pacer that gain never throttles a packet and the congestion window is
what sets bytes in flight, but DRAIN sets `cwnd_gain` to
`drain_cwnd_gain`, which is 2.0, so the window holds them at twice the
target the exit test reads and DRAIN does not end. Unpaced, DRAIN now
sets `cwnd_gain` to 1.0 and allows `max_ack_height` in the exit target,
because `update_congestion_window` adds `max_ack_height` on top of the
gain's product once full bandwidth is reached.

PROBE_UP has the same missing actuator, and `inflight_hi` caps the window
at whatever the last loss episode set, so the probe walks up to the
previous ceiling and stops rather than probing. Unpaced, the constructor
sets `probe_up_ignore_inflight_hi`, an option the fork already carries and
ships false, which bounds PROBE_UP by `inflight_lo` alone. PROBE_REFILL
has just cleared that bound. A round allowed to overshoot raises its own
delivery sample, and that sample is what `adapt_lower_bounds` floors its
next cut against, so the recovery after a loss episode compounds instead
of stepping.

Measured on an emulated 107 ms 2 Gbit/s path, eight rails, 213 graded
runs, both ends in one network namespace pair. A 12 GiB transfer at 12
percent loss each way falls from a median 154.95 s to 120.07 s on the
reliable path, with every changed run faster than every stock run, and
from 105.09 s to 85.76 s with automatic forward error correction. One
rail at 12 percent falls from 414 s to 301 s. A 4 GiB transfer at 0, 1,
3, 5 and 12 percent loss stays inside the stock spread at every rate, and
the clean standing queue falls from 8.51 to 7.93 times the minimum round
trip. Those numbers come from a build that reached both halves through
environment variables so every setting could interleave on one binary;
the same grid on plain release binaries is pending.

Three gates are not yet run. The first is the 2026-08-06 loss grid, the
one where unpaced bbr2 finishes three to five times faster than cubic at
0.5 to 1 percent loss, which is the claim the shipped default rests on;
this change alters how the window recovers after every loss episode, so
it governs that grid directly. The second is a shaped cell, delay-only
netem over an 800 Mbit token bucket with a 400 kb queue, which is what
screens a sender that overruns a shaper; the change probes harder after
loss, so that cell is the one most likely to refuse it. The third is a
real policed home link. Until all three are measured the pin carries the
change on the emulated grid alone.
