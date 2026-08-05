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
