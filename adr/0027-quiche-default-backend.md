# ADR-0027: quiche becomes the default backend

Status: Accepted

Amends ADR-0026, on the terms ADR-0026 itself set: its consequences clause
says a PERF-002 result that closes the wire gap reopens the default question
with numbers rather than by fiat, and names the path-MTU blackhole as the
robustness item quiche had to answer first. Both happened on 2026-08-04, and
the evidence is `bench/results/perf-001-quic-bakeoff.md`.

## Context

ADR-0026 chose MsQuic on three measured facts and one robustness fact. Each
has moved, and every movement is in the report:

1. **The wire gap is closed.** The 6.4x lead at matched ~1250-byte packets is
   now 2511 against 2492 Mbit/s, the same number inside spread, on the same
   path as the baseline. What closed it was the driver's own per-packet cost:
   the drained pump, segmentation-offload bursts, and the coalesced-receive
   split took quiche's sender system time down 9.6x and its receiver's 19x,
   into MsQuic's territory on both ends.
2. **The spine verdict now favors what quiche needs least.** quiche's shared
   connection was the arm that needed provisioned rails to scale; after the
   offload work its single connection carries the path's ceiling alone, and
   on loopback it holds 14.8 Gbit/s at jumbo datagrams against MsQuic's 10.4.
3. **Cycles favor quiche where packets are large and tie where they are
   small.** 7.45 against 10.72 cycles per byte at jumbo datagrams on
   loopback; within 6% on the wire at matched packets, both directions.
4. **The blackhole is closed at full speed.** `discover_pmtu` is on in the
   pump: the 1350-byte default over the 1280-byte path, the configuration the
   report records as a hang, now probes, settles, and carries the case at a
   2519 Mbit/s median, even with the hand-pinned datagram row.

What did not move is the axis ADR-0026 said speed alone could not decide,
and it points the same way it always did: quiche is sans-IO Rust with no
unsafe in its adapter, no pinned git revision, no bundled C library the
binary needs at run time, and none of ADR-0012's isolation burden. The
datagram lever and the pump are ours, which is what made this week's work
possible at all; MsQuic's equivalents are internal to a C library.

## Decision

quiche is the default backend. Anything selecting a backend by default
selects quiche.

MsQuic stays, as the second engine and the cross-check. The bakeoff's method
is two engines behind one seam, and an independent implementation is what
keeps the numbers honest; it is also the fallback for any path where a future
measurement reverses this one.

Multi-worker defaults are unchanged from ADR-0026: workers above one cost
throughput on one connection at this scale, and provisioned rails are a
measured configuration, not a recommendation.

## Consequences

- ADR-0012's isolation rules now apply to an explicit choice rather than the
  default; a default build carries no C FFI transport.
- PERF-002's remaining acceptance, the 10 Gbps target, is measured on quiche
  first. The current two-machine path ceilings near 2.5 Gbit/s in the WSL2
  NAT, so that target needs a path before it needs more engine work.
- The wire evidence comes from one path, sender in WSL2. A native-to-native
  confirmation at matched packets is the first thing to run when a second
  path exists; if it reverses the parity result, this is the ADR to amend.
