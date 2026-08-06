# PERF-001: MsQuic and quiche on the same workload

Date: 2026-08-04

Both QUIC backends carry one object through the same transfer loop, the same
framing, and the same inline verification, so a difference between two results
is a difference between two carriers. The first table is the one-rail,
one-worker half of PERF-001; the spine measurement that completes it follows.
What is not here, and why, is at the bottom.

## Environment

- Linux 6.8.0-110-generic, x86_64
- 13th Gen Intel Core i5-13500, 20 logical CPUs, 134 GB memory
- Loopback, MTU 65536. **Both endpoints run on this one host**, so each result
  pays for the sender and the receiver together and understates what either
  carrier would do with a machine to itself. It is a fair comparison and an
  unfair absolute.
- Source commit: `e332ad4`

## Workload

One 512 MB object, one lane, one worker, 64 KiB records, `blake3-bao64`,
seed 42, no impairment shaping. Five runs per configuration, medians reported,
because at this size a single run decides nothing: see the spread column.

## Result

| carrier | datagram | Mbit/s (median) | spread | user CPU | system CPU |
| --- | --- | --- | --- | --- | --- |
| simulator | none | 18976 | 1.02x | 0.23 s | 0.00 s |
| MsQuic | segmented | 9984 | 1.28x | 0.99 s | 0.21 s |
| quiche | 1350 | 1460 | 1.41x | 2.72 s | 3.52 s |
| quiche | 16384 | 5849 | 1.51x | 0.97 s | 0.82 s |
| quiche | 32768 | 7190 | 1.60x | 0.90 s | 0.49 s |
| quiche | 65527 | 7071 | 1.27x | 0.92 s | 0.58 s |

CPU is the median of each column and covers the timed section only, both
endpoints and the driver together.

## What it says

**At its default the quiche backend is nearly seven times slower, and that is
almost entirely one constant of ours.** The pump sized every datagram at 1350,
which is what an endpoint facing an unknown path must assume, against a
loopback MTU of 65536. One datagram is one syscall and one packet's worth of
header protection and AEAD, so the default paid both on every 1350 bytes:
system time falls from 3.52 s to 0.49 s when the datagram is sized to the path,
and user time falls from 2.72 s to 0.90 s, because per-packet crypto cost about
as much as the syscalls did.

**MsQuic is still ahead once packet sizes are sane, on both numbers that decide
a default.** It carries about 1.4x the throughput and spends about 1.16x less
total CPU. quiche spends less *user* CPU (0.90 s against 0.99 s), but that is a
tenth of one component and system time more than cancels it, 0.49 s against
0.21 s. A reader choosing a backend today should read this row as MsQuic
winning, not as a tie.

What the split says about *why* is worth separating from the ranking. The whole
remaining gap is system time, which is what segmentation offload buys, and
PERF-002 is chartered to bring that to this path. If it lands, quiche's lower
user CPU would put the two at or past parity. That is a forecast rather than a
measurement, and two forecasts in this file were already dissolved by repeating
the experiment.

One caveat on the word "comparable". quiche was handed a datagram size and
MsQuic used its own offload strategy, so this compares each engine's best
available amortisation on this path rather than matched amortisation. That is
the right question for choosing a default today and the wrong one for ranking
the engines themselves.

**More is not always better.** 65527 measured slightly below 32768. Whatever
the mechanism, the useful reading is that the largest datagram a path allows is
not automatically the fastest, so the size belongs in the result rather than
being assumed.

**Neither carrier is hash-bound, and the harness is not the ceiling.** The
costs stack up like this on this host:

| | throughput | CPU for 512 MB |
| --- | --- | --- |
| `blake3-bao64` verifier alone (ADR-0020) | 33.6 Gb/s | |
| driver over the in-process carrier | 19.0 Gb/s | 0.23 s |
| driver over MsQuic | 10.0 Gb/s | 1.20 s |
| driver over quiche at 32768 | 7.2 Gb/s | 1.39 s |

The driver's own per-byte work, generating the object, framing it, and
verifying it, costs 0.23 s of CPU and caps any carrier at about 19 Gb/s here.
Each real carrier adds roughly a further second, so the transport costs about
five times what everything else in the run costs together. The in-process
carrier also holds to a 1.02x spread where both real ones are looser, which is
worth remembering when reading any single number below it.

**Record size is not a lever.** Measured at 16 KiB, 64 KiB, and 256 KiB records
with the datagram at 32768, every result sat inside the others' spread for both
carriers. Datagram size moves this workload; record size does not.

## Reproducing

```sh
cargo build --release -p vot-bench-driver --features msquic,quiche
export LD_LIBRARY_PATH="$(dirname "$(find target -name libmsquic.so.2 | head -1)")"
VOT_BENCH_BACKEND=quiche VOT_BENCH_SUITE=blake3-bao64 VOT_BENCH_WORKERS=1 \
VOT_BENCH_SEED=42 VOT_BENCH_OBJECT_BYTES=536870912 VOT_BENCH_RECORD_BYTES=65536 \
VOT_BENCH_IMPAIRMENT_MTU_BYTES=1500 VOT_BENCH_IMPAIRMENT_RTT_US=1000 \
VOT_BENCH_IMPAIRMENT_LOSS_PPM=0 VOT_BENCH_IMPAIRMENT_REORDER_WINDOW=0 \
VOT_BENCH_IMPAIRMENT_BANDWIDTH_BPS=10000000000 \
VOT_BENCH_IMPAIRMENT_QUEUE_BYTES=33554432 \
VOT_BENCH_QUICHE_DATAGRAM_BYTES=32768 \
target/release/vot-bench-driver
```

Each run reports its own `datagram_bytes`, `cpu_user_ns`, and `cpu_sys_ns` in
`notes`, so a result says which path it describes without a reader having to
reconstruct the configuration.

## The spine measurement: workers against rails

Ruling 6's hypothesis: one connection with W payload workers retains a
serialized packet-number, loss-detection, and ACK spine, and tops out below W
provisioned connections carrying one worker each. Same workload, host, and seed
as above, 512 MB, three runs per cell, medians, source commit `1c72173`. The
W=1 rows are the sequential path and anchor each curve; every W>1 cell runs the
ranged path (ADR-0025), which pays its own bundle framing and whole-object
receive staging, so the comparison the hypothesis is about is shared against
provisioned at the same W, never W=1 against anything.

| carrier | datagram | W | rails | Gbit/s (median) | spread | user CPU | system CPU |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MsQuic | segmented | 1 | | 11.07 | 1.13x | 0.91 s | 0.20 s |
| MsQuic | segmented | 2 | shared | 8.94 | 1.07x | 1.59 s | 0.37 s |
| MsQuic | segmented | 2 | provisioned | 8.83 | 1.22x | 1.76 s | 0.47 s |
| MsQuic | segmented | 4 | shared | 8.01 | 1.34x | 1.76 s | 0.38 s |
| MsQuic | segmented | 4 | provisioned | 7.51 | 1.24x | 1.85 s | 0.42 s |
| quiche | 1350 | 1 | | 1.74 | 1.05x | 2.23 s | 3.09 s |
| quiche | 1350 | 2 | shared | 1.54 | 1.21x | 3.00 s | 3.65 s |
| quiche | 1350 | 2 | provisioned | 1.58 | 1.62x | 5.45 s | 6.14 s |
| quiche | 1350 | 4 | shared | 1.43 | 1.38x | 3.43 s | 3.84 s |
| quiche | 1350 | 4 | provisioned | 2.51 | 1.11x | 5.84 s | 6.26 s |
| quiche | 32768 | 1 | | 6.87 | 1.34x | 0.96 s | 0.60 s |
| quiche | 32768 | 2 | shared | 5.79 | 1.03x | 1.60 s | 0.95 s |
| quiche | 32768 | 2 | provisioned | 7.19 | 1.15x | 2.06 s | 1.13 s |
| quiche | 32768 | 4 | shared | 5.21 | 1.05x | 1.73 s | 1.11 s |
| quiche | 32768 | 4 | provisioned | 8.65 | 1.06x | 2.00 s | 0.96 s |

Provisioned cells carry `rails=provisioned-multi-rail` in `notes`.

- **For quiche the hypothesis holds, at both datagram sizes.** The shared
  connection loses throughput as workers rise (6.87 to 5.79 to 5.21 at 32768)
  while rails gain it (6.87 to 7.19 to 8.65); at W=4 rails lead 1.66x at 32768
  and 1.76x at 1350, with 1.05-1.11x spreads on those four cells, far outside
  the twenty-percent band ruling 6 set for run variance. Each quiche
  connection is one socket-owning pump thread (ADR-0024), CPU-bound per
  packet, so W connections are W pumps, and the CPU columns show the rails
  buying their throughput with proportional CPU.
- **For MsQuic it does not hold.** Shared and provisioned differ by 1.2% at
  W=2 and 6.2% at W=4, inside spreads of 1.07-1.34x: the connection is not
  what binds, because giving each worker its own moved nothing.
- **The host is not the ceiling.** The heaviest cell (quiche at 1350, W=4,
  provisioned) spends 12.1 s of CPU on a 20-CPU host inside a 1.6 s transfer;
  the flat MsQuic curves are not machine saturation.
- **The ranged path itself costs.** MsQuic user CPU rises from 0.91 s
  sequential to 1.59 s ranged on the same object, and every W>1 cell of both
  backends sits below its backend's W=1 anchor. That is the path's framing and
  staging cost plus the driver spine, not a connection property, which is why
  the anchors are context and not a curve point.

Reproducing: the command above, with `VOT_BENCH_WORKERS` set to the cell's W,
`VOT_BENCH_RAILS=provisioned` for the provisioned cells (absent or `shared`
otherwise), and `VOT_BENCH_QUICHE_DATAGRAM_BYTES` at the figure's datagram
size, absent for the 1350 default and for MsQuic.

## Two-machine confirmation

Labeled and never mixed with the loopback numbers above: this is a different
path with different facts, and each side pays only for its own endpoint.

- Sender: tr-desktop, Windows 11, inside WSL2 (Ubuntu, x86_64, NAT networking).
  Receiver: this host, native Linux. Wired at 10 Gbit/s, physical MTU 1500.
- **The effective path MTU is 1280 bytes**, measured by UDP probe: the WSL2
  NAT path forwards a 1252-byte UDP payload and silently drops 1300. Every
  number below describes that path. Neither carrier approaches the link rate,
  so this confirms the engines' relative cost, not the link's capacity.
- One 512 MB object, one lane, one worker, 64 KiB records, `blake3-bao64`,
  seed 42. Five runs per configuration; the receiver's clock, from accepted
  connection to verified object, is the throughput claim.

| carrier | datagram | Mbit/s (median) | spread | recv CPU user/sys | send CPU user/sys |
| --- | --- | --- | --- | --- | --- |
| MsQuic | probed | 2480 | 1.19x | 0.92 s / 0.23 s | 0.65 s / 0.81 s |
| quiche | 1252 | 387 | 1.08x | 3.77 s / 4.83 s | 3.97 s / 7.09 s |

What it confirms, and one thing it found:

- **The per-packet gap widens on a real path.** At matched ~1250-byte packets
  MsQuic leads 6.4x, against 1.4x on loopback where quiche was allowed jumbo
  datagrams. The quiche sender spends 11.06 s of CPU carrying an 11.11 s
  transfer: the path is CPU-bound on per-packet work, and the system-time
  split (7.09 s against 0.81 s sending, 4.83 s against 0.23 s receiving) is
  the segmentation-offload difference PERF-002 exists to close.
- **quiche blackholes on a path narrower than its datagram size.** At the
  1350-byte default the handshake completes, because handshake packets are
  1200 bytes, and then every data packet vanishes and the transfer stalls at
  zero until the round budget calls it stalled. MsQuic probed the path and
  settled under the ceiling on its own. Whoever writes ADR-0026 should weigh
  this with the datagram-size lever above: the same control that let quiche
  win back 4.2x on loopback is, unset, the thing that hangs it on a narrow
  path, because the backend does no path-MTU discovery.
- The wire runs hold a 1.08-1.19x spread where loopback held 1.3-1.6x, which
  is consistent with loopback's noise being two endpoints contending for one
  host.

### Rerun after the offload work (2026-08-04, `7db16b6`)

Same path, same shape, five runs per backend, after the drained pump, the
segmentation-offload bursts, and the coalesced-receive split landed:

| carrier | datagram | Mbit/s (median) | spread | recv CPU user/sys | send CPU user/sys | recv cyc/B | send cyc/B |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MsQuic | probed | 2492 | 1.05x | 0.61 s / 0.25 s | 0.66 s / 0.91 s | 7.53 | 6.17 |
| quiche | 1252 | 2511 | 1.39x | 0.69 s / 0.25 s | 0.72 s / 0.74 s | 8.00 | 6.27 |

The 6.4x gap of the baseline above is gone: the two engines are the same
number inside their spreads, both a few percent above the iperf single-flow
figure below, so this path can no longer separate them. quiche's 1.39x
spread is one cold first run at 1841 Mbit/s; runs two through five hold
2499-2557, a 1.02x band tighter than the baseline's. What closed it was
per-packet cost, not engine work: quiche's sender system time fell from
7.09 s to 0.74 s and its receiver's from 4.83 s to 0.25 s, into MsQuic's
territory on both ends. ADR-0026's consequences clause names this result as
what reopens the default question; the path-MTU blackhole it also names is
closed as of `discover_pmtu` landing in the pump: the 1350-byte default over
this 1280-byte path, the exact configuration the finding above records as a
hang, now probes, settles, and carries 512 MB at a 2519 Mbit/s median over
five runs, even with the pinned-1252 row above. The burst slots follow the
connection's discovered packet size rather than the configured ceiling,
because ceiling-cut slots made every settled packet short and gave the
offload back one flush at a time, which cost 19% until it was caught. The
first run after the path goes quiet is cold here too (1694; the other four
hold 2476-2572).

### The path widened, and the ceiling followed (2026-08-04, `8c0b8b4`)

The WSL NAT path changed under us: a UDP payload sweep now passes every size
through 1472 bytes, full ethernet framing, where it dropped everything over
1252 before. Anything needing fragmentation still dies, so it is a wider
pipe with the same cliff. Rerun on the widened path, five runs per arm:

| carrier | datagram | Mbit/s (median) | spread | recv CPU user/sys | send CPU user/sys | recv cyc/B | send cyc/B |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MsQuic | probed | 2584 | 1.17x | 0.58 s / 0.26 s | 0.64 s / 0.84 s | 7.30 | 5.75 |
| quiche | 1472 pinned | 2899 | 1.07x | 0.66 s / 0.23 s | 0.66 s / 0.71 s | 7.69 | 5.83 |
| quiche | 1350 ceiling, discovered | 2339 | 1.09x | 0.68 s / 0.26 s | 0.65 s / 0.76 s | 8.00 | 5.94 |
| quiche | 1472 ceiling, discovered | 2769 | 1.31x | 0.66 s / 0.25 s | 0.59 s / 0.70 s | 7.96 | 5.64 |

Pinned at 1472, quiche leads MsQuic's probed arm by 12%, outside both
spreads; the table does not record what size MsQuic settled at, so the
comparison is between configurations, not proven-equal packets. The third
row is the lesson: discovery probes up to `max_send_udp_payload_size`, so
the old 1350 default was a ceiling the path never asked for, and it priced
the stock config 9% under MsQuic on a path that carries 1472. The default
ceiling is now 1472, what a 1500-byte ethernet frame carries over IPv4,
with discovery settling under it where the path is narrower; that is the
fourth row, taken at the new default with nothing pinned, 7% over MsQuic.
Its 1.31x spread is the familiar cold first run (2205; the other four hold
2718-2895). Every arm sits near 240k packets per second, the Windows-side
send ceiling the iperf section below measured, so the ordering here is
packets carried, not engine cost: the wider path moved the same pps ceiling
up by the ratio of the packet sizes.

### The ceiling was twice a lie (2026-08-04, after `ce0bcf4`)

Two corrections from making the largest configurable datagram provable.
`LARGEST_DATAGRAM_SIZE` said 65527, which is IPv6's payload ceiling; IPv4's
total-length field also counts its own and UDP's 28 header bytes, so the
largest payload a v4 socket carries is 65507, and validation accepted a
size nothing could send. The constant now says 65507, and the loopback
suite sends a record at exactly that size and then asserts the discovered
path MTU equals the ceiling, which is what turned up the second lie:
discovery never converged at jumbo ceilings. quiche only generates a probe
when the send buffer offered could hold one, and its packet-size accessor
caps its answer at 16383, so burst slots sized from it could never carry a
probe for a larger ceiling and the connection stayed at the 1200-byte
handshake floor for its whole life. The burst now opens at the configured
ceiling and takes its segment size from the first packet written. Ceilings
at or under 16383, including the 1472 default, were never affected: their
probes always fit the slot. Confirmed on the wire at the stock config,
2735 Mbit/s median over five runs (1.44x, the familiar cold first run;
the warm four hold 2679-2777) against 2769 before, the same band. On
loopback the stock config measures a 9.0 Gbit/s median over five runs
(1.27x, 8.0-10.2), its first stock measurement there; the jumbo rows in
the loopback table above predate discovery and pinned their sizes, so
they stand as history.

### What the path does without VOT

iperf 3.21, same direction, measured to separate this stack's overhead from
the path's. TCP reaches 9.2-9.5 Gbit/s from both WSL and native Windows, so
the wire and both kernel stacks are line rate when segmentation offload
applies. A single unpaced UDP flow at 1252-byte datagrams tops out at 2.44
Gbit/s from WSL and 2.24 from native Windows, both limited by the Windows-side
send path at roughly 240k packets per second; erebus sending the reverse
direction reaches 5.68 Gbit/s at the same size. Four unpaced flows carried
3.5 Gbit/s aggregate at 30% loss, so multiple rails can exceed the single-flow
ceiling. Native Windows also passes 1472-byte payloads (2.77 Gbit/s, 0.05%
loss), so the 1280-byte MTU is the WSL NAT path's alone.

Read against the table above: **MsQuic's 2480 Mbit/s is the path's own
single-flow UDP ceiling**, so it leaves nothing on the table here, and
quiche's 387 is 6.3x under a ceiling the same socket layer serves. On this
path the whole gap is the engine's per-packet cost, none of it the wire's.

Reproducing, receiver first, then the sender on the other machine:

```sh
VOT_BENCH_ROLE=receive VOT_BENCH_LISTEN=192.168.1.131:4433 \
  <the loopback command above, with VOT_BENCH_QUICHE_DATAGRAM_BYTES=1252>
VOT_BENCH_ROLE=send VOT_BENCH_CONNECT=192.168.1.131:4433 \
  <same case on the sending machine>
```

## Ram-to-disk, added 2026-08-05

The ranged receiver can now place verified bytes in a file
(`VOT_BENCH_SINK_FILE`, ADR-0029), which turns the same case ram-to-disk;
absent, the discard sink is what every number above used. First numbers,
1 GB, W=4, quiche, provisioned rails, five runs each, same hour:

| path | destination | Gbit/s (median) | spread |
| --- | --- | --- | --- |
| loopback | discard | 12.11 | 1.12x |
| loopback | ZFS NVMe mirror | 11.49 | 1.09x |
| wire (W=6) | discard | 9.21 | 9.17-9.30 |
| wire (W=6) | receiver's NVMe | 7.45 | 6.72-8.67 |

On loopback the disk is nearly free: placement runs outside the admission
lock and the poll loop (PRs 100-101), so the sink's latency prices a
pool, not the transfer. The post-clock `sync_ns` field carries what
making it durable cost (~575 ms per GB on the mirror).

The wire rows were remeasured on 2026-08-06 and say something different
from the first attempt, which was taken on an evening when the wire
itself only carried 5.8 and reported the sink as free. At 9.2 the
receiver's NVMe is the slower half: 19% off the median, declining
monotonically across five consecutive runs (8.67 to 6.72) with `sync_ns`
growing from 229 to 422 ms, while discard runs taken immediately before
and after the set hold 9.21 and 9.18. The device, not the path: one disk
run is not a measurement of it.

## What this does not cover

**The default backend is ADR-0026's ruling, not this report's.** All three
acceptance criteria are now measured here:
`one_rail_one_worker_and_multi_worker_measured` by the first table and the
spine matrix, `provisioned_multi_rail_labeled` by the provisioned cells and
their notes label, and `serialized_spine_hypothesis_tested` by the shared and
provisioned curves and the per-carrier verdict above. What remains uncovered:

- The spine matrix is loopback only and stands as history at its commit. The
  ranged multi-rail role mode it lacked was built since (PR 87, 2026-08-05),
  and wire multi-rail numbers now exist: once the rail startup race was fixed
  (PR 88), W=4 carried 7.8 and W=6 8.5 Gbit/s with a 1 GB object, and on the
  pinned quiche of ADR-0028 five W=6 runs hold an 8.83 Gbit/s median against
  the path's own single-flow TCP ceiling of 9.45. Remeasured on 2026-08-06
  on a quiet box, the same five-run set holds a 9.21 Gbit/s median of
  receiver-verified goodput (9.17-9.30), which is 97.5% of that TCP ceiling
  for a transfer that proves every byte against a chain. Those runs are
  provisioned rails only, so the shared arm of the hypothesis still has no
  two-machine measurement.
- Every multi-worker number pays the ranged path's own framing and staging, so
  cross-path comparisons against the sequential rows conflate path and worker
  count; only same-W cells are commensurable.

**Nothing here weighs what is not speed.** ADR-0012 isolates MsQuic because it
is a C FFI dependency that requires unsafe code, is pinned to a git revision,
builds a bundled C library, and leaves the driver binary needing that library at
run time. quiche is sans-IO Rust with no unsafe in its adapter. ADR-0024 chose a
second backend for explicit UDP I/O, pacing, and congestion-control control, and
this report is itself evidence that the control matters: the datagram size worth
five times the throughput was ours to set on quiche, and MsQuic offers no
equivalent lever. A default chosen on throughput alone is choosing on one axis
of several.

One caveat the spine measurement accounted for: `TransportAdapter` takes
`&mut self`, so several workers cannot submit through one adapter concurrently
without a lock, while separate connections each have their own adapter. Multi-
worker and multi-rail therefore differ in more than the connection count; the
spine section reads its curves per carrier at the same W so as not to attribute
the driver's
serialization to the carrier's.
