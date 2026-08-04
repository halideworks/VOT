# PERF-001: MsQuic and quiche on the same workload

Date: 2026-08-04

Both QUIC backends carry one object through the same transfer loop, the same
framing, and the same inline verification, so a difference between two results
is a difference between two carriers. This is the one-rail, one-worker half of
PERF-001. What is not here, and why, is at the bottom.

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

## What this does not cover

**No default backend is selected here.** That is ADR-0026, and it should not be
written from this table alone: two of PERF-001's three acceptance criteria are
still unmeasured, and one of them could move the answer.

- `one_rail_one_worker_and_multi_worker_measured`: the one-worker half only.
  Multi-worker needs the driver to send proof-bearing ranges, whose groundwork
  landed as ADR-0025 and the range-proof entry points in both proof crates.
- `provisioned_multi_rail_labeled`: not measured. It splits one object across
  several connections and needs the same range path.
- `serialized_spine_hypothesis_tested`: not tested, and it is the criterion that
  could change the choice. It predicts that payload workers sharing one
  connection top out below independent rails, which is a claim about the
  connection's packet-number and ACK spine rather than about either engine's
  single-stream speed.

**No two-machine run.** Loopback numbers do not transfer to a wire.

**Nothing here weighs what is not speed.** ADR-0012 isolates MsQuic because it
is a C FFI dependency that requires unsafe code, is pinned to a git revision,
builds a bundled C library, and leaves the driver binary needing that library at
run time. quiche is sans-IO Rust with no unsafe in its adapter. ADR-0024 chose a
second backend for explicit UDP I/O, pacing, and congestion-control control, and
this report is itself evidence that the control matters: the datagram size worth
five times the throughput was ours to set on quiche, and MsQuic offers no
equivalent lever. A default chosen on throughput alone is choosing on one axis
of several.

One further caveat for whoever writes ADR-0026: `TransportAdapter` takes
`&mut self`, so several workers cannot submit through one adapter concurrently
without a lock, while separate connections each have their own adapter. Multi-
worker and multi-rail therefore differ in more than the connection count, and
the spine measurement has to account for that or it will attribute the driver's
serialization to the carrier's.
