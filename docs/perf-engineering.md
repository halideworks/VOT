# Performance engineering notes

A running log of what was measured, what it cost to learn, and which plausible
explanations turned out to be wrong. Entries are written when the measurement
happens, not reconstructed afterwards, because the wrong guesses are the
valuable part and they are the first thing hindsight erases. Add an entry
whenever a change was made for performance, a number moved for a reason that
was not the predicted one, or an approach was rejected by measurement.

Each entry records: the date, the configuration measured, the number, and what
was believed before the measurement. Absolute numbers are only comparable
within one machine and one configuration; the report format in
`bench/results/` exists for claims meant to travel.

## Method

- A probe must be long enough to believe. On the development host a 64 MB
  transfer varied by a factor of two between identical configurations; 512 MB
  brings run-to-run variance to about twenty percent. Compare medians over
  several runs, and treat any difference inside the variance band as no result.
- Loopback pays for both endpoints on one host. It compares two engines fairly
  and understates what either does with a machine to itself, so loopback and
  two-machine numbers are labelled and never mixed.
- Measure before believing an explanation. Every entry below that names a
  wrong suspect earned its place by someone spending time on it.

## Entries

### 2026-08-03: the benchmark driver is not the ceiling, and the quiche path varies 2x

Wiring both carriers into `vot-bench-driver` made the first like-for-like
comparison possible: the same transfer loop, the same framing, and the same
inline verification over an in-process carrier and over a socket. One 512 MB
object, one lane, one worker, 64 KiB records, on the development host.

- Simulator, five runs: 16878, 18211, 18270, 18495, 19024 Mbit/s. Median
  18270, spread 1.13x.
- quiche over loopback, nine runs: 805, 885, 905, 1084, 1117, 1148, 1152,
  1503, 1595 Mbit/s. Median 1117, spread 2.0x.

Two things follow. The driver's own work is not the ceiling and not the source
of variance: it carries the same case sixteen times faster and within six
percent of itself when the carrier is in process, so what PERF-001 measures is
the engine. And the quiche loopback path varies by a factor of two run to run
at 512 MB, which is the size chosen precisely because the standalone pump test
was steady to about twenty percent there.

The difference between those two variance figures is the driver's path doing
work the pump test does not: BLAKE3 verification inline on the receive side,
and a flush and drain every sixteen records. Which of those it is has not been
measured, and neither has the obvious third possibility, that two driver
threads and a verifying application thread simply schedule differently run to
run.

The consequence for PERF-001 is concrete and not optional: at this size a
single run decides nothing, and a difference between two backends smaller than
about 1.4x is inside one configuration's own spread. The report needs medians
over enough runs to state a confidence interval, and the plan's earlier
"±20% at 512 MB" figure does not apply to this path.

### 2026-08-03: a 64 MiB probe invented a record-size effect that does not exist

At 64 MiB per run, quiche appeared to carry 256 KiB records 3.5x faster than
64 KiB records (1849 against 531 Mbit/s), which is exactly the shape of a real
per-record overhead. Repeating at 512 MB with three runs each dissolved it:
64 KiB gave 1241, 1137, 1497; 128 KiB gave 889, 748, 1522; 256 KiB gave 1428,
1709, 923. The spread within each configuration covers the whole gap between
them, and the ordering is not even monotonic.

Nothing about record size is established. What is established is that this
codebase's own rule was right and got skipped anyway: the 64 MiB probe was
known to vary 2x before it was run, and its number was still convincing enough
to reach for an explanation. The check that caught it was repetition, not
insight.

### 2026-08-03: the adapter was the ceiling, not the engine

One quiche lane over loopback went from about 740 to about 1400 Mbit/s by
holding the caller's `Payload` instead of copying each record three times on
its way through the adapter (PR #60). The suspects before measuring were the
driver tick and the datagram size. Both were wrong:

- Shortening the driver tick made throughput worse, not better. The path is
  CPU-bound per byte, not latency-bound, so a faster tick just spent more CPU
  on the loop itself.
- Datagram size changed nothing across a 24x range in syscall count. Syscalls
  were not the cost; copies were.

The general form: when a backend adapter sits between the benchmark and the
engine, the first ceiling found is usually the adapter's. PERF-001's numbers
are only about the engines if the adapter's own costs are known to be small.

### 2026-08-03: sleeping in the send loop stops the world

Waiting out the pacing deadline inside the send loop stopped the driver from
reading, so acknowledgements queued and the congestion window stopped opening.
The deadline belongs on the socket wait, where sleeping and listening are the
same act. A command channel of depth one had the same shape: any point where
the driver can only do one thing at a time bounds throughput by the loop rate.

### 2026-08-03: per-pass allocation in a hot loop

Allocating the stream read buffer per pass cost 64 KB of allocation every loop.
Buffers that live as long as the loop should be allocated once outside it; the
profile shows this as allocator time, not as any function that looks hot.
