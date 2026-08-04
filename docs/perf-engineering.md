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

### 2026-08-03: how long the driver waits changes what the driver measures

The transfer loop waits when a delivery finds nothing, because the carrier's
own thread is what makes progress. How long it waits turned out to change the
number the run reports, which makes it a property of the harness sitting inside
every result PERF-001 will publish. One 512 MB object, one lane, 64 KiB
records, five runs at each fixed wait:

| wait | throughput (Mbit/s) | median | spread |
| --- | --- | --- | --- |
| 20 us | 769, 969, 1041, 1081, 1127 | 1041 | 1.5x |
| 200 us | 902, 1011, 1018, 1203, 1233 | 1018 | 1.4x |
| 1 ms | 1316, 1389, 1491, 1532, 1810 | 1491 | 1.4x |
| 2 ms | 1033, 1034, 1548, 1549, 1629 | 1548 | 1.6x |
| 5 ms | 1510, 1526, 1581, 1602, 1646 | 1581 | 1.09x |
| 10 ms | 1348, 1412, 1503, 1567, 1891 | 1503 | 1.4x |

Waiting less made the carrier slower and the result noisier. The 20 and 200
microsecond groups do not overlap the 1 to 5 millisecond groups at all. The
reading that fits: polling a carrier that has nothing to give contends with the
thread that would otherwise be filling it, and past about a millisecond the
driver is out of its way. It plateaus rather than climbing, which is what
distinguishes that reading from "less overlap looks like more throughput".

This also revises the entry below. The quiche path's 2x run-to-run spread was
read there as the carrier's own; a good part of it was the driver polling into
the carrier's thread, and it falls to 9 percent at a 5 millisecond wait.

A fixed long wait cannot just be adopted, because it pads the small cases,
where one wait is most of the run: a 64 KiB object completes in about 2.5 ms
and takes seven waits to do it. So the wait backs off, 16 microseconds doubling
to 1 millisecond.

What the count backs off over turned out to matter as much as the interval. A
backoff over *consecutive* idle deliveries, reset whenever one found data,
landed back in the slow regime: a median of 1366 Mbit/s over seven runs with a
2.2x spread and about 22,000 waits per run. This workload arrives in bursts, so
the reset kept putting the driver back into the short waits. Decaying by half
instead of resetting gave 1418 and 1.9x, inside the noise of the same thing.

Counting the transfer's *total* idle deliveries, so the wait climbs once and
stays, gives a median of 1530 with about 2,100 waits, which is the same regime
as the best fixed waits and leaves the small cases untouched at 1.4 to 3.6 ms.
It is also simpler: with no reset there is no branch, and the loop's round
budget then bounds the wall clock, because the wait can no longer stay short
for an unbounded number of deliveries.

The honest state: the interval is a knob that changes the answer, and the driver
is guessing at it because the transport contract offers no way to wait for an
event. `poll` returns what has already arrived and nothing blocks. The fix is a
bounded blocking wait on the adapter, so the driver sleeps until there is
something instead of guessing how long to sleep; that is a change to the
transport contract and belongs with PERF-001's measurement PR, not smuggled
into the seam. Until then, every published number states the wait it was taken
at, and both backends are measured at the same one.

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

Partly answered by the entry above, which was measured afterwards: a good part
of this spread was the driver's own polling contending with the carrier's
thread, and it falls to 9 percent when the driver waits longer between polls.
The figures here were taken at a 200 microsecond wait.

The consequence for PERF-001 is concrete and not optional: at this size a
single run decides nothing, and a difference between two backends smaller than
about 1.4x is inside one configuration's own spread. The report needs medians
over enough runs to state a confidence interval, and the plan's earlier
"±20% at 512 MB" figure does not apply to this path.

### 2026-08-03: open, the driver drains its receiver only every sixteen records

Not measured, recorded so it is not forgotten. The transfer loop submits
`SUBMIT_BATCH_RECORDS` records before it flushes and drains, and that constant
exists to bound staging rather than to pace the carrier. On a real carrier the
receiving endpoint's inbound queue fills in the meantime, and the quiche pump
holds an event rather than dropping it when its queue is full, which stops it
reading the stream, which stops the connection window opening. That is a
driver-side knob capable of bounding the carrier, which is the one thing
PERF-001 must not measure.

There is no evidence it is biting: the driver's quiche median of 1117 Mbit/s
and the standalone pump test's 1400 Mbit/s are the same number given the spread
of either. But "no evidence" here means the spread is too wide to see an effect
this size, not that the effect is absent. Sweeping the batch constant is
cheap and belongs in PR 4, before any number is published.

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
