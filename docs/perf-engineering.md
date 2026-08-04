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
