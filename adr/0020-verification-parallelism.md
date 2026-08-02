# ADR-0020: Parallel verification needs subtree merging, not a thread pool

Status: Accepted

## Context

The stated Wave 6 target is tens of gigabits per second, and the working
assumption was that single-threaded BLAKE3 sits near 10 Gb/s, making the hash
the binding constraint and a thread pool the obvious fix.

Both halves of that were worth checking before designing around them.

## Measurements

On a 13th Gen i5-13500, 20 logical CPUs, 1 GiB per pass
(`cargo run --release -p vot-verifier --example hash_throughput`):

| path | throughput |
|---|---|
| BLAKE3 over one whole buffer | 35.15 Gb/s |
| VOT BLAKE3 verifier | 33.62 Gb/s |
| VOT SHA-256 verifier | 16.42 Gb/s |
| BLAKE3 with its own thread pool over one whole buffer | 275 Gb/s |

Two corrections fall out. Single-threaded BLAKE3 is about 35 Gb/s here, not 10,
so the ceiling is three times higher than assumed. And the VOT verifier is
within four percent of raw BLAKE3, so the group loop and the aligned fast path
cost almost nothing. SHA-256 is half the speed of BLAKE3 and is the suite that
will bind first.

## The attempt that did not work

Enabling BLAKE3's `rayon` feature and calling `update_rayon` was tried, wired
through to the benchmark driver so `worker_count` sized the pool. Measured
across one, two, four and eight workers on a 1 GiB object, throughput was
36.1, 34.3, 33.1 and 33.3 Gb/s: no gain, and slightly worse.

The reason is structural. VOT hashes in 64 KiB verification groups and the
verifier is fed one group at a time, by design, because a group is the unit that
becomes verified state. BLAKE3's internal parallelism splits one large
contiguous input; it never sees a buffer bigger than a group, so it never
splits. The feature was inert everywhere, and the run still reported a worker
count, which is exactly the false claim the benchmark contract exists to
prevent.

## Decision

No thread pool. Parallel verification requires hashing disjoint subtrees and
merging them at the root, using the BLAKE3 tree API rather than its streaming
API, and it requires ranges to reach the verifier as subtrees rather than as a
sequence of groups. That is a change to how verified state is accumulated, not a
flag.

Until that exists, `worker_count` above one stays an error in the benchmark
driver.

The microbenchmark is committed so the numbers above can be reproduced and
rechecked on other hardware rather than taken on trust.

## Consequences

The hash is not the immediate constraint it was assumed to be. At 35 Gb/s for
BLAKE3, a single-threaded receive path is adequate for a 10 or 25 Gb/s link, and
the transport is more likely to bind first. That reorders the remaining work:
the assembled QUIC transport should be measured before verification is
parallelised, because the measurement may show the hash is not what needs
fixing.

For SHA-256 at 16.4 Gb/s the margin is thinner, and a 25 Gb/s link would be
hash-bound on that suite today.
