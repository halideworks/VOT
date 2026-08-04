# ADR-0025: Parallel verification is range proofs, and proving needs a CV layer

Status: Accepted

Amends ADR-0020, which deferred parallel verification and made `worker_count`
above one an error in the benchmark driver until subtree merging existed.

## Context

ADR-0020 deferred this work on a condition: "the assembled QUIC transport should
be measured before verification is parallelised, because the measurement may
show the hash is not what needs fixing." That measurement has now been made, on
the same host and the same 13th Gen i5-13500 the ADR-0020 figures come from.

| path | throughput |
|---|---|
| MsQuic, one lane, one worker, loopback | 9.4 Gb/s |
| quiche, same, at a matched datagram size | 6.9 Gb/s |
| VOT BLAKE3 verifier, one thread | 33.6 Gb/s |
| VOT SHA-256 verifier, one thread | 16.4 Gb/s |

The hash is not the constraint at any transport speed this codebase can
currently produce, and neither suite is close to binding. That is the outcome
ADR-0020 anticipated, and on its own it argues for leaving verification alone.

It is not the whole picture, because two of PERF-001's three acceptance criteria
depend on this path rather than on verification speed.
`one_rail_one_worker_and_multi_worker_measured` needs more than one worker, and
`serialized_spine_hypothesis_tested` needs a workload that can saturate a
connection's packet-number and ACK spine. The benchmark workload is one object
per case with `worker_counts` of 1, 2, 4, and 8, and the result schema has one
seed and one subject per case with no object count, so workers necessarily split
a single object. Splitting one object means ranges arrive out of order, and that
is a verification question whatever the hash costs.

## Decision

**Parallel verification is the proof-bearing range path, not subtree merging of
a streamed hash.** `ReliableReceiver::receive_range` already accepts a
64 KiB-aligned range in any arrival order and verifies it against the subject
root using a proof that comes with it. Each range is therefore independently
verifiable, by construction, which is what parallel verification requires.
ADR-0020's subtree merging was aimed at splitting *one contiguous streamed
hash*, and it is not needed for this: the ranges are already disjoint subtrees,
and the proof is what merges them at the root.

**`worker_count` is concurrent payload workers over disjoint ranges of one
object.** Not a verification thread pool, which is the reading ADR-0020 measured
and rejected, and not one object per worker, which the result schema cannot
express. This is what the serialized-spine hypothesis is about: payload workers
sharing a connection's packet-number, loss-detection, and ACK spine.

**Proving requires a group CV layer, because proving from the object does not
scale.** `vot_proof_blake3::prove` recomputes each sibling subtree's chaining
value from the data, so proving one range costs a hash of the whole object;
proving every range of a 16384-group object costs that 16384 times.
`vot_proof_sha256::prove` recomputes the whole piece layer per call. Both crates
gain:

- a streaming builder that takes one 64 KiB group at a time and keeps only its
  chaining value, so a sender never holds the object; and
- a prove entry point that takes that layer instead of the object, with the
  caller supplying the range bytes it already has.

The layer is 32 bytes per 64 KiB group: about 512 KiB for a 1 GiB object, which
is the largest the workload defines. That is what lets the benchmark driver keep
its rule that peak memory describes transport and verification rather than the
fixture, which materialising a 1 GiB object to call `prove` would break.

## Consequences

ADR-0020's measurements stand and so does its rejection of a thread pool over a
streamed hash. What changes is its final line: `worker_count` above one stops
being an error once the driver can send proof-bearing ranges, and the mechanism
is the range path rather than the subtree merging it named.

The hash still is not the bottleneck, so this buys throughput only if the
transport is what parallel workers relieve. That is the hypothesis PERF-001
exists to test, and it is now testable rather than assumed. A result showing
multi-worker no faster than one worker is a real answer, and the report says so.

Both proof crates are required mutation packages, so the new entry points come
back at zero missed mutants like everything else in them.

The existing `prove(data, offset, length)` stays. It is the honest thing for a
caller that has the object and wants one range, and every new entry point is
tested against it: the same range proved both ways produces the same proof, so
the fast path cannot drift from the one already covered by tests and fuzzing.
