# ADR-0057: Incremental object checkpoints

- Status: Accepted for controlled-source proof preparation.
- Date: 2026-09-12
- Applies to: `vot-object`, both proof suites, and `vot-proof-store`.

## Decision

Implement the metadata boundary identified by ADR-0056 using shared immutable
subtrees. `ObjectCheckpoint` accepts complete changed proof groups and returns a
new canonical identity and proof snapshot. `prepared()` exposes that snapshot
through the existing `PreparedObject` interface without flattening the tree.
Ordinary streaming preparation keeps its existing vector or spill backend.

The checkpoint retains proof metadata, not payload bytes. Its caller must own
or control the source and report every change. Cached metadata cannot establish
the identity of an uncontrolled filesystem file. Checkpoint creation does not
establish producer completion, source coherence, receiver coverage, or durability.
Earlier checkpoint proofs remain valid, but serving their bytes requires the
caller to retain those bytes separately.

## Update contract

`updated(offset, bytes, length)` replaces one contiguous group-aligned range and
sets the new logical byte length. Multiple disjoint changes can be supplied as
successive immutable updates. Only the final 64 KiB group may be short.

- Growth supplies every appended group and refreshes an old partial tail.
- Partial truncation supplies the shortened final group.
- Aligned truncation above one group can supply an empty slice.
- An output of at most one group supplies all its bytes, except for a no-op.
- Growing from at most one group to a larger object resupplies the first group.
- Invalid ranges, missing growth data, and lengths above the object limit fail
  before changing any checkpoint.

The small-object rule preserves BLAKE3 root mode and SHA-256's 16 KiB leaf
geometry. A retained non-root group value cannot generally recover a standalone
small-object root. At most 64 KiB is resupplied at the small-to-large boundary.

## Representation and costs

`ProofTree` uses a dense left-balanced binary tree with `Arc` ownership. Each
node retains its hash, leaf count, and optional children. A nonempty tree has
`2n - 1` nodes for `n` leaves. Replacement, append, and prefix truncation rebuild
only affected ancestors. No dependency, hash algorithm, object identity, proof
encoding, wire identifier, manifest schema, or assurance transition changes.

BLAKE3 retains positioned non-root chaining values and applies root mode only
to the final two subtrees. SHA-256 reuses complete subtrees and applies its
existing zero-hash padding along the ragged right edge. Generic hashes of
incomplete subtrees are not used as SHA-256 canonical hashes.

For `k` supplied groups and `n` represented groups, update hashing, allocation,
and tree traversal cost O(k + log n), in addition to hashing supplied payload.
An unchanged snapshot shares its root. The 4,096-leaf work test requires exactly
12 merges for a one-leaf replacement, one merge when appending the 4,097th leaf,
and zero merges when truncating back to 4,096 leaves. It also verifies that an
unchanged half-tree retains the same allocation.

Node allocations and reference counts increase the cost of one isolated tree
relative to flat vectors. Retaining many nearby snapshots shares unchanged
nodes rather than duplicating all metadata. Allocation failure follows ordinary
Rust allocation behavior; this API does not promise recoverable out-of-memory
errors. Dropping snapshots can reclaim every node they alone retain, so snapshot
destruction and large truncation reclamation are not bounded by tree depth.

BLAKE3 proofs walk retained branches directly. SHA-256 proof lookups still walk
from the root for individual requested subtrees: a one-group proof takes
O(log squared n) node visits, and a large proof window can take O(window size
times log n). Hashing and canonical proof bytes remain unchanged. A proof cursor
is a later optimization if this lookup cost matters for a caller's workload.

## Measurement

`incremental_checkpoints` compares rebuilding from cached leaves with shared
checkpoint updates. Both consume identical owned mutations and supplied groups.
The benchmark checks the final root against fresh byte hashing for every run.
The optional argument is the initial group count for rewrite and truncate/regrow;
append always grows by 4 KiB for 1,024 updates, ending at 4 MiB.

`payload_bytes` counts supplied bytes. `leaf_input_bytes` counts leaf hashes
supplied to a complete rebuild or an incremental update; it excludes interior
hash work, allocation overhead, disk I/O, and wire bytes. Both counters are
identical across suites. For 1,024 rewrites of a 256 MiB draft, both paths hash
67,108,864 payload bytes. Leaf input falls from 134,217,728 to 32,768 bytes.

Median aggregate milliseconds across three sequential release runs on an Intel
Core i5-13500, Linux 6.8.0, Rust 1.97.1:

| Draft size | Suite | Workload | Cached-leaf rebuild | Shared checkpoint |
| --- | --- | --- | ---: | ---: |
| 4 MiB | BLAKE3 | Rewrite | 17.870 | 14.705 |
| 4 MiB | SHA-256 | Rewrite | 37.291 | 32.462 |
| 256 MiB | BLAKE3 | Rewrite | 219.221 | 15.223 |
| 256 MiB | SHA-256 | Rewrite | 337.850 | 33.188 |
| 256 MiB | BLAKE3 | Truncate/regrow | 211.896 | 8.215 |
| 256 MiB | SHA-256 | Truncate/regrow | 319.517 | 17.813 |

Timing includes preparation, allocation, replacement of the immediately previous
checkpoint, and dropping each returned preparation handle. It excludes initial
preparation, input mutation, final independent verification, and destruction of
the final retained checkpoint. These runs retain no older checkpoint history.
The host was not isolated or CPU-pinned. The benchmark does not establish a
network transfer speedup, storage durability, or peak memory usage.

## Validation and next boundary

Tests compare canonical roots and exact proof bytes against fresh preparation
for both suites, including empty objects, 16 KiB and 64 KiB boundaries, power-of-two
growth, out-of-order edits, partial tails, truncation, regrowth, and old snapshots.
The shared-tree test uses an independent recursive reference map, including
invalid subtree requests. The update validator tests the maximum length without
allocating a correspondingly large payload.

The changed paths reject all 189 viable generated mutants. Twenty other variants
do not compile; no variant survives or times out. A separate deliberate deep-copy
variant preserves hashes but fails the shared-allocation test. Captured diffs and
failures are in [the mutation evidence](../test-vectors/mutants/adr_0057_incremental_checkpoints.md).

ADR-0058 implements authentication of retained immutable owned range bytes.
Disk staging and retained coverage still need the real-provider invalidation
journal and crash/failure injection. This increment adds no capture wire protocol,
mutable receiver, filesystem watcher, completion heuristic, or VOTPort integration.

## Reproduction

```sh
cargo +1.97.1 test --locked -p vot-proof-store -p vot-proof-blake3 -p vot-proof-sha256 -p vot-object
cargo +1.97.1 run --release --locked -p vot-object --example incremental_checkpoints -- 64
cargo +1.97.1 run --release --locked -p vot-object --example incremental_checkpoints -- 4096
```
