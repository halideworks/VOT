# ADR-0056: Capture foundation experiments

- Status: Accepted for experiments; capture APIs and wire changes remain undecided.
- Date: 2026-09-12
- Applies to: `vot-object` and `vot-resume-core` examples.

## Context

Transferring a file while its producer is still working requires reconciliation
of append, overwrite, and truncation operations. An immutable object identity
cannot identify the mutable capture itself. Before introducing a composition
format or extending the receiver, test the existing proof representation and the
persistence ordering required when staging bytes are replaced in place.

## Representation experiment

`capture_checkpoints` compares full preparation, retained canonical proof leaves,
and a flat description of independently identified 64 KiB byte objects. All three
consume the same owned input and mutations. Dirty groups are recomputed after
writes, including partial trailing groups after growth or truncation. The
canonical candidate keeps `(suite, root, length)` unchanged. The composition
candidate hashes a domain-tagged description containing the suite, logical length,
and ordered `(offset, length, child root)` entries. Its object identity names the
description, not the file bytes. This experimental encoding has no wire identifier.

The example retains the entire input in memory. Cached leaves are valid here
because every input mutation passes through the draft. This does not authorize
using cached leaves to identify an uncontrolled filesystem source. It provides
neither a source snapshot nor evidence of producer completion.

Tests compare checkpoints with fresh hashing for both suites across empty and
single-group objects, tree boundaries, same-length edits, batched out-of-order
edits, truncation to aligned and partial groups, and regrowth. A separate test
verifies retained receiver bytes against the new root and its new proofs. It
copies only the changed group, rejects stale proof material, and checks the final
bytes and hash independently. That test rereads retained bytes; it does not yet
implement authenticated persistent coverage reuse without readback.

The runnable benchmark uses 1,024 checkpoints per workload:

- Append 4 KiB at a time until the draft reaches 4 MiB.
- Replace byte zero of a 4 MiB draft at each checkpoint.
- Alternate truncating the last group to 17 bytes and regrowing it.

`payload_bytes` counts bytes passed to payload preparation. `metadata_bytes`
counts canonical leaf bytes supplied to a full tree rebuild or encoded
composition bytes supplied to description preparation. These are algorithm input
counts, not disk I/O, actual wire bytes, peak memory, or total internal hash work.
Elapsed time covers checkpoint preparation, including its allocations, but
excludes input mutation and destruction of the returned checkpoint.

Both incremental candidates still rebuild all checkpoint metadata. A one-byte
edit recomputes one payload group but processes metadata proportional to the
whole file. Tests pin this cost instead of hiding it behind a throughput claim.
The flat composition does not remove this limit; a paged or incrementally updated
representation would require another comparison.

Measured aggregate input counts, identical for both suites:

| Workload | Full payload bytes | Reused-leaf or composition payload bytes | Canonical metadata input bytes | Composition metadata input bytes |
| --- | ---: | ---: | ---: | ---: |
| Append | 2,149,580,800 | 35,651,584 | 1,064,960 | 1,639,424 |
| Rewrite | 4,294,967,296 | 67,108,864 | 2,097,152 | 3,187,712 |
| Truncate/regrow | 4,261,421,568 | 33,563,136 | 2,097,152 | 3,187,712 |

Median total preparation milliseconds across three sequential release runs on
an Intel Core i5-13500, Linux 6.8.0, Rust 1.97.1:

| Suite | Workload | Full | Retained leaves | Composition |
| --- | --- | ---: | ---: | ---: |
| BLAKE3 | Append | 1,391.723 | 12.552 | 25.215 |
| BLAKE3 | Rewrite | 1,264.528 | 22.474 | 38.035 |
| BLAKE3 | Truncate/regrow | 1,316.496 | 12.028 | 22.652 |
| SHA-256 | Append | 1,342.684 | 26.220 | 70.438 |
| SHA-256 | Rewrite | 2,499.022 | 43.859 | 116.315 |
| SHA-256 | Truncate/regrow | 2,429.048 | 25.616 | 63.321 |

The host was not isolated or pinned to a CPU. Timings include scheduler and host
load variation and do not establish a transfer speedup. The exact input counts
are the stronger evidence for avoiding repeated payload preparation.

## Overwrite recovery experiment

`capture_overwrite` enumerates persistence outcomes for replacing two units while
retaining a third. It reuses `UnitRanges` and `ResumeState::prepare_checkpoint`.
The sequence is:

1. Record invalidation of affected coverage under the next operation sequence.
2. Persist that journal record before touching the affected bytes.
3. Write the replacement units.
4. Persist the data.
5. Record complete coverage for the replacement.
6. Persist that checkpoint before acknowledging it.

At every boundary, unsynced data bytes can independently retain their old or new
value, and a pending journal record can be absent or complete. The model checks
88 enumerated outcomes across nine boundaries; some outcomes have identical
durable state. Every claimed unit must match its recorded content. An
acknowledged replacement must be recoverable. Removing either journal barrier
or the data barrier produces a counterexample.

After durable invalidation, the old checkpoint is superseded even if replacement
data is lost. Recovery explicitly requests those units again and preserves the
unaffected unit. A completed checkpoint can resolve a lost acknowledgment without
repeating the operation. This is private draft recovery, not retained revision
history or rollback to every previously acknowledged checkpoint.

The model assumes a single writer and journal records that are atomic or rejected.
It does not implement a journal encoder, native persistence adapter, asynchronous
write draining, writer takeover, or publication. It does not qualify NFS, SMB,
object stores, power-loss behavior, or corruption handling. A native prototype
must establish these assumptions through the existing journal and provider
contracts before this sequence becomes an application-facing guarantee.

## Consequences and next implementation boundary

Continue the canonical-root candidate first. The experiments show no need to
change file identity for append, replacement, truncation, or verified range reuse.
They do not establish acceptable performance for large production captures.

The next implementation must bound checkpoint metadata work, bind retained
coverage to exact content and its owned storage lifetime, and execute the
invalidation sequence through a real provider with crash and failure injection.
Keep capture recovery evidence separate from immutable object assurance. A new
capture must not turn an existing object's monotonic assurance state backward.

No production crate API, object identity, manifest schema, assurance transition,
dependency, or wire identifier changes in this increment. Ordinary immutable
receiving retains its existing storage path. The examples add test and measurement
code only; their tests run in the normal workspace suite.

## Reproduction

```sh
cargo +1.97.1 test --locked -p vot-object -p vot-resume-core
cargo +1.97.1 run --release --locked -p vot-object --example capture_checkpoints
cargo +1.97.1 run --release --locked -p vot-resume-core --example capture_overwrite
```

Deliberate mutants and rejected output are recorded in
`test-vectors/mutants/adr_0056_capture_foundations.md`.
