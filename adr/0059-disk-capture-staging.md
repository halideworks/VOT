# ADR-0059: Bounded disk capture staging

- Status: Accepted for the Unix local-storage prototype.
- Date: 2026-09-12
- Applies to: `vot-sdk-file::capture`.

## Decision

`CaptureFile` owns a private mutable payload and a checksummed journal. It accepts
one authenticated 64 KiB verification group, or the selected object's short final
group, at a time. `select` changes the canonical target and retires its previous
coverage. Cached groups remain available for explicit proof-based `reuse` under
the new root, using ADR-0058's existing commitment verifiers. Changed bytes require
a new `VerifiedSlice`. Both canonical suites keep their identities and proofs.

`CaptureProgress` reports the selected object, durable journal sequence, current
covered bytes, and cached-group count. It is local bookkeeping. It does not
supply a durability observation, at-rest receipt, publication receipt, or a
`VerifiedSlice` that borrows mutable disk storage. `read` returns an immutable RAM
owner only after reading and freshly verifying payload against the selected root.

## Ownership and ordering

The caller supplies an existing owner-only local directory and a stable 16-byte
capture incarnation. The files are `capture.data` and `capture.journal`; both
names must be absent on creation. The data file and parent device/inode identities
are bound into admission. Symlinks, hardlinked payloads, substituted names, and
insecure directories are refused. The payload handle stays private and mutations
require exclusive access to the owner. Payload and journal locks reject a second
writer, including across journal inode replacement during compaction.

All same-user access to the directory must remain serialized by the caller.
Advisory locks cannot stop unrelated code from modifying a file. Payload corruption
detected by `read` invalidates that group's persisted coverage before returning an
error. The owner does not continuously monitor external mutations.

For replacement, the journal first durably invalidates the affected group. The
owner writes the bytes, flushes the payload, then durably records the verified
group commitments. It acknowledges only after both barriers. A failed mutation or
barrier poisons the owner; subsequent operations require dropping and reopening.
Preflight identity, geometry, proof, and cache-budget refusals preserve the owner.

Target selection is durable before resizing the payload. Selection discards
removed and shortened groups before truncation. A previous partial tail can remain
cached after growth, but cannot cover a differently sized target group.

## Recovery and bounded state

Recovery validates admission and journal transitions, then synchronizes replay
and its parent directory before modifying payload or reporting coverage. Complete
records may have survived an unsuccessful durability acknowledgment. The directory
flush makes a previously ambiguous compaction rename durable. Every surviving
cached group is read and rehashed. Mismatches or unexpected end of file cause a
durable invalidation; other I/O errors refuse recovery. The payload is resized to
the selected target and flushed before the reopened owner becomes usable.

The existing journal repairs incomplete final records and rejects bad checksums.
Compaction stores admission, the selected target, generations, cached groups, and
any pending invalidation in one checkpoint. A full journal triggers compaction
and one append retry. No earlier coverage is resurrected after invalidation.

The caller chooses a limit from 1 to 8,192 groups. The maximum fits the journal's
existing 1 MiB record limit and fully tracks 512 MiB. Sparse groups in a larger
logical object are allowed within that budget. The owner refuses new groups at
capacity before changing bytes; explicit `invalidate` releases a cache entry.
Payload disk quotas belong to the caller. This is a deliberate prototype ceiling:
paged metadata is required before supporting larger fully tracked captures.

## Validation and next boundary

Tests exercise both proof suites, changed groups, growth, truncation, malformed
snapshots, wrong incarnations, aliasing, substitution, writer contention, cache
limits, replay synchronization, torn commits, payload corruption, and compaction
with a pending invalidation. Injected failures check invalidation/write/data-sync/
commit ordering and refusal after ambiguous errors. A separate test executable
kills a subprocess during repeated target changes and group writes, then freshly
verifies recovered coverage. These are process and barrier-order checks, not
physical power-loss qualification.

```sh
cargo +1.97.1 test --locked -p vot-sdk-file
```

Mutation results are recorded in
`test-vectors/mutants/adr_0059_disk_capture.md`.

The next storage work is paged metadata and equivalent native Windows ownership
and recovery. Source lifecycle, producer completion, capture wire orchestration,
watch folders, publication, and VOTPort integration remain separate work. This
increment does not qualify mutable capture on NFS or SMB.
