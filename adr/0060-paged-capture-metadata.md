# ADR-0060: Paged capture metadata

- Status: Accepted for Unix local capture staging.
- Date: 2026-09-12
- Applies to: `vot-sdk-file::capture` and `vot-platform-fs`.
- Replaces the in-memory group map and snapshot ceiling in ADR-0059.

## Decision

Store group metadata in `capture.groups`, alongside the payload and journal.
Each positional 96-byte slot contains the existing 88-byte group encoding, a
CRC32C bound to its position and format domain, and reserved zero bytes. An
all-zero slot means no cached group. The metadata file is sparse and addressed
by verification-group offset. It holds no payload and changes no canonical root
or proof encoding.

One 48 KiB page buffer serves metadata reads. There is no resident group map or
page index. Recovery reads one payload group at a time and streams invalidations.
The existing journal replay still has its independent 64 MiB file bound and
allocates decoded records; 48 KiB is not a bound on the entire process.

`max_groups`, `MAX_CAPTURE_GROUPS`, and `CaptureProgress::cached_groups` use
`u64`. The hard maximum follows the canonical object-length limit. The caller's
chosen cached-group budget and filesystem capacity still apply. There is no
512 MiB complete-coverage ceiling. The new admission format binds the metadata
inode as well as the payload and parent. The prerelease snapshot format changes
from `VOTCAP01` to `VOTCAP02`; old capture directories are refused without a
compatibility reader.

## Journal and metadata ordering

The journal is the redo authority. INVALIDATE is durable before the owner writes
the metadata tombstone and changes payload. Payload is flushed before COMMIT.
COMMIT and REUSE carry complete group records, including generation, so their
metadata writes can be repaired without consulting an earlier slot value.
Acknowledgment follows installation of the journaled metadata change. Ambiguous
errors poison the owner.

Compaction flushes the metadata file before replacing the journal with a
122-byte control snapshot. The snapshot retains binding, budget, target,
generation, and pending invalidation. It does not include group records or
coverage counters. The journal retains all required redo until that flush has
succeeded. Its existing replacement, writer-lock and parent-sync rules remain.

Recovery synchronizes the journal and its parent, validates control transitions,
and replays every retained record in order before reading final group state or
performing compaction. A table can already contain later records. Historical
SELECT may therefore remove newer slots; later full COMMIT/REUSE records restore
them. Restarting interrupted recovery repeats the same complete redo sequence.
Replay never derives count deltas from a table that may be newer than its record.

SELECT truncates removed slots and clears an oversized or malformed partial-tail
slot. A malformed tail can be an interrupted clear; inspecting only its torn
length field would fail to finish the invalidation. SELECT has retired that
coverage, and any newer surviving slot has a later full afterimage. The final
scan validates slot checksums, positions, lengths and generations, rehashes
payload, and recomputes counts before the owner becomes usable.

## Resource and performance boundary

The filesystem's sparse-data hint skips holes when available. Unsupported
queries fall back to linear scanning. Returned positions are rounded down to
include slots split by filesystem extent boundaries. The buffer bound holds in
either case. Recovery time includes reading and hashing all surviving payload;
metadata scans can also traverse allocated empty slots.

Target selection scans retained metadata to recompute cached counts. Page
summaries can reduce that cost if it becomes material. Ordinary replacements and
reuse touch one slot. Metadata uses 96 bytes per 64 KiB verification group before
filesystem allocation overhead, about 0.15% for a fully tracked large object.

Five-run median peak RSS measurements on the same Linux/ZFS host, with one warm
recovery before each set, were:

| Capture and journal state | Previous implementation | Paged metadata |
| --- | ---: | ---: |
| 512 MiB, uncompact journal | 5,296 KiB | 5,120 KiB |
| 512 MiB, compacted journal | 4,320 KiB | 2,240 KiB |
| 2 GiB, uncompact journal | Unsupported | 15,040 KiB |
| 2 GiB, compacted journal | Unsupported | 2,240 KiB |

The same-size measurements do not show increased peak process memory. The
2 GiB uncompact journal uses more replay memory; compaction returns recovery to
the same measured process footprint. These figures include process allocations
and exclude the kernel's reclaimable filesystem cache.

Paging adds I/O. Median 512 MiB recovery increased from 0.18 to 0.31 seconds with
an uncompact journal and from 0.17 to 0.22 seconds after compaction. The 2 GiB
compacted recovery took 0.88 seconds. These are local warm-cache measurements,
not transfer throughput claims. Raw samples are recorded in
`test-vectors/experiments/adr_0060_capture_memory.json`.

## Validation and next boundary

Tests cover more than 16,384 metadata entries with fixed page allocation,
sparse gaps, allocated empty pages, split-slot hints, checksum corruption, inode
substitution, budget refusal, constant-size compaction, metadata flush errors,
complete afterimage repair, repeated replay over newer metadata, and all 97 partial-tail clear
prefixes. The existing payload-write and subprocess-termination tests remain.
A standalone example prepares and recovers a fully authenticated 2 GiB capture
using one payload buffer; it also separates preparation from memory measurement.

```sh
cargo +1.97.1 test --locked -p vot-sdk-file
cargo +1.97.1 test --locked -p vot-platform-fs sparse::
cargo +1.97.1 build --release --locked -p vot-sdk-file --example capture_memory
target/release/examples/capture_memory prepare /tmp/vot-capture-2gib 32768
/usr/bin/time -v target/release/examples/capture_memory recover /tmp/vot-capture-2gib
target/release/examples/capture_memory compact /tmp/vot-capture-2gib
/usr/bin/time -v target/release/examples/capture_memory recover /tmp/vot-capture-2gib
```

Mutation evidence is recorded in `test-vectors/mutants/adr_0060_paged_capture.md`.
Native Windows capture ownership and recovery remain the next platform work.
Source lifecycle, producer completion, capture transport, watch folders,
publication, and VOTPort integration remain separate. No power-loss or NFS/SMB
capture qualification is claimed.
