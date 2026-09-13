# ADR-0063: Growing-file source lifecycle

- Status: Accepted for native source capture.
- Date: 2026-09-12
- Applies to: `vot-sdk-file::capture::CaptureSource`.

## Decision

Compose `ObjectCheckpoint` and `CaptureFile` in one handle-oriented source
adapter. The host owns filesystem watching and producer coordination. The
adapter owns an independently opened regular-file handle, private disk
staging, one current proof checkpoint, and a reusable 65,537-byte source
buffer.

`refresh(changed)` accepts one dirty byte range and observes the source length.
It expands the hint to complete verification groups and includes growth or a
shortened tail automatically. A host can coalesce nearby edits into one range;
`0..0` handles append-only observations. A full-length hint reconciles all bytes.
The caller's cached-group budget is checked before preparation or staging writes.

Preparation builds the next canonical root from bounded source reads and
shared proof subtrees. Small-to-large promotion resupplies the first group
with one byte of the next group; that byte is reread by the bounded group
iteration. No append-sized allocation is needed. Installation selects one
target for the batch. A matching cached group needs no payload I/O; changed
groups are read again, authenticated against the prepared root, and admitted
through the existing durable capture write sequence. Source changes between
those reads cause refusal rather than unverified writes.

A draft root identifies the captured bytes. It does not assert that the producer
file ever contained that exact combination at one instant. Unreported overwrites,
including truncate-and-regrow between observations, remain absent until the host
refreshes those ranges. Hints and file metadata are not coherence evidence.

## Ownership and recovery

No source path is followed after opening. The host compares the retained source
identity with its watched entry and supplies a new handle through `replace` when
appropriate. Replacement clears the draft explicitly. Sources cannot alias the
capture's own payload, metadata, or journal. Windows source handles must be
independently opened, not cloned from a producer handle with a shared cursor.

An installation failure withdraws the in-memory checkpoint. The next refresh
reconciles the entire source, so a new dirty hint cannot discard interrupted work.
Ambiguous staging write or flush errors retain `CaptureFile`'s poisoned-owner
rule: drop and reopen before continuing. A failed staged read also withdraws the
checkpoint and forces reconciliation.

Open first performs existing capture recovery, then reconstructs proof
metadata from staged bytes using the same bounded buffer. This is a second
staging read pass after capture recovery readback. It requires the
reconstructed root and every cached group's proof to match before exposing a
checkpoint. Counting cached groups alone is insufficient: an interrupted
growth can leave an old short tail beside newly zero-extended bytes that
already hash to the new root. Incomplete staging stays unavailable until a
full refresh repairs it.

## Explicit completion

`finish` is the host's explicit assertion that the producer is stopped and the
source will remain stable through the call. It independently streams the entire
source through `StreamVerifier` and compares length and root with the draft.
Missed header rewrites or other changes refuse completion. A second length check
catches observed growth during verification, but does not replace the host's
quiescence obligation. Neither quiet time nor two matching stats establishes
producer completion or an atomic source snapshot.

After verification, the adapter authenticates all cached groups against the
final root and compacts the existing capture journal. Success freezes normal
refreshes. Replacement or a failed staged read withdraws completion. Completion
is not persisted: reopening
requires a new host completion decision and another verification. It establishes
neither publication nor an at-rest verification receipt. Returned proof metadata
does not preserve old payload revisions; reads authenticate current staged bytes.

## Costs and scope

Dirty refreshes avoid reading the entire source payload. Target selection
still scans capture metadata, and final coverage reuse durably records each
group. These existing costs make batching preferable to selecting a root for
every renderer write. Proof metadata remains proportional to group count and
is bounded by the caller's group limit; retaining old checkpoints can retain
old proof nodes. The 65,537-byte source buffer is additional to capture's 48
KiB metadata page and the journal's separate 64 MiB replay-file bound plus
decoded records. A staged read adds `CaptureFile::read`'s one-group read
buffer and owned returned range. These are component bounds, not a total
process memory cap.

No wire or on-disk format changes, new external dependency, watcher, publication
adapter, filename projection, mounted filesystem, or VOTPort integration is added.
Live checkpoint transfer is the next integration boundary. Destination filename
preflight remains required before cross-platform materialization (ADR-0062).

## Validation

Tests cover both suites, empty and small objects, group boundaries, disjoint
header changes with growth, partial and aligned truncation, path replacement,
resource refusal, no-op refreshes, source mutation between reads, interrupted
installation, poisoned ownership, corrupted staging, and zero-extended stale
tails on recovery. Completion catches missed rewrites and observed final growth.
The shared suite runs natively on Linux, macOS, and Windows.

`capture_source` compares eight single-byte header edits using full dirty hints
and incremental hints on identical disk-backed fixtures. Each run performs final
full-source verification. Timing and peak RSS are recorded separately; these
measurements do not establish network throughput or power-loss qualification.

Three alternating runs per mode on Linux/ext4, Intel Core i5-13500, Rust 1.97.1
release, with no concurrent VOT validation processes:

| 128 MiB source, eight header edits | Full dirty hints | Incremental hints |
| --- | ---: | ---: |
| Median aggregate refresh time | 412.648 ms | 20.496 ms |
| Median initial capture time | 814.241 ms | 793.277 ms |
| Median finish time | 190.815 ms | 198.309 ms |
| Median peak process RSS | 2,560 KiB | 2,560 KiB |

The exact I/O test requires zero payload bytes for an unchanged observation,
131,072 for a changed full header group (preparation and installation), and
zero for aligned truncation of a larger object. A full hint reads the object
plus changed groups needing installation. Earlier runs on shared ZFS showed
unstable flush latency, so no reliable timing improvement is concluded there.
The committed [measurement data](../test-vectors/experiments/adr_0063_source_capture.json)
records all ext4 runs. The host was not isolated or CPU-pinned.

```sh
cargo +1.97.1 test --locked -p vot-sdk-file capture::source
cargo +1.97.1 build --release --locked -p vot-sdk-file --example capture_source
/usr/bin/time -v target/release/examples/capture_source /tmp/vot-source-full 2048 full
/usr/bin/time -v target/release/examples/capture_source /tmp/vot-source-incremental 2048 incremental
```
