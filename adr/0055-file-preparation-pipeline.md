# ADR-0055: File preparation pipeline

- Status: Accepted
- Date: 2026-09-11
- Applies to: `vot-cli` manifest preparation and native hosts preparing file proof leaves.

## Context

Manifest preparation reads and hashes each source before admitting a transfer.
The reader waits for each chunk's hashes before reading the next chunk. On an
8-vCPU Linux VM, preparing a fully written 32 GiB file took 53.4 to 54.4 seconds
in two matched baseline runs. A separate plain read took 45.0 seconds. Storage
and hashing both contribute to the delay; parallel hashing alone cannot remove
the storage cost.

## Decision

`file_proof_leaves` reads an already open regular file sequentially from byte
zero. It rejects invalid object lengths and an initial length mismatch before
reading. Reads must consume the declared length and encounter EOF immediately
afterward. Read failures and short or extra bytes fail preparation.

For files of at least 64 MiB, one reader supplies 1 MiB chunks to at most eight
hash workers, capped by available parallelism. Each worker owns at most one
chunk. Bounded standard-library channels return the input buffer and proof
leaves. The reader consumes completions in submission order, reuses buffers,
and joins all workers before returning, including after a read failure.
Sources below the threshold stay on the calling thread. Manifest preparation
keeps its existing streaming builder for these small files.

Workers use the existing suite-specific `proof_leaves_at` implementation.
`PreparedObject::from_proof_leaves` reconstructs the canonical identity from
freshly computed leaves. Cached or externally supplied leaves still require
comparison against an independently known root. The source must remain
immutable while being prepared and served; this does not create a filesystem
snapshot. Existing range-time source mutation checks still apply.

Native hosts may use the same helper for initial delivery preparation. The
helper neither stages payloads nor changes receiver verification, publication,
receipts, wire identifiers, or conformance vectors.

## Consequences

- Memory: at most eight 1 MiB input buffers plus existing retained proof leaves
  and trees. Leaves cost 32 bytes per 64 KiB group for either suite. The reader
  retains one ordered leaf vector; completed worker results hold at most one
  chunk's leaves each.
- CPU: the same suite hashes plus channel coordination. Up to eight hash
  workers overlap with the sequential reader; one-core hosts stay inline.
- Storage: one complete source read, no payload writes and no extra read pass.
  Sequential reads preserve locality on HDD and NAS sources.
- Wire: no amplification or format change.
- The first two matched pipeline runs prepared the same 32 GiB source in 49.1
  and 37.4 seconds. Their manifests were byte-identical to the baseline. The
  VM timings varied, so these are preparation measurements, not a fixed
  end-to-end throughput guarantee. Warm 1,000-file EXR preparation remained
  approximately 0.14 to 0.16 seconds.

## Required verification

- Both suites produce the streaming builder's exact leaves, object identity,
  and range proofs across partial final chunks and repeated worker turns.
- Short, extra, and failed reads return errors and release workers within the
  bounded test deadline.
- Regular-file admission checks declared lengths and starts at byte zero.
- Small sources stay inline and worker counts remain capped at eight.
- Manual mutants and their rejected output are recorded in
  `test-vectors/mutants/adr_0055_file_preparation.md`.
