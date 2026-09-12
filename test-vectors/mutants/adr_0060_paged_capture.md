# ADR-0060 paged capture mutation evidence

The changed `vot-sdk-file` and `vot-platform-fs` paths were tested with Rust 1.97.1 and cargo-mutants 26.0.0. Of 160 generated mutants, 146 were caught by test failure and 14 did not compile. None survived or timed out. No mutation exclusions were added.

The sweep covers full journal afterimages, metadata replay, coverage counters, snapshot binding and limits, slot checksums and geometry, sparse-query handling, page alignment, scan bounds, and partial-tail clearing. The existing payload-write, lock, and recovery-barrier checks remain active.

The initial sweep exposed missing checks for native sparse-query results and a partial slot at a nonzero offset. The platform crate now tests a real written extent independently of its consumers. The partial-slot test requires refusal even when page padding would otherwise complete reserved zero bytes. Page alignment and scan bounds moved to pure helpers so tests exercise the guards independently of filesystem EOF behavior. Truncation uses the minimum of current and selected lengths.

The large metadata fixture seeds encoded pages in bulk. It verifies more than 16,384 entries and sparse gaps with a fixed 48 KiB page allocation without making thousands of individual setup writes in every mutation run. The separate public example exercises durable per-group acceptance and recovery of a fully authenticated 2 GiB payload; its memory measurements are recorded in ADR-0060.

## Reproduction

```sh
git diff 84a2402 -- crates/vot-sdk-file crates/vot-platform-fs > changed.diff
cargo +1.97.1 mutants --package vot-sdk-file --package vot-platform-fs \
  --in-diff changed.diff --jobs 4 --timeout 45 -C=--offline -C=--locked
```
