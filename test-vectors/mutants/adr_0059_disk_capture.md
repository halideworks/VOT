# ADR-0059 disk capture mutation evidence

The changed `vot-sdk-file` capture paths were tested with Rust 1.97.1 and cargo-mutants 26.0.0. Of 149 generated mutants, 133 were caught by test failure and 16 did not compile. None survived or timed out.

The sweep covers group authentication, geometry, snapshot decoding, replay transitions, owner checks, write ordering, recovery synchronization, and compaction. Selected replacements and observed failures follow.

| Replacement | Failing checks |
| --- | --- |
| `CaptureFile::sync_recovery_journal` returns `Ok(())` | `capture::tests::recovery_parent_sync_failure_cannot_admit_coverage`, `capture::tests::torn_commit_and_complete_unsynced_invalidation_recover_conservatively` |
| `claim` returns `Ok(())` | `capture::tests::payload_lock_remains_held_across_journal_replacement` |
| `complete_read` returns `Ok(true)` | `capture::tests::only_short_reads_invalidate_missing_payload` |
| `Group::validate` returns `Ok(())` | `capture::tests::cached_group_shapes_and_small_proofs_are_strict` |
| `State::apply` returns `Ok(())` | `capture::tests::cached_group_shapes_and_small_proofs_are_strict`, `capture::tests::snapshots_preserve_pending_operations_and_reject_malformed_records` |

The initial sweep exposed missing refusal tests for malformed group metadata, small-object proof material, admission length boundaries, non-EOF read errors, and the payload lock independently of the journal lock. These checks were added; read-error classification was extracted into a pure function so all error classes are exercised without relying on a host I/O failure.

The subprocess test runs in a separate executable. Spawning it from the parallel unit suite briefly inherited unrelated open-file locks and caused intermittent reopen refusals. Isolation removed that fixture interference while retaining real process termination during mutation. Precise invalidation, partial-write, data-sync, and commit boundaries remain covered by injected failures on actual local files.

## Reproduction

```sh
git diff 45983af -- crates/vot-sdk-file > changed.diff
cargo +1.97.1 mutants --package vot-sdk-file --in-diff changed.diff \
  --jobs 4 --timeout 30 -C=--offline -C=--locked
```
