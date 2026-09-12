# ADR-0056 capture foundation mutants

Each mutant below was applied separately, its named test failed, and the
original source was restored. These are mutations of the experiments, not
claims of native storage crash qualification.

## Writes invalidate every affected group

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-self.dirty.extend(offset / GROUP..end.div_ceil(GROUP));
+self.dirty.extend(offset / GROUP..end / GROUP);
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::checkpoints_match_fresh_hashing_across_mutations -- --exact
```

```text
test tests::checkpoints_match_fresh_hashing_across_mutations ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
```

## Truncation invalidates the partial final group

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-self.dirty.insert(length / GROUP);
+self.dirty.remove(&(length / GROUP));
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::checkpoints_match_fresh_hashing_across_mutations -- --exact
```

```text
test tests::checkpoints_match_fresh_hashing_across_mutations ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
```

## Canonical leaves bind their global position

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-offset as u64,
-                            bytes,
+0,
+                            bytes,
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::checkpoints_match_fresh_hashing_across_mutations -- --exact
```

```text
test tests::checkpoints_match_fresh_hashing_across_mutations ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
```

## Composition binds logical offsets

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-encoded.extend_from_slice(&(offset as u64).to_le_bytes());
+encoded.extend_from_slice(&0_u64.to_le_bytes());
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::checkpoints_match_fresh_hashing_across_mutations -- --exact
```

```text
test tests::checkpoints_match_fresh_hashing_across_mutations ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.02s
```

## A new root must verify reused ranges

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-verify_proof(object.object_id(), offset, bytes, cover.proof())
+true
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::changed_root_can_reuse_unchanged_bytes_with_new_proofs -- --exact
```

```text
test tests::changed_root_can_reuse_unchanged_bytes_with_new_proofs ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

## Metadata rebuilding remains accounted

File: `crates/vot-object/examples/capture_checkpoints.rs`.

```diff
-work.metadata_bytes = self.leaves.len() as u64 * 32;
+work.metadata_bytes = 0;
```

```sh
cargo +1.97.1 test --locked --offline -p vot-object --example capture_checkpoints tests::small_rewrites_still_rebuild_metadata_for_the_whole_object -- --exact
```

```text
test tests::small_rewrites_still_rebuild_metadata_for_the_whole_object ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.02s
```

## Invalidation is durable before replacement

File: `crates/vot-resume-core/examples/capture_overwrite.rs`.

```diff
-Step::Invalidate,
-    Step::SyncJournal,
+Step::Invalidate,
+    Step::WriteFirst,
```

```sh
cargo +1.97.1 test --locked --offline -p vot-resume-core --example capture_overwrite tests::every_crash_boundary_preserves_truthful_coverage -- --exact
```

```text
test tests::every_crash_boundary_preserves_truthful_coverage ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```

## Data is durable before the replacement checkpoint

File: `crates/vot-resume-core/examples/capture_overwrite.rs`.

```diff
-Step::SyncData => self.durable = self.visible,
+Step::SyncData => {},
```

```sh
cargo +1.97.1 test --locked --offline -p vot-resume-core --example capture_overwrite tests::every_crash_boundary_preserves_truthful_coverage -- --exact
```

```text
test tests::every_crash_boundary_preserves_truthful_coverage ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```

## Acknowledgment follows checkpoint persistence

File: `crates/vot-resume-core/examples/capture_overwrite.rs`.

```diff
-Step::Checkpoint,
-    Step::SyncJournal,
+Step::Checkpoint,
+    Step::WriteSecond,
```

```sh
cargo +1.97.1 test --locked --offline -p vot-resume-core --example capture_overwrite tests::every_crash_boundary_preserves_truthful_coverage -- --exact
```

```text
test tests::every_crash_boundary_preserves_truthful_coverage ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```

## Invalidation retains unaffected coverage

File: `crates/vot-resume-core/examples/capture_overwrite.rs`.

```diff
-coverage: self.record.coverage.difference(&replaced),
+coverage: UnitRanges::new(),
```

```sh
cargo +1.97.1 test --locked --offline -p vot-resume-core --example capture_overwrite tests::invalidation_supersedes_the_old_checkpoint_before_replacement -- --exact
```

```text
test tests::invalidation_supersedes_the_old_checkpoint_before_replacement ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```

## A completed operation resolves a lost acknowledgment

File: `crates/vot-resume-core/examples/capture_overwrite.rs`.

```diff
-self.record.sequence == 1 && self.record.coverage == all_units()
+false
```

```sh
cargo +1.97.1 test --locked --offline -p vot-resume-core --example capture_overwrite tests::lost_acknowledgment_can_query_the_completed_operation -- --exact
```

```text
test tests::lost_acknowledgment_can_query_the_completed_operation ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```
