# Incremental checkpoint evidence (ADR-0057)

The changed production paths were checked with cargo-mutants 26.0.0 and Rust 1.97.1. The sweep tested 209 mutants: 189 caught, 20 unviable, zero missed, and zero timeouts. The unmutated baseline passed. Unviable variants failed compilation and are not counted as rejected by tests.

```sh
git diff 8cd02d7 > /tmp/vot-checkpoint.diff
cargo +1.97.1 mutants --package vot-proof-store --package vot-proof-blake3 --package vot-proof-sha256 --package vot-object --in-diff /tmp/vot-checkpoint.diff --jobs 4 --timeout 30 -C=--offline -C=--locked
```

Representative viable mutants and their captured test failures follow. Each excerpt comes from a successful build followed by `cargo test` for the named package.

## Length bounds

`crates/vot-object/src/checkpoint.rs`, `validate_update`.

```diff
-    if length > MAX_OBJECT_LENGTH {
+    if length >= MAX_OBJECT_LENGTH {
```

```text
test checkpoint::tests::update_boundaries_reject_missing_bytes_before_changing_the_checkpoint ... FAILED
test result: FAILED. 23 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.43s
```

## Update validation

`crates/vot-object/src/checkpoint.rs`, `validate_update`.

```diff
-    if length > MAX_OBJECT_LENGTH {
-        return Err(Error::ExpectedLengthOutOfRange);
-    }
-    let end = offset.checked_add(bytes).ok_or(Error::LengthOverflow)?;
-    if !offset.is_multiple_of(PROOF_LEAF_SIZE)
-        || end > length
-        || (!bytes.is_multiple_of(PROOF_LEAF_SIZE) && end != length)
-    {
-        return Err(Error::InvalidRange);
-    }
-    if length > previous && (offset > previous / PROOF_LEAF_SIZE * PROOF_LEAF_SIZE || end != length)
-    {
-        return Err(Error::InvalidRange);
-    }
-    if length < previous && !length.is_multiple_of(PROOF_LEAF_SIZE) && end != length {
-        return Err(Error::InvalidRange);
-    }
-    if length > PROOF_LEAF_SIZE && previous <= PROOF_LEAF_SIZE && offset != 0 {
-        return Err(Error::InvalidRange);
-    }
-    if length <= PROOF_LEAF_SIZE && !(length == previous && bytes == 0) && bytes != length {
-        return Err(Error::InvalidRange);
-    }
-    Ok(())
+    Ok(())
```

```text
test checkpoint::tests::update_boundaries_reject_missing_bytes_before_changing_the_checkpoint ... FAILED
test result: FAILED. 23 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.76s
```

## Changed content cannot take the no-op path

`crates/vot-object/src/checkpoint.rs`, `ObjectCheckpoint::updated`.

```diff
-        if bytes.is_empty() && length == self.object.length {
+        if bytes.is_empty() || length == self.object.length {
```

```text
test checkpoint::tests::checkpoints_preserve_canonical_roots_proofs_and_prior_snapshots ... FAILED
test result: FAILED. 23 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
```

## Append geometry

`crates/vot-proof-store/src/tree.rs`, `Node::append`.

```diff
-        let take = (left_width - (node.count - left_width)).min(leaves.len());
+        let take = (left_width + (node.count - left_width)).min(leaves.len());
```

```text
test tree::tests::edits_match_rebuilding_and_leave_earlier_snapshots_unchanged ... FAILED
test result: FAILED. 7 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

## Exact retained subtree lookup

`crates/vot-proof-store/src/tree.rs`, `Node::subtree`.

```diff
-            right.subtree(start - left.count, count)
+            right.subtree(start + left.count, count)
```

```text
test tree::tests::edits_match_rebuilding_and_leave_earlier_snapshots_unchanged ... FAILED
test result: FAILED. 7 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## BLAKE3 range traversal

`crates/vot-proof-blake3/src/checkpoint.rs`, `encode`.

```diff
-        encode(right, start + left.leaf_count() as u64, first, end, output);
+        encode(right, start - left.leaf_count() as u64, first, end, output);
```

```text
test checkpoint::tests::snapshots_match_fresh_proofs_and_reject_invalid_shapes ... FAILED
test result: FAILED. 26 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

## SHA-256 padding levels

`crates/vot-proof-sha256/src/checkpoint.rs`, `padded`.

```diff
-        hash = parent(&hash, &zero(1 << level));
+        hash = parent(&hash, &zero(1 >> level));
```

```text
test checkpoint::tests::snapshots_match_fresh_proofs_and_reject_invalid_shapes ... FAILED
test result: FAILED. 29 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.56s
```

## Full metadata copying is rejected

In `ProofTree::updated`, replace its borrowed previous root with a recursively copied tree. Hash values and proof results remain identical, but unchanged branches no longer share their allocations.

```diff
-            let previous = self.root.as_ref()?;
+            fn copy(node: &Arc<Node>) -> Arc<Node> {
+                Arc::new(Node {
+                    hash: node.hash,
+                    count: node.count,
+                    children: node.children.as_ref().map(|(left, right)| (copy(left), copy(right))),
+                })
+            }
+            let copied = copy(self.root.as_ref()?);
+            let previous = &copied;
```

```sh
cargo +1.97.1 test --locked --offline -p vot-proof-store tree::tests::a_small_edit_shares_unchanged_subtrees_and_bounds_merges -- --exact
```

```text
test tree::tests::a_small_edit_shares_unchanged_subtrees_and_bounds_merges ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s
```
