# ADR-0049 assemble a server from what the host holds

Criterion: a host serves a package from a manifest directory and objects it
locates itself, with leaves it supplies held to the object they claim to
describe, an object of one group or less read rather than rebuilt, and
every stored object named exactly once.

The following minimal mutants were applied independently and reverted. Each
named test failed.

## Supplied leaves must rebuild the object's root

In `prepared_from_leaves` (`crates/vot-cli/src/serve/object.rs`):

```diff
-    if layer.object_id().root != root {
-        return Ok(None);
-    }
```

`cargo +1.97.1 test -p vot-cli --locked --no-default-features an_assembled_server_refuses_leaves_that_name_another_object`

```text
test serve::tests::an_assembled_server_refuses_leaves_that_name_another_object ... FAILED
thread 'serve::tests::an_assembled_server_refuses_leaves_that_name_another_object' panicked at crates/vot-cli/src/serve/mod.rs:240:9:
assertion failed: matches!(BundleServer::assemble(&bundle, sources), Err(Error::RootMismatch))
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 289 filtered out; finished in 0.08s
```

The assertion is the altered-middle-leaf case: the first and last groups still hold, so only the rebuilt root tells.

## The file's length must match behind leaves

In `prepared_from_leaves`:

```diff
-    if file.metadata()?.len() != length {
-        return Ok(None);
-    }
```

`cargo +1.97.1 test -p vot-cli --locked --no-default-features an_assembled_server_refuses_a_truncated_object_behind_valid_leaves`

```text
test serve::tests::an_assembled_server_refuses_a_truncated_object_behind_valid_leaves ... FAILED
thread 'serve::tests::an_assembled_server_refuses_a_truncated_object_behind_valid_leaves' panicked at crates/vot-cli/src/serve/mod.rs:258:9:
assertion failed: matches!(BundleServer::assemble(&bundle, sources.clone()),
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 289 filtered out; finished in 0.06s
```

The assertion is the appended-bytes case: every sampled group still holds, so only the length tells.

## A source the manifest never names is refused

In `BundleServer::assemble` (`crates/vot-cli/src/serve/server.rs`):

```diff
-        if !sources.is_empty() {
-            return Err(Error::InvalidBundle);
-        }
```

`cargo +1.97.1 test -p vot-cli --locked --no-default-features an_assembled_server_refuses_a_missing_or_unnamed_source`

```text
test serve::tests::an_assembled_server_refuses_a_missing_or_unnamed_source ... FAILED
thread 'serve::tests::an_assembled_server_refuses_a_missing_or_unnamed_source' panicked at crates/vot-cli/src/serve/mod.rs:292:9:
assertion failed: matches!(BundleServer::assemble(&bundle, extra), Err(Error::InvalidBundle))
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 289 filtered out; finished in 0.06s
```

## An object of one group or less is read whatever its leaves

In `ServedObject::build_at` (`crates/vot-cli/src/serve/object.rs`):

```diff
-        if let Some(leaves) = leaves.filter(|_| length > GROUP_SIZE as u64) {
+        if let Some(leaves) = leaves {
```

`cargo +1.97.1 test -p vot-cli --locked --no-default-features an_assembled_server_reads_a_one_group_object_whatever_its_leaves`

```text
test serve::tests::an_assembled_server_reads_a_one_group_object_whatever_its_leaves ... FAILED
thread 'serve::tests::an_assembled_server_reads_a_one_group_object_whatever_its_leaves' panicked at crates/vot-cli/src/serve/mod.rs:211:63:
called `Result::unwrap()` on an `Err` value: RootMismatch
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 289 filtered out; finished in 0.03s
```

The panic is `assemble` refusing with `RootMismatch` where the test expects a server: one leaf cannot rebuild a tree, so without the filter the one-group object is refused.
