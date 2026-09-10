
## public callback cancellation 0

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                plan.abandoned |= self.seams.cancellation.is_cancelled();
+                plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (319) panicked at crates/vot-cli/src/fetch/mod.rs:3669:17:
cancelled factory invoked its checkpoint
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.03s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## public callback cancellation 1

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                plan.abandoned |= self.seams.cancellation.is_cancelled();
+                plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (620) panicked at crates/vot-cli/src/fetch/mod.rs:3679:17:
cancelled checkpoint was flushed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.02s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## public callback cancellation 2

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                plan.abandoned |= self.seams.cancellation.is_cancelled();
+                plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (926) panicked at crates/vot-cli/src/fetch/mod.rs:3720:25:
cancelled flush completed its object
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.03s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## public callback cancellation 3

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                plan.abandoned |= self.seams.cancellation.is_cancelled();
+                plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (1237) panicked at crates/vot-cli/src/fetch/mod.rs:3733:17:
assertion `left == right` failed
  left: Complete
 right: Cancelled(1)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.03s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## public callback cancellation 4

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                plan.abandoned |= self.seams.cancellation.is_cancelled();
+                plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (1553) panicked at crates/vot-cli/src/fetch/mod.rs:3733:17:
assertion `left == right` failed
  left: Complete
 right: Cancelled(1)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.05s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## cancelled plan re-enters sealing

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-            if plan.abandoned {
-                return Ok(());
-            }
+            if false {
+                return Ok(());
+            }
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing' (299) panicked at crates/vot-cli/src/fetch/mod.rs:3746:17:
another rail sealed the cancelled plan
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_during_custom_callbacks_prevents_sealing

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 336 filtered out; finished in 0.04s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## public cancellation before sealing

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-
-            plan.abandoned |= self.seams.cancellation.is_cancelled();
+
+            plan.abandoned |= false;
```

```text
running 1 test

thread 'fetch::tests::public_cancellation_before_advance_preserves_an_unsealed_plan' (615) panicked at crates/vot-cli/src/fetch/mod.rs:3767:9:
assertion failed: !fetcher.complete()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::public_cancellation_before_advance_preserves_an_unsealed_plan ... FAILED

failures:

failures:
    fetch::tests::public_cancellation_before_advance_preserves_an_unsealed_plan

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 336 filtered out; finished in 0.02s

error: test failed, to rerun pass `-p vot-cli --lib`
```
