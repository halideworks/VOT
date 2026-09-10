The first five callback mutations were captured before the shared advance guard
was added. The final implementation checks factory, prefix and flush callbacks
in place and uses one completion transition to publish cancellation before the
object becomes done. This prevents a rail with a different cancellation handle
from sealing between the callback owner's advance iterations. The completion
mutations verify that transition. The final section covers the shared predicate
for resumed completion and flushing.

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

## completion omits cancelled rail

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-plan.abandoned |= cancelled || completed.is_err();
+plan.abandoned |= completed.is_err();
```

```text
running 1 test

thread 'fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance' (2248391) panicked at crates/vot-cli/src/fetch/mod.rs:3794:17:
assertion `left == right` failed
  left: false
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance ... FAILED

failures:

failures:
    fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 337 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## completion ignores failed callback

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-plan.abandoned |= cancelled || completed.is_err();
+plan.abandoned |= cancelled;
```

```text
running 1 test

thread 'fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance' (2248763) panicked at crates/vot-cli/src/fetch/mod.rs:3794:17:
assertion `left == right` failed
  left: false
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance ... FAILED

failures:

failures:
    fetch::tests::completion_publishes_cancellation_before_another_rail_can_advance

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 337 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## Shared completion predicate after the CI survivor

The original inline `custom.is_some() || path.exists()` mutation to `&&` passed the complete vot-cli test suite. It selected the asynchronous completion path with the same outcome. The code now computes one completion predicate for synchronous completion and custom flushing; its truth table covers every boolean combination.

### requires empty and resumed

```diff
-length == 0 || fully_resumed && stored
+length == 0 && fully_resumed && stored
```

```text
running 1 test

thread 'fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole' (2385635) panicked at crates/vot-cli/src/fetch/mod.rs:4354:13:
assertion `left == right` failed
  left: false
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole ... FAILED

failures:

failures:
    fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 410 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-cli --lib`
```

### accepts resumed or stored

```diff
-length == 0 || fully_resumed && stored
+length == 0 || fully_resumed || stored
```

```text
running 1 test

thread 'fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole' (2385935) panicked at crates/vot-cli/src/fetch/mod.rs:4354:13:
assertion `left == right` failed
  left: true
 right: false
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole ... FAILED

failures:

failures:
    fetch::tests::only_whole_nonempty_objects_reserve_and_resume_whole

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 410 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## Shared storage presence after the second CI survivor

The inline storage-presence check used only for completion survived replacement of `||` with `&&` in the complete vot-cli suite. Partial and complete resume now use one `stored` value. The existing custom-prefix test rejects that mutation because the 65536-byte prefix must not be requested again.

```diff
-let stored = custom.is_some() || path.exists();
+let stored = custom.is_some() && path.exists();
```

```text
running 1 test

thread 'fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object' (299) panicked at crates/vot-cli/src/fetch/mod.rs:3625:17:
assertion `left == right` failed
  left: 900001
 right: 834465
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object ... FAILED

failures:

failures:
    fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 410 filtered out; finished in 0.13s

error: test failed, to rerun pass `-p vot-cli --lib`
```
