
## custom full prefix flush

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                custom.is_some() || path.exists(),
+                path.exists(),
```

```text
running 1 test

thread 'fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object' (327) panicked at crates/vot-cli/src/fetch/mod.rs:3630:17:
assertion failed: flushed.load(Ordering::Relaxed)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object ... FAILED

failures:

failures:
    fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 334 filtered out; finished in 0.76s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## custom prefix bounds

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-    if prefix > length
+    if false && prefix > length
```

```text
running 1 test

thread 'fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object' (638) panicked at crates/vot-cli/src/fetch/mod.rs:3649:13:
assertion `left == right` failed
  left: true
 right: false
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object ... FAILED

failures:

failures:
    fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 334 filtered out; finished in 0.93s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## custom prefix forwarding

File: `crates/vot-cli/src/fetch/mod.rs`

```diff
-        (**self).resumed_prefix()
+        Ok(0)
```

```text
running 1 test

thread 'fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object' (964) panicked at crates/vot-cli/src/fetch/mod.rs:3625:17:
assertion `left == right` failed
  left: 900001
 right: 834465
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object ... FAILED

failures:

failures:
    fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 334 filtered out; finished in 0.66s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## custom prefix pacing

File: `crates/vot-cli/src/fetch/sink.rs`

```diff
-        Self::opened(sink, placed, None)
+        Self::opened(sink, 0, None)
```

```text
running 1 test

thread 'fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object' (1270) panicked at crates/vot-cli/src/fetch/mod.rs:3607:13:
assertion `left == right` failed
  left: 0
 right: 65536
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object ... FAILED

failures:

failures:
    fetch::tests::custom_sink_prefixes_seed_only_their_own_authenticated_object

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 334 filtered out; finished in 0.56s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## custom prefix abandonment

File: `crates/vot-cli/src/fetch/protocol.rs`

```diff
-                    Ok(resumed) if !plan.abandoned => resumed,
+                    Ok(resumed) => resumed,
```

```text
running 1 test

thread 'fetch::tests::custom_prefix_callback_can_abandon_without_opening_a_sink' (1571) panicked at crates/vot-cli/src/fetch/mod.rs:3699:9:
assertion failed: plan.lock().unwrap().active.is_empty()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::tests::custom_prefix_callback_can_abandon_without_opening_a_sink ... FAILED

failures:

failures:
    fetch::tests::custom_prefix_callback_can_abandon_without_opening_a_sink

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 334 filtered out; finished in 0.31s

error: test failed, to rerun pass `-p vot-cli --lib`
```
