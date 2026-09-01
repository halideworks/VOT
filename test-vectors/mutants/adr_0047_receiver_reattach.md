# ADR-0047 receiver re-attach

Criterion: resume refuses a journal claimed under another incarnation
before any write, and from_runs refuses overlapping run lists before any
allocation proportional to the input.

The following minimal mutants were applied independently and reverted. Each
named test failed.

## The journal must refuse a stale incarnation

```diff
-            return Err(Error::StaleIncarnation);
+            // mutant: refusal skipped
```

`cargo +1.97.1 test -p vot-sdk-file --locked resume_refuses_before_any_write`

```text
thread 'tests::resume_refuses_before_any_write' panicked at crates/vot-sdk-file/src/lib.rs:1483:43:
called `Option::unwrap()` on a `None` value
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 23 filtered out
```

## from_runs must refuse overlapping runs

```diff
-            if previous_end.is_some_and(|previous| offset <= previous) {
+            if false {
```

`cargo +1.97.1 test -p vot-coverage --locked runs_round_trip`

```text
thread 'tests::runs_round_trip_and_from_runs_validates_before_building' panicked at crates/vot-coverage/src/lib.rs:565:9:
assertion failed: matches!(Coverage::from_runs(64, [(20, 10), (0, 10)]),
    Err(Error::PartialOverlap))
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 13 filtered out
```
