# ADR-0064 ongoing host access

Each deliberate mutant below was applied independently, tested, and reverted.

## Skipping the service guard

```diff
-if self.access.as_ref().is_some_and(|access| !access()) {
+if false {
```

`cargo +1.97.1 test -p vot-cli --locked --features wire revoked_access_stops_before_the_next_service_pass`

```text
test drive::tests::revoked_access_stops_before_the_next_service_pass ... FAILED
thread 'drive::tests::revoked_access_stops_before_the_next_service_pass' (3936943) panicked at crates/vot-cli/src/drive.rs:1025:13:
assertion failed: matches!(Engine::service(&mut serving), Err(Error::Cancelled))
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 427 filtered out; finished in 0.06s
```

## Dropping the admission guard

```diff
-serving.set_access_guard(access);
+serving.set_access_guard(None);
    drop(access);
```

`cargo +1.97.1 test -p vot-cli --locked --features wire serve_on_admits_by_root_and_reports_each_session`

```text
test wire::tests::serve_on_admits_by_root_and_reports_each_session ... FAILED
thread 'wire::tests::serve_on_admits_by_root_and_reports_each_session' (3937874) panicked at crates/vot-cli/src/wire/mod.rs:285:9:
assertion failed: fetch_holding(at, &cancelled, built_a.root,
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 427 filtered out; finished in 0.42s
```
