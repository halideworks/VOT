# ADR-0048 serve, the host admits

Criterion: a host serves any package it holds on a listener it bound, with
per-session admission that is held to the bundle it names, a Retry-only
listener, and an authorization deadline.

The following minimal mutants were applied independently and reverted. Each
named test failed.

## The granted scope must name the served bundle

```diff
-        && scope.root == served_root
+        && true
```

`cargo +1.97.1 test -p vot-cli --locked --features wire serve_on_admits_by_root_and_reports_each_session`

```text
test wire::tests::serve_on_admits_by_root_and_reports_each_session ... FAILED
thread 'wire::tests::serve_on_admits_by_root_and_reports_each_session' panicked at crates/vot-cli/src/wire/mod.rs:253:13:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 348 filtered out; finished in 0.70s
```

The panic is the `mismatched` case's `matches!(outcome, Err(Error::Session(_)))`: with the root check gone, B's token answered from A is served instead of refused.

## A listener without stateless Retry is refused

In `accept_sessions` (`crates/vot-cli/src/wire/push.rs`), shared by the push and serve seams:

```diff
-    if !listener.stateless_retry_enabled() {
-        return Err(Error::InvalidArguments);
-    }
     std::thread::scope(|scope| {
```

`cargo +1.97.1 test -p vot-cli --locked --features wire serve_on_refuses_a_listener_without_retry`

```text
test wire::tests::serve_on_refuses_a_listener_without_retry ... FAILED
thread 'wire::tests::serve_on_refuses_a_listener_without_retry' panicked at crates/vot-cli/src/wire/mod.rs:280:9:
assertion failed: matches!(serve_on(&listener, |_| panic!("a session was accepted")),
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 348 filtered out; finished in 10.08s
```

## A silent peer is closed at the authorization deadline

```diff
     let admission = loop {
-        if std::time::Instant::now() >= authentication_deadline {
-            let _ = session
-                .driver()
-                .close(vot_codec::error_code::AUTHENTICATION_FAILED);
-            return Err(Error::PeerClosed(
-                vot_codec::error_code::AUTHENTICATION_FAILED,
-            ));
-        }
         if let Some((challenge, open)) = session.pending_authorization() {
```

`cargo +1.97.1 test -p vot-cli --locked --features wire serve_on_closes_a_silent_peer_at_the_deadline`

```text
test wire::tests::serve_on_closes_a_silent_peer_at_the_deadline ... FAILED
thread 'wire::tests::serve_on_closes_a_silent_peer_at_the_deadline' panicked at crates/vot-cli/src/wire/mod.rs:314:14:
the serve did not close the silent peer at the deadline: Timeout
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 348 filtered out; finished in 5.08s
```
