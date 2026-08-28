# ADR-0045 push

Criterion: a holder can publish an exactly authorized package to a receiving
server, with reversed transfer directions, receiver integration seams,
cursor-bounded cancellation, stateless Retry, and the registered GOAWAY wire
shape.

The following minimal mutants were applied independently and reverted. Each
named test failed.

## Direction reversal

```diff
- let publisher = if push { EndpointRole::Client } else { EndpointRole::Server };
+ let publisher = EndpointRole::Server;
```

`cargo +1.97.1 test -p vot-session --locked push_reverses_exactly_the_publish_and_request_frames`

```text
assertion `left == right` failed: outbound 0x21, push true, sender Client
  left: false
 right: true
```

## Exact authorization

```diff
- && scope.length.is_some()
+ && true
```

`cargo +1.97.1 test -p vot-cli --lib --no-default-features --locked a_push_token_is_publish_only_exact_and_accepted`

```text
assertion failed: requirement.decide(&challenge, &open, binding, NOW).is_none()
```

```diff
- || scope.root != descriptor.package.root
+ || false
```

`cargo +1.97.1 test -p vot-cli --lib --no-default-features --locked a_push_descriptor_must_match_the_granted_scope_before_any_object`

```text
called `Result::unwrap_err()` on an `Ok` value: ()
```

## Receive seams and cancellation

```diff
- && hook(self.receive_session, summary, &entries).is_err()
+ && false
```

`cargo +1.97.1 test -p vot-cli --lib --no-default-features --locked a_manifest_seam_refusal_precedes_every_range_request`

```text
assertion `left == right` failed
  left: Complete
 right: Closed(1281)
```

```diff
- cursor: cursor as u64,
+ cursor: 0,
```

`cargo +1.97.1 test -p vot-cli --lib --no-default-features --locked cancellation_discards_the_partial_and_bounds_queued_answers`

```text
assertion `left == right` failed
  left: Some(0)
 right: Some(1)
```

## Stateless Retry

```diff
- if token.is_empty() {
+ if false {
```

`cargo +1.97.1 test -p vot-transport-quiche --features live --locked a_retrying_listener_allocates_nothing_for_an_unanswered_initial`

```text
a retry: Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }
```

```diff
- if first < MIN_DATAGRAM_SIZE {
+ if false {
```

`cargo +1.97.1 test -p vot-transport-quiche --features live --locked a_retrying_listener_drops_an_undersized_initial_without_answering`

```text
a short Initial was amplified
```

## GOAWAY encoding

```diff
- encode_varint(value.cursor, output)?;
+ encode_varint(value.cursor + 1, output)?;
```

`cargo +1.97.1 test -p vot-codec --locked goaway_has_one_varint_payload`

```text
assertion `left == right` failed
  left: [64, 131, 1, 8]
 right: [64, 131, 1, 7]
```

The live conformance test `a_push_crosses_a_retrying_live_listener` completes
the same package at one and four rails through a Retry-enabled listener, then
mutates the exact certificate pin and proves the holder disconnects before
`SESSION_OPEN`. Removing the `verify_serve_identity` call makes that assertion
fail. `push_requires_an_exact_identity_before_it_can_dial` kills accepting a
missing CLI pin, and the public push API requires the pin as a non-optional
`[u8; 32]` argument.
