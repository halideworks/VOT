# Quiche datagrams backpressure without loss

When quiche and the bounded driver outbox are full, the driver retains the
next datagram and stops consuming later submissions. If the driver exits, it
reports every retained datagram in submission order.

Mutant:

```diff
-return Err(Command::Datagram { context, bytes });
+return Ok(None);
```

Observed failure:

```text
test live::tests::a_full_datagram_outbox_backpressures_without_loss ... FAILED
the refused submission was not held
```

Ordering mutant:

```diff
-abandon_datagrams(datagrams, inbound);
 match pending.take() {
     ...
 }
+abandon_datagrams(datagrams, inbound);
```

Observed failure:

```text
test live::tests::a_driver_that_stops_ends_every_datagram_it_still_holds ... FAILED
left: [4, 1, 2, 3]
right: [1, 2, 3, 4]
```

State-overflow mutant:

```diff
 if let Err(observed) = queue.push(observed) {
-    *pending_state = Some(observed);
     return;
 }
```

Observed failure:

```text
test live::tests::a_full_event_queue_holds_a_datagram_state_before_sending_more ... FAILED
assertion failed: matches!(&pending_state, Some(NativeEvent::DatagramSent { context: 1 }))
```

Saturated-cleanup mutant:

```diff
-queue.push_unlosable(NativeEvent::DatagramDropped { context });
+let _ = queue.push(NativeEvent::DatagramDropped { context });
```

Observed failure:

```text
test live::tests::a_driver_that_stops_preserves_states_past_the_normal_event_bound ... FAILED
left: [0, 2049]
right: [0, 1, ..., 2049]
```

Common-error-cleanup mutant:

```diff
-abandon_all_datagrams(pending_state, pending, datagrams, inbound);
+let _ = (pending_state, pending, datagrams, inbound);
```

Observed failure:

```text
test live::tests::a_driver_that_stops_preserves_states_past_the_normal_event_bound ... FAILED
left: []
right: [0, 1, ..., 2049]
```
