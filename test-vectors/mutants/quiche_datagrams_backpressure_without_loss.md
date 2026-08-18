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
