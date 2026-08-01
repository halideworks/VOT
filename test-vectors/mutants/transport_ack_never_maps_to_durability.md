# transport_ack_never_maps_to_durability

`TransportAck` is a private-field delivery witness with no conversion to
`DurableWitness` or any assurance level. Runtime ACK handling changes telemetry
only.

Mutant:

```diff
 pub fn acknowledged(&mut self, _ack: TransportAck) {
     self.ack_count = self.ack_count.saturating_add(1);
+    self.verified.extend(self.active.keys().copied());
 }
```

Observed failure:

```text
test tests::verified_state_survives_disconnect_and_ack_has_no_assurance_effect ... FAILED
assertion failed: !receiver.is_verified(subject)
```

The API also has a compile-fail doctest that attempts to convert a transport ACK
into `vot_journal::DurableWitness`. Compilation fails because no such conversion
exists.
