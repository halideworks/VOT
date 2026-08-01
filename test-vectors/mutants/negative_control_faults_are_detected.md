# negative_control_faults_are_detected

The Wave 3 integration test deliberately injects all of these defects:

- silently drop a reliable frame;
- reorder a progressive manifest page;
- replay a journal from a prior incarnation;
- request publication before the Strict predecessor; and
- attempt to convert `TransportAck` into `DurableWitness`.

The first four are rejected at runtime. The ACK conversion is a compile-fail
doctest.

Observed output:

```text
test broken_transport_defects_are_detected ... ok
test crates/vot-transport-sim/src/lib.rs - TransportAck (...) - compile fail ... ok
```

The exact reliable-drop failure is archived in
`sim/failures/drop-reliable.trace`.
