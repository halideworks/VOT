# Negotiation gates the data plane

Criterion: an endpoint does not carry application data until the `spec/wire.md`
section 1 exchange has finished, and a peer whose records arrive during that
exchange is not punished for the protocol's own shape.

Passing evidence: `the_exchange_follows_the_order_the_specification_gives_it`
drives a client and a server through `HELLO`, `SETTINGS`, `SETTINGS`,
`SETTINGS_ACK` and checks each frame type and each state transition in order.
`the_data_plane_is_refused_until_the_exchange_finishes` proves every send path
is refused before `Ready` and that nothing reached the backend.
`records_that_arrive_early_are_held_rather_than_refused` interleaves a record
between the two negotiation frames, which is the worst ordering a carrier can
produce, and proves the record neither surfaces early nor blocks the frame
behind it. `held_records_are_bounded` and `the_held_byte_bound_is_exact` prove
the holding buffer is bounded by count and by bytes, that the bound itself is
allowed, and that one byte past it fails with `RESOURCE_LIMIT`.
`only_the_peers_faults_reach_the_carrier` proves a peer fault closes the carrier
under its registered code and that a local misuse, a backend refusal, and an
already-gone carrier do not.
`a_backend_that_would_accept_more_than_is_advertised_is_refused` proves an
endpoint will not advertise a control-frame limit its backend would exceed.

Over a real carrier,
`two_endpoints_negotiate_over_the_real_carrier_before_any_data_moves` runs the
same exchange between the assembled client and the assembled server,
`records_sent_before_readiness_are_held_over_the_real_carrier` reproduces the
in-flight record against MsQuic, and `a_registered_close_code_reaches_the_peer`
proves the peer reads `UNSUPPORTED_VERSION` back off the wire.

Mutants: accept `SETTINGS` before `HELLO`; accept a second `HELLO`; let the
client become ready without `SETTINGS_ACK`; return `Ok` from `require_ready`;
drop a held record instead of releasing it; compare the pending byte total with
`>=` instead of `>`; delete the `Event::Reliable` arm from `hold` so held bytes
are not counted; treat `NotReady` as a peer fault; skip the receive-limit check
in `begin`.

Observed failure:

```text
assertion `left == right` failed
  left: Ready
 right: HelloSent
called `Result::unwrap()` on an `Err` value: Error { kind: OutOfSequence { frame_type: 3, state: ControlReserved }, close: 258 }
assertion failed: early.adapter().closed.is_empty()
assertion `left == right` failed: a record in flight was lost
  left: []
 right: [[49, 9, 105, 110, 32, 102, 108, 105, 103, 104, 116]]
assertion `left == right` failed
  left: PendingRecordsExhausted { bytes: 1024, count: 1 }
 right: PendingRecordsExhausted { bytes: 2048, count: 2 }
```

The required `vot-session` mutation run reports 107 total, 78 caught, 29
unviable, and 0 missed. The required `vot-transport-api` run reports 50 total,
49 caught, 1 unviable, and 0 missed.
