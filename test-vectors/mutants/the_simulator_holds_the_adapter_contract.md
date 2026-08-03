# The simulator holds the adapter contract

Criterion: the simulator answers the `TransportAdapter` contract the way a
backend does, so a session driven over it is held to the limits it advertised and
can end under a registered code.

`set_control_payload_limit` was an inherent method on `SimulatorAdapter` rather
than an implementation of the trait's. An inherent method of the same name
shadows the trait's for a caller holding the concrete type, so the limit was
reachable from the simulator's own tests and unreachable from anything generic:
`Session::apply_peer_limits` is generic over `TransportAdapter`, so it reached the
default, was told `Unsupported`, and applied nothing. The test that covered it
passed the whole time, because it called the method the session cannot reach.

`close` and `receive_limits` were the trait defaults, so a close over this
carrier did nothing at all and no advertised limit was enforced anywhere.

Passing evidence: `a_peer_limit_reaches_the_adapter_through_the_trait` applies
the limit through a generic function, which is what a session does, and then
proves the bound arrived by submitting a frame past it.
`a_closed_carrier_reports_its_code_and_carries_nothing_further` proves the code
is recorded, that the first code wins, and that nothing further is queued on a
carrier that has ended. `what_is_advertised_is_what_delivery_holds_a_peer_to`
proves the limits are absent until a caller sets them, that they round-trip, and
that a lane past the advertised count is refused in delivery while the lanes
already seen stay free. `the_two_control_bounds_move_independently` proves the
send bound and the receive bound are separate: a frame the peer would accept and
this endpoint would not is submitted and then refused at delivery.

Mutants: answer `set_control_payload_limit`, `receive_limits`, or `close` from
the trait default; keep the limit a peer sent as the bound delivery is held to;
record the last close code rather than the first; accept a submission after the
carrier closed; deliver what was queued when it closed; admit a lane past the
advertised count; count a lane already seen against the limit again.

Observed failure:

```text
called `Result::unwrap()` on an `Err` value: Unsupported
assertion `left == right` failed
  left: Some(258)
 right: Some(1282)
assertion `left == right` failed
  left: Ok(())
 right: Err(LaneLimitExceeded)
assertion `left == right` failed
  left: Ok(())
 right: Err(RecordTooLarge)
assertion `left == right` failed
  left: 1
 right: 0
```

What the simulator still does not answer is `path_stats`, which stays `None`
because it models no path, and lifecycle events: it emits neither `Connected` nor
`Disconnected`, because a loopback has no connection identity to name. A session
over it therefore learns the carrier ended from the error it gets rather than
from an event.

Nothing drives a `Session` over the simulator yet, and it cannot: inbound events
are the adapter's own loopback of what was submitted, so there is no way to feed
one the frames a peer would send. The contract holds for whoever wires that up,
and a public way to inject a peer's frames is what it needs first.

The required `vot-transport-sim` mutation run reports 0 missed.
