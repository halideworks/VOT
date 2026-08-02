# Peer streams have distinct lanes

Criterion: every peer-initiated stream is reported under a lane of its own,
outside the range either side can name on the wire, so interleaving between
independent streams is never mistaken for reordering within one.

This matters most on an accepting endpoint, where the peer opens the
negotiation stream and every application lane, so a shared identifier would
leave nothing to tell one lane from another.

Passing evidence: `every_peer_stream_gets_a_lane_of_its_own` allocates four
lanes and proves they are distinct, consecutive from `PEER_LANE_BASE`, and all
reserved. `a_spent_lane_range_refuses_rather_than_wraps` proves the allocator
refuses at the end of the range and keeps refusing, rather than wrapping onto a
live stream. `reserved_lanes_cannot_collide_with_an_application_stream` pins
`PEER_LANE_BASE` to one past the largest QUIC varint, so no lane either side can
encode reaches it. `a_reserved_lane_is_refused_at_submission` proves an
application cannot send on the control lane, the first peer lane, the last peer
lane, or `u64::MAX`, while the largest nameable lane is still ordinary.

Over a real carrier,
`an_accepted_connection_drives_the_same_transport_as_the_client` has a client
open two application lanes and the negotiation stream, and proves the accepted
connection reports the two records under two distinct reserved lanes and the
control frame separately.

Mutants: return one shared identifier from `classify_peer_stream`; classify the
peer's stream zero as a reliable lane rather than as the negotiation stream;
allocate with an unchecked `fetch_add` so the range wraps; set `PEER_LANE_BASE`
one below the varint ceiling so an application lane can collide; make
`is_reserved_lane` an equality test against a single value.

Observed failure:

```text
assertion `left != right` failed: two peer streams must not share one lane identity
  left: 4611686018427387904
 right: 4611686018427387904
assertion `left == right` failed
  left: Some(4611686018427387904)
 right: None
assertion failed: !is_reserved_lane(vot_codec::MAX_QUIC_VARINT)
the negotiation stream carried the frame
```

The required `vot-transport-msquic` mutation run reports 72 total, 68 caught, 4
unviable, and 0 missed. cargo-mutants generates no mutants inside the
`#[cfg(feature = "live")]` module, so the live paths are covered by the
msquic-live and msquic-sanitizer jobs instead.
