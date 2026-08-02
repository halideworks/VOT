# ADR-0021: Negotiation gates the data plane, and peer streams get lanes of their own

Status: Accepted

## Context

The MsQuic backend could open streams, frame bytes, and deliver records before
any of this was written. What it could not do was negotiate. `spec/wire.md`
section 1 puts negotiation on the first client-initiated bidirectional stream:
the client sends `HELLO` then `SETTINGS`, and the server answers with its own
`SETTINGS` then `SETTINGS_ACK`. The transport reserved that stream and never
spoke on it, and `vot-codec` had decoders for both payloads and no encoders, so
no endpoint could have sent either frame.

Two smaller facts turned out to be part of the same problem.

Every peer-initiated stream was reported under one shared identifier. On a
connecting endpoint that is an edge case. On an accepting one it is the whole
receive path: the client opens the negotiation stream and every application
lane, so all of them arrived indistinguishable. Interleaving between two lanes
would have looked like reordering within one.

And there was no accepting endpoint. The live tests hand-rolled a listener with
its own receive logic, so the only server-side stack that existed was the one
nothing else used.

## Decision

### The exchange lives in `vot-session`, above the transport

`Negotiation` is the `spec/wire.md` section 1 sequence as a state machine, with
no carrier and no buffers. `Session<A: TransportAdapter>` owns a backend and
runs that machine over it. Backends keep their ability to open streams and move
bytes on their own, which is what makes them testable in isolation; the session
is what stops a deployment doing it before there is anything to send under.

`HELLO` is sent by the client only. `spec/wire.md` section 5 lists it as "once
per VOT session" while `SETTINGS` is "once per direction", and section 1 says a
role inconsistent with the stream initiator is `MALFORMED_FRAME`. On a
client-initiated stream that leaves exactly one sender. A server therefore never
sends `HELLO` and never advertises `EndpointRole::Server`.

`Ready` means negotiated, not authenticated. `AUTH_CONTEXT`, `SESSION_OPEN`, and
`SESSION_ACCEPT` are unimplemented, so every frame the registry marks
`auth: yes` is not yet conforming.

### The gate is asymmetric

Application sends are refused before local readiness. Application records that
arrive before local readiness are held, not refused.

The two endpoints reach `Ready` at different moments, and QUIC orders nothing
between the negotiation stream and an application lane, so a conforming peer can
have records in flight before it learns this side is ready. Closing the session
over them would punish it for the protocol's own shape.

Those records are held in the session rather than left in the adapter. An
adapter queue is one ordered stream of events, so leaving a record in it would
block the control frames behind it, and those are what readiness is waiting for.
The buffer is bounded by bytes and by count, and exceeding it fails the session
with `RESOURCE_LIMIT`.

### Negotiation applies what it learns

On readiness the peer's advertised `MAX_CONTROL_FRAME_PAYLOAD` is pushed to the
backend through `TransportAdapter::set_control_payload_limit`. Without that the
exchange would be a state enum: the peer's maximum is the bound on what this
endpoint may send, and ignoring it means sending frames the peer is entitled to
close the session over. A backend with no such bound returns `Unsupported` and
the session reports the limit as not applied.

### A failure closes the carrier only when the peer caused it

Session failures carry a registered close code, and a peer-caused one is applied
to the carrier before the error is returned, so the peer learns which rule it
broke. A local caller misusing the API, a backend refusing a submission, and a
carrier that has already gone are not: closing over the first would tear down a
healthy connection, over the second would turn backpressure into a teardown, and
the third has nothing left to close. `ErrorKind::is_peer_fault` is where that
split lives, and it is the question one registered code cannot answer on its own.

### An endpoint is held to the bound it advertises

The control-frame bound an endpoint reassembles under has to be in force before
the peer's first byte, so it is taken at construction by
`MsQuicTransport::connect` and `MsQuicServer::listen` rather than set once a
session exists. `Session::begin` refuses to advertise a limit the backend will
not keep. Advertising one bound and accepting up to another is silent: the peer
sends what it was told it could, and this endpoint takes more.

### Peer streams are numbered above everything either side can name

A peer-initiated stream is given a lane from `PEER_LANE_BASE`, which is `2^62`,
one past the largest QUIC varint. No lane an application or a peer can name on
the wire reaches it, so the two ranges cannot meet. Exhausting the range refuses
the stream rather than wrapping, because a wrapped lane would alias a live
stream and splice two peers' records together.

The negotiation stream is recognised by its QUIC identifier being zero rather
than by arrival order, which nothing guarantees. On an accepting endpoint that
stream is peer-created and its handle is kept, because every frame a receiver
sends back goes out on it. It is the only peer stream whose handle is kept;
application lanes are receive-only there, so leaving them to their callbacks is
both correct and what keeps stream state from growing with the number of lanes
the peer has ever opened.

### One driver shell, two endpoints

`Carrier` holds the adapter, callback state, stream pool, and connection, and
both `MsQuicTransport` and `AcceptedTransport` delegate to it. The only
difference between them is where the negotiation stream comes from, expressed as
a two-variant `Control` enum. Framing, callback budgeting, close-code
propagation, and teardown order are one implementation rather than two.

## Consequences

A negotiated session over a real MsQuic carrier is now a test rather than a
plan, and the accepting side of it runs the same code a deployment would.

A session holds up to `DEFAULT_PENDING_RECORD_BYTES` of peer data before it has
agreed to anything. That is deliberate and bounded, but it is memory spent on an
unnegotiated peer and belongs in any whole-path accounting.

Adding `set_control_payload_limit` to `TransportAdapter` with a default of
`Unsupported` means every existing backend reports honestly without changing.
The simulator and TCP backends do not apply negotiated limits today.
