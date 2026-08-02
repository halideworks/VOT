# Sessions and negotiation

A VOT session is the exchange `spec/wire.md` section 1 defines, plus the gate it
puts in front of everything else. `vot-session` holds both.

## The exchange

Negotiation runs on the first client-initiated bidirectional stream, which is
QUIC stream zero.

| Step | Client | Server |
| --- | --- | --- |
| 1 | sends `HELLO` | |
| 2 | sends `SETTINGS` | |
| 3 | | reads `HELLO` |
| 4 | | reads `SETTINGS`, sends its own, sends `SETTINGS_ACK` |
| 5 | reads `SETTINGS`, reads `SETTINGS_ACK` | |

Only the client sends `HELLO`. The registry lists it as once per session while
`SETTINGS` is once per direction, and a role inconsistent with the stream
initiator is `MALFORMED_FRAME`; on a client-initiated stream that leaves one
sender. A server never advertises `EndpointRole::Server`.

The states are `Connecting`, `ControlReserved`, `HelloSent`,
`SettingsExchanged`, `Ready`, `Closed`. They are named from the client's side.
On a server, `HelloSent` means the peer's `HELLO` arrived.

## What `Ready` does not mean

`Ready` means version and limits are agreed. It does not mean authenticated.

`spec/wire.md` also defines `AUTH_CONTEXT`, `SESSION_OPEN`, and
`SESSION_ACCEPT`, and marks most application frames as requiring an
authenticated session. None of those are implemented, so every frame the
registry marks `auth: yes` is not yet conforming.

## The gate is asymmetric

Sending application data before local readiness is refused. Receiving it before
local readiness is not.

The two endpoints reach readiness at different moments, and QUIC orders nothing
between the negotiation stream and an application lane. A conforming peer can
have records in flight before it learns this side is ready, so closing the
session over them would punish it for the protocol's own shape. Those records
are held and released in order once readiness is reached.

They are held in the session, not left in the transport. A transport's event
queue is one ordered stream, so an undrained record would block the control
frames behind it, and those are what readiness is waiting for.

The buffer is bounded by bytes and by count. Exceeding it fails the session with
`RESOURCE_LIMIT`. `Session::set_pending_limits` changes the bounds and refuses
one too small to hold a single maximum record.

## Close codes, and who is at fault

Every session failure carries the registered code from `spec/registries.md` on
`Error::close_code`. Whether it reaches the wire depends on who caused the
failure, which `ErrorKind::is_peer_fault` answers.

A fault the peer caused closes the carrier under that code before the error is
returned. A peer that sends a `HELLO` from another draft is closed under
`UNSUPPORTED_VERSION` and can see it.

| Cause | On the wire |
| --- | --- |
| Bad `HELLO`, bad `SETTINGS`, undecodable frame | yes |
| Frame out of sequence, application frame before readiness | yes |
| Pre-readiness buffer exhausted | yes |
| Application used the data plane too early | no |
| Backend refused a submission | no |
| Carrier already gone | no |

The last three are local. Closing over an API misuse would tear down a healthy
connection, closing over a full queue would turn backpressure into a teardown,
and a carrier that has already gone has nothing left to close. One registered
code covers both a peer that sent a frame out of sequence and a caller that
asked for something too early; only the first is the peer's doing.

## Negotiation applies what it learns

On readiness the peer's advertised `MAX_CONTROL_FRAME_PAYLOAD` becomes the bound
this endpoint sends control frames under, through
`TransportAdapter::set_control_payload_limit`. A backend that enforces no such
bound returns `Unsupported`, and `Session::control_limit_applied` reports false
rather than implying the limit took effect.

The reverse direction is configuration rather than negotiation. An endpoint's
own reassembly bound has to be in force before the peer's first byte, so
`MsQuicTransport::connect` and `MsQuicServer::listen` take it, and
`Session::begin` refuses to advertise a limit the backend will not keep.
Advertising one bound and accepting frames up to another is silent otherwise:
the peer sends what it was told it could, and this endpoint takes more.

## Lane identity

Records carry a `StreamId`. Two rules keep those identifiers meaningful.

Lanes an application opens are numbered by the application. Lanes a peer opens
are numbered by the transport, from `PEER_LANE_BASE`, which is one past the
largest value a QUIC varint can hold. Neither side can name a lane that reaches
into the other range.

Every peer-initiated stream gets its own lane. Reporting several under one
identifier would make interleaving between independent streams look like
reordering within one, and on an accepting endpoint every application lane is
peer-initiated, so there would be nothing left to tell them apart by.

## Client and server transports

`vot-transport-msquic` provides both directions:

- `MsQuicTransport::connect` opens a connection and claims stream zero for
  negotiation before any application lane.
- `MsQuicServer::listen` accepts connections and hands out `AcceptedTransport`,
  which adopts the peer's negotiation stream so the receiver can reply on it.

Both delegate to one internal driver, so framing, callback budgeting, close-code
propagation, and teardown order are a single implementation. `Session` wraps
either.
