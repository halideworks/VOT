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
`SESSION_ACCEPT`, and section 1 makes a frame the registry marks `auth: yes`
invalid until the authentication policy succeeds and `SESSION_ACCEPT` is sent.
None of those are implemented, so no session can reach that state.

Refusing every `auth: yes` frame would leave no data plane at all, since
`DATA_RECORD` is one of them. So a session is constructed with an explicit
`Authentication` instead, whose only variant is `Unimplemented`. A caller that
wants to move records has to name the state it is accepting, and cannot reach it
by default. The variant that means authenticated appears when there is an
implementation behind it.

This is the largest gap in the vertical path and it cannot be closed without
implementing the authentication frames.

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

## Which settings are enforced

`spec/registries.md` defines eight settings. Four bound framing and are applied
by `vot-session`, in both directions: a frame is measured against the peer's
limits on the way out and against this endpoint's on the way in.

| Setting | Enforced | Where |
| --- | --- | --- |
| `MAX_CONTROL_FRAME_PAYLOAD` | yes | payload limit table |
| `MAX_DATA_RECORD_PAYLOAD` | yes | payload limit table |
| `MAX_MANIFEST_PAGE_PAYLOAD` | yes | payload limit table, and `PROGRESSIVE_PAGE` |
| `RELIABLE_LANE_LIMIT` | yes | outbound in the session, inbound in the transport |
| `IDLE_TIMEOUT_MS` | no | nothing here keeps time |
| `ACTIVE_KEEPALIVE_MS` | no | nothing here keeps time |
| `COMPRESSION_MIN_GAIN_BPS` | no | nothing compresses yet |
| `TELEMETRY_LEVEL` | no | advisory, read elsewhere |

The four payload limits go through one table, so a frame type the registry adds
later is a row rather than another check. The same check requires exactly one
whole frame and refuses an experimental frame whose extension was not
negotiated.

The lane limit is split by what each layer can see. A session opens lanes, so it
counts its own. Only the transport sees a peer stream open and close, so it
counts those: a session would count lanes ever used and refuse a peer that
closed one and opened another.

The two carriers count differently because their lanes differ. MsQuic opens a
stream per lane, so it counts streams open at once and releases one at shutdown.
TCP carries every lane on one byte stream, where a lane is a logical identifier
with no open or close of its own, so distinct identifiers seen is the whole
count and it only grows. A limit below a codec per-type maximum
takes effect only here, because the codec's limits are fixed.

The first two unenforced settings are timers. A session that agreed an idle
timeout and never applied it will not close an idle carrier, and neither
endpoint sends keepalives.

## Extensions

`HELLO` carries the extensions the client offers, and `spec/registries.md` says
both endpoints must negotiate one before it is used. Only the client sends
`HELLO`, so the server learns the client's set and the client learns nothing
about the server's.

A session is therefore strict about what it sends and uses the intersection only
for what it accepts. No endpoint may send an experimental frame: a server can
compute an intersection and a client cannot, so sending under the server's half
would put a frame on the wire the client is obliged to refuse, closing a session
that had negotiated correctly. `DATAGRAM_CREDIT` and the coding-epoch frames are
refused with `EXPERIMENT_NOT_NEGOTIATED` whatever either side advertised: as a
local refusal on the way out, and as a peer fault on the way in.

That is the safe reading while every experimental feature is disabled by
default and none are implemented. Making one usable needs the specification to
say how a server reports which extensions it accepted.

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

## The carrier and the advertised limits

The two have to come from one place. A QUIC configuration allowing fewer peer
bidirectional streams than the advertised lane count blocks a lane the session
said it would carry, and the session cannot see it: the software bound passes
and the carrier refuses the stream anyway.

`peer_stream_settings` builds the MsQuic settings from the same `ReceiveLimits`
an endpoint advertises. One more stream than the lane count, because negotiation
takes the first client-initiated bidirectional stream and that is not a lane.

## Early data

`spec/wire.md` section 4 makes no v0.3 application frame valid in 0-RTT. The
MsQuic receive path checks the flag before framing anything and closes under
`REPLAY_REJECTED`. Framing it first would hand the session replayable early data
that becomes an ordinary record once negotiation finishes.

## Driving a session

`Session` owns its backend so an application cannot reach past the readiness
gate to the raw adapter. Some backends need more than the adapter contract
covers, though: a `TcpAdapter` moves bytes through `drain_commands` and
`record_native_event`, neither of which the contract has a place for.

`Session::driver` exists for that code. It is the same borrow the gate is meant
to prevent an application taking, so it is named for the role that needs it. An
application sending through it is doing what `send_reliable` exists to refuse.

Known gap: TCP has no assembled transport, so a session over it needs an
external driver. MsQuic does, and its `flush` and `poll` do that work.

## Client and server transports

`vot-transport-msquic` provides both directions:

- `MsQuicTransport::connect` opens a connection and claims stream zero for
  negotiation before any application lane.
- `MsQuicServer::listen` accepts connections and hands out `AcceptedTransport`,
  which adopts the peer's negotiation stream so the receiver can reply on it.

Both delegate to one internal driver, so framing, callback budgeting, close-code
propagation, and teardown order are a single implementation. `Session` wraps
either.
