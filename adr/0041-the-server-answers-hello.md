# ADR-0041: the server answers HELLO

Status: Accepted

## Context

`spec/wire.md` section 1 has the client send `HELLO` with its extension list
and the server send only `SETTINGS` and `SETTINGS_ACK`. The server therefore
knows the negotiated intersection and the client never does. `vot-session`
records this in `Negotiation::usable_extensions`, which is empty by design,
and refuses every experimental frame outbound on both ends.

Datagram FEC (ADR-0040) cannot start under that rule. Datagram mode begins
with zero credit, so the receiver, which is the fetch client, must send
`DATAGRAM_CREDIT` first, and it may only do so knowing `DATAGRAM_FEC` was
negotiated; a server that did not offer the extension closes the session on
receiving the frame. Inferring negotiation from an inbound experimental frame
is circular, since the server sends none before credit arrives.

## Decision

**The server answers the client's `HELLO` with its own `HELLO`, carrying the
extensions it accepts from the client's list. Extension negotiation is then
known at both ends, and either end may send an experimental frame once its
extension is in the intersection.**

- The server's `HELLO` has `endpoint_role` 1 and lists exactly the
  intersection of the client's extensions and the server's own. It is the
  first frame of the server's reply, before its `SETTINGS`, on the control
  stream. The client requires it before the server's `SETTINGS`.
- The client's negotiated set is its own list intersected with the answer,
  which equals the answer. `usable_extensions` is that set on both ends and
  `Session::extension_negotiated(id)` exposes membership to callers.
- Outbound frame policy checks the same negotiated set inbound policy does.
  An experimental frame sent before negotiation, or under an extension not
  negotiated, is still refused locally without closing the carrier.
- The answer carries the intersection rather than the server's full list so
  the server discloses nothing the client did not ask about, the same shape
  as `SESSION_ACCEPT` carrying the scope actually granted.
- `HELLO` is once per direction; a second from the same end remains an
  error. No draft revision bump: nothing outside this repository implements
  vot-draft-05, and the change is amended in place as ADR-0035 did.

## Consequences

- Both ends can act on negotiation before any experimental traffic flows;
  FEC credit and epochs can be sent by the end the spec assigns them to.
- One more 4 KiB-bounded control frame per session, already representable by
  the codec and its vectors (`server-role-is-representable`).
- A client on the previous sequence would refuse the unexpected server
  `HELLO`; there is no such client.
