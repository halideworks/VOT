# ADR-0037: the capability proof binds to the channel that carries it

Status: Accepted

## Context

ADR-0036 gave the serve capability authorization. A token names its issuer,
holder, audience, and root, and the holder proves possession by signing the
serve's per-session nonce. That proof authorizes the holder and says nothing
about the channel: the signature travels over an unauthenticated transport,
because the serve's certificates are ephemeral and self-signed by design and
the fetch verifies nothing about them.

Content never needed channel identity. Every range proves to the root and
the pin decides, which is the trust story ADR-0030 carries for the whole
unauthenticated channel. What that story does not cover is the session an
interposer sits inside. It cannot steal the token, because the nonce is
drawn per session. It cannot forge a byte, because the proofs decide. But an
on-path attacker that terminates the transport on both sides occupies the
authorized session itself: it sees what an authorized fetch asks for, it
withholds at range granularity, and it stands exactly where the deployment
configured a token to say only the holder stands.

ADR-0034 made this concrete. A relay is an interposer by construction, and
the consequences priced it as a withholding point that cannot forge. That
price is right for content and wrong for authorization: a relay, or anyone
on the path of any rung, can answer the fetch's handshake with its own
certificate, open its own session to the serve, and forward the possession
proof between the two. Both ends see a valid exchange. The deployment that
set `VOT_SERVE_ISSUER` believed it was buying more than that.

Two fixes were on the table. Pinning a serve identity key out of band would
authenticate the serve the way the root pins the content, but it builds an
identity lifecycle this design has deliberately avoided: stable serve keys
where certificates are ephemeral today, a second pin distributed to every
fetch, rotation nobody owns, and at the end of it the capability layer is
still not bound to the channel, only guarded by a mechanism beside it.
Binding the proof to the channel needs no identity at all, and ADR-0036
already named its missing piece: a keying-material exporter that quiche does
not expose. The exporter is standard TLS (RFC 8446 section 7.5, the
`tls-exporter` channel binding of RFC 9266), BoringSSL implements it, and
the project already carries a pinned quiche fork with an upstreamed patch,
so the mechanics and the upstream relationship both exist.

## Decision

**The possession proof signs the channel: the authentication context grows
the TLS exporter output of the session presenting the token, so a proof made
on one session verifies on no other.**

- **Both ends compute, nothing travels.** Each end exports keying material
  from its own TLS session under a VOT-specific label, and the holder signs
  it alongside the nonce. An interposer terminating the transport holds two
  sessions whose exporter outputs disagree, so the forwarded proof fails
  against the serve's own material, under the binding-mismatch error the
  session protocol already names. The wire carries the same proof bytes it
  carries today: zero added bytes, zero added round trips.
- **The fork exposes the exporter.** One passthrough from quiche to
  BoringSSL's keying-material export, carried on the pinned fork and opened
  upstream, the same shape as the ack-latency fix before it.
- **A carrier answers or says it cannot.** The transport adapter grows one
  question: the exporter output for this session, or a plain answer that
  this carrier cannot bind. The session takes the material as a value, the
  way every reader here takes its values, so the binding logic is held by
  tests that never open a socket.
- **Required means required.** A serve configured to require capabilities
  refuses to start on a carrier that cannot bind, at startup and by name,
  the same all-or-nothing posture the requirement configuration already
  takes. MsQuic remains the cross-check for unauthenticated transfers until
  it exposes an exporter; nothing is duplicated to let it limp alongside.
- **No negotiation down.** A presentation without the binding, offered to a
  serve that requires one, is refused. A protocol that could be talked down
  to the unbound proof would hand the interposer back everything this
  buys.

## Consequences

- An interposer is back to what ADR-0030 priced: it can stall or drop, and
  it can no longer sit inside an authorized session. Through a relay the
  transport stays end to end across the slot, and the binding is what proves
  it stayed.
- Serves stay anonymous. No identity keys, no distribution, no rotation;
  deployments that pin nothing but the root keep exactly the properties
  they have today.
- Capability deployments narrow to carriers with exporters, which today
  means the default engine. That is a named limitation surfaced at startup,
  not a silent downgrade on the wire.
- The pinned fork grows one patch, with the upstream PR opened alongside so
  the fork stays a lead rather than a divergence.
- The authentication context changes shape for bound presentations, which
  is a wire-visible revision: the registries section that ADR-0033 deferred
  and ADR-0034 renewed is owed once more, and it should be written once for
  the rendezvous, the relay, and the authentication context together.

## Sequence

1. The fork patch: keying-material export on the connection, upstream PR
   opened.
2. `vot-session`: the authentication context carries binding material, the
   possession proof signs it, and the featureless suite holds the mismatch,
   downgrade, and absent-binding cases by injected values.
3. The carriers and the CLI: the quiche adapter answers the exporter, the
   MsQuic adapter answers that it cannot, a capability-requiring serve
   refuses a carrier without binding at startup, and the loopback wire
   tests present bound tokens end to end.
4. `spec/registries.md`: the deferred section, written once for the
   rendezvous datagrams, the relay datagrams, and the authentication
   context.
