# ADR-0022: Capability authentication behind a policy boundary, bound by proof of possession

Status: Accepted

## Context

`Ready` means negotiated, not authenticated. `spec/wire.md` section 1 makes a
frame the registry marks `auth: yes` invalid until the authentication policy
succeeds and `SESSION_ACCEPT` is sent, and none of `AUTH_CONTEXT`,
`SESSION_OPEN`, `SESSION_ACCEPT`, or `SESSION_REJECT` is implemented. A session
therefore carries every one of those frames unauthenticated, which is why
`Session` is constructed with an explicit `Authentication::Unimplemented`.

The specification already fixes more than the frame identifiers.
`spec/security.md` section 5 requires TLS 1.3 with server authentication, and
defines what a capability contains: issuer, audience, holder constraint,
operation set, object scope with suite, root and exact length, allowed byte
ranges, tenant and concurrency limits, not-before, expiry, unique identifier,
delegation constraints, key identifier, and format version. Capabilities are
verified before protected operations, unknown mandatory claims fail closed, and
authorization is rechecked when scope expands or a carrier switches.

What the specification does not fix is the payload of any of the four frames.
There is no CDDL, no vector, and no typed schema, so nothing can interoperate on
them today.

Two constraints decide the binding.

`spec/security.md` section 5 prefers a capability bound to a TLS exporter, a
peer key, or a proof-of-possession key. The MsQuic wrapper exposes no RFC 5705
exporter. It exposes `QUIC_PARAM_CONN_TLS_SECRETS`, which is the
SSLKEYLOGFILE debugging facility, and deriving binding material from traffic
secrets would be an abuse of it.

`spec/wire.md` section 7 requires a switch from QUIC to TCP to preserve object,
verified-range, durable, and receipt state. A capability bound to a TLS exporter
is invalidated by that switch by construction. One bound to a holder key is not,
and needs nothing from the carrier.

## Decision

Authentication arrives in two stages.

### Stage one: the exchange, with the capability opaque

Define the payloads of `AUTH_CONTEXT`, `SESSION_OPEN`, `SESSION_ACCEPT`, and
`SESSION_REJECT`. `AUTH_CONTEXT` carries a server nonce and the channel binding
this deployment uses. `SESSION_OPEN` carries the requested scope, a session
identifier, and the capability as an opaque versioned blob. The server answers
`SESSION_ACCEPT` or `SESSION_REJECT`.

`Session` gains an authenticated state, and every frame the registry marks
`auth: yes` is refused until it is reached. `Authentication` gains the variant
that means authenticated, so `Unimplemented` stops being the only one.

The capability is verified through a `CapabilityPolicy` boundary rather than by
the session. A deployment that authenticates some other way implements the
boundary; the session owns the exchange and the state machine.

### Stage two: one concrete capability format

Ed25519 over canonical CBOR, reusing the signing, key identifier, and canonical
encoding machinery `vot-receipt` already has, with proof of possession: the
capability names a holder public key and the client signs the `AUTH_CONTEXT`
nonce with it.

## Consequences

Defining these payloads breaks no conforming peer, because none can exist. It
needs no ALPN change. It does need a wire-change manifest entry, conformance
vectors, and the versioning treatment any wire-visible addition gets.

Stage one closes the gate without committing the project to a capability format
before anything exercises one. The cost is that stage one alone authenticates
nothing on its own: it moves the decision to a policy boundary and refuses to
proceed without one.

Proof of possession is the only binding available on both carriers. It survives
the carrier switch the specification requires, and it needs nothing the MsQuic
wrapper does not expose. A deployment wanting certificate binding can implement
it in the policy boundary.

Two specification questions remain open and are recorded here rather than
answered.

`SESSION_OPEN` is marked `auth: yes` in the frame behaviour registry while being
the frame that opens a session. Either the column means the authentication
policy has succeeded and the session frames are the mechanism, or the table is
wrong. Stage one assumes the first reading.

Nothing says who issues capabilities. Section 5 names issuer and audience but no
trust anchor distribution. Stage two cannot ship without an answer.
