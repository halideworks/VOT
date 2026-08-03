# ADR-0023: Capabilities are anchored by a verifier-configured issuer set

Status: Accepted

## Context

ADR-0022 closed with one question open: nothing says who issues capabilities.
`spec/security.md` section 5 requires a capability to name an issuer and an
audience, and says nothing about how a verifier comes to trust an issuer. Stage
two cannot ship without an answer, because a format that defines how to check a
signature and not whose signature to accept is not checkable.

The same question has been answered twice in this repository already. ADR-0018
made a witness "a key pair and a clock, with no protocol role beyond signing what
it saw", explicitly so the design stays "open to a counterparty, a customer, an
auditor, or a third-party operator, rather than requiring one blessed service".
`verify_chain` "deliberately does not verify signatures, so a caller chooses the
key policy rather than inheriting one". ADR-0022 then put the capability decision
at the caller's boundary for the same reason: a policy needs a deployment's own
identity store and clock, and a session has neither.

Three constraints rule out most of the alternatives before any preference does.

An issuer key fetched while authenticating puts an unauthenticated peer in charge
of when the verifier originates a request. `spec/security.md` section 7 denies it
that lever on the VOT connection, limiting pre-authentication traffic to bounded
handshake, settings, challenge, and error data; a key fetch moves the same lever
to another service, and makes authentication fail whenever that service is
unreachable while failing open is not allowed. That rules out an identity
provider whose keys are read at authentication time, and a transparency log
consulted for the same purpose.

ADR-0022 decoupled the capability from the carrier so that the QUIC to TCP switch
`spec/wire.md` section 7 requires preserves verified state. Issuer certificates
chained to the carrier's own PKI would recouple them.

Nothing in `spec/wire.md` section 1.1 or `spec/registries.md` constrains the
issuer claim: the capability bytes are opaque at the wire layer and only the
format identifier is registered. So this decision is above the encoding, and
stage two cites it rather than arguing it.

## Decision

The trust anchor is a set of issuer entries configured at the verifier. No
certificate authority, no fetch, and no blessed issuer.

Each entry is three things together:

- a key identifier, which names the key rather than being the key;
- a verification key, which is an Ed25519 public key wherever the capability
  crosses a trust boundary, and may be a shared secret only where the issuer and
  the verifier are the same party; and
- the audiences that key may issue for.

A capability is accepted only when its signature verifies under an entry's key,
**and** its issuer claim matches that entry's identity, **and** its audience
claim is one that entry permits. All three, because each alone admits something
the deployment did not authorize.

A key identifier is chosen by its issuer and is not globally unique, so it
selects candidate entries rather than one, and the issuer claim decides between
them. A verifier keyed on the identifier alone works until the second issuer
arrives and then silently resolves to whichever entry it happened to keep.

Audience is a checked bound and not a claim carried for the record. Without it, a
capability issued for one deployment verifies at every other deployment that
trusts the same issuer. `security/abuse-cases.yaml` already requires
`token_audience_rejected`, so the case was written before the mechanism.

Issuer identity and key identifier are bound to each other in the entry. Section
5 lists both, separately. Keyed on the key identifier alone the issuer claim is
decorative, and a verifier ends up trusting a key to sign for a name nobody
authorized it for. This mirrors ADR-0017, which binds the key identifier into the
signed input precisely so it cannot be relabelled.

Self-issuance is the degenerate case: one entry whose key is the verifier's own.
A deployment inside one trust boundary needs no third party and no distribution
problem, and by ADR-0017's rule it may use HMAC-SHA-256 there, since nothing
crosses a boundary. Anything that does crosses under Ed25519 with
`verify_strict`, so one signature cannot verify under two public keys.

The anchor set lives at the policy boundary ADR-0022 already put at the caller:
`Session::pending_authorization`, `grant`, and `refuse`. This decision therefore
adds nothing to `vot-session` and nothing to the wire.

### Whose clock

The verifier's. No VOT frame carries an absolute clock and `vot-session` keeps no
time, so not-before and expiry are evaluated where the identity store already is.
Skew tolerance is deployment policy, declared rather than fixed here, because a
tolerance wide enough for one deployment's clocks is a replay window in another.

### Revocation

Short lifetimes are the primary control, and a deployment-local deny list on the
unique token identifier section 5 already requires is the secondary one. Neither
is a protocol mechanism: no frame carries a revocation, and a verifier that
cannot reach an authority must not fail open.

This is written down rather than left silent because the gap between issuance and
expiry is the obvious question about any capability system, and an unanswered
question reads as an oversight later. A deployment needing revocation faster than
expiry shortens the lifetime.

### Delegation

Deferred, and bounded rather than omitted. Section 5 requires a delegation
constraints claim; in `ed25519-cbor-v1` its only conforming value is that no
further delegation is permitted, and a verifier enforces that rather than reading
past it. A claim that is expressed and checked is not a promise unkept; omitting
it, or accepting any value unread, would be.

Chained attenuation arrives as a new capability format identifier, `0x0002`,
which breaks no conforming peer: `spec/wire.md` section 1.1 has the server
advertise the formats it accepts and the client name the one it presents, so a
verifier that does not implement chains never advertises them. That escape hatch
is what makes deferring safe rather than a debt.

## Consequences

Distribution is a deployment problem, deliberately. Configuring an issuer set is
the same operational task as configuring the receipt verification keys ADR-0017
left to the caller, and it needs no new protocol surface.

What this does not give is cross-deployment discovery. Two deployments that have
never exchanged an issuer entry cannot authenticate to each other, and there is
no in-protocol way to bootstrap one. That is the price of refusing a fetch before
authentication, and it is the same price ADR-0018 accepted for witnesses.

A verifier configured with no entries accepts nothing. `spec/wire.md` section 1.1
already covers the deployment that requires no authentication: it advertises no
capability format, and the exchange concludes at `AUTH_CONTEXT`. An empty issuer
set with a format advertised is a misconfiguration that fails closed, which is
the direction section 5 requires of unknown mandatory claims.

Stage two now has everything it needs: the claims from section 5, the binding from
ADR-0022, the signing mechanics from ADR-0017, and the anchor from here.
