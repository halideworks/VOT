# ADR-0036: who may fetch a package

Status: Accepted

## Context

A serve answers anyone who reaches its port and names the package root. There
is no other check. `spec/security.md` section 1 requires a conforming
implementation to "authorize every package, object, range, upload, and
publication operation", and this one authorizes none of them.

The root is not a password. `vot send` prints it, `vot serve` prints it, and
the fetch command carrying it travels by whatever the two ends use to talk:
email, chat, a ticket. Anyone who sees that message, or who guesses a listen
address and tries roots, gets the package. For the transfers this tool is for,
a large file sent to one named recipient, that is the wrong default.

The exchange to fix it already exists. `spec/wire.md` section 1.1 defines
`AUTH_CONTEXT`, `SESSION_OPEN`, `SESSION_ACCEPT`, and `SESSION_REJECT`, and
`vot-session` implements all four with `present`, `grant`, `refuse`, and
`pending_authorization`. `vot-capability` implements the token: issue, sign,
verify against anchored issuer keys, check audience, validity window, scope,
and operations. Neither is wired to the CLI. `vot-transport-msquic` is the
only crate that depends on `vot-capability` at all.

### What proof of possession is, and what an earlier note got wrong

Working notes in this project recorded that quiche 0.24.9 having no
keying-material exporter "kills the spec's `Binding::ProofOfPossession`". That
is wrong, and it is worth writing down why, because it nearly cost this
decision.

There are two different bindings and the note conflated them. Binding a
capability to the *TLS channel* needs an exporter, and quiche does not offer
one. Binding it to the *holder's key* does not: `spec/wire.md` 1.1 says the
proof "proves possession of the key the capability names, over the
`AUTH_CONTEXT` nonce". That is a signature over 32 bytes. `vot-session` checks
only that the proof is non-empty and hands the bytes to the deployment's
policy, which is exactly the split the spec describes.

So the capability path is buildable on the carrier as it is.

## Decision

**A serve may require a capability, and does not by default.** With no issuer
configured it advertises no capability format, the exchange concludes at
`AUTH_CONTEXT`, and nothing changes for a caller who wants the current
behaviour. With one configured it advertises `Binding::ProofOfPossession` and
the VOT capability format, and refuses a session that cannot present one.

**The token is scoped to the package root, and the grant is decided once per
session.** `Capability::scope` carries one root, and a VOT package has a
package root and many object roots. Checking a token scoped to the package
root against each object range would compare roots that are not meant to
match. The authorization asked at session open is therefore
`Operation::ReadManifest` and `Operation::ReadRanges` over the package root
under suite 1, which is what `spec/object.md` 5.1 gives package identity. A
token that does not carry both operations for that exact root is refused.

**The issuer anchor is an Ed25519 public key the serve is given the way it is
given any other key.** `KEY_SOURCE` and `load_key_spec` already exist and
already distinguish a public key from a secret by label, which is the mistake
worth preventing here too.

**A refusal says one thing.** `spec/wire.md` 1.1: a server "MUST NOT put
anything in the detail that distinguishes a valid capability with insufficient
scope from an invalid one, since that difference is an oracle." One detail
string for every refusal, whatever the reason, and a test that the bytes are
identical across an unknown key, a wrong audience, an expired token, and a
scope that does not cover the package.

## What this does not do

**It is authorization, not protection from an interposer.** The proof is over
the nonce, so an attacker sitting between the two ends forwards the nonce one
way and the proof the other and the exchange succeeds. What the capability
decides is that whoever completes the session holds the private key the token
names. It does not decide that the peer at the far end of the QUIC connection
is that holder.

Closing that needs the capability bound to the channel rather than to a nonce,
which needs a keying-material exporter the carrier does not expose. This is
recorded rather than implied: the usage text and the serve's own output say
what the requirement does, in the same terms.

An interposer still cannot give you different bytes. The package root pins
what the fetch accepts and every range proves to it.

## Consequences

A serve without an issuer behaves exactly as before, so nothing that works
today stops working. A serve with one refuses every fetch that does not
present a token, including its own operator's, so the issuing side has to
exist in the same change rather than after it.

The capability's validity window is the grant's lifetime, which is what
`spec/wire.md` 1.1 says: "the capability governs how long the grant lasts,
since it already carries not-before and expiry, and no VOT frame carries an
absolute clock." A serve that wants to stop honouring a token before it
expires stops the serve.
