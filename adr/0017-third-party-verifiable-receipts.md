# ADR-0017: Sign receipts with Ed25519

Status: Accepted

## Context

Receipts were authenticated only with HMAC-SHA-256. Verifying one required the
shared secret, and holding that secret is enough to forge one. So a receipt
could not be handed to a third party: the auditor either could not check it, or
became able to manufacture it.

Every scenario that motivates the assurance ladder crosses an organisational
boundary. A studio delivering to a distributor, a CRO delivering to a sponsor, a
vendor delivering to a regulator. Symmetric authentication serves none of them.

`ED25519` was already registered as scheme `0x0001` at 64 bytes, and
`spec/receipt.cddl` already allowed a 32 to 512 byte authenticator. Only the
implementation was symmetric: the Rust envelope held `[u8; 32]` and the encoder
wrote scheme `0x0002` unconditionally.

## Decision

Ed25519 is the scheme for any receipt that crosses a trust boundary.
HMAC-SHA-256 stays registered for receipts that never leave one trust domain.

The envelope carries its scheme, and the authenticator is variable length,
checked against the length the registry fixes for that scheme.

The authenticator covers a domain separator, the scheme as two bytes, then the
canonical receipt. Binding the scheme into the signed input means an
authenticator produced under one scheme is not valid input for another, so a
verifier cannot be walked from the strong scheme to the weak one by an attacker
who can choose the envelope.

Verification uses `verify_strict`, which rejects signatures under low-order or
torsion public keys. Without it one signature can verify under more than one
public key, which would let two issuers claim the same receipt.

A verifier that requires a scheme rejects any other outright rather than
reporting an authentication failure, so a caller cannot treat a downgrade as a
retryable error.

## Consequences

`ed25519-dalek` 2.2.0 enters the dependency graph, with `curve25519-dalek`,
`ed25519`, and `signature`. All are BSD-3-Clause or Apache-2.0 or MIT, already
in the `deny.toml` allow list. `curve25519-dalek` contains `unsafe` in its
backends. That does not weaken the workspace lint, which governs VOT's own
crates, but it is a real addition to the audited surface and is recorded in
DEPENDENCIES.md.

Existing HMAC receipts do not verify against this implementation, because the
signed input now includes the scheme. Both schemes were draft and no wire
vectors were published, so nothing deployed is invalidated.

This ADR covers authentication only. A single signed receipt is still a claim
about history rather than the history itself: an issuer holding its own key can
rewrite and re-sign the whole record, and `observed_at` remains self-asserted.
Chaining observations and anchoring them outside the issuer are separate
decisions.
