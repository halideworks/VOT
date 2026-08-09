# ADR-0007: Draft ALPN and length-delimited registries govern evolution

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A01 wire protocol

## Context

VOT needs compatible extensions without claiming an unregistered production
ALPN or allowing old parsers to misinterpret new critical behavior.

## Decision

The prototype ALPN is `vot-draft-05`. Major incompatible changes use another
ALPN. Compatible behavior uses `SETTINGS`, registered extension identifiers, and
length-delimited frames on the first client-initiated bidirectional stream.

Frame and setting identifiers use the least-significant bit: even unknown values
are optional and skipped after enforcing bounds; odd unknown values are critical
and close the VOT session. Reserved even grease frame types are mandatory in
conformance tests and occasional live use.

V1 adds no mandatory custom QUIC transport parameter. All numeric allocation
occurs in `spec/registries.md`, and wire-visible changes require vectors.

## Consequences

- Parsers can skip optional evolution without understanding payloads.
- Critical semantics never disappear silently.
- Draft identifiers may change only with a new draft ALPN and vectors.

## Revisions

`vot-draft-03` to `vot-draft-05`, `draft_revision` 3 to 4. Two changes to the
receipt authenticator broke the transcript under the frozen identifier: ADR-0017
added the two-byte scheme, and binding the key identifier added its length and
bytes. Either alone makes two peers advertising the same ALPN unable to check
each other's `PUBLISH_RECEIPT`, which is what a new draft identifier is for.
Both are covered by this one bump rather than left as an unversioned break.

`test-vectors/receipt/signing-transcript.json` is the conformance vector this
clause requires. `tools/validate_receipt_vectors.py` rebuilds the transcript
from the registry's description and recomputes the MAC, so an implementation
that reads only the specification can check itself against it.

## Rejected alternatives

- Advertising `vot/1` before registration.
- Unframed CBOR items on the control stream.
- Ignoring every unknown frame.
- Mandatory custom QUIC transport parameters for application negotiation.
