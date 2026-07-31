# ADR-0007: Draft ALPN and length-delimited registries govern evolution

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A01 wire protocol

## Context

VOT needs compatible extensions without claiming an unregistered production
ALPN or allowing old parsers to misinterpret new critical behavior.

## Decision

The prototype ALPN is `vot-draft-03`. Major incompatible changes use another
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

## Rejected alternatives

- Advertising `vot/1` before registration.
- Unframed CBOR items on the control stream.
- Ignoring every unknown frame.
- Mandatory custom QUIC transport parameters for application negotiation.
