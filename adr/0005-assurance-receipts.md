# ADR-0005: Publication receipts bind requested and actual assurance

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A05 commit model; A16 identity

## Context

Publication is not equivalent to transport delivery, and different commit
providers can perform materially different durability and at-rest checks. A
single success flag would conceal these differences and make silent downgrade
possible.

## Decision

VOT exposes `ADMITTED`, `TRANSIT_VERIFIED`, `DURABLE`, `AT_REST_VERIFIED`, and
`PUBLISHED` as non-equivalent observations. Fast publication requires transit
verification, Balanced requires durability, and Strict requires at-rest
verification.

Every publication receipt binds the subject identity, requested profile, actual
predecessor assurance, provider and version, session and incarnation, monotonic
sequence, wall observation and clock source, verification suite, and all
delegation, downgrade-history, unsupported, or experimental flags. The data
model is `spec/receipt.cddl`.

Receipts crossing a trust boundary are authenticated. V0.3 registers Ed25519
and HMAC-SHA-256; deployment policy determines which is acceptable and how keys
are provisioned. Receipt authentication is independent of object proof suites.

Unsupported requested assurance fails. A later explicit request for a weaker
profile is a new auditable choice, not a silent continuation of the failed one.

## Consequences

- Consumers can compare actual completion semantics across providers.
- Receipts need replay and monotonic-sequence validation.
- Wall time is audit metadata and cannot drive correctness.
- Provider conformance profiles must define their durability and integrity
  semantics precisely.

## Rejected alternatives

- Transport ACK or stream completion as receipt.
- A boolean success result.
- Inferring provider guarantees from platform name.
- Reusing object roots as receipt signatures.
