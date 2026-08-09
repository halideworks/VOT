# ADR-0013: Authenticate fallback and constrain Careful Resume

- Status: Accepted
- Date: 2026-07-31
- Decision owner: David Torcivia

## Context

VOT must recover from blocked or degraded UDP without losing verified object
state. Carrier changes must not weaken peer authentication or copy transport
congestion state onto a different path. Resume state must remain valid across
process and connection replacement without treating connection identity as
object identity.

## Decision

The TCP fallback uses rustls 0.23.43 with the same `vot-draft-05` ALPN and the
same VOT frame bytes. No VOT plaintext is exposed before the TLS peer and server
name authenticate. QUIC starts first. TLS/TCP starts after a short configurable
virtual-time delay and may replace QUIC only after TLS is ready and bounded
observation windows report neither data acknowledgements nor probe
acknowledgements.

Persistent resume state is checksummed, size bounded, atomically replaced, and
keyed by immutable object identity. Verified and durable state is independent of
carrier and connection identifiers. Retransmission after a crash is bounded by
the checkpoint window plus active unverified units.

Writers for one resume-store path take a cross-platform exclusive file lock,
reload the current durable store, merge checkpointed units, and only then
atomically replace it. A stale process cannot discard another process's
checkpoint progress.

RFC 9959 Careful Resume state is keyed by interface, destination, and DSCP. It
has a lifetime and configuration epoch, is exclusive to one connection, and is
used only after an acknowledged reconnaissance flight without congestion or path
change. RTT and congestion-window jumps use the limits in `spec/security.md`.
Transport backends that cannot expose enough state do not use Careful Resume.

Windows provider 3 reports Fast only. macOS provider 4 reports Fast and
Balanced. Neither platform reports Strict until a native implementation can
perform and test the required independent read-back.

## Consequences

Fallback can improve connectivity without changing the wire format or assurance
meaning. A carrier switch never redownloads verified units. Stale congestion
state fails closed. Platform receipts identify the provider, requested profile,
and actual predecessor assurance instead of implying unsupported durability.
