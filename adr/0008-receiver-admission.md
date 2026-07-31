# ADR-0008: Transport credit is the hard receiver-admission loop

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A08 simulator; A09 scheduler

## Context

Separate transport and application credit loops can oscillate, oversubscribe
staging, or disagree about which acknowledgement releases capacity. Datagram
work has no reliable-stream flow-control protection and requires explicit
absolute bounds.

## Decision

Reliable mode uses QUIC flow control as the hard admission mechanism. The target
connection window is bounded by estimated BDP, assigned staging, and a configured
maximum. Credit extends below one quarter of target, restores toward target in
increments of at least one eighth, and never exceeds bytes the receiver can
stage. Capacity telemetry is advisory.

Datagram mode begins at zero credit. A monotonic `credit_epoch` replaces prior
credit and sets absolute maxima for unretired bytes, active generations, and
decode work. Transport ACK does not release staging or mean application
acceptance.

Default connections use a 90-second idle timeout and active-transfer keepalive
of 20 seconds, configurable from 10 through 30 seconds. Keepalive is off without
an active reservation or resumable lease. Server CIDs are opaque to application
logic; the relay profile reserves nonzero 16-byte CIDs and supports a
deployment-supplied generator/router.

## Consequences

- Reservation and flow-control accounting share one authoritative byte bound.
- Simulator models memory, verification, decode, disk, and journal retirement.
- Datagram overload cannot create implicit credit.

## Rejected alternatives

- Capacity telemetry as a second hard window.
- Wall-clock datagram-credit expiry.
- Releasing admission on transport ACK.
- Embedding application semantics in server CIDs.
