# ADR-0004: Rails are distinct from congestion domains

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A09 scheduler; A12 performance
- Applies to: transport execution and pacing

## Context

Parallel transport execution can raise throughput on provisioned paths and
multi-core hosts, but uncoupled congestion controllers sharing a bottleneck can
take unfair capacity. Treating an execution worker or QUIC connection as the
fairness boundary confuses implementation parallelism with network policy.

## Decision

A **rail** is an execution unit. A **congestion domain** is the aggregate
fairness, pacing, administrative-cap, and receiver-cap unit.

For shared/public paths in production v1:

- the default and only supported configuration is one rail per presumed
  bottleneck;
- a rail may use multiple payload workers when the backend permits it; and
- multiple uncoupled rails over one shared bottleneck are prohibited.

For provisioned paths, multiple rails are allowed only by explicit operator
policy. Administrative caps, pacing budgets, and receiver backpressure apply to
the aggregate congestion domain. Telemetry discloses both rail count and
aggregate behavior.

Public-path multi-rail is experimental and disabled by default until both are
available and validated:

1. coupled congestion control with justified fairness behavior; and
2. shared-bottleneck detection.

All speculative work, including hedges and parity, counts against job,
receiver, rail, and congestion-domain caps. A transport acknowledgement never
releases storage admission credit or implies application completion.

## Consequences

- The transport API models rail membership separately from congestion-domain
  membership.
- Performance reports label provisioned and experimental multi-rail results and
  never compare them as the shared-internet default.
- Multi-worker scaling can be studied without multiplying congestion domains.
- Coupling unrelated bottlenecks is recorded as a performance failure; failing
  to couple a shared bottleneck is recorded as a fairness failure.

## Rejected alternatives

- **One independent congestion controller per worker:** implementation
  parallelism would multiply network aggressiveness.
- **Uncoupled public multi-rail by default:** lacks fairness and shared-bottleneck
  evidence.
- **Couple every path unconditionally:** needlessly suppresses independent-path
  capacity.
- **Capacity telemetry as hard admission:** creates a second credit loop; QUIC
  flow control remains the reliable-mode hard bound.

## Required verification

- Aggregate caps hold across every rail in a domain.
- One-rail/multi-worker and provisioned multi-rail measurements are reported
  separately.
- Hedges and parity cannot bypass any applicable cap.
- Shared-path production settings reject uncoupled multi-rail.
- Telemetry records policy, rail count, and aggregate pacing without raw path
  identifiers at the default redaction level.
