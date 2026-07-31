# ADR-0009: Custom congestion control does not gate production

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A12 performance; A15 research

## Context

Reliable transfer, proof, and commit correctness can ship using established
transport controllers. A new controller adds fairness, safety, route-change,
application-limited, legal, and coexistence risk unrelated to the first product
invariant.

## Decision

Shared Internet production uses one congestion fairness domain per presumed
bottleneck with CUBIC as baseline. A Bulk Internet experimental profile may
compare model-based plugins, including BBRv3 only after legal and coexistence
review. Provisioned paths use declared capacity, administrative caps, receiver
backpressure, and ECN/queue/delivery-rate safety backoff.

The clean-room normalized law in the v0.3 architecture remains simulator-only
until reliable transport and benchmarks stabilize. Feedback epochs are measured
in smoothed RTTs. The model requires application-limited detection, windowed
minimum RTT with route reset, missing-feedback and persistent-congestion
fallback, and explicit coexistence scope. Evaluation follows RFC 9743 criteria.

## Consequences

- No lossy-LFN performance claim precedes evidence for the selected profile.
- Prior-art positioning includes Copa, PCC/Vivace, Veno/Westwood, BBR, and
  related rate/delay controllers.
- Public multi-rail remains disabled until coupling and shared-bottleneck work
  pass their own gate.

## Rejected alternatives

- Making a custom controller a release dependency.
- Fixed wall-clock control updates.
- Updating bandwidth estimates while application-limited.
- Shipping public uncoupled multi-rail as a throughput shortcut.

Reference: <https://www.rfc-editor.org/rfc/rfc9743.html>
