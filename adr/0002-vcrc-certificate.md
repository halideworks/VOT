# ADR-0002: VCRC certifies first-wave frontier risk with a spend-down ledger

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A05 formal model; A15 VCRC research
- Applies to: experimental VCRC decisions

## Context

An end-to-end deadline depends on network, source, receiver, storage, and
scheduling behavior that cannot be certified from a small online scenario
ensemble. VOT still needs precise semantics for allocating a bounded speculative
risk budget and for behavior after that budget is exhausted.

## Decision

A protection decision is one scheduling epoch that assigns a risk charge to a
defined set of currently critical units and a defined first transmission wave.

For decision `t`, event `F_t` is:

> At least one protected unit fails to reach `TRANSIT_VERIFIED` by the end of
> its scheduled first wave and therefore needs another network action.

The ledger obeys:

```text
0 <= delta_t <= B_t
B_(t+1) = B_t - delta_t
B_0 = delta_job
```

Every decision durably records the job, budget epoch, decision epoch, protected
unit set, first-wave boundary, `B_t`, `delta_t`, and `B_(t+1)`. Charges are never
negative and unspent risk is not inferred from successful outcomes.

When `B_t` reaches zero:

- no new speculative parity is authorized;
- no new hedged duplicate request is authorized;
- reliable repair and ordinary retransmission continue;
- already in-flight work may complete;
- `vcrc.budget_exhausted` is emitted with job, budget epoch, decision epoch, and
  remaining frontier state; and
- the budget does not reset automatically.

Only an operator or higher-level policy may begin a new, explicitly logged
budget epoch. The new epoch has a new identity and declared `delta_job`.

The certificate concerns the defined first-wave failure event. It is not a
certificate of deadline attainment, first-usable-subset completion, durable
completion, or publication.

V0.3 ranks actions using CVaR95 from paired, block-resampled scenarios with
common random numbers. It starts with 256 scenarios and expands to at least
1,024 when leading paired uncertainty intervals overlap. p99 and CVaR99 remain
end-to-end reporting metrics.

## Consequences

- The ledger is a correctness state machine and receives deterministic and
  formal tests rather than living only in scheduler bookkeeping.
- Exhaustion produces reliable-only forward progress instead of stopping a job.
- Calibration reports compare observed `F_t` frequency with allocated risk and
  report estimator uncertainty.
- Claims and telemetry must distinguish frontier risk from outcome metrics.

## Rejected alternatives

- **End-to-end deadline certificate:** overclaims what the estimator controls.
- **Automatic replenishment after success or time passage:** violates spend-down
  semantics and makes the total risk allocation unbounded.
- **Stopping retransmission at exhaustion:** converts a speculation budget into a
  liveness failure.
- **Decision-time CVaR99 from the initial ensemble:** insufficiently supported by
  the specified sample size.

## Required verification

- Boundary cases for zero initial budget and exact exhaustion.
- Rejection of `delta_t < 0` and `delta_t > B_t`.
- Idempotent decision replay without double spending.
- Crash recovery preserving budget and epoch identity.
- No parity or hedge authorization after exhaustion.
- Reliable repair continues after exhaustion.
- A new budget requires an explicit, separately logged epoch.
