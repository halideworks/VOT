# Proof workers are a fetch budget

Criterion: a fetch divides its proving-thread budget across its rails, while
leaving at least one worker on every active rail.

Passing evidence: `proof_workers_are_a_fetch_budget_not_a_per_rail_multiplier`
checks one, two, four, and eight rails, an explicit larger budget, zero rails,
and the existing zero-worker refusal.

Mutant: return `provers` unchanged instead of dividing it by the rail count,
restoring the prior per-rail multiplier.

Observed failure:

```text
thread 'wire::tests::proof_workers_are_a_fetch_budget_not_a_per_rail_multiplier' panicked at crates/vot-cli/src/wire/mod.rs:1432:13:
assertion `left == right` failed: 4 workers across 2 rails
  left: 4
 right: 2
test result: FAILED. 0 passed; 1 failed
```
