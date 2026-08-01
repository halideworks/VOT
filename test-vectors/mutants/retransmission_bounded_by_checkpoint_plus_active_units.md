# Retransmission bounded by checkpoint plus active units

Criterion: crash recovery resends no more than the checkpoint window plus active
unverified units.

Passing evidence: `retransmission_is_bounded_by_window_plus_active_units` checks
the exact bound, and E-RESUME kills the process at every completion percentage
from 1 through 99 before reopening the persistent identity-keyed store.

`store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic` rejects a
checkpoint window larger than the object and rejects `usize::MAX`, so both
terms in the bound are constrained by the accepted object geometry.

Mutants: replace addition in `ResumeTracker::retransmission_bound` with
subtraction, or remove the upper bound from `validate_checkpoint_window`.

Observed failure:

```text
assertion failed: tracker.retransmission_units_after_crash()
    <= tracker.retransmission_bound()
```

The required `vot-resume` mutation run reports 144 total, 137 caught, 7
unviable, and 0 missed. Both mutants are caught.
