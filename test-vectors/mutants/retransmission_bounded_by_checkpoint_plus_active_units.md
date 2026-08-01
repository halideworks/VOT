# Retransmission bounded by checkpoint plus active units

Criterion: crash recovery resends no more than the checkpoint window plus active
unverified units.

Passing evidence: `retransmission_is_bounded_by_window_plus_active_units` checks
the exact bound, and E-RESUME kills the process at every completion percentage
from 1 through 99 before reopening the persistent identity-keyed store.

Mutant: replace addition in `ResumeTracker::retransmission_bound` with
subtraction.

Observed failure:

```text
assertion failed: tracker.retransmission_units_after_crash()
    <= tracker.retransmission_bound()
```

The required `vot-resume` mutation run caught the mutant.
