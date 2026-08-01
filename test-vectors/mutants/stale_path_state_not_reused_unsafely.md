# Stale path state is not reused unsafely

Criterion: congestion state is reused only under RFC 9959 Careful Resume safety
conditions.

Passing evidence: `stale_path_state_not_reused_unsafely`,
`careful_resume_rejects_each_condition_and_accepts_exact_rtt_edge`, and E-RESUME
cover endpoint, interface, DSCP, configuration epoch, lifetime, exclusivity,
initial-flight acknowledgement, congestion, RTT, and jump limits.

Mutant: invert the saved-endpoint equality check in
`CarefulResumeCache::reconnoitre`.

Observed failure:

```text
assertion failed: matches!(cache.reconnoitre(saved, changed, input),
    Err(PathReject::PathChanged))
```

The required `vot-resume` mutation run caught the mutant.
