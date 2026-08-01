# Stale path state is not reused unsafely

Criterion: congestion state is reused only under RFC 9959 Careful Resume safety
conditions.

Passing evidence: `stale_path_state_not_reused_unsafely`,
`careful_resume_rejects_each_condition_and_accepts_exact_rtt_edge`, and E-RESUME
cover endpoint, interface, DSCP, configuration epoch, lifetime, exclusivity,
initial-flight acknowledgement, congestion, RTT, and jump limits.
Path changes and configuration-epoch changes also delete the saved observation;
a second attempt returns `Unknown` until fresh parameters are observed.

Mutants: invert the saved-endpoint equality check, or retain the saved entry
after rejecting a path or configuration-epoch change.

Observed failure:

```text
assertion failed: matches!(cache.reconnoitre(saved, changed, input),
    Err(PathReject::PathChanged))
assertion failed: left Ok(ResumePermit { .. }), right Err(Unknown)
```

The required `vot-resume` mutation run and the manual deletion mutant caught
the defects.
