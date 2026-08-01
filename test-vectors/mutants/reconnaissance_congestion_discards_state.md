# Reconnaissance congestion discards state

Criterion: congestion observed during a Careful Resume reconnaissance flight
invalidates the saved congestion-control parameters.

Passing evidence: `reconnaissance_congestion_discards_saved_state` receives a
congestion rejection and proves a second attempt for the same endpoint is
`Unknown` until a new observation is stored.

Mutant: return `PathReject::Congestion` without removing the saved entry.

Observed failure:

```text
assertion failed: second reconnaissance result is Unknown
```

The required `vot-resume` mutation run reports 118 total, 111 caught, 7
unviable, and 0 missed.
