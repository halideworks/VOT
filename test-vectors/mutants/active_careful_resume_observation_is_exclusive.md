# Active Careful Resume observation is exclusive

Criterion: an observation cannot replace saved congestion state while another
connection holds its Careful Resume permit.

Passing evidence: `active_careful_resume_observation_cannot_be_replaced`
obtains a permit, attempts a refreshed observation, requires `AlreadyInUse`,
and proves a second reconnaissance also remains blocked.

Mutant: remove the `in_use` check from `CarefulResumeCache::observe`.

Observed failure:

```text
expected AlreadyInUse, received Ok(())
```

The required `vot-resume` mutation run reports 128 total, 120 caught, 8
unviable, and 0 missed.
