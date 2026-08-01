# Active Careful Resume observation is exclusive

Criterion: an observation cannot replace saved congestion state while another
connection holds its Careful Resume permit.

Passing evidence: `active_careful_resume_observation_cannot_be_replaced`
obtains a permit, attempts a refreshed observation, requires `AlreadyInUse`,
and proves a second reconnaissance also remains blocked.
`delayed_release_cannot_clear_a_newer_permit_owner` releases a first permit,
grants a second, then proves a delayed duplicate release from the first owner
cannot clear the second owner.

Mutants: remove the active-owner check from `CarefulResumeCache::observe`, or
release an endpoint without matching the private monotonic permit owner.

Observed failure:

```text
expected AlreadyInUse, received Ok(())
assertion failed: !cache.release(endpoint, &first, false)
```

The required `vot-resume` mutation run reports 144 total, 137 caught, 7
unviable, and 0 missed.
