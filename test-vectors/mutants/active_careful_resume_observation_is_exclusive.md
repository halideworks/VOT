# Active Careful Resume observation is exclusive

Criterion: an observation cannot replace saved congestion state while another
connection holds its Careful Resume permit.

Passing evidence: `active_careful_resume_observation_cannot_be_replaced`
obtains a permit, attempts a refreshed observation, requires `AlreadyInUse`,
and proves a second reconnaissance also remains blocked.
`delayed_release_cannot_clear_a_newer_permit_owner` releases a first permit,
grants a second, then proves a delayed duplicate release from the first owner
cannot clear the second owner.
The active-owner test also attempts path, local-interface, congestion, expiry,
and configuration invalidation while the permit is held. Every attempt returns
`AlreadyInUse`, marks the saved record for deletion, and leaves only the permit
owner able to release it. Release then deletes the record even if its caller
does not repeat the transient invalidation signal.

Mutants: remove the active-owner check from `CarefulResumeCache::observe`, or
release an endpoint without matching the private monotonic permit owner, or
perform invalidation before checking the active owner, or clear ownership
without honoring `discard_on_release`.

Observed failure:

```text
expected AlreadyInUse, received Ok(())
assertion failed: !cache.release(endpoint, &first, false)
expected AlreadyInUse, received PathChanged
expected Unknown after release, received Ok(ResumePermit { ... })
```

The required `vot-resume` mutation run reports 153 total, 146 caught, 7
unviable, and 0 missed.
