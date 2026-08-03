# A proof-bearing range becomes verified state over a session

Criterion: a bundle and the records it covers, arriving over a negotiated
session in either order, promote a subject to verified state, and nothing an
unauthenticated peer sends can spend more than its own budget.

`vot-session` gated the data plane and `ReliableReceiver` verified ranges, but
nothing joined them, so a live carrier moved opaque records and verified
nothing.

Passing evidence: `a_bundle_and_its_records_become_verified_state` and
`records_arriving_before_their_bundle_are_held` prove both orderings reach
verified state and that the held state is released exactly.
`a_subject_nobody_admitted_is_refused_before_anything_is_held` proves a peer
cannot spend memory by naming an object.
`records_without_a_proof_cannot_crowd_out_an_admitted_bundle` proves a record
that arrives before its proof, which names no subject and so cannot be
authorised, holds a separate budget. `the_held_byte_bound_is_exact` and
`held_bundle_state_is_bounded` prove both budgets bound by count and by bytes,
that the bound itself is allowed, and that one past it fails.
`a_held_bundle_is_charged_for_its_proof` proves the proof is charged, not only
the records. `more_records_than_the_proof_covers_are_refused` proves an entry
that could never complete is refused and released rather than left holding.

On replay, `an_exact_duplicate_is_ignored_and_a_conflicting_one_is_refused`,
`a_replay_of_a_delivered_bundle_is_idempotent`,
`a_record_conflicting_with_a_delivered_bundle_is_refused`, and
`a_replay_is_idempotent_even_after_its_identity_is_forgotten` prove the section
5 duplicate rules hold before and after delivery, and that the bound on
remembered identities does not reintroduce the failure.
`a_bundle_that_failed_verification_is_still_retryable` proves an unverified
bundle is not remembered as delivered.

Over a real carrier,
`a_proof_bearing_range_becomes_verified_state_over_the_carrier` drives the
whole path across MsQuic, from negotiation to verified state, with the proof on
the control stream and its records on a lane.

Mutants: route `PROOF_BUNDLE` onto a reliable lane, where every backend frames
at the fixed record limit; charge only the records against the byte bound;
count bundles without counting bytes; hold records for an unadmitted subject;
share one budget between admitted bundles and orphan records; treat an exact
duplicate as a conflict; remember a bundle before the receiver accepted it;
evict the whole memory of delivered identities on each delivery; leave the
entry in place when a proof is refused.

Observed failure:

```text
assertion `left == right` failed
  left: Err(Session(Error { kind: FrameOnTheWrongLane { frame_type: 47, lane: Reliable, side: Local }, close: 258 }))
 right: Ok(None)
called `Result::unwrap()` on an `Err` value: PendingBundlesExhausted
assertion failed: driver.is_verified(subject)
assertion `left == right` failed: the replay held nothing
  left: 1
 right: 0
```

The required `vot-scheduler` mutation run reports 195 total, 174 caught, 21
unviable, and 0 missed. The required `vot-session` run reports 148 total, 114
caught, 34 unviable, and 0 missed.
