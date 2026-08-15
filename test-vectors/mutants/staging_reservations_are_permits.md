# Staging reservations are permits

Criterion: a `StagingCapacity` reservation is a `Permit`. Dropping it
returns the bytes. The receiver stores the verifier reservation on the
active object or range state and does not call a bare `release`.

Passing evidence: `flow_credit_is_derived_from_remaining_staging` holds
permits across credit checks and drops them to restore credit.
`a_poisoned_ledger_recovers_only_with_nothing_in_flight` calls the
test-only `poison` hook and refuses rebuild while `begin` still holds
a permit.

Mutants: restore a public `release(bytes)` that subtracts without a
permit, which `releasing_more_than_was_held_poisons_the_ledger` no
longer offers a matching path; drop the verifier `Permit` field and
release a constant instead, which leaves used high after `finish` and
fails peak or recover tests that expect the reservation to die with
the object.
