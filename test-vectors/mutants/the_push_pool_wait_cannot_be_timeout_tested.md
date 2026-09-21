# The push session pool's waits hang the live sweep by construction

The `wire-mutation` sweep runs the live wire tests, and three mutants of the
session pool in `crates/vot-cli/src/wire/push.rs` invert or remove its waits:

- `SessionSlots::admitted`: `replace >= with <` waits while the pool has room
  and drives while it is full, so the first grant never returns.
- `SessionSlots::admitted`: `replace += with *=` leaves the driving count at
  zero, so the pool's width is never spent and the waiting grants below it
  hang on a notification that arrives before they listened.
- `<impl Drop for AdmittedSession<'_>>::drop` replaced with `()`: the release
  notification is gone, so every waiting grant waits forever.

Each of these makes every live wire test that admits a session hang until the
mutation timeout. That is the mutant working as mutated: the wait is the
behavior. No test can both exercise the pool and fail fast under a wait that
never ends, so these are classified rather than killed.

The pool's real behavior is pinned by bounded unit tests in the same file,
which fail at a ten second deadline when these same conditions are inverted
(`the_default_gate_uses_the_documented_budgets`,
`an_admitted_session_takes_a_free_slot_without_waiting`,
`dropping_an_admitted_session_frees_the_pool_slot_promptly`, and the
deadline-bounded `a_granted_session_waits_for_a_pool_slot_and_releases_it_on_end`),
and the default `mutation (vot-cli)` sweep, which runs those tests without the
live feature, kills the pool's logic mutants. The exclusion below removes only
the hang-by-construction wait mutants from the live sweep.
