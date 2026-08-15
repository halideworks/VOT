# Framing holds are permits

Criterion: a partial frame's charge is a `Hold` that returns the bytes when
dropped. `AssemblyBudget::reserve` yields that hold. There is no separate
`release(bytes)` on the trait.

Passing evidence: `held_bytes_are_charged_and_returned` and
`a_peer_cannot_hold_more_than_the_budget_across_streams` drop a `Framing`
or call `Framing::release` and see `held()` return to zero.
`a_budget_admits_what_it_has_room_for_and_no_more` fills the budget with
a permit, refuses one more byte, and restores room when the permit drops.

Mutants: keep a numeric `reserved` and call `release(reserved)` on settle
without dropping a hold, which leaves `held()` high after
`take_pending`. Change `reserve` to return `None` at `next >= limit`,
which `a_budget_admits_what_it_has_room_for_and_no_more` fails on
`reserve(10)`.
