# Queue holds are permits

Criterion: a queued command or event charges a `Permit` for its payload
bytes. Pop and drop return those bytes by dropping the permit. There is
no `saturating_sub` of a parallel byte counter.

Passing evidence: `charged_bytes_are_the_sum_of_payloads` holds a
5-byte frame plus zero-cost credit, sees `charged() == 5`, and sees
zero after each pop. `a_full_queue_refuses_by_count_and_by_bytes`
refuses a byte past the limit and accepts again after `next_command`.
`a_poisoned_queue_refuses_submissions_and_events` poisons the outbound
ledger and refuses a later frame, zero-cost credit, and a preflight.

Mutants: skip `acquire` and push anyway, which
`a_full_queue_refuses_by_count_and_by_bytes` fails when a second
record fits past the byte limit. Skip the poison check, which
`a_poisoned_queue_refuses_submissions_and_events` fails on credit.

Local `cargo mutants --package vot-transport-queue`: 63 caught, 5
unviable, 0 missed.
