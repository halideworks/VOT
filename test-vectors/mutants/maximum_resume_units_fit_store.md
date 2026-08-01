# Maximum resume units fit the store

Criterion: every accepted per-object unit count can be fully checkpointed in
the bounded resume store.

Passing evidence: `store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic`
derives the unit ceiling from the 64 MiB payload budget, the store header, the
object header, and the eight-byte unit encoding. It accepts the exact
8,388,595-unit boundary and rejects one more unit.

Mutant: restore the prior 16,777,216-unit limit or omit an encoding header from
the budget calculation.

Observed failure:

```text
assertion failed: validate_payload_length(maximum_object_payload).is_ok()
expected InvalidConfiguration, received Ok(...)
```

The required `vot-resume` mutation run reports 136 total, 128 caught, 8
unviable, and 0 missed.
