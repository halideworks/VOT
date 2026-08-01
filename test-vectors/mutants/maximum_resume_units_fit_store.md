# Maximum resume units fit the store

Criterion: every accepted collection of object unit counts can be fully
checkpointed in the bounded resume store.

Passing evidence: `store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic`
derives the per-object ceiling from the 64 MiB payload budget, the store
header, the object header, and the eight-byte unit encoding. It accepts the
exact 8,388,595-unit boundary and rejects one more unit.
`aggregate_capacity_is_reserved_before_transfer` reserves the full eventual
encoding cost of two objects, persists both empty reservations, and rejects a
third object before any unit transfer begins.

Mutants: restore the prior 16,777,216-unit limit, omit an encoding header from
the budget calculation, or replace `validate_reserved_capacity` with `Ok(())`.

Observed failure:

```text
assertion failed: validate_payload_length(maximum_object_payload).is_ok()
expected InvalidConfiguration, received Ok(...)
assertion failed: third object discovery returned Ok(...)
```

The required `vot-resume` mutation run reports 139 total, 132 caught, 7
unviable, and 0 missed.
