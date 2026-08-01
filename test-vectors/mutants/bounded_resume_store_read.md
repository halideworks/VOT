# Resume store read is bounded on one handle

Criterion: resume decoding cannot allocate from a replaced or enlarged
checkpoint path after checking a different file's metadata.

Passing evidence: `read_bounded_store` opens once, reads at most
`maximum + 1` bytes through that handle, and rejects the extra byte.
`store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic` checks the
exact boundary and a store shorter than its digest.

Mutant: change the exact greater-than comparison to greater-than-or-equal, less
than, or equality.

Observed failure:

```text
assertion failed: read_bounded_store(&bounded, 5).is_ok()
```

The required `vot-resume` mutation run reports 130 total, 122 caught, 8
unviable, and 0 missed.
