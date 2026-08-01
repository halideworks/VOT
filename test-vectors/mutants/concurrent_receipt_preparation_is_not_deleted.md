# Concurrent receipt preparation is not deleted

Criterion: a competing receive cannot remove another process's live prepared
receipt files.

Passing evidence: `live_receipt_preparation_is_not_removed_by_a_contender`
creates authenticated prepared evidence, checks it through the contender path
with both the right and wrong key, and proves both files remain present until
their owner drops them.

Mutant: restore the pre-transfer stale-file deletion loop.

Observed failure:

```text
assertion failed: prepared receipt and summary still exist
```

Valid preparation can be reused after a prior crash. Partial or unauthenticated
preparation is rejected without deletion.
