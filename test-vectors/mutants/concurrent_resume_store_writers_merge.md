# Concurrent resume store writers merge

Criterion: two processes checkpointing the same resume store cannot discard
each other's durable units or race through the shared replacement path.

Passing evidence: `checkpoint_waits_for_the_store_transaction_lock` holds the
store lock and proves another writer cannot finish until it is released.
`stale_store_writers_reload_and_merge_checkpointed_units` opens two stores
from the same stale snapshot, checkpoints different units, and proves the
durable result and the second tracker both contain the union.

Mutant:

```diff
-fs4::FileExt::lock(&lock)?;
```

Observed failure:

```text
test tests::checkpoint_waits_for_the_store_transaction_lock ... FAILED
assertion failed: matches!(finished_rx.recv_timeout(...),
    Err(RecvTimeoutError::Timeout))
```

The required `vot-resume` mutation run reports 139 total, 132 caught, 7
unviable, and 0 missed. Replacement and merge mutants are caught. The direct
lock-deletion mutant above is recorded separately because cargo-mutants cannot
construct a default `File` for its whole-function replacement.
