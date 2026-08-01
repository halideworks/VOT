# Receipt publication recovers after destination

Criterion: a process exit after destination publication cannot strand the
receipt or replace conflicting receipt evidence.

Passing evidence: `receipt_publication_recovers_after_destination_publish`
drops prepared receipt state after publishing the destination, then retries and
recovers both receipt outputs. The companion conflict tests reject pre-existing
outputs with different bytes. `receipt_recovery_completes_after_one_preparation_was_cleaned`
repeats recovery after either prepared file has already been removed.
`destination_sync_failure_preserves_receipt_recovery_evidence` injects failure
in the destination directory durability barrier after the rename, drops both
owners, and proves authenticated recovery evidence remains usable.

Mutants: remove the package-root keyed prepared files immediately after the
destination rename, or require both prepared files when both final files are
already authenticated and complete, or preserve preparations only after the
fallible destination directory sync.

Observed failure:

```text
receipt recovery returned DestinationExists after the simulated process exit
called Result::unwrap() on an Err value: InvalidBundle
prepared receipt evidence was deleted after injected directory sync failure
```

The prepared files are retained until both no-replace hard links are durable,
so retry is idempotent and cannot overwrite another publication's evidence.
The required `vot-cli` mutation run reports 227 total, 207 caught, 20
unviable, and 0 missed.
