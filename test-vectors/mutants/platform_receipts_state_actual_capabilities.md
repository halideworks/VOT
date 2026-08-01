# Platform receipts state actual capabilities

Criterion: Windows and macOS publication claims cannot report an unsupported
commit profile or predecessor assurance.

Passing evidence: `platform_receipts_state_only_actual_capabilities` checks the
capability tables and rejected profiles.
`provider_operations_match_the_claimed_profile_exactly` checks the operations
behind each claim. Windows and macOS CI run the native provider test on their
respective systems. `macos_namespace_failure_retains_staging` injects a failed
directory synchronization, proves staging has not been removed, retries with
the destination already linked to the same inode, and completes publication.
`native_same_file_identity_is_exact` covers linked, different, missing, and
metadata-error cases. `macos_destination_replacement_after_sync_retains_staging`
proves publication is rejected and staging retained if the destination stops
referring to the staged inode during the namespace barrier.

Mutants: make the Windows Balanced capability true, or delete macOS staging
before the namespace durability barrier, or retry the hard link without first
recognizing that staging and destination are the same file.

Observed failure:

```text
assertion failed: !windows.balanced
assertion failed: !replaced.removed
retry returned AlreadyExists before the namespace barrier
```

The required `vot-commit-platform` mutation run and the manual ordering mutant
caught the defects. The required run reports 28 total, 21 caught, 7 unviable,
and 0 missed.
