# Platform receipts state actual capabilities

Criterion: Windows and macOS publication claims cannot report an unsupported
commit profile or predecessor assurance.

Passing evidence: `platform_receipts_state_only_actual_capabilities` checks the
capability tables and rejected profiles.
`provider_operations_match_the_claimed_profile_exactly` checks the operations
behind each claim. Windows and macOS CI run the native provider test on their
respective systems. `macos_namespace_failure_retains_staging` injects a failed
directory synchronization and proves staging has not been removed.

Mutants: make the Windows Balanced capability true, or delete macOS staging
before the namespace durability barrier.

Observed failure:

```text
assertion failed: !windows.balanced
assertion failed: left ["sync-file", "link", "remove", "sync-parent"],
right ["sync-file", "link", "sync-parent"]
```

The required `vot-commit-platform` mutation run and the manual ordering mutant
caught the defects.
