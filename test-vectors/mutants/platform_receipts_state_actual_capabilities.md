# Platform receipts state actual capabilities

Criterion: Windows and macOS publication claims cannot report an unsupported
commit profile or predecessor assurance.

Passing evidence: `platform_receipts_state_only_actual_capabilities` checks the
capability tables and rejected profiles.
`provider_operations_match_the_claimed_profile_exactly` checks the operations
behind each claim. Windows and macOS CI run the native provider test on their
respective systems.

Mutant: make the Windows Balanced capability true.

Observed failure:

```text
assertion failed: !windows.balanced
```

The required `vot-commit-platform` mutation run caught the mutant.
