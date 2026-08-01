# CLI receipt claims performed predecessor

Criterion: the Wave 4 CLI does not claim journal durability it did not perform.

Passing evidence: `publication_receipt_claims_only_performed_assurance` checks
that CLI publication emits the Fast profile with `TRANSIT_VERIFIED` as the
actual predecessor.

Mutant:

```diff
-profile: CommitProfile::Fast,
-actual_predecessor: AssuranceLevel::TransitVerified,
+profile: CommitProfile::Balanced,
+actual_predecessor: AssuranceLevel::Durable,
```

Observed failure:

```text
assertion failed: receipt.profile == CommitProfile::Fast
```

The required `vot-cli` mutation run reports 226 total, 206 caught, 20
unviable, and 0 missed.
