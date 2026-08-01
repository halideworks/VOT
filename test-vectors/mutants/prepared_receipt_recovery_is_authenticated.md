# Prepared receipt recovery is authenticated

Criterion: crash recovery publishes only an authenticated receipt bound to the
expected package and the exact CLI assurance claim.

Passing evidence: `receipt_recovery_authenticates_prepared_evidence` rejects a
wrong-key HMAC and a tampered summary. `recovered_receipt_requires_every_publication_field`
rejects the wrong key identifier, subject kind, suite, digest, length,
assurance, profile, predecessor, and provider independently.
`receipt_file_bounds_are_exact` reads through a hard byte limit instead of
trusting metadata followed by an unbounded allocation.

Mutant: skip decoding or HMAC verification, remove any package-field check, or
change the exact bounded-read comparison.

Observed failure:

```text
unauthenticated or mismatched prepared evidence was accepted
```

The required `vot-cli` mutation run reports 204 total, 184 caught, 20
unviable, and 0 missed. The required `vot-receipt` run reports 219 total, 215
caught, 4 unviable, and 0 missed.
