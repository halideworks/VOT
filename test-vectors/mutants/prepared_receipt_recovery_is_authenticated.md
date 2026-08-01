# Prepared receipt recovery is authenticated

Criterion: crash recovery publishes only an authenticated receipt bound to the
expected package and the exact CLI assurance claim.

Passing evidence: `receipt_recovery_authenticates_prepared_evidence` rejects a
wrong-key HMAC and a tampered summary. `recovered_receipt_requires_every_publication_field`
rejects the wrong key identifier, subject kind, suite, digest, length,
assurance, profile, predecessor, and provider independently.
`receipt_file_bounds_are_exact` reads through a hard byte limit instead of
trusting metadata followed by an unbounded allocation.
`existing_destination_must_match_before_receipt_recovery` independently walks
the visible destination, rejects special files and excessive path depth, and
recomputes every logical file root before any prepared receipt is finalized.

Mutants: skip decoding or HMAC verification, remove any package-field check,
change the exact bounded-read comparison, or omit visible-destination
verification before recovery.

Observed failure:

```text
unauthenticated or mismatched prepared evidence was accepted
assertion failed: receive_bundle(...).is_err()
```

The required `vot-cli` mutation run reports 227 total, 207 caught, 20
unviable, and 0 missed. The required `vot-receipt` run reports 219 total, 215
caught, 4 unviable, and 0 missed.
