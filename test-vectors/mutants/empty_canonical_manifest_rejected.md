# Empty canonical manifest is rejected

Criterion: a package must contain at least one file entry before publication.

Passing evidence: `empty_canonical_manifest_cannot_publish` creates a valid
canonical empty page and seal whose package root matches the empty transcript.
The receive path returns `InvalidBundle` and creates neither destination nor
receipt.

Mutant: replace `actual.entries == 0` with `actual.entries != 0`.

Observed failure:

```text
test tests::empty_canonical_manifest_cannot_publish ... FAILED
```

The required `vot-cli` mutation run reports 226 total, 206 caught, 20
unviable, and 0 missed.
