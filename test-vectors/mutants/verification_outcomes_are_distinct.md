# verification_outcomes_are_distinct

Strict verification returns one of three explicit values: `Verified`,
`Unsupported`, or `Mismatch`. The POSIX commit path advances only on `Verified`,
returns `StrictUnsupported` for `Unsupported`, and poisons on `Mismatch`.

Mutant:

```diff
-DirectHash::Supported(_) => Ok(VerificationOutcome::Mismatch),
+DirectHash::Supported(_) => Ok(VerificationOutcome::Unsupported),
```

Observed failure:

```text
test tests::verification_outcomes_are_distinct ... FAILED
assertion `left == right` failed
left: Unsupported
right: Mismatch
```
