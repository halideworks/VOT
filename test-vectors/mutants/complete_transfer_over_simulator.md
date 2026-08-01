# complete_transfer_over_simulator

The deterministic simulator must complete a reliable transfer before the
scheduler accepts the same bytes and verifies the declared object root.

Mutant:

```diff
-self.verified.insert(subject);
+return Ok(());
```

Observed failure:

```text
test tests::complete_transfer_over_simulator ... FAILED
assertion failed: receiver.is_verified(subject)
```

The required mutation runs reported 28 caught and 4 unviable scheduler mutants,
with no surviving mutant.
