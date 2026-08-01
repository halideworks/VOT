# receipt_was_performed

Mutant configuration:

```diff
-CONSTANT InjectUnsafeReceipt = FALSE
+CONSTANT InjectUnsafeReceipt = TRUE
```

The mutant lets `EmitReceipt` claim a level absent from `performed`.

Observed failure:

```text
CommitUnsafeReceipt exit=12
Error: Invariant ReceiptWasPerformed is violated.
```
