# failed_flush_cannot_retry_to_success

Mutant configuration:

```diff
-CONSTANT InjectRetrySuccess = FALSE
+CONSTANT InjectRetrySuccess = TRUE
```

The mutant enables a transition from a flush-poisoned incarnation to
`PUBLISHED`.

Observed failure:

```text
CommitUnsafeRetry exit=12
Error: Invariant FailedFlushNeverAdvances is violated.
```
