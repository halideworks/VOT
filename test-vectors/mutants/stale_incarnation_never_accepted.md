# stale_incarnation_never_accepted

Mutant configuration:

```diff
-CONSTANT InjectStalePublish = FALSE
+CONSTANT InjectStalePublish = TRUE
```

The mutant changes a stale publish attempt from an explicit rejection into a
publication.

Observed failure:

```text
CommitUnsafeStale exit=12
Error: Invariant StaleAttemptsRejected is violated.
```
