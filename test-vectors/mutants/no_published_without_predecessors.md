# no_published_without_predecessors

Passing control:

```text
Model checking completed. No error has been found.
2216534 states generated, 597350 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 29.
```

Mutant configuration:

```diff
-CONSTANT InjectUnsafePublish = FALSE
+CONSTANT InjectUnsafePublish = TRUE
```

The mutant enables `UnsafePublishWithoutPredecessor`, which publishes a new
incarnation without performing the required assurance.

Observed failure:

```text
CommitUnsafePublish exit=12
Error: Invariant PublishedHasPredecessor is violated.
```
