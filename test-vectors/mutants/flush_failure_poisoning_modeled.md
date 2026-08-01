# flush_failure_poisoning_modeled

Mutant configuration:

```diff
-CONSTANT InjectPoisonAfterPublish = FALSE
+CONSTANT InjectPoisonAfterPublish = TRUE
```

The mutant permits an incarnation that already performed publication to be
rewritten as poisoned.

Observed failure:

```text
CommitUnsafePoison exit=12
Error: Invariant PoisonedNeverPublished is violated.
```
