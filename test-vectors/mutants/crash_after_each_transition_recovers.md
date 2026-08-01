# crash_after_each_transition_recovers

Passing tests cover a crash and exact-state recovery after every nonterminal
Rust transition. The TLA liveness property checks recovery in the full state
space.

Mutant:

```diff
 Recover(i) ==
     /\ i = current
+    /\ ~InjectRecoverySink
```

The negative configuration sets `InjectRecoverySink = TRUE`.

Observed failure:

```text
CommitRecoverySink exit=11
Error: Deadlock reached.
```
