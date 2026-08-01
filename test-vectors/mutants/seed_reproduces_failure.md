# seed_reproduces_failure

The simulator runs the same versioned scenario twice and compares the event
sequence byte for byte. A second test changes only the seed and requires the
simulated event sequence, not the trace header, to change.

Mutant:

```diff
-prng: Prng::new(seed),
+prng: Prng::new(0),
```

The original digest comparison survived this mutant because the digest included
the seed in the trace header. The gate was corrected to compare `Trace::entries`.

Observed failure after correcting the gate:

```text
tests::seed_changes_reordered_trace --- FAILED
assertion `left != right` failed
test result: FAILED. 0 passed; 1 failed
```

The production seed path was restored and the corrected test passed.
