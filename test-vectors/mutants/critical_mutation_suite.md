# critical_mutation_suite

The required mutation packages were tested with cargo-mutants 26.0.0 under
Rust 1.85. No mutation exclusions were configured.

Observed results:

```text
vot-commit-model: 31 total, 29 caught, 2 unviable, 0 missed
vot-commit-posix: 19 total, 9 caught, 10 unviable, 0 missed
vot-commit-strict: 34 total, 29 caught, 5 unviable, 0 missed
vot-journal: 104 total, 95 caught, 9 unviable, 0 missed
vot-proof-blake3: 93 total, 91 caught, 2 unviable, 0 missed
vot-proof-sha256: 159 total, 158 caught, 1 unviable, 0 missed
```

Aggregate: 440 total, 411 caught, 29 unviable, 0 missed.

Surviving runs were used to strengthen tests or simplify equivalent
expressions. Each package was rerun until no viable mutant survived.
