# critical_mutation_suite

The required mutation packages were tested with cargo-mutants 26.0.0 under
Rust 1.85. No mutation exclusions were configured.

Observed results:

```text
vot-commit-model: 31 total, 29 caught, 2 unviable, 0 missed
vot-commit-posix: 18 total, 8 caught, 10 unviable, 0 missed
vot-commit-strict: 31 total, 21 caught, 10 unviable, 0 missed
vot-journal: 104 total, 95 caught, 9 unviable, 0 missed
vot-proof-blake3: 93 total, 91 caught, 2 unviable, 0 missed
vot-proof-sha256: 159 total, 158 caught, 1 unviable, 0 missed
vot-transport-sim: 223 total, 206 caught, 17 unviable, 0 missed
```

Aggregate: 659 total, 608 caught, 51 unviable, 0 missed.

The simulator was promoted to a required package after its initial report-only
run found 66 missed mutants and 5 timeouts. Parser edge tests, process-level CLI
tests, and bounded shrinker control flow reduced that result to zero missed and
zero timeouts. Final results use isolated per-mutant target directories so
parallel workers cannot reuse another mutant's build artifacts.

Surviving runs were used to strengthen tests or simplify equivalent
expressions. Each package was rerun until no viable mutant survived.
