# Coverage bookkeeping

Run the retained workload with:

```sh
cargo +1.97.1 run --release -p vot-coverage --example measure_coverage
```

Each sample builds and fills 4,096 disjoint fragments in a deterministic
permutation, repeated 200 times. Results are medians of seven samples.

Measured on the same Linux host on 2026-09-07, comparing
`aba35a0aeb8a51abd8e7fde2e3b00285e1a4d29e` with the coverage fixes. Both library
versions and the same example were compiled directly with Rust 1.97.1,
`--edition=2024 -O`, then run sequentially after workspace validation finished.

| Operation | Before | After | Time reduction |
| --- | ---: | ---: | ---: |
| Check and commit | 586.70 ms | 580.42 ms | 1.1% |
| Reserve and commit | 617.61 ms | 503.54 ms | 18.5% |

The booking result was effectively flat. An earlier run concurrent with tests
showed larger reductions, which did not hold for bookings in the quiet rerun.
These measurements cover bookkeeping only, not end-to-end transfer throughput.
