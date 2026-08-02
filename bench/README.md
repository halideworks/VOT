# Wave 5.5 benchmark contract

This directory defines the reproducible workload and result contract required
before Wave 6. It contains no performance claim.

The initial workload varies the logical-object suite and payload-worker count
while keeping the packet-number/loss-detection spine in the backend driver.
Impairments are versioned instead of being unrecorded command-line flags.

Validate the checked-in contract with:

```sh
python3 tools/validate_benchmark_contract.py
```

The executable runner supplies every checked-in matrix combination to a real
backend command. The command receives the selected case through
VOT_BENCH_* environment variables and must print one JSON object containing
bytes_sent, verified_bytes, elapsed_ns, memory_high_water_bytes, and
cycles (an integer or null). The runner rejects missing measurements,
partial verification, and inconsistent byte counts; it never turns a failed
or absent measurement into a performance claim.

For example, a backend driver can be run as:

```sh
python3 tools/run_benchmark.py --backend msquic --seed 42 \
  --command path/to/backend-driver
```

Output is JSON Lines: every measured iteration independently satisfies
public_result_schema.json, and can be archived without aggregation losing
the seed, workload case, machine metadata, or dirty-worktree note. Warmups and
measurement counts come from the workload file. Use --suite, --workers, or
the workload/impairment options to select a reproducible subset.

Results must identify the source commit, seed, machine, backend, and assurance
level. Missing cycle counters cannot satisfy the Wave 6 cycle metric.
