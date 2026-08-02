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

`crates/vot-bench-driver` is the in-tree driver:

```sh
cargo build --release -p vot-bench-driver
python3 tools/run_benchmark.py --backend simulator --seed 42 --workers 1 \
  --output results.jsonl --command target/release/vot-bench-driver
python3 tools/validate_benchmark_results.py results.jsonl
```

`--workers 1` is required: the driver rejects every other worker count, so the
default matrix would fail partway through.

## What the driver implements today

Only the `simulator` backend, and only `worker_count` 1. Both limits are
errors, not silent substitutions: there is no assembled QUIC transport yet, and
parallel verification of a single object needs the proof-bearing range path.
Running the full checked-in matrix therefore needs `--workers 1` until those
land.

The transfer uses the sequential reliable path, which reserves and releases
staging per record, so peak memory follows the receive window rather than the
object. `notes` reports the observed staging peak, the advertised credit, and
the number of flushes.

The object is generated one record at a time inside the timed section, because
materialising it first would put the fixture into the high-water mark that is
supposed to describe transport and verification. Generation is therefore part
of `elapsed_ns`. `notes` carries `generator_ns`, measured over the same
schedule with nothing else running, so it can be subtracted. On current
hardware it is a little over forty percent of the total, which is large enough
that quoting `elapsed_ns` as a transport number would be wrong. The driver does
not do that subtraction itself and call the difference a result.

The receive window comes from the impairment file: bandwidth times round-trip
time is the credit target. That is the only effect any impairment field has.
The simulator has no packetisation, pacing, queue, delay, or loss, and the
transfer uses one stream, which is never reordered against itself. So
`mtu_bytes`, `bandwidth_bps`, `queue_bytes`, and any non-zero `rtt_us`,
`reorder_window` or `loss_ppm` describe the case without shaping it. `notes`
names each one rather than leaving a reader to assume the path matched the
file.

`memory_high_water_bytes` is `VmHWM` from `/proc/self/status`. On a platform
without that, the driver fails instead of reporting zero. `cycles` is always
null; no cycle counter is wired, and the contract is explicit that a missing
counter cannot satisfy the Wave 6 cycle metric.

Output is JSON Lines: every measured iteration independently satisfies
public_result_schema.json, and can be archived without aggregation losing
the seed, workload case, machine metadata, or dirty-worktree note. Warmups and
measurement counts come from the workload file. Use --suite, --workers, or
the workload/impairment options to select a reproducible subset.

Results must identify the source commit, seed, machine, backend, and assurance
level. Missing cycle counters cannot satisfy the Wave 6 cycle metric.
