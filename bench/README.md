# Benchmark driver

Reproducible workload and result contract. Contains no performance claim.

## Validate the contract

```sh
python3 tools/validate_benchmark_contract.py
```

## Run benchmarks

```sh
cargo build --release -p vot-bench-driver
python3 tools/run_benchmark.py --backend simulator --seed 42 --workers 1 \
  --output results.jsonl --command target/release/vot-bench-driver
python3 tools/validate_benchmark_results.py results.jsonl
```

`--workers 1` is required (parallel verification is not yet implemented).

## QUIC backends

```sh
cargo build --release -p vot-bench-driver --features quiche,msquic
python3 tools/run_benchmark.py --backend quiche --seed 42 --workers 1 \
  --output results.jsonl --command target/release/vot-bench-driver
```

Both need `openssl` on `PATH`. The `msquic` feature needs:

```sh
export LD_LIBRARY_PATH="$(dirname "$(find target -name libmsquic.so.2 | head -1)")"
```

## Output

JSON Lines. Each line is one measured iteration with: `bytes_sent`,
`verified_bytes`, `elapsed_ns`, `memory_high_water_bytes`, `cycles` (int or
null), and `notes` (wire bytes, staging peak, generator time, backpressure
waits, credit mode).

The runner rejects missing measurements, partial verification, and inconsistent
byte counts. It never turns a failure into a result.

## Notes

- Object generation runs inside the timed section. `generator_ns` in `notes`
  can be subtracted to isolate transport cost.
- `memory_high_water_bytes` is `VmHWM` from `/proc/self/status` (Linux only).
- `cycles` uses `perf_event_open` with inheritance. Null if the host refuses
  (`kernel.perf_event_paranoid` > 2 without `CAP_PERFMON`).
- Impairment fields describe the case; only the receive window (from BDP) has
  effect on the simulator.
- Loopback results pay for both endpoints on one host.
