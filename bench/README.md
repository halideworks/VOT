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

The `simulator` backend always, the `quiche` backend when built with its
feature, and only `worker_count` 1. Both remaining limits are errors rather
than silent substitutions: a backend with no carrier in this build cannot be
measured, and parallel verification of a single object needs the proof-bearing
range path. Running the full checked-in matrix therefore needs `--workers 1`
until that lands. The plan that lifts it is `perf-001-plan.md` in this
directory.

The quiche backend carries the case over a real socket between a loopback pair
of endpoints, each owning its connection on a driver thread of its own
(ADR-0024). Build it in, and the handshake and the self-signed loopback
credential both happen before the timed section:

```sh
cargo build --release -p vot-bench-driver --features quiche
python3 tools/run_benchmark.py --backend quiche --seed 42 --workers 1 \
  --output results.jsonl --command target/release/vot-bench-driver
```

It needs `openssl` on the path. A loopback result pays for both endpoints on
one host, so it compares two carriers fairly and understates what either does
with a machine to itself; that distinction belongs in any report that quotes
one.

Every backend runs the same transfer loop, so a difference between two results
is a difference between two carriers rather than between two transfer
strategies. Records are submitted as `DATA_RECORD` frames and the envelope is
stripped on delivery, which is why `notes` carries `wire_bytes` alongside
`bytes_sent`: the carrier moved strictly more than the object, and the
difference is stated rather than assumed away. A full queue is treated as
backpressure and the record is offered again, counted in `backpressure_waits`;
a carrier that delivers nothing at all for thirty seconds ends the run with an
error instead of reporting a partial transfer.

`idle_waits` counts the deliveries that found nothing, which the driver waits
after because the carrier's own thread is what makes progress. How long it
waits changes what a run reports, so the wait backs off from 16 microseconds to
a millisecond rather than being one interval, and `docs/perf-engineering.md`
records what each setting measured. A result quoted against another must have
been taken at the same interval.

`credit_bytes` is what the receiver advertised, which the receiver enforces by
refusing staging past it. `credit_mode` says whether the carrier was also given
that credit (`set`) or fixes its own inbound bound at construction
(`constructed`), which is what quiche does: it extends connection flow control
as the application reads, so there is no absolute credit to set, and ADR-0024
has it report `Unsupported` rather than accept a bound it would not apply.

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
