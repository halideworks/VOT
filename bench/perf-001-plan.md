# PERF-001 implementation plan: the QUIC engine bakeoff

Status: decided 2026-08-03, main at `3bcda40`. This plan rules on the decisions
PERF-001 left open so the implementation does not make them ad hoc. The
backlog entry asks for a `MsQuic_vs_quiche_report` and a
`selected_default_backend_ADR`, with three acceptance criteria:
`one_rail_one_worker_and_multi_worker_measured`, `provisioned_multi_rail_labeled`,
and `serialized_spine_hypothesis_tested`.

The report goes to `bench/results/perf-001-quic-bakeoff.md` in the shape of
`bench/results/wave2-balanced.md`: date, environment facts, medians, and the
exact command that reproduces each number. The ADR is
`adr/0025-selected-default-backend.md`. `bench/public_result_schema.json`
already accepts backend `msquic` and `quiche`; the contract does not change.

## Starting position

Both QUIC backends carry VOT over a real socket on a driver thread of their own
(ADR-0024), sitting on the same queue and the same reassembly, so the bakeoff
compares two engines rather than two schedulings. The baseline is
`one_lane_throughput`, an ignored test in
`crates/vot-transport-quiche/src/live.rs`: about 1400 Mbit/s median at one
lane, one worker, no offload, loopback, 512 MB per run.

`crates/vot-bench-driver` implements only the simulator. Three lines in
`lib.rs` are where a real backend breaks in:

- The backend gate refuses everything but `simulator`.
- The worker gate refuses every count but 1, because parallel verification of
  one object needs the proof-bearing range path (ADR-0020).
- `set_receive_credit` is called unconditionally, and the quiche transport
  answers `Unsupported` by design: its flow-control bound is fixed at
  construction, and accepting the call silently would let an endpoint advertise
  a credit no carrier enforces.

The record loop also assumes what only the simulator provides: a send that
never refuses and a flush whose effects `poll` sees immediately. On a real
carrier a full queue is backpressure to retry after flushing, and a flushed
batch lands only after the peer's driver has carried it, so delivery is a loop
under a deadline. `one_lane_throughput` is the template for both, including
completing the handshake before the clock starts.

## Decisions

### 1. The carrier seam is a private `Carrier` enum in the driver

Three variants: `Simulator(SimulatorAdapter)`, and `Quiche { client, server }`
and `MsQuic { client, server }` behind cargo features named `quiche` and
`msquic`. All three cases exist today, so the enum is shaped by real code
rather than speculation. Its methods are exactly what `measure()` needs:

- `send_record`, returning a distinct would-block signal for a full queue;
- `deliver`, which flushes the sender, polls the receiver into the
  `ReliableReceiver`, drains the sender's own events, and for real carriers
  loops under a deadline until the in-flight batch has landed;
- `enforced_credit`, which reports what decision 3 defines;
- `close`.

Construction performs the handshake, before the timed section.

### 2. The mutation gate keeps its arrangement

Everything that touches a socket or a real backend lives in feature-gated
files, `backend_quiche.rs` and `backend_msquic.rs`, named in
`.cargo/mutants.toml`'s `exclude_globs` for the same reason
`crates/vot-transport-quiche/src/live.rs` is: a mutant in a module the matrix
never compiles is reported missed whatever the tests say. Everything in
`lib.rs`, including the seam dispatch, credit reporting, and notes, stays
feature-free and is killed through the simulator variant. The feature-gated
files get loopback tests run by the existing live jobs with the driver's
feature enabled. No new feature enters the required mutation matrix, and
BoringSSL is never paid per mutant.

### 3. The report carries the credit that was enforced, never one that was not

The driver calls `set_receive_credit` once. On success, notes carry
`credit_mode=set` and `credit_bytes` is the value that was set. On
`Unsupported`, notes carry `credit_mode=constructed` and `credit_bytes` is the
bound the transport's `receive_limits()` advertised at construction. Any other
error propagates. Reporting a credit nothing enforced is the failure the
benchmark contract exists to prevent, so the enforced value is the only one
that appears.

### 4. Multi-worker is in scope, as its own PR

The proof-bearing range path is what the worker gate's comment is waiting for.
It lands as a separate PR after both backends are wired and before the report,
so `one_rail_one_worker_and_multi_worker_measured` is met across the series and
every number in the report is measurable when the report is written.

### 5. Four PRs, and the report comes last

1. Carrier seam, quiche wiring, loopback tests.
2. MsQuic wiring through the same seam.
3. The multi-worker path.
4. Measurements, the report, and ADR-0025.

One seam reviewed once, each backend change small, and no report exists before
it can be a comparison.

### 6. The serialized-spine measurement is decided before the code

The hypothesis, from the baseline plan: one connection with multiple payload
workers retains a serialized packet-number, loss-detection, and ACK spine, and
tops out below independent provisioned rails on sufficiently fast hardware.

The test: same total workload, same seed, for worker counts 1, 2, and 4,
measure (a) one connection with W workers and (b) W provisioned connections
with one worker each, labelled `provisioned-multi-rail` in notes, which is what
`provisioned_multi_rail_labeled` requires. The hypothesis counts as tested when
the report shows both curves and the ADR states whether (b) exceeded (a) beyond
run variance, in either direction. Run variance at 512 MB per run is about
twenty percent, so a difference inside that band decides nothing and the
report must say so rather than picking a winner from noise. If loopback CPU
saturation masks the difference, the two-machine run decides.

### 7. Loopback settles the comparison; two machines confirm it

Loopback pays for both endpoints on one host and pays it equally for both
engines, so it is a fair comparison and an unfair absolute. The two-machine run
over the 10 Gbps link between the development host and `tr-desktop` is recorded
in the same report with both machines' facts, labelled as a two-machine result,
and never presented as the same quantity as a loopback one. The driver gets a
role mode in the feature-gated files, `VOT_BENCH_ROLE=send` or `receive` plus
listen and connect addresses, run manually and never in CI.

## Out of scope

PERF-002 owns offload, pacing, and the 10 Gbps link target. PERF-001 compares
engines at the current scale and does not chase link saturation. The settled
decisions in ADR-0024 are not revisited: both backends own their socket on a
driver thread, receive credit on quiche is `Unsupported`, and a quiche datagram
never reports `Acknowledged`.

## Measurement discipline

Learned on the pump, at full price: 512 MB per run minimum, because 64 MB
varied by a factor of two between identical configurations and 512 MB brings
that to about twenty percent. Medians over several runs. The two obvious
explanations for the first slow number were both wrong when measured, and the
real cost was a copy nobody suspected, so measure before believing any
explanation. Performance observations made along the way are recorded in
`docs/perf-engineering.md` as they happen, not reconstructed afterwards.
