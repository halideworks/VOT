# ADR-0016: Single driver thread with a shared-payload worker pool

Status: Accepted

## Context

Every `TransportAdapter` method takes `&mut self`. That is a deliberate
constraint, not an oversight: it makes the adapter a single-owner state machine
whose queue accounting, sequence numbering, and path sample cannot be observed
mid-update. But the trait alone does not say who owns that `&mut self`, and Wave
6 measures multi-worker throughput. Without a written model, each backend driver
would invent its own concurrency shape and the measurements would not be
comparable.

Two facts constrain the answer. `MsQuic` delivers connection, stream, and send
completions on its own worker threads, so callbacks cannot own the adapter
directly. And `Payload` is `Arc<[u8]>`, so moving a record between threads is a
refcount bump rather than a copy.

## Decision

One driver thread owns each adapter for the adapter's lifetime. It is the only
thread that calls `TransportAdapter` methods. It runs a single loop:

1. drain backend callbacks that were parked by the backend's own threads,
2. `poll` events out of the adapter and dispatch them,
3. submit outbound work and `flush`.

Backend callback threads never touch the adapter. They hand records to the
driver over a channel carrying `Payload`, and the driver replays them through
`record_native_event`. The bounded inbound queue is what applies backpressure to
that channel; a full queue is a protocol-visible error, not a silent drop.

Verification, proof checking, decompression, and commit are performed by a
worker pool. Workers receive `Payload` clones over channels and return results
over channels. No worker holds a reference to an adapter or to receiver state.
`ReliableReceiver` is likewise owned by exactly one thread — the driver — and is
mutated only in response to messages the driver has already sequenced.

Path metrics are pushed, not pulled. A backend driver samples its connection on
its own thread and delivers the sample to the adapter through
`record_path_stats` on the driver thread, in the same direction as native
events. Consequently `path_stats()` reports the last sample the driver recorded,
never a live `GetParam` result.

Scaling is by adapter, not by lock. Multiple connections mean multiple driver
threads, each owning its own adapter, sharing one worker pool.

## Consequences

Adapters need no interior mutability and no locks, so their bounds checks stay
readable and their mutation tests stay meaningful. The cost of parallelism is
paid in channel traffic rather than in copies, because `Payload` is shared.

A slow driver thread is a head-of-line block for its connection. That is the
intended failure mode: it surfaces as inbound queue pressure and receive-credit
starvation rather than as unbounded memory growth.

Wave 6 measures worker-pool scaling with the driver-thread count held fixed per
connection. A benchmark that puts an adapter behind a mutex is measuring a
different system and its numbers are not comparable to this model.
