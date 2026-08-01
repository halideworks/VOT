# Deterministic simulator

Scenarios use virtual time and contain a fixed seed, an expected outcome, and an
optional expected trace digest. The simulator does not wait on wall-clock time.

Replay a scenario:

```sh
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
```

Minimize a failing scenario:

```sh
cargo run -p vot-transport-sim --bin vot-trace-shrink -- sim/scenarios/storage-fault.vot
```

The replay command fails if the outcome or a pinned trace digest changes.

Versioned negative-control inputs and their captured failing traces are stored in
`sim/failures/`. They prove that the simulator detects deliberately broken
transport behavior.
