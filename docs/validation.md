# Validation

Every check the repository can run, in review order.

## Specification and vectors

```sh
python3 tools/validate_registries.py
python3 tools/validate_wire_vectors.py
python3 tools/validate_negotiation_vectors.py
python3 tools/validate_session_vectors.py
python3 tools/validate_capability_vectors.py
python3 tools/validate_receipt_vectors.py
python3 tools/validate_security_matrix.py
python3 tools/validate_benchmark_contract.py
python3 tools/validate_commit_fixtures.py
python3 tools/validate_commit_model_sync.py
python3 tools/validate_wave0.py
python3 tools/verify_wave1_vectors.py
python3 tools/verify_manifest_pack_vectors.py
python3 tools/verify_wave4_package.py
python3 tools/differential_fuzz_codec.py
```

Several validators reimplement spec sections in Python and cross-check against
the Rust crates through oracle binaries (`vot-codec-oracle`,
`vot-capability-oracle`). These need `cargo` on `PATH`.

`validate_capability_vectors.py` checks 13 cases including 5 refusals. A file of
only accepted cases would prove nothing about what the crate rejects.

`validate_registries.py` compares `spec/registries.md` tables against `vot-codec`
constants. It does not yet cover the error-code table.

## Rust

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
```

Some suites need a platform or network that a workspace run does not provide:

```sh
cargo test -p vot-resume --test e_resume --locked
cargo test -p vot-transport-tcp --locked
cargo test -p vot-commit-platform --locked
cargo test -p vot-platform-fs --locked
```

## Live MsQuic

```sh
cargo test -p vot-transport-msquic --features live --locked
cargo test -p vot-transport-msquic --features live --release --locked
cargo clippy -p vot-transport-msquic --all-targets --features live --locked -- -D warnings
```

Run both profiles: debug builds carry telemetry assertions that release builds
omit, and release builds catch issues hidden behind `debug_assert`.

## Sanitizers

```sh
RUSTFLAGS="-Zsanitizer=address" \
LSAN_OPTIONS=suppressions=tools/lsan-msquic.supp:print_suppressions=1 \
cargo +nightly-2026-07-15 test -p vot-transport-msquic \
  --features live --target x86_64-unknown-linux-gnu --locked
```

Covers FFI ownership in `vot-transport-msquic`: connection/stream handle
lifetimes, send-buffer ownership, teardown order. Needs the pinned nightly
toolchain. Run the whole suite serially; parallel reports interleave.

## Live quiche

```sh
cargo test -p vot-transport-quiche --features live --locked
cargo clippy -p vot-transport-quiche --all-targets --features live --locked -- -D warnings
```

## Benchmark driver

```sh
cargo build --release -p vot-bench-driver
python3 tools/run_benchmark.py --backend simulator --seed 42 --workers 1 \
  --output results.jsonl --command target/release/vot-bench-driver
python3 tools/validate_benchmark_results.py results.jsonl
```

For QUIC backends:

```sh
cargo build --release -p vot-bench-driver --features quiche,msquic
```

Both need `openssl` on `PATH`. The `msquic` feature also needs:

```sh
export LD_LIBRARY_PATH="$(dirname "$(find target -name libmsquic.so.2 | head -1)")"
```

## Mutation testing

Full sweep (runs on every push to main):

```sh
cargo mutants --package PACKAGE --jobs 2
```

Diff run (runs on pull requests):

```sh
git diff origin/main...HEAD > changed.diff
cargo mutants --package PACKAGE --jobs 2 --in-diff changed.diff
```

The package matrix is in `.github/workflows/ci.yml`. Every package is required;
no mutant survives any of them.

Live transport mutation testing classifies survivors rather than requiring zero:

```sh
cargo mutants --package vot-transport-msquic --features live \
  --config .cargo/mutants-live.toml --timeout 120 --jobs 2 | tee mutants.log
python3 tools/check_live_mutants.py --full mutants.log
```

Survivors are classified in
`test-vectors/mutants/the_live_transport_is_mutation_tested.md`.

## Fuzzing

```sh
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

## Simulator

```sh
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
```
