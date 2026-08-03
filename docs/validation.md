# Validation

Every check the repository knows how to run, in the order a reviewer should run
them. There is no single entry point yet; adding one is open work.

Nothing here is a substitute for reading what a job actually covered. A skipped
job is not a passing job.

## Specification and vectors

```sh
python3 tools/validate_registries.py
python3 tools/validate_wire_vectors.py
python3 tools/validate_negotiation_vectors.py
python3 tools/validate_session_vectors.py
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

`validate_negotiation_vectors.py` reimplements `spec/wire.md` section 1 in
Python and compares it against the Rust codec through the `vot-codec-oracle`
binary, so it needs `cargo` on `PATH` as well.

`validate_session_vectors.py` does the same for the section 1.1 payloads and the
`spec/session.cddl` schemas, and needs `cargo` for the same reason. It covers the
four payloads in isolation. The rules that span two frames are not vectorable and
are enforced in `vot-session`: a binding proof matches the binding the challenge
named, and an answer repeats the identifier of the request it answers.

`validate_registries.py` compares the frame-type and setting-id tables in
`spec/registries.md` against the constants in `vot-codec`, and checks that
`REGISTERED_SETTINGS` lists every setting the constants define, since encoding
walks that list. It does not yet cover the error-code table.

`differential_fuzz_codec.py` builds the Rust oracle, so it needs `cargo` on
`PATH` and fails for that reason rather than a real mismatch if it is missing.

## Rust

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
```

Some suites are separate because they need a platform, a device, or a network
that a plain workspace run does not have:

```sh
cargo test -p vot-resume --test e_resume --locked
cargo test -p vot-transport-tcp --locked
cargo test -p vot-commit-platform --locked
cargo test -p vot-platform-fs --locked
```

## Live MsQuic

The `live` feature builds MsQuic from a pinned revision and runs the assembled
client, the assembled server, and the session layer over a real carrier.

```sh
cargo test -p vot-transport-msquic --features live --locked
cargo test -p vot-transport-msquic --features live --release --locked
cargo clippy -p vot-transport-msquic --all-targets --features live --locked -- -D warnings
```

Run both profiles. MsQuic's telemetry assertions are compiled in only for its
debug build, so a debug run catches callback contract violations a release run
silently tolerates, and a release run catches anything a `debug_assert` would
have hidden.

## Sanitizers

```sh
RUSTFLAGS="-Zsanitizer=address" \
LSAN_OPTIONS=suppressions=tools/lsan-msquic.supp:print_suppressions=1 \
cargo +nightly-2026-07-15 test -p vot-transport-msquic \
  --features live --target x86_64-unknown-linux-gnu --locked
```

This is the only check that covers the FFI ownership in
`vot-transport-msquic`: adopted connection and stream handles, send-buffer
lifetime, and teardown order. It needs the pinned nightly toolchain.

Pass the options exactly. LeakSanitizer matches suppressions against symbolised
frames, so dropping `symbolize=1` or `allow_addr2line=1` stops
`tools/lsan-msquic.supp` matching and the openssl allocations it covers are
reported as leaks.

Run the whole suite, not one test. Restricting it to one test left the
peer-created stream path, the accepted-connection path, and the handshake
unsanitised, and a send-buffer leak in a test listener survived for exactly that
reason. Run it serially too: reports from parallel tests interleave and cannot
be attributed.

## Mutation and fuzzing

```sh
cargo mutants --package PACKAGE --jobs 2
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

`.github/workflows/ci.yml` holds the package matrix and which packages are
required rather than advisory. `vot-codec` is advisory: roughly 158 of its
mutants survive, almost all in the frame parser.

## Simulator

```sh
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
```
