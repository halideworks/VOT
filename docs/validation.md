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

`validate_negotiation_vectors.py` reimplements `spec/wire.md` section 1 in
Python and compares it against the Rust codec through the `vot-codec-oracle`
binary, so it needs `cargo` on `PATH` as well.

`validate_session_vectors.py` does the same for the section 1.1 payloads and the
`spec/session.cddl` schemas, and needs `cargo` for the same reason. It covers the
four payloads in isolation. The rules that span two frames are not vectorable and
are enforced in `vot-session`: a binding proof matches the binding the challenge
named, and an answer repeats the identifier of the request it answers.

`validate_capability_vectors.py` reimplements `spec/capability.cddl` and the rules
`spec/security.md` section 5 puts on a capability, and cross-checks 13 cases
against the Rust crate through `vot-capability-oracle`. Five of them are refusals,
which the validator requires: a file of nothing but accepted cases proves only
that the decoder decodes. The canonical cases are the bytes the crate writes; the
refusals are hand-written, so a rule the crate cannot express is visible in the
file rather than absent from it.

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
git diff origin/main...HEAD > changed.diff
cargo mutants --package PACKAGE --jobs 2 --in-diff changed.diff
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

`vot-cbor` is the deterministic CBOR every VOT structure encodes in, and it is
where the head rules and the shortest-form checks live. Three crates had grown
their own copy of them; a change to canonical encoding now has one place to be
made and one mutation run to answer for.

`.github/workflows/ci.yml` holds the package matrix. Every package in it is
required, and no mutant survives any of them: a survivor fails the run rather
than being noted. The matrix also carries the features a package must be built
with, because a mutant in a module the tests never compile is reported missed
whatever the tests say. That is what `vot-object-store` needs `s3-live` for.

The live transport is the one exception, and it is a separate job rather than a
matrix entry, because what survives there is classified rather than absent. See
below.

The second form is what a pull request runs, and it mutates only the lines the
change touched. It is minutes rather than half an hour, and it cannot see a
change that uncovers code it did not touch. The full sweep runs on every push to
main, which is what covers that.

The live transport is measured under its own configuration, because its module
only compiles with the feature on:

```sh
cargo mutants --package vot-transport-msquic --features live \
  --config .cargo/mutants-live.toml --timeout 120 --jobs 2 | tee mutants.log
python3 tools/check_live_mutants.py --full mutants.log
```

What survives there is classified in
`test-vectors/mutants/the_live_transport_is_mutation_tested.md`, with a reason per
mutant. `check_live_mutants.py` holds the run against that table: an
unclassified survivor fails, and a classified one that no longer survives is
reported so the row can go. It compares mutants rather than counting them,
because a count passes a run that kills one survivor and grows another. Pass
`--full` only for a sweep; a diff run tests a subset and cannot say a row is
stale.

## Simulator

```sh
cargo run -p vot-transport-sim --bin vot-trace-replay -- sim/scenarios/rebind-fallback.vot
```
