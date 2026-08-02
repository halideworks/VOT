# Frame codec fuzz driver

`vot_frame_fuzz_driver::exercise` invokes the borrowed decoder with a bounded
frame count and a 256 MiB allocation ceiling. SETTINGS frames also exercise
bounded negotiation, duplicate detection, unknown identifier handling, and
registered value ranges. Any parse error is an expected result; a panic, abort,
excessive allocation, or hang is a failure.

Two gates share that function, so they cannot drift apart.

## Pinned-stable gate

The standalone binary reads a seed from standard input, up to the hard frame
ceiling plus 64 KiB. `--corpus <dir>` adds the committed corpus as extra seed
material.

```sh
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
fuzz/frame_codec/target/debug/vot-frame-fuzz-driver \
  --iterations 10000 --corpus fuzz/frame_codec/corpus < fuzz/frame_codec/corpus/seed-envelope.bin
```

The pinned stable toolchain cannot instrument for coverage, so this gate drives
`vot-fuzz-mutator` instead: mutants are fed back into a bounded population, so
edits accumulate, inputs change length, and crossover splices two population
members. `--seed <n>` selects a different deterministic run; the same seed
replays the same candidates, so a CI failure reproduces locally.

The unmutated seed is always exercised first, which keeps a committed crashing
input a permanent regression test.

## Coverage-guided gate

`fuzz/cargo-fuzz` holds libFuzzer targets built from the same `exercise`. They
need a nightly toolchain for sanitizer coverage instrumentation and run in the
scheduled `fuzz-nightly` workflow.

```sh
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz frame_codec fuzz/frame_codec/corpus
```

Passing the committed corpus directory makes it the persistent corpus: libFuzzer
writes newly interesting inputs back into it, and those are worth committing.

Seed from `test-vectors/wire/frame-envelope.json`, which the driver accepts in
hex form. Crashing inputs must be minimized and committed without customer data,
paths, tokens, or payloads.
