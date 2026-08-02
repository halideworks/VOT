# Manifest fuzz driver

`vot_manifest_fuzz_driver::exercise` invokes the bounded canonical decoder with
a 256 MiB allocation ceiling. A successful decode must re-encode to the exact
input bytes. Parse errors are expected. A panic, abort, excessive allocation, or
hang is a failure.

Two gates share that function, so they cannot drift apart.

## Pinned-stable gate

```sh
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
fuzz/manifest/target/debug/vot-manifest-fuzz-driver \
  --iterations 10000 --corpus fuzz/manifest/corpus < fuzz/manifest/corpus/seed-page.bin
```

The pinned stable toolchain cannot instrument for coverage, so this gate drives
`vot-fuzz-mutator`: mutants are fed back into a bounded population, so edits
accumulate, inputs change length, and crossover splices two population members.
`--seed <n>` selects a different deterministic run; the same seed replays the
same candidates. The unmutated seed is always exercised first, which keeps a
committed crashing input a permanent regression test.

CI runs 256 iterations per seed; the scheduled workflow runs 10,000.

## Coverage-guided gate

```sh
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz manifest fuzz/manifest/corpus
```

The committed corpus directory doubles as the persistent corpus; libFuzzer
writes newly interesting inputs back into it.

Seed from `test-vectors/manifest/page.json`. Minimized failures may be committed
only when they contain no customer data, paths, tokens, or payloads.
