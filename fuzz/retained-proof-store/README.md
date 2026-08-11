# Retained proof store fuzz driver

`vot_retained_proof_store_fuzz_driver::exercise` compares default and
host-stored object preparation for both verification suites. Inputs are capped
at 256 KiB and the driver allocation ceiling is 128 MiB. Object identity,
range covers, readback checks, and static catalog bytes must remain exact.

The input also selects one host-store failure: initial length failure, partial
append failure, unavailable read, corrupt read, or missing read. Storage errors
must remain typed, append failure must poison the builder, and a failed read
must not return a partial range cover. The fault store is memory-only.

## Pinned-stable gate

```sh
cargo build --manifest-path fuzz/retained-proof-store/Cargo.toml --locked
fuzz/retained-proof-store/target/debug/vot-retained-proof-store-fuzz-driver \
  --iterations 10000 --corpus fuzz/retained-proof-store/corpus \
  < fuzz/retained-proof-store/corpus/append-partial.bin
```

`--seed <n>` selects a deterministic mutation sequence. The unmutated stdin
seed runs before accumulated mutations.

## Coverage-guided gate

The libFuzzer target calls the same `exercise` function. Corpus additions must
contain no customer data, paths, tokens, or payloads.
