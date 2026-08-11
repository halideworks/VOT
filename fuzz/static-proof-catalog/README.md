# Static proof catalog fuzz driver

`vot_proof_catalog_fuzz_driver::exercise` drives complete and selected-entry
catalog decoding under a 256 MiB allocation ceiling. Inputs are capped at 256
KiB. Header-declared object and catalog lengths never control a whole-object
allocation. One out of every 256 selector values also streams a synthesized
object slightly larger than 4 MiB through the encoder and checks cumulative
record offsets. Parse, identity, availability, and proof failures are expected.
A panic, abort, excessive allocation, or hang is a failure.

Two gates share that function, so they cannot drift apart.

## Pinned-stable gate

```sh
cargo build --manifest-path fuzz/static-proof-catalog/Cargo.toml --locked
fuzz/static-proof-catalog/target/debug/vot-proof-catalog-fuzz-driver \
  --iterations 10000 --corpus fuzz/static-proof-catalog/corpus \
  < fuzz/static-proof-catalog/corpus/blake3-65537.bin
```

The pinned stable toolchain cannot instrument for coverage, so this gate drives
`vot-fuzz-mutator`. Mutants are fed back into a bounded population, allowing
edits to accumulate while population size and input length remain capped.
`--seed <n>` selects a deterministic run. The unmutated seed always runs first.

Pull requests run 256 iterations per suite seed. The scheduled workflow runs
10,000.

## Coverage-guided gate

```sh
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz static_proof_catalog \
  fuzz/static-proof-catalog/corpus
```

The corpus starts with committed BLAKE3 and SHA-256 catalogs. Newly interesting
inputs may be committed only when they contain no customer data, paths, tokens,
or payloads.
