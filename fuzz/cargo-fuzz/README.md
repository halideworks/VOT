# Coverage-guided fuzz targets

libFuzzer targets for the decoders. Each target's body is the `exercise`
function from the matching standalone driver, so the pinned-stable gate and the
coverage-guided gate always test the same thing.

Sanitizer coverage instrumentation is nightly-only, which is why these are not
part of the pinned-stable CI job. That job builds them so they cannot rot; the
scheduled `fuzz-nightly` workflow runs them.

```sh
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz frame_codec fuzz/frame_codec/corpus
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz manifest    fuzz/manifest/corpus
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz static_proof_catalog \
  fuzz/static-proof-catalog/corpus
cargo +nightly fuzz run --fuzz-dir fuzz/cargo-fuzz retained_proof_store \
  fuzz/retained-proof-store/corpus
```

The corpus directory passed on the command line is the persistent corpus.
Pointing it at the committed corpus means newly interesting inputs land there
and can be reviewed and committed. Crashing inputs are written to
`fuzz/cargo-fuzz/artifacts`; minimize with `cargo fuzz tmin` before committing,
and only commit inputs free of customer data, paths, tokens, or payloads.
