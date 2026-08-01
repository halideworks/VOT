# Frame codec fuzz driver

The standalone driver reads at most the hard frame ceiling plus 64 KiB from
standard input and invokes the borrowed decoder with a bounded frame count.
SETTINGS frames also exercise bounded negotiation, duplicate detection, unknown
identifier handling, and registered value ranges. Any parse error is an expected
result; a panic, abort, excessive allocation, or hang is a failure.

Build with the pinned lockfile:

```sh
cargo build --manifest-path fuzz/frame_codec/Cargo.toml --locked
```

Coverage-guided engines may execute the resulting binary repeatedly with mutated
stdin. Seed from `test-vectors/wire/frame-envelope.json`. Crashing inputs must be
minimized and committed without customer data, paths, tokens, or payloads.

CI also runs --iterations 256 against the committed corpus and the canonical
wire seed. A scheduled workflow runs the same bounded driver for 10,000
iterations.
