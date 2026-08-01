# Manifest fuzz driver

The standalone driver reads at most one byte beyond the manifest page ceiling
and invokes the bounded canonical decoder. Successful decodes must re-encode to
the exact input bytes. Parse errors are expected. A panic, abort, excessive
allocation, or hang is a failure.

Build with the pinned lockfile:

```sh
cargo build --manifest-path fuzz/manifest/Cargo.toml --locked
```

Seed from `test-vectors/manifest/page.json`. Minimized failures may be committed
only when they contain no customer data, paths, tokens, or payloads.
