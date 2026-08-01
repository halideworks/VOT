# Independent package-root recomputation

Criterion: an end-to-end `PUBLISHED` receipt names the canonical package root.

Passing evidence: `tools/verify_wave4_package.py` parses the canonical CBOR
manifest pages, manifest seal, and objects without using the Rust CLI. It uses
the standard-library SHA-256 tree and from-scratch BLAKE3 implementation from
the independent Wave 1 verifier.

Mutant: change any logical root, length, path byte, object byte, or receipt root.

Observed failure: the independent verifier fails the corresponding object,
package-transcript, or receipt equality assertion.

The required Rust mutation runs also completed with no viable survivors:

```text
vot-cli: 204 total, 184 caught, 20 unviable, 0 missed
```

The thin argument dispatcher in `crates/vot-cli/src/main.rs` is excluded. All
bundle construction, verification, publication, and receipt logic is required.
