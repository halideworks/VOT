# Canonical CLI manifest pages and seal

Criterion: CLI package bundles use the frozen canonical manifest page and seal
encoding instead of a private transfer-only format.

Passing evidence: `canonical_manifest_bundle_publishes_with_matching_receipt`
decodes every emitted page and the seal through `vot-manifest`, checks the page
chain, and streams the entries back through the CLI reader. The independent
`tools/verify_wave4_package.py` decoder parses the same CBOR without Rust code.

Mutant: restore the private `VOTPKG0` manifest file or change a page digest in
the seal.

Observed failure:

```text
manifest directory, canonical page decoding, or seal commitment check failed
```

The focused manifest mutation run tested 40 mutations in page and seal
encoding, decoding, and bounds: 38 caught, 2 unviable, 0 missed.
