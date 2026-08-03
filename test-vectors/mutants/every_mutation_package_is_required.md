# Every mutation package is required

Criterion: no package in the mutation matrix is advisory. A surviving mutant
fails the run rather than being noted beside it, and a package whose code only
compiles under a feature is measured with that feature on.

Four packages were advisory. Their results before and after, with
cargo-mutants 26.0.0 under Rust 1.88:

```text
vot-codec          563 total, 117 missed  ->  526 total, 487 caught, 39 unviable, 0 missed
vot-manifest       231 total,  46 missed  ->  226 total, 220 caught,  6 unviable, 0 missed
vot-object-store    96 total,  54 missed  ->   96 total,  87 caught,  9 unviable, 0 missed
vot-commit-object   11 total,   0 missed  ->    11 total,  4 caught,  7 unviable, 0 missed
```

`vot-object-store` was never measured before this. `aws.rs` is behind the
`s3-live` feature, so a run without it mutated a file the tests never compiled
and called all fifty-two of those mutants missed. The matrix now carries the
feature, and the adapter answers an S3 endpoint in process:
`FakeS3` serves canned S3 responses over a local socket from a rule rather than
a script, so the SDK may retry and reorder as it likes. That covers the part
checksum S3 echoes back, the completion that a `NoSuchUpload` answer means
already landed, the completion no answer arrives for at all, a service error
that is not reconciled, and the read back that decides between an object and a
mismatch. The MinIO job still proves the same adapter against a real
implementation.

`vot-commit-object` was already at zero. It has no feature-gated source of its
own, so its default run covers all of it.

Three classes accounted for the survivors:

- A rule written twice, where the second copy is unreachable because the first
  already refused the value. No test can distinguish these, so they are gone
  rather than covered: the request offset bound in `encode_range_request`, the
  covered length and covered end in the proof bundle, the group alignment of the
  covered length, the HAVE run count bound, the file length a signed integer
  cannot hold, and the comparisons against `"."` and `".."` that the rule
  against a trailing dot already refuses.
- A rule with no test. Every validator here is a chain, and a chain hides a rule
  whose row no other rule also refuses, so each now has a table that breaks one
  link at a time.
- An edge computed with slack. A bound with room to spare absorbs a mutation, so
  the HAVE map at four MiB, the widest proof that fits its payload, and the
  index entry size are measured or pinned exactly rather than bounded.

Observed failure, from the mutant that a bound could not catch:

```text
assertion `left == right` failed
  left: Ok(())
 right: Err(TooLarge)
assertion `left == right` failed
  left: Ok(CompletedObject { key: "key", ... })
 right: Err(CompletionMismatch)
```

One survivor could not be killed and was removed instead. The HAVE run count
bound refused a count larger than half the remaining bytes, but a run is three
bytes at the very least, so the loop could never read more runs than the input
holds, the reservation is capped rather than taken from the claim, and
truncation answers `Malformed` exactly as the bound did. It did not bind on the
case it was written for either: two million runs against a four MiB frame passes
it.

One test had to be fixed rather than added. `have_at_payload_limit` builds a map
up to the registry's limit, and it accumulated what a run costs with arithmetic
written beside the encoder rather than the encoder's own measure. A mutant that
changed a CBOR head width made the two disagree, and the correction loop went
quadratic and timed out. A test that hangs under a mutation is worse than a
survivor: it costs sixty seconds in every later sweep. The per-run size is now
one function that both the encoder and the test call.
