# Borrowed data-record encoding is exact

Criterion: the borrowed data-record encoder produces the same bounded wire
frame as the owned encoder and rejects an invalid record without changing its
output.

Passing evidence:
`direct_data_record_envelope_matches_generic_framing_and_fails_atomically`
compares both encoders with independently framed bytes, then gives both an
out-of-range record index and checks their unchanged output.

Mutant: remove `validate_data_record(value)?` from `encode_data_record`.

Observed failure:

```text
thread 'frames::tests::direct_data_record_envelope_matches_generic_framing_and_fails_atomically' panicked at crates/vot-codec/src/frames/mod.rs:1485:9:
assertion `left == right` failed
  left: Ok(())
 right: Err(InvalidValue)
test result: FAILED. 0 passed; 1 failed
```
