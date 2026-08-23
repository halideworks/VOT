# Owned payload adopts its input allocation

Criterion: converting a compact owned vector into a transport payload preserves
the vector's byte allocation, cloning shares it, and excess capacity is removed
before bounded queues retain it.

Passing evidence: `payload_adopts_owned_vec_and_shares_clones` records the
vector's data pointer, converts it into a payload, clones it, and checks both
payload pointers against the original. It also converts a one-byte vector with
one MiB of capacity and checks retained capacity equals its length.

Mutant: replace `Self(Arc::new(bytes))` with
`Self(Arc::new(bytes.to_vec()))` in `From<Vec<u8>> for Payload`.

Observed failure:

```text
thread 'tests::payload_adopts_owned_vec_and_shares_clones' panicked at crates/vot-transport-api/src/lib.rs:1105:9:
assertion `left == right` failed
  left: 0x57708ba59bd0
 right: 0x57708ba53710
test result: FAILED. 0 passed; 1 failed
```

Mutant: remove the `into_boxed_slice().into_vec()` capacity normalization.

Observed failure:

```text
thread 'tests::payload_adopts_owned_vec_and_shares_clones' panicked at crates/vot-transport-api/src/lib.rs:1111:9:
assertion `left == right` failed
  left: 1048576
 right: 1
test result: FAILED. 0 passed; 1 failed
```
