# Encoded record allocation is exact

Criterion: a maximum ordinary data record reserves exactly its encoded wire
length, and conversion to a transport payload keeps the same allocation.

Passing evidence: `data_record_envelopes_reserve_each_varint_width_exactly`
checks exact capacity for valid records spanning the one-, two-, and four-byte
length varints inside `vot-codec`. The downstream
`an_encoded_record_keeps_its_allocation_as_a_payload` test encodes a
`RECORD_PLAINTEXT_BYTES` record, converts it to `Payload`, and checks the data
pointer is unchanged.

Mutant: restore the former worst-case `payload_len + 9` reservation in
`encode_data_record`.

Observed failure:

```text
thread 'serve::tests::an_encoded_record_keeps_its_allocation_as_a_payload' panicked at crates/vot-cli/src/serve/mod.rs:254:9:
assertion `left == right` failed
  left: 258102
 right: 258098
test result: FAILED. 0 passed; 1 failed
```
