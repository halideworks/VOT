# Encoded length matches written bytes

Criterion: `head_len`, `int_len`, and `payload_len` equal the number of
bytes the corresponding writer emits. `page_encoded_len` and
`seal_encoded_len` equal `encode_page` and `encode_seal`. Encoding
refuses a page whose counted length exceeds `MAX_PAGE_BYTES` before
writing it.

Passing evidence: `every_head_is_the_shortest_that_holds_its_value`,
`payload_len_counts_the_head_and_the_bytes`,
`signed_integers_round_trip_at_their_limits`, and the page/seal
round-trip tests compare counted length to written length.

Mutants: change a `head_len` width boundary, which
`every_head_is_the_shortest_that_holds_its_value` fails. Drop the
payload addend in `payload_len`, which
`payload_len_counts_the_head_and_the_bytes` fails. Drop an optional
metadata field from `metadata_encoded_len`, which the packed raw page
round-trip fails.
