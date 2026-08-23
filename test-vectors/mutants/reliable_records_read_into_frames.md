# Reliable records are read into their wire frames

Criterion: a reliable answer reads covered object bytes directly into the
encoded fields of its final data-record frames, including when proof groups
cross record boundaries.

Passing evidence: the codec test fills a reserved encoded field and requires
byte-for-byte equality with both existing encoders. The service split-read test
joins destinations one byte before a proof-group boundary, verifies the source
bytes, and rejects an empty verification span.

The targeted codec mutation run selected the new header, reservation,
validation, and sizing surface. It reported 42 mutants: 33 caught, 9 unviable,
and none missed. The targeted service run selected `read_covered_into`,
`holds_parts`, and `answer_reliably`. Its final iteration caught all 13 new or
previously surviving mutants; combined with the first pass, none remain missed
or timed out.

Six interleaved, storage-inclusive 4 GiB loopback transfers reduced median
sender CPU from 7.79 to 6.49 core-seconds and median wall time from 2.74 to 2.68
seconds. Every run verified the same root and byte count.
