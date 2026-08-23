# Quiche streams share transport payloads

Criterion: reliable stream submissions hand the payload allocation to quiche,
and flow-control splits retain byte ranges over that same allocation.

Passing evidence: `shared_buffers_split_without_copying` splits one payload
twice, checks all three byte ranges, and checks their pointers remain offsets
into the original allocation. The live flow-control and socket suites exercise
partial and complete stream submissions through `stream_send_zc`.

The targeted live mutation run selected the shared-buffer and `write_outbox`
surface. It reported 17 mutants: 15 caught, 2 unviable, and none missed. The
unviable mutants replaced `split_at` and `buf_from_slice` with `Default`, which
cannot compile because `SharedBuf` deliberately has no meaningless default.

Three interleaved 4 GiB final-code sender profiles against merged main reduced
mean task-clock from 14.888 to 12.111 seconds and mean CPU cycles from 69.458 to
51.176 billion. End-to-end verified bytes and storage behavior were unchanged.
