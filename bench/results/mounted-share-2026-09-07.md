# Mounted-share validation, 2026-09-07

Windows native VOT on tr-desktop wrote through its existing X: mapping to
the Linux host's `mediastorage-pool` Samba share. The server ran Samba
4.19.5-Ubuntu on Linux 6.8.0-138-generic. Rust was 1.97.1 on both hosts.
All work used isolated test directories; no media files were modified.

The initial SDK run failed all five native file tests with Windows error 87.
A filesystem probe isolated the refusal to `FileDispositionInfoEx`: create,
file identity, data flush, and hard-link creation succeeded. After the
handle-based legacy disposition fallback, all five tests passed, including
competing publishers, cancellation, and no-overwrite checks.

The CLI mounted-share test also passed: direct and packed object extraction,
receipt verification, publication retry, destination conflict, and cancellation
while retaining the sink. This establishes functional behavior on this share,
not conformance under server power loss or network reconnect. Those remain
unqualified; no live service was interrupted to test them.

A real QUIC `pull` from the Linux host to native Windows also passed, with
both the fetched bundle and published delivery on X:. The package contained
a 64 MiB + 3 byte direct object and a 22 byte packed text file. The client
pinned the package root and server certificate digest, verified its receipt,
and both published files' SHA-256 hashes matched the Linux sources.

Validation also passed 1,364 Linux workspace tests, 306 Windows unit tests
across the affected crates, 42 Python tests, 14 specification validators,
and the affected public API checks. Clippy with warnings denied passed on
Linux and Windows. The temporary listener, scheduled task, and share test
data were removed after validation.

## Sink timing

`crates/vot-cli/examples/measure_sink.rs` wrote 128 MiB in 1 MiB positional
writes, including periodic and final flushes in the timed interval. Every byte
was checked after timing. Both binaries used the same source and release
compiler options except `fetch/sink.rs`: the baseline used that file from
`aba35a0aeb8a51abd8e7fde2e3b00285e1a4d29e`, and the changed binary used the
concurrent sink with sticky errors and cancellation handle release.

Each worker count had three paired runs; arm order alternated. Times are ms.

| Workers | Before samples | After samples | Before median | After median |
| --- | --- | --- | ---: | ---: |
| 1 | 734.748, 771.799, 696.744 | 698.326, 801.253, 632.354 | 734.748 | 698.326 |
| 4 | 715.337, 725.229, 1012.433 | 799.242, 742.332, 644.249 | 725.229 | 742.332 |

The four-worker median increased by 2.4%, while the one-worker median decreased
by 5.0%. Variation was larger than either difference. This run establishes no
throughput improvement from removing sink serialization on this SMB path.
The bounded concurrency regression test separately confirms that two disjoint
writes can enter the sink concurrently and that cancellation waits for writers.

Reproduction commands and support limits are in
[Mounted SMB shares](../../docs/mounted-shares.md).
