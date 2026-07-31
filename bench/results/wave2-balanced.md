# Wave 2 Balanced commit benchmark

Date: 2026-07-31

The clean-path workload writes and verifies one 256 MiB object. Both paths
compute CRC32C, write the object, flush the data file, publish with a hard link,
and flush the parent directory. The Balanced path additionally writes and
flushes its transition journal. Strict read-back is not included.

The benchmark ran seven interleaved samples and compares medians.

Environment:

- Linux 6.8.0-110-generic
- x86_64
- Docker rust:1.85.0-bookworm
- overlayfs temporary storage

Result:

- Journal disabled median: 1101.760 ms
- Balanced median: 1106.528 ms
- Measured overhead: 0.433%
- Gate: at most 5%
- Status: pass

Run:

```sh
cargo run --release --locked -p vot-commit-posix \
  --example measure_balanced -- 256 7
```

The executable exits with failure when measured overhead exceeds 5%.
