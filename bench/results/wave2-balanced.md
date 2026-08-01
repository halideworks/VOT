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
- Docker rust:1.85
- `nvme-mirror` ZFS mirror on two 3.7 TB NVMe devices
- ZFS `sync=standard`, `compression=lz4`, `recordsize=128K`

Result:

- Journal disabled median: 1089.389 ms
- Balanced median: 1097.538 ms
- Measured overhead: 0.748%
- Gate: at most 5%
- Status: pass

Run:

```sh
VOT_BENCH_ROOT=/path/on/storage sh tools/run_storage_benchmark.sh
```

The wrapper refuses overlayfs and tmpfs. The executable exits with failure when
measured overhead exceeds 5%.
