# balanced_overhead_percent_lte_5

The seven-sample 256 MiB benchmark ran on the `nvme-mirror` ZFS mirror backed by
two physical NVMe devices. The storage wrapper refuses overlayfs and tmpfs.

Observed control:

```text
storage filesystem: zfs
{"size_mib":256,"iterations":7,"baseline_median_ms":1089.389,"balanced_median_ms":1097.538,"overhead_percent":0.748}
```

Mutant inserted before the Balanced durability path:

```diff
 fn prepare_durable(&mut self) -> Result<(), Error> {
+    std::thread::sleep(std::time::Duration::from_millis(100));
```

Observed failure:

```text
{"size_mib":256,"iterations":7,"baseline_median_ms":1087.334,"balanced_median_ms":1197.910,"overhead_percent":10.169}
```

The benchmark exited with status 1. The mutant was removed.
