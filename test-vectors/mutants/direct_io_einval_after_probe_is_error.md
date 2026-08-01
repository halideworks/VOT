# direct_io_einval_after_probe_is_error

`LinuxDirectReader::open` performs one aligned direct read at offset zero and
caches whether the backend supports direct I/O. Capability-probe `EINVAL`,
`EOPNOTSUPP`, and `ENOSYS` produce `Unsupported`. Once the probe succeeds, every
read error, including `EINVAL`, is returned as `Error::Io`.

Mutant:

```diff
-fn post_probe_io_error(error: std::io::Error) -> Error {
-    Error::Io(error)
+fn post_probe_io_error(_error: std::io::Error) -> Error {
+    Error::HashMismatch
 }
```

Observed failure:

```text
test tests::direct_flags_and_capability_classification_are_exact ... FAILED
assertion failed: matches!(post_probe_io_error(...), Error::Io(error) if ...)
test result: FAILED. 6 passed; 1 failed
```

This prevents a later alignment or length defect from being reclassified as a
backend capability limitation.
