# strict_readback_memory_bounded

Mutant:

```diff
-DIRECT_READ_BUFFER_BYTES
-    .div_ceil(self.alignment)
-    .checked_mul(self.alignment)
-    .ok_or(Error::BufferSizeOverflow)
+usize::try_from(self.logical_length).map_err(|_| Error::BufferSizeOverflow)
```

Observed failure for a declared 500 GiB object:

```text
assertion left == right failed
left: 536870912000
right: 1048576
test result: FAILED. 0 passed; 1 failed
```
