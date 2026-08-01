# no_unbounded_allocation

Both standalone fuzz targets install a 256 MiB capped global allocator. Their
input readers also stop at protocol-specific hard limits before parsing.

Mutant inserted into the frame fuzz target:

```diff
 fn main() -> io::Result<()> {
+    let _mutant = Vec::<u8>::with_capacity(ALLOCATION_LIMIT + 1);
```

Observed failure:

```text
memory allocation of 268435457 bytes failed
Aborted (core dumped)
```

The process exited with status 134. The mutant was removed.
