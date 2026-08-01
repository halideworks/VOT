# million_file_index_memory_bounded

The integration test installs a `cap::Cap` global allocator with a 512 MiB
hard limit, then indexes 1,000,000 two-component paths. The normal implementation
passed in 1.85 seconds.

Mutant:

```diff
 let mut index = ManifestIndex::with_capacity(1_000_000);
+let mut retained = Vec::with_capacity(1_000_000);
 ...
 index.push(&path, ...)?;
+retained.push(path);
```

Observed failure:

```text
memory allocation of 960 bytes failed
process did not exit successfully (signal: 6, SIGABRT)
```
