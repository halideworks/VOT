# strict_catches_backing_corruption

Passing control:

```text
running 1 test
test direct_read_detects_corruption_hidden_by_buffered_cache ... ok
test result: ok. 1 passed; 0 failed
```

The test primes an ext4 buffered file read, reloads the underlying dm-flakey
mapping with deterministic read-bio corruption, and requires the strict reader
to reject the changed hash.

Mutant:

```diff
-let flags =
-    OFlags::RDONLY | OFlags::DIRECT | OFlags::CLOEXEC;
+let flags = OFlags::RDONLY | OFlags::CLOEXEC;
```

Observed failure:

```text
test direct_read_detects_corruption_hidden_by_buffered_cache ... FAILED
direct read returned cached bytes instead of backing corruption
test result: FAILED. 0 passed; 1 failed
```
