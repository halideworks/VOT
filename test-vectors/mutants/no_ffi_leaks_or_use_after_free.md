# no_FFI_leaks_or_use_after_free

The live localhost transfer runs under Rust nightly AddressSanitizer with leak
detection enabled. It sends an owned 192 KiB buffer, reclaims it exactly once on
`SendComplete`, and waits for stream, connection, and listener shutdown before
closing the registration.

Mutant:

```diff
-let _ = unsafe { Box::from_raw(context.cast_mut().cast::<SendBuffer>()) };
+return;
```

Observed failure before restoring reclamation:

```text
ERROR: LeakSanitizer: detected memory leaks
Direct leak of 196656 byte(s) in 1 object(s)
SUMMARY: AddressSanitizer: 196656 byte(s) leaked in 1 allocation(s).
```

quictls retains its process-global provider registry until OpenSSL process
cleanup. The job suppresses only allocations rooted at `CRYPTO_zalloc`, after
resolving the retained native offsets with `addr2line`. VOT callback contexts,
send buffers, MsQuic handles, and all other native allocation roots remain
unsuppressed.
