# grease_and_unknown_frame_tests

The codec asserts the complete grease range and parity rule, skips grease and
unknown optional frames, and rejects unknown critical frames before consuming
their payload. The independent Rust/Python differential corpus also compares
unknown-frame decisions.

Grease mutant:

```diff
 pub const fn is_grease(frame_type: u64) -> bool {
-    frame_type >= 0x1f00 && frame_type <= 0x1ffe && frame_type & 1 == 0
+    false
 }
```

The original named test survived because even grease IDs also classify as
unknown optional frames. Exact predicate assertions were added.

Observed failure after correcting the gate:

```text
tests::grease_is_tolerated --- FAILED
assertion failed: is_grease(0x1f00)
test result: FAILED. 0 passed; 1 failed
```

Unknown critical handling is independently falsified in
`rust_python_codec_differential_agrees.md`.
