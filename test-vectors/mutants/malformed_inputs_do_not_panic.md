# malformed_inputs_do_not_panic

The standalone frame and manifest fuzz drivers accept bounded stdin and return
normally for malformed input. The codec and manifest crates also run fixed
deterministic mutation corpora in unit tests.

Mutant:

```diff
-if let Ok(frames) = decode_all(&input, limits) {
+let frames = decode_all(&input, limits).unwrap();
```

Observed failure for the input `malformed`:

```text
thread 'main' panicked at src/main.rs:26:45:
called `Result::unwrap()` on an `Err` value: UnknownCritical(11617)
```

The process exited with status 101. The mutant was removed and both fuzz-driver
smoke runs returned status 0.
