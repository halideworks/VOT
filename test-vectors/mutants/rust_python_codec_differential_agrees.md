# rust_python_codec_differential_agrees

The Rust codec oracle and independent Python decoder compare accept/reject
decisions and every parsed frame field over a fixed 10,000-case corpus.

Observed control:

```text
Rust/Python frame differential: PASS (10000 cases)
```

Mutant:

```diff
-frame_type & 1 == 1
+frame_type & 1 == 0
```

Observed failure:

```text
AssertionError: case 8 differs: input=0600fa11... python=err|INCOMPLETE rust=err|UNKNOWN_CRITICAL_FRAME
```

The mutant exited with status 1. The production check was restored and the
10,000-case corpus passed again.
