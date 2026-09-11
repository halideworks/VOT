# ADR-0055 file preparation mutants

Each mutation below was applied separately to `crates/vot-cli/src/package/prepare.rs`, tested with `cargo test -p vot-cli --lib package::prepare::tests`, and restored. The unmodified tests pass. Failure excerpts omit long leaf arrays.

## ordered-leaves

```diff
--- prepare.rs
+++ prepare.rs
@@ -107,5 +107,5 @@
                         .recv()
                         .map_err(|_| io::Error::other("preparation worker stopped"))?;
-                    leaves.extend(result.map_err(|_| Error::InvalidBundle)?);
+                    leaves.extend(result.map_err(|_| Error::InvalidBundle)?.into_iter().rev());
                     buffer
                 };
```

```text
failures:

---- package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns stdout ----

thread 'package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns' (321) panicked at crates/vot-cli/src/package/prepare.rs:175:17:
assertion `left == right` failed
[leaf array omitted]
[leaf array omitted]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns

test result: FAILED.
```

## complete-worker-drain

```diff
--- prepare.rs
+++ prepare.rs
@@ -98,5 +98,5 @@
             }
             // Consume completions in submission order; workers never seek the source.
-            for turn in 0..chunks + workers as u64 {
+            for turn in 0..chunks {
                 let lane = &lanes[usize::try_from(turn % workers as u64).unwrap()];
                 let mut buffer = if turn < workers as u64 {
```

```text
failures:

---- package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns stdout ----

thread 'package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns' (641) panicked at crates/vot-cli/src/package/prepare.rs:175:17:
assertion `left == right` failed
[leaf array omitted]
[leaf array omitted]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::preparation_preserves_both_suites_and_proofs_across_worker_turns

test result: FAILED.
```

## reject-extra-bytes

```diff
--- prepare.rs
+++ prepare.rs
@@ -131,5 +131,5 @@
         }
     }
-    if input.read(&mut [0])? != 0 {
+    if false {
         return Err(Error::SourceMutation);
     }
```

```text
failures:

---- package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers stdout ----

thread 'package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers' (962) panicked at crates/vot-cli/src/package/prepare.rs:209:17:
assertion failed: matches!(checked_read(Cursor::new(vec![7;
    usize::try_from(observed).unwrap()]), Suite::Blake3Bao64, length,
    workers), Err(Error::SourceMutation))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers

test result: FAILED.
```

## reject-short-read

```diff
--- prepare.rs
+++ prepare.rs
@@ -65,5 +65,5 @@
     input.read_exact(buffer).map_err(|error| {
         if error.kind() == io::ErrorKind::UnexpectedEof {
-            Error::SourceMutation
+            Error::InvalidArguments
         } else {
             Error::Io(error)
```

```text
failures:

---- package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers stdout ----

thread 'package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers' (1282) panicked at crates/vot-cli/src/package/prepare.rs:209:17:
assertion failed: matches!(checked_read(Cursor::new(vec![7;
    usize::try_from(observed).unwrap()]), Suite::Blake3Bao64, length,
    workers), Err(Error::SourceMutation))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::preparation_rejects_short_long_and_failed_reads_without_stranding_workers

test result: FAILED.
```

## admit-length-before-read

```diff
--- prepare.rs
+++ prepare.rs
@@ -35,5 +35,5 @@
         return Err(Error::InvalidArguments);
     }
-    if metadata.len() != expected_length {
+    if false {
         return Err(Error::SourceMutation);
     }
```

```text
failures:

---- package::prepare::tests::file_preparation_checks_length_and_starts_at_zero stdout ----

thread 'package::prepare::tests::file_preparation_checks_length_and_starts_at_zero' (1598) panicked at crates/vot-cli/src/package/prepare.rs:250:13:
assertion `left == right` failed: reject before reading
  left: 65553
 right: 0
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::file_preparation_checks_length_and_starts_at_zero

test result: FAILED.
```

## seek-source-start

```diff
--- prepare.rs
+++ prepare.rs
@@ -38,5 +38,5 @@
         return Err(Error::SourceMutation);
     }
-    input.seek(SeekFrom::Start(0))?;
+    input.seek(SeekFrom::Current(0))?;
     let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
     let leaves = read_leaves(
```

```text
failures:

---- package::prepare::tests::file_preparation_checks_length_and_starts_at_zero stdout ----

thread 'package::prepare::tests::file_preparation_checks_length_and_starts_at_zero' (1932) panicked at crates/vot-cli/src/package/prepare.rs:253:92:
called `Result::unwrap()` on an `Err` value: SourceMutation
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::file_preparation_checks_length_and_starts_at_zero

test result: FAILED.
```

## minimum-object-length

```diff
--- prepare.rs
+++ prepare.rs
@@ -28,5 +28,5 @@
     expected_length: u64,
 ) -> Result<Vec<[u8; 32]>, Error> {
-    if !(PROOF_LEAF_SIZE + 1..=MAX_OBJECT_LENGTH).contains(&expected_length) {
+    if !(PROOF_LEAF_SIZE..=MAX_OBJECT_LENGTH).contains(&expected_length) {
         return Err(Error::InvalidArguments);
     }
```

```text
failures:

---- package::prepare::tests::file_preparation_checks_length_and_starts_at_zero stdout ----

thread 'package::prepare::tests::file_preparation_checks_length_and_starts_at_zero' (2266) panicked at crates/vot-cli/src/package/prepare.rs:240:13:
assertion failed: matches!(file_proof_leaves(&mut input, Suite::Blake3Bao64, length),
    Err(Error::InvalidArguments))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::file_preparation_checks_length_and_starts_at_zero

test result: FAILED.
```

## regular-files-only

```diff
--- prepare.rs
+++ prepare.rs
@@ -32,5 +32,5 @@
     }
     let metadata = input.metadata()?;
-    if !metadata.is_file() {
+    if false {
         return Err(Error::InvalidArguments);
     }
```

```text
failures:

---- package::prepare::tests::file_preparation_rejects_a_directory stdout ----

thread 'package::prepare::tests::file_preparation_rejects_a_directory' (2601) panicked at crates/vot-cli/src/package/prepare.rs:267:9:
assertion failed: matches!(file_proof_leaves(&mut input, Suite::Blake3Bao64, PROOF_LEAF_SIZE +
    1), Err(Error::InvalidArguments))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::file_preparation_rejects_a_directory

test result: FAILED.
```

## small-file-threshold

```diff
--- prepare.rs
+++ prepare.rs
@@ -50,5 +50,5 @@

 pub(crate) fn parallel_preparation(length: u64) -> bool {
-    length >= PARALLEL_PREPARATION_MIN_BYTES
+    length > PARALLEL_PREPARATION_MIN_BYTES
 }

```

```text
failures:

---- package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers stdout ----

thread 'package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers' (2938) panicked at crates/vot-cli/src/package/prepare.rs:276:9:
assertion `left == right` failed
  left: None
 right: Some(8)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers

test result: FAILED.
```

## worker-limit

```diff
--- prepare.rs
+++ prepare.rs
@@ -57,5 +57,5 @@
         None
     } else {
-        Some(available.min(8))
+        Some(available.min(9))
     }
 }
```

```text
failures:

---- package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers stdout ----

thread 'package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers' (3272) panicked at crates/vot-cli/src/package/prepare.rs:276:9:
assertion `left == right` failed
  left: Some(9)
 right: Some(8)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers

test result: FAILED.
```

## literal-threshold

```diff
--- prepare.rs
+++ prepare.rs
@@ -9,5 +9,5 @@
 use crate::{Error, Suite};

-const PARALLEL_PREPARATION_MIN_BYTES: u64 = 64 * 1024 * 1024;
+const PARALLEL_PREPARATION_MIN_BYTES: u64 = 64 * 1024 + 1024;
 const STEP: usize = 1024 * 1024;

```

```text
failures:

---- package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers stdout ----

thread 'package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers' (3606) panicked at crates/vot-cli/src/package/prepare.rs:275:9:
assertion `left == right` failed
  left: Some(8)
 right: None
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers

test result: FAILED.
```

## inline-on-one-core

```diff
--- prepare.rs
+++ prepare.rs
@@ -54,5 +54,5 @@

 fn worker_count(length: u64, available: usize) -> Option<usize> {
-    if !parallel_preparation(length) || available < 2 {
+    if !parallel_preparation(length) || available < 1 {
         None
     } else {
```

```text
failures:

---- package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers stdout ----

thread 'package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers' (3940) panicked at crates/vot-cli/src/package/prepare.rs:285:13:
assertion `left == right` failed
  left: Some(1)
 right: None
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    package::prepare::tests::small_sources_stay_inline_and_large_sources_cap_workers

test result: FAILED.
```
