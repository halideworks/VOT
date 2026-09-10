# Shared publication recovery cancellation mutants

Base: `5c89030cfd46cb2df4ed058829f0950cfabfb9b6`. Each change was applied separately and restored before the next run.

Command: `cargo +1.97.1 test -p vot-sdk-file --test shared_directory interrupted_publication_rechecks_content_and_preserves_conflicts --locked -- --exact`

## omit entry ownership check

```diff
--- a/crates/vot-sdk-file/src/directory.rs
+++ b/crates/vot-sdk-file/src/directory.rs
@@ -198,5 +198,4 @@
             }
         };
-        check_active()?;
         let mut commit = self.reopen_publication(name, state)?;
         let suite = vot_verifier::Suite::try_from(object.suite)
```

Exit status: `101`.

```text
---- interrupted_publication_rechecks_content_and_preserves_conflicts stdout ----

thread 'interrupted_publication_rechecks_content_and_preserves_conflicts' (2949229) panicked at crates/vot-sdk-file/tests/shared_directory.rs:352:5:
assertion `left == right` failed
  left: [86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 0, 0, 0, 0, 0, 0, 0, 0, 1, 83, 0, 0, 0, 1, 1, 0, 52, 0, 0, 0, 0, 0, 0, 0, 96, 50, 66, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 121, 49, 66, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 120, 49, 66, 0, 0, 0, 0, 0, 157, 138, 146, 83, 85, 163, 197, 251, 128, 196, 118, 23, 110, 94, 61, 199, 100, 223, 150, 196, 73, 123, 187, 38, 189, 186, 105, 245, 132, 34, 57, 78, 198, 9, 68, 209, 86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 171, 174, 62, 225, 86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 168, 137, 89, 136]
 right: [86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 0, 0, 0, 0, 0, 0, 0, 0, 1, 83, 0, 0, 0, 1, 1, 0, 52, 0, 0, 0, 0, 0, 0, 0, 96, 50, 66, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 121, 49, 66, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 120, 49, 66, 0, 0, 0, 0, 0, 157, 138, 146, 83, 85, 163, 197, 251, 128, 196, 118, 23, 110, 94, 61, 199, 100, 223, 150, 196, 73, 123, 187, 38, 189, 186, 105, 245, 132, 34, 57, 78, 198, 9, 68, 209, 86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 171, 174, 62, 225, 86, 79, 84, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 45, 0, 214, 19, 127, 115, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 168, 137, 89, 136, 128]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    interrupted_publication_rechecks_content_and_preserves_conflicts

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.01s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```

## omit bounded-read ownership check

```diff
--- a/crates/vot-sdk-file/src/directory.rs
+++ b/crates/vot-sdk-file/src/directory.rs
@@ -210,5 +210,4 @@
         let mut remaining = object.length;
         for _ in 0..object.length.div_ceil(buffer.len() as u64) {
-            check_active()?;
             let count = usize::try_from(remaining.min(buffer.len() as u64))
                 .map_err(|_| Error::plain(ErrorKind::Internal))?;
```

Exit status: `101`.

```text
---- interrupted_publication_rechecks_content_and_preserves_conflicts stdout ----

thread 'interrupted_publication_rechecks_content_and_preserves_conflicts' (2949467) panicked at crates/vot-sdk-file/tests/shared_directory.rs:362:14:
called `Result::unwrap_err()` on an `Ok` value: PublishObservation { incarnation: [3, 0, 0, 0, 0, 0, 0, 0, 90, 1, 45, 0, 59, 123, 143, 138], sequence: 6 }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    interrupted_publication_rechecks_content_and_preserves_conflicts

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.04s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```

## omit final ownership check

```diff
--- a/crates/vot-sdk-file/src/directory.rs
+++ b/crates/vot-sdk-file/src/directory.rs
@@ -229,5 +229,4 @@
             ))
             .map_err(|_| Error::plain(ErrorKind::IdentityMismatch))?;
-        check_active()?;
         let receipt = commit.finish_recovered_publication().map_err(map_posix)?;
         Ok(super::PublishObservation {
```

Exit status: `101`.

```text
---- interrupted_publication_rechecks_content_and_preserves_conflicts stdout ----

thread 'interrupted_publication_rechecks_content_and_preserves_conflicts' (2949652) panicked at crates/vot-sdk-file/tests/shared_directory.rs:362:14:
called `Result::unwrap_err()` on an `Ok` value: PublishObservation { incarnation: [0, 0, 0, 0, 0, 0, 0, 0, 19, 2, 45, 0, 99, 228, 169, 159], sequence: 6 }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    interrupted_publication_rechecks_content_and_preserves_conflicts

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.02s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```

## ignore cancellation callback

```diff
--- a/crates/vot-sdk-file/src/directory.rs
+++ b/crates/vot-sdk-file/src/directory.rs
@@ -189,5 +189,5 @@
     ) -> Result<super::PublishObservation, Error> {
         let check_active = || {
-            if active() {
+            if { let _ = &active; true } {
                 Ok(())
             } else {
```

Exit status: `101`.

```text
---- interrupted_publication_rechecks_content_and_preserves_conflicts stdout ----

thread 'interrupted_publication_rechecks_content_and_preserves_conflicts' (2949820) panicked at crates/vot-sdk-file/tests/shared_directory.rs:347:5:
assertion failed: namespace.recover_publication(object, OsStr::new("frame.exr"), &state,
        || false).is_err()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    interrupted_publication_rechecks_content_and_preserves_conflicts

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.01s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```
