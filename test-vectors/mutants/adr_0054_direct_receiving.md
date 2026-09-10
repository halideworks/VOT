# ADR-0054 direct receiving rejection checks

Each temporary mutation below was applied to the implementation, rejected by its named test, and restored. Fixture paths were on the test volume.

## private namespace

File: `crates/vot-platform-fs/src/directory.rs`

```diff
-    pub fn require_private(&self) -> io::Result<()> {
+    pub fn require_private(&self) -> io::Result<()> {
+        return Ok(());
```

```text
running 1 test

thread 'directory::tests::private_children_and_regular_names_reject_substitution' (172) panicked at crates/vot-platform-fs/src/directory.rs:469:9:
assertion failed: directory.private_child(OsStr::new("shared")).is_err()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test directory::tests::private_children_and_regular_names_reject_substitution ... FAILED

failures:

failures:
    directory::tests::private_children_and_regular_names_reject_substitution

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-platform-fs --lib`
```

## mount guarantees

File: `crates/vot-platform-fs/src/nas.rs`

```diff
-    if has("ro")
+    if false && has("ro")
```

```text
running 1 test

thread 'nas::tests::qualification_requires_every_client_guarantee' (338) panicked at crates/vot-platform-fs/src/nas.rs:126:17:
assertion failed: validate_options(filesystem, &unsafe_options).is_err()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test nas::tests::qualification_requires_every_client_guarantee ... FAILED

failures:

failures:
    nas::tests::qualification_requires_every_client_guarantee

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-platform-fs --lib`
```

## admission binding

File: `crates/vot-commit-posix/src/lib.rs`

```diff
-.any(|record| record.payload != expected)
+.any(|_record| false)
```

```text
running 1 test

thread 'tests::reattach_binds_staging_and_both_parent_identities' (657) panicked at crates/vot-commit-posix/src/lib.rs:1296:13:
assertion failed: matches!(PosixCommit::reattach(Profile::Balanced, [4; 16], stage, destination,
    &root.join("journal"), NoFaults), Err(Error::AdmissionMismatch))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test tests::reattach_binds_staging_and_both_parent_identities ... FAILED

failures:

failures:
    tests::reattach_binds_staging_and_both_parent_identities

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 35 filtered out; finished in 0.19s

error: test failed, to rerun pass `-p vot-commit-posix --lib`
```

## retired journal

File: `crates/vot-journal/src/io_impl.rs`

```diff
-        renamed.inspect_err(|_| {
-            self.poisoned = true;
-        })?;
+        renamed?;
```

```text
running 1 test

thread 'tests::a_lost_compaction_acknowledgment_never_resumes_the_retired_inode' (783) panicked at crates/vot-journal/src/lib.rs:488:9:
assertion failed: journal.is_poisoned()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test tests::a_lost_compaction_acknowledgment_never_resumes_the_retired_inode ... FAILED

failures:

failures:
    tests::a_lost_compaction_acknowledgment_never_resumes_the_retired_inode

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 26 filtered out; finished in 0.09s

error: test failed, to rerun pass `-p vot-journal --lib`
```

## resume preservation

File: `crates/vot-sdk-file/src/lib.rs`

```diff
-                if !preserve_on_error {
+                if true {
```

```text
running 1 test

thread 'tests::resumed_backend_setup_failure_preserves_existing_bytes_and_journal' (1036) panicked at crates/vot-sdk-file/src/lib.rs:1119:13:
assertion `left == right` failed
  left: false
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test tests::resumed_backend_setup_failure_preserves_existing_bytes_and_journal ... FAILED

failures:

failures:
    tests::resumed_backend_setup_failure_preserves_existing_bytes_and_journal

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 25 filtered out; finished in 0.13s

error: test failed, to rerun pass `-p vot-sdk-file --lib`
```

## verified witness

File: `crates/vot-scheduler/src/receiver.rs`

```diff
-        sink.write_verified(&self.inner.as_slice())?;
+        sink.write_at(self.inner.covered_offset(), self.inner.data())?;
```

```text
running 1 test

thread 'tests::sinks_receive_the_verified_witness_on_every_placement_path' (420) panicked at crates/vot-scheduler/src/lib.rs:134:17:
verification witness was discarded
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test tests::sinks_receive_the_verified_witness_on_every_placement_path ... FAILED

failures:

failures:
    tests::sinks_receive_the_verified_witness_on_every_placement_path

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-scheduler --lib`
```

## counted witness

File: `crates/vot-cli/src/fetch/sink.rs`

```diff
-            sink.write_verified(verified)
+            sink.write_at(verified.covered_offset(), verified.data())
```

```text
running 1 test

thread 'fetch::sink::tests::counted_placement_preserves_the_witness_and_its_flush_failure' (1292) panicked at crates/vot-cli/src/fetch/sink.rs:320:17:
counting sink discarded the verification witness
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test fetch::sink::tests::counted_placement_preserves_the_witness_and_its_flush_failure ... FAILED

failures:

failures:
    fetch::sink::tests::counted_placement_preserves_the_witness_and_its_flush_failure

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 332 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-cli --lib`
```

## retained publication

File: `crates/vot-sdk-file/src/lib.rs`

```diff
-        self.publish_inner()
-    }
+        self.publish()
+    }
```

```text
running 1 test

thread 'publication_journal_survives_until_the_application_checkpoint' (1459) panicked at crates/vot-sdk-file/tests/shared_directory.rs:354:5:
assertion failed: journal.is_file()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test publication_journal_survives_until_the_application_checkpoint ... FAILED

failures:

failures:
    publication_journal_survives_until_the_application_checkpoint

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.02s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```

## repeated recovery

File: `crates/vot-sdk-file/src/directory.rs`

```diff
-        let receipt = commit.finish_recovered_publication().map_err(map_posix)?;
+        let receipt = commit.finish_recovered_publication().map_err(map_posix)?;
+        let _ = commit.cleanup_published();
```

```text
running 1 test

thread 'interrupted_publication_rechecks_content_and_preserves_conflicts' (1626) panicked at crates/vot-sdk-file/tests/shared_directory.rs:291:14:
called `Result::unwrap()` on an `Err` value: Error { kind: Io, io: Some(Os { code: 2, kind: NotFound, message: "No such file or directory" }) }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test interrupted_publication_rechecks_content_and_preserves_conflicts ... FAILED

failures:

failures:
    interrupted_publication_rechecks_content_and_preserves_conflicts

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.02s

error: test failed, to rerun pass `-p vot-sdk-file --test shared_directory`
```

## provider registration

File: `crates/vot-receipt/src/model.rs`

```diff
-        if !(1..=5).contains(&self.provider) {
+        if !(1..=4).contains(&self.provider) {
```

```text
running 1 test

thread 'tests::nas_provider_is_registered_and_authenticated' (1794) panicked at crates/vot-receipt/src/lib.rs:242:92:
called `Result::unwrap()` on an `Err` value: InvalidProvider
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test tests::nas_provider_is_registered_and_authenticated ... FAILED

failures:

failures:
    tests::nas_provider_is_registered_and_authenticated

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.00s

error: test failed, to rerun pass `-p vot-receipt --lib`
```
