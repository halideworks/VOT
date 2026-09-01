# ADR-0046 parallel acceptance

Criterion: disjoint verified ranges write and commit concurrently through
`NativeFile::accept(&self)`; a failed write poisons the commit, releases its
reservation, and every later accept refuses; a range whose bytes landed
while another thread poisoned the commit is released, never committed.

The following minimal mutants were applied independently and reverted. Each
named test failed.

## A failed write must release, never commit

```diff
             Err(error) => {
-                shared.coverage.release_reservation(reservation);
+                shared.coverage.commit_reservation(reservation);
```

`cargo +1.97.1 test -p vot-sdk-file --locked a_failed_write_under_concurrency`

```text
thread 'tests::a_failed_write_under_concurrency_poisons_and_releases_its_range' panicked at crates/vot-sdk-file/src/lib.rs:1106:9:
assertion `left == right` failed
  left: 65536
 right: 0
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 17 filtered out
```

## Accept must observe the poisoned state on entry

```diff
         match backend.commit.state() {
-            vot_commit_model::State::Poisoned => Err(map_posix(vot_commit_posix::Error::Poisoned)),
+            vot_commit_model::State::Poisoned => Ok(()),
             vot_commit_model::State::Admitted => Ok(()),
```

`cargo +1.97.1 test -p vot-sdk-file --locked a_failed_write_under_concurrency`

```text
thread '<unnamed>' panicked at crates/vot-sdk-file/src/lib.rs:1115:58:
called `Result::unwrap_err()` on an `Ok` value: Acceptance { status: Accepted, progress: Progress { covered_bytes: 65536, prefix_bytes: 65536, total_bytes: 131072, fragments: 1 } }
thread '<unnamed>' panicked at crates/vot-sdk-file/src/lib.rs:1115:58:
called `Result::unwrap_err()` on an `Ok` value: Acceptance { status: Accepted, progress: Progress { covered_bytes: 131072, prefix_bytes: 131072, total_bytes: 131072, fragments: 1 } }
thread 'tests::a_failed_write_under_concurrency_poisons_and_releases_its_range' panicked at crates/vot-sdk-file/src/lib.rs:1110:9:
a scoped thread panicked
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 17 filtered out
```

## A landed write must re-check the poison before committing

```diff
-                if let Err(error) = Self::ensure_accepting(&shared) {
-                    shared.coverage.release_reservation(reservation);
-                    return Err(error);
-                }
-                shared.coverage.commit_reservation(reservation);
+                shared.coverage.commit_reservation(reservation);
```

`cargo +1.97.1 test -p vot-sdk-file --locked a_poison_landing_mid_write`

```text
thread 'tests::a_poison_landing_mid_write_releases_the_landed_range' panicked at crates/vot-sdk-file/src/lib.rs:1070:50:
called `Result::unwrap_err()` on an `Ok` value: Acceptance { status: Accepted, progress: Progress { covered_bytes: 65536, prefix_bytes: 65536, total_bytes: 131072, fragments: 1 } }
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 17 filtered out
```
