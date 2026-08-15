//! Persistent carrier-neutral resume state and RFC 9959 Careful Resume policy.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vot_transport_api::{PathStats, SubjectId};

pub mod units;
pub use units::UnitRanges;
use vot_transport_tcp::Carrier;

mod careful;
mod carrier;
mod store;
mod tracker;

pub use careful::*;
pub use carrier::*;
pub use store::*;
pub use tracker::*;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Corrupt,
    TooLarge,
    InvalidConfiguration,
    InvalidUnit,
    UnitAlreadyActive,
    UnitNotActive,
    CheckpointRequired,
    IdentityMismatch,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(byte: u8) -> SubjectId {
        SubjectId::new(1, [byte; 32], 100).unwrap()
    }

    /// Builds a checkpoint set from individual units, as the tests think of them.
    fn units(units: impl IntoIterator<Item = u64>) -> UnitRanges {
        let mut set = UnitRanges::new();
        set.extend_units(units);
        set
    }

    /// A store path that takes its own files with it.
    ///
    /// Every one of these names three files, and a test that removed only
    /// the store left the lock behind. One sweep runs the suite once per
    /// mutant, so a lock per test per mutant is thousands of files in the
    /// shared temp directory, which is what has killed mutation runners here
    /// before. Cleaning up in a `Drop` is the only version of this a later
    /// test cannot forget.
    struct TempStore(PathBuf);

    impl std::ops::Deref for TempStore {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TempStore {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<std::ffi::OsStr> for TempStore {
        fn as_ref(&self) -> &std::ffi::OsStr {
            self.0.as_os_str()
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            if let Ok(lock) = lock_path(&self.0) {
                let _ = fs::remove_file(lock);
            }
            if let Ok(temporary) = temporary_path(&self.0) {
                let _ = fs::remove_file(temporary);
            }
        }
    }

    fn temp_path(name: &str) -> TempStore {
        TempStore(std::env::temp_dir().join(format!(
            "vot-resume-{name}-{}-{}",
            std::process::id(),
            subject(name.as_bytes()[0]).root()[0]
        )))
    }

    fn write_raw(path: &Path, payload: &[u8]) {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&encode_record(payload).unwrap());
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn checkpoints_accumulate_under_identity_and_subjects_enumerate() {
        let path = temp_path("accumulate");
        let _ = fs::remove_file(&path);
        let mut store = ResumeStore::create(&path).unwrap();
        store
            .reserve_many([(subject(0x31), 4), (subject(0x32), 2)])
            .unwrap();
        store
            .checkpoint_units(subject(0x31), 4, &units([0, 2]))
            .unwrap();
        store
            .checkpoint_units(subject(0x31), 4, &units([1]))
            .unwrap();
        drop(store);
        let mut store = ResumeStore::open(&path).unwrap();
        assert_eq!(
            store.checkpointed(subject(0x31)).unwrap(),
            &units([0, 1, 2]),
            "unions accumulate across calls and reopens"
        );
        assert_eq!(
            store.subjects().collect::<Vec<_>>(),
            vec![subject(0x31), subject(0x32)],
            "every reserved subject, in key order"
        );
        assert!(matches!(
            store.checkpoint_units(subject(0x31), 5, &units([3])),
            Err(Error::IdentityMismatch)
        ));
        assert!(matches!(
            store.checkpoint_units(subject(0x33), 4, &units([0])),
            Err(Error::IdentityMismatch)
        ));
        assert!(matches!(
            store.checkpoint_units(subject(0x31), 4, &units([4])),
            Err(Error::InvalidUnit)
        ));
        store.remove().unwrap();
    }

    #[test]
    fn a_reset_clears_the_checkpoint_and_keeps_the_reservation() {
        let path = temp_path("reset");
        let _ = fs::remove_file(&path);
        let mut store = ResumeStore::create(&path).unwrap();
        store.reserve_many([(subject(0x41), 4)]).unwrap();
        store
            .checkpoint_units(subject(0x41), 4, &units([0, 1, 2, 3]))
            .unwrap();
        store.reset(subject(0x41)).unwrap();
        drop(store);
        let mut store = ResumeStore::open(&path).unwrap();
        assert!(
            store.checkpointed(subject(0x41)).unwrap().is_empty(),
            "the claim is gone across a reopen"
        );
        store
            .checkpoint_units(subject(0x41), 4, &units([1]))
            .unwrap();
        assert_eq!(
            store.checkpointed(subject(0x41)).unwrap(),
            &units([1]),
            "the reservation survived and checkpoints again"
        );
        store.reset(subject(0x42)).unwrap();
        store.reset(subject(0x41)).unwrap();
        store.reset(subject(0x41)).unwrap();
        assert!(store.checkpointed(subject(0x41)).unwrap().is_empty());
        store.remove().unwrap();
    }

    #[test]
    fn a_created_store_exists_at_once_and_a_removed_one_is_gone_whole() {
        let path = temp_path("created");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path(&path).unwrap());

        let store = ResumeStore::create(&path).unwrap();
        assert!(path.exists(), "created means on disk, empty or not");
        drop(store);
        let mut store = ResumeStore::create(&path).unwrap();
        store.reserve_many([(subject(0x21), 4)]).unwrap();
        drop(store);
        let store = ResumeStore::create(&path).unwrap();
        assert!(
            store.checkpointed(subject(0x21)).is_some(),
            "creation over an existing store reopened it"
        );

        store.remove().unwrap();
        assert!(!path.exists(), "the store is gone");
        assert!(
            lock_path(&path).unwrap().exists(),
            "and its lock stayed, so the name keeps meaning one inode"
        );
        ResumeStore::create(&path)
            .unwrap()
            .remove_unshared()
            .unwrap();
        assert!(
            !lock_path(&path).unwrap().exists(),
            "a sole user takes the lock file too"
        );
        ResumeStore::create(&path).unwrap().remove().unwrap();
        ResumeStore::open(&path).unwrap().remove().unwrap();

        let store = ResumeStore::create(&path).unwrap();
        fs::create_dir(temporary_path(&path).unwrap()).unwrap();
        fs::write(temporary_path(&path).unwrap().join("held"), b"x").unwrap();
        assert!(
            store.remove().is_err(),
            "a temporary that will not go is not swallowed"
        );
        fs::remove_dir_all(temporary_path(&path).unwrap()).unwrap();
        ResumeStore::open(&path).unwrap().remove().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn store_is_keyed_by_subject_and_rejects_corruption() {
        let path = temp_path("store");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(1), 10, 3).unwrap();
        tracker.begin_unit(0).unwrap();
        tracker.complete_unit(0).unwrap();
        tracker.checkpoint(&mut store).unwrap();
        let mut reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject(1)).unwrap().contains(0));
        assert!(reopened.checkpointed(subject(9)).is_none());
        assert!(matches!(
            ResumeTracker::discover(&mut reopened, subject(1), 11, 3),
            Err(Error::IdentityMismatch)
        ));
        let mut rediscovered = ResumeTracker::discover(&mut reopened, subject(1), 10, 3).unwrap();
        assert!(!rediscovered.begin_unit(0).unwrap());
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn torn_final_record_is_truncated_and_valid_prefix_replayed() {
        let path = temp_path("torn-tail");
        let mut store = ResumeStore::open(&path).unwrap();
        store.reserve_many([(subject(11), 3)]).unwrap();
        let valid_length = fs::metadata(&path).unwrap().len();
        let torn_record = encode_record(&encode_reserve(subject(12), 3).unwrap()).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&torn_record[..torn_record.len() - 1]);
        fs::write(&path, bytes).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject(11)).is_some());
        assert!(reopened.checkpointed(subject(12)).is_none());
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_length);

        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&[0, 0]);
        fs::write(&path, bytes).unwrap();
        ResumeStore::open(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_length);

        let exact_header_path = temp_path("torn-header-boundary");
        let mut exact_header = MAGIC.to_vec();
        exact_header.extend_from_slice(&vec![0; RECORD_HEADER_BYTES as usize - 1]);
        fs::write(&exact_header_path, exact_header).unwrap();
        let reopened = ResumeStore::open(&exact_header_path).unwrap();
        assert!(reopened.objects.is_empty());
        assert_eq!(
            fs::metadata(&exact_header_path).unwrap().len(),
            MAGIC.len() as u64
        );
        fs::remove_file(&exact_header_path).unwrap();
        fs::remove_file(lock_path(&exact_header_path).unwrap()).unwrap();

        let zero_header_path = temp_path("zero-length-header");
        let mut zero_header = MAGIC.to_vec();
        zero_header.extend_from_slice(&vec![0; RECORD_HEADER_BYTES as usize]);
        fs::write(&zero_header_path, zero_header).unwrap();
        assert!(matches!(
            ResumeStore::open(&zero_header_path),
            Err(Error::Corrupt)
        ));
        fs::remove_file(&zero_header_path).unwrap();
        fs::remove_file(lock_path(&zero_header_path).unwrap()).unwrap();

        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn retransmission_is_bounded_by_window_plus_active_units() {
        let path = temp_path("bounded");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(2), 20, 4).unwrap();
        for unit in 0..7 {
            tracker.begin_unit(unit).unwrap();
            let checkpoint_due = tracker.complete_unit(unit).unwrap();
            assert!(!tracker.begin_unit(unit).unwrap());
            if checkpoint_due {
                tracker.checkpoint(&mut store).unwrap();
            }
        }
        tracker.begin_unit(7).unwrap();
        tracker.begin_unit(8).unwrap();
        assert_eq!(tracker.retransmission_units_after_crash(), 5);
        assert_eq!(tracker.retransmission_bound(), 6);
        assert!(tracker.retransmission_units_after_crash() <= tracker.retransmission_bound());

        let mut reopened = ResumeStore::open(&path).unwrap();
        let restarted = ResumeTracker::discover(&mut reopened, subject(2), 20, 4).unwrap();
        for unit in 0..4 {
            assert!(restarted.is_checkpointed(unit));
        }
        assert_eq!(restarted.missing_units().take(21).count(), 16);
        assert_eq!(
            restarted.missing_units().take(21).collect::<Vec<_>>(),
            (4..20).collect::<Vec<_>>()
        );
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn full_window_blocks_completion_until_checkpoint_succeeds() {
        let path = temp_path("full-window");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(7), 4, 2).unwrap();
        for unit in 0..3 {
            tracker.begin_unit(unit).unwrap();
        }
        assert!(!tracker.complete_unit(0).unwrap());
        assert!(tracker.complete_unit(1).unwrap());
        assert!(matches!(
            tracker.complete_unit(2),
            Err(Error::CheckpointRequired)
        ));
        assert_eq!(tracker.retransmission_units_after_crash(), 3);
        assert_eq!(tracker.retransmission_bound(), 3);
        tracker.checkpoint(&mut store).unwrap();
        assert!(!tracker.complete_unit(2).unwrap());
        assert_eq!(tracker.retransmission_units_after_crash(), 1);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn repeated_checkpoints_append_and_replay() {
        let path = temp_path("repeated-checkpoint");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(8), 3, 1).unwrap();
        tracker.begin_unit(0).unwrap();
        assert!(tracker.complete_unit(0).unwrap());
        tracker.checkpoint(&mut store).unwrap();
        tracker.begin_unit(1).unwrap();
        assert!(tracker.complete_unit(1).unwrap());
        tracker.checkpoint(&mut store).unwrap();
        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject(8)).unwrap(), &units([0, 1]));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn stale_store_writers_reload_and_merge_checkpointed_units() {
        let path = temp_path("merged-checkpoints");
        let mut first_store = ResumeStore::open(&path).unwrap();
        let mut second_store = ResumeStore::open(&path).unwrap();
        let mut first = ResumeTracker::discover(&mut first_store, subject(9), 3, 1).unwrap();
        let mut second = ResumeTracker::discover(&mut second_store, subject(9), 3, 1).unwrap();
        first.begin_unit(0).unwrap();
        first.complete_unit(0).unwrap();
        second.begin_unit(1).unwrap();
        second.complete_unit(1).unwrap();

        first.checkpoint(&mut first_store).unwrap();
        second.checkpoint(&mut second_store).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject(9)).unwrap(), &units([0, 1]));
        assert!(second.is_checkpointed(0));
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn checkpoint_waits_for_the_store_transaction_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let path = temp_path("checkpoint-lock");
        let mut store = ResumeStore::open(&path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(10), 1, 1).unwrap();
        let held = lock_store(&path).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            tracker.begin_unit(0).unwrap();
            tracker.complete_unit(0).unwrap();
            started_tx.send(()).unwrap();
            finished_tx.send(tracker.checkpoint(&mut store)).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        drop(held);
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn removing_a_store_that_is_already_gone_is_not_a_failure() {
        let path = temp_path("remove-absent");
        // Nothing there at all: no store, no lock, nothing to lock against.
        assert!(!path.exists());
        remove_files(&path, true).unwrap();
        assert!(
            !lock_path(&path).unwrap().exists(),
            "removal minted the lock file it was asked to delete"
        );

        // And a whole directory that has gone, which is what a caller tearing
        // down a fetch whose output was deleted underneath it sees.
        let vanished = std::env::temp_dir()
            .join("vot-resume-no-such-dir")
            .join("s");
        remove_files(&vanished, true).unwrap();
    }

    #[test]
    fn a_lock_that_cannot_be_opened_is_not_read_as_absent() {
        // A name no platform will open, and not because it is missing: an
        // interior NUL is invalid input everywhere, where "a component of the
        // path is a file" is NotADirectory on Unix and NotFound on Windows,
        // which is the arm this test exists to rule out. Treating any failure
        // as "no lock file" would remove a store somebody is holding.
        let unopenable = Path::new("vot-resume-\0-lock");
        assert!(matches!(held_lock(unopenable), Err(Error::Io(_))));
    }

    #[test]
    fn a_removal_that_fails_keeps_the_lock_file() {
        let path = temp_path("remove-keeps-lock");
        let store = ResumeStore::create(&path).unwrap();
        drop(store);
        // A temporary that will not go, so the removal fails part way.
        let temporary = temporary_path(&path).unwrap();
        fs::create_dir(&temporary).unwrap();
        fs::write(temporary.join("held"), b"x").unwrap();

        assert!(remove_files(&path, true).is_err());
        assert!(
            lock_path(&path).unwrap().exists(),
            "a failed removal took the lock with it"
        );
        fs::remove_file(temporary.join("held")).unwrap();
        fs::remove_dir(&temporary).unwrap();
    }

    #[test]
    fn removal_waits_for_the_store_transaction_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let path = temp_path("remove-lock");
        let mut store = ResumeStore::open(&path).unwrap();
        store.reserve_many([(subject(10), 1)]).unwrap();
        let held = lock_store(&path).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let remover = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx.send(store.remove()).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            matches!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(RecvTimeoutError::Timeout)
            ),
            "removal ran while a transaction held the lock"
        );
        drop(held);
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        remover.join().unwrap();
        assert!(!path.exists());
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    // The hazard is a POSIX one: unlinking a locked name leaves the lock
    // held on an inode nothing else can reach. Windows refuses the unlink
    // outright, so there is nothing to check there.
    #[cfg(unix)]
    #[test]
    fn removal_keeps_the_lock_inode_so_two_writers_cannot_split() {
        use std::os::unix::fs::MetadataExt;

        let path = temp_path("remove-lock-inode");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path(&path).unwrap());

        let store = ResumeStore::create(&path).unwrap();
        let before = fs::metadata(lock_path(&path).unwrap()).unwrap().ino();
        store.remove().unwrap();
        let after = fs::metadata(lock_path(&path).unwrap()).unwrap().ino();
        assert_eq!(
            before, after,
            "removal replaced the lock, so a writer holding the old inode would not block the next one"
        );
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn open_waits_for_the_store_transaction_lock() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        let path = temp_path("open-lock");
        let mut store = ResumeStore::open(&path).unwrap();
        store.reserve_many([(subject(10), 1)]).unwrap();
        let held = lock_store(&path).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let open_path = path.to_path_buf();
        let reader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx.send(ResumeStore::open(open_path)).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        drop(held);
        let reopened = finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert!(reopened.checkpointed(subject(10)).is_some());
        reader.join().unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn store_and_unit_bounds_are_exact_and_checkpoint_failure_is_atomic() {
        assert_eq!(MAX_STORE_BYTES, 67_108_864);
        assert_eq!(MAX_STORE_PAYLOAD_BYTES, 67_108_844);
        assert_eq!(MIN_STORE_BYTES, 8);
        assert_eq!(MAX_UNITS_PER_OBJECT, 16_777_198);
        assert!(validate_payload_length(MAX_STORE_PAYLOAD_BYTES).is_ok());
        assert!(matches!(
            validate_payload_length(MAX_STORE_PAYLOAD_BYTES + 1),
            Err(Error::TooLarge)
        ));
        let bounded = temp_path("bounded-read");
        fs::write(&bounded, b"12345").unwrap();
        assert_eq!(read_bounded_store(&bounded, 5).unwrap(), b"12345");
        assert!(matches!(
            read_bounded_store(&bounded, 4),
            Err(Error::TooLarge)
        ));
        fs::write(
            &bounded,
            vec![0; usize::try_from(MIN_STORE_BYTES - 1).unwrap()],
        )
        .unwrap();
        assert!(matches!(ResumeStore::open(&bounded), Err(Error::Corrupt)));
        fs::remove_file(bounded).unwrap();

        let missing_root = temp_path("missing-parent");
        fs::create_dir(&missing_root).unwrap();
        let missing_parent = missing_root.join("state");
        let mut store = ResumeStore::open(&missing_parent).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(3), 1, 1).unwrap();
        fs::remove_file(&missing_parent).unwrap();
        fs::remove_file(lock_path(&missing_parent).unwrap()).unwrap();
        fs::remove_dir(&missing_root).unwrap();
        tracker.begin_unit(0).unwrap();
        tracker.complete_unit(0).unwrap();
        assert!(matches!(tracker.checkpoint(&mut store), Err(Error::Io(_))));
        assert_eq!(tracker.retransmission_units_after_crash(), 1);
        assert!(!tracker.is_checkpointed(0));

        let bounds_path = temp_path("bounds");
        let mut store = ResumeStore::open(&bounds_path).unwrap();
        assert!(matches!(
            ResumeTracker::discover(&mut store, subject(4), 0, 1),
            Err(Error::InvalidConfiguration)
        ));
        assert!(ResumeTracker::discover(&mut store, subject(4), MAX_UNITS_PER_OBJECT, 1).is_ok());
        assert!(matches!(
            ResumeTracker::discover(&mut store, subject(4), MAX_UNITS_PER_OBJECT + 1, 1),
            Err(Error::InvalidConfiguration)
        ));
        fs::remove_file(&bounds_path).unwrap();
        fs::remove_file(lock_path(&bounds_path).unwrap()).unwrap();

        let exact_path = temp_path("exact-bounds");
        let mut exact_store = ResumeStore::open(&exact_path).unwrap();
        assert!(matches!(
            ResumeTracker::discover(&mut exact_store, subject(6), 1, usize::MAX),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            ResumeTracker::discover(&mut exact_store, subject(6), 1, 2),
            Err(Error::InvalidConfiguration)
        ));
        let mut exact = ResumeTracker::discover(&mut exact_store, subject(6), 1, 1).unwrap();
        assert!(exact.begin_unit(0).unwrap());
        assert!(matches!(exact.begin_unit(1), Err(Error::InvalidUnit)));
        fs::remove_file(&exact_path).unwrap();
        fs::remove_file(lock_path(&exact_path).unwrap()).unwrap();
    }

    #[test]
    fn reservation_capacity_includes_worst_case_checkpoint_ranges() {
        let mut one = BTreeMap::new();
        one.insert(
            subject(17),
            StoredObject {
                total_units: MAX_UNITS_PER_OBJECT,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(validate_reserved_capacity(&one).is_ok());
        assert_eq!(worst_case_ranges_length(1), 3);
        assert_eq!(
            [
                uvarint_length(0),
                uvarint_length(127),
                uvarint_length(128),
                uvarint_length(16_383),
                uvarint_length(16_384),
                uvarint_length(u64::MAX),
            ],
            [1, 1, 2, 2, 3, 10]
        );

        let mut two = one.clone();
        two.insert(
            subject(18),
            StoredObject {
                total_units: MAX_UNITS_PER_OBJECT,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(matches!(
            validate_reserved_capacity(&two),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn max_units_per_object_is_derived_from_the_snapshot_format() {
        let ceiling = MAX_STORE_BYTES
            - MAGIC.len() as u64
            - RECORD_HEADER_BYTES
            - RECORD_CHECKSUM_BYTES
            - 1
            - uvarint_length(1);
        assert!(worst_case_object_payload_length(MAX_UNITS_PER_OBJECT).unwrap() <= ceiling);
        assert!(worst_case_object_payload_length(MAX_UNITS_PER_OBJECT + 1).unwrap() > ceiling);
        let max_object_bytes = MAX_UNITS_PER_OBJECT * 65_536;
        assert!(max_object_bytes < 1 << 40);
        assert!(max_object_bytes > (1 << 40) - (2 << 20));
    }

    #[test]
    fn resume_store_boundaries_are_explicit() {
        assert_eq!(COMPACTION_THRESHOLD, 50_331_648);
        assert!(store_size_fits(MAX_STORE_BYTES - 1));
        assert!(store_size_fits(MAX_STORE_BYTES));
        assert!(!store_size_fits(MAX_STORE_BYTES + 1));
        assert!(reserve_requires_compaction(false, COMPACTION_THRESHOLD - 1));
        assert!(!reserve_requires_compaction(true, COMPACTION_THRESHOLD - 1));
        assert!(reserve_requires_compaction(true, COMPACTION_THRESHOLD));
        assert!(!should_compact(COMPACTION_THRESHOLD - 1));
        assert!(should_compact(COMPACTION_THRESHOLD));
        assert!(append_fits(
            0,
            MAGIC.len() as u64,
            MAX_STORE_BYTES - MAGIC.len() as u64
        ));
        assert!(!append_fits(
            0,
            MAGIC.len() as u64,
            MAX_STORE_BYTES - MAGIC.len() as u64 + 1
        ));
        assert!(!append_fits(u64::MAX, 0, 1));
        assert_eq!(append_header_length(0), MAGIC.len() as u64);
        assert_eq!(append_header_length(1), 0);
        assert!(!record_length_valid(0));
        assert!(record_length_valid(1));
        assert!(record_length_valid(MAX_STORE_BYTES as usize));
        assert!(!record_length_valid(MAX_STORE_BYTES as usize + 1));
        assert!(compact_fits(MAX_STORE_BYTES - MAGIC.len() as u64));
        assert!(!compact_fits(MAX_STORE_BYTES - MAGIC.len() as u64 + 1));
        assert!(!compact_fits(u64::MAX));
        assert!(validate_checkpoint_window(1, 1).is_ok());
        assert!(matches!(
            validate_checkpoint_window(1, 0),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            validate_checkpoint_window(1, 2),
            Err(Error::InvalidConfiguration)
        ));
        let mut invalid_objects = BTreeMap::new();
        invalid_objects.insert(
            subject(15),
            StoredObject {
                total_units: 0,
                checkpointed: UnitRanges::new(),
            },
        );
        assert!(matches!(
            validate_reserved_capacity(&invalid_objects),
            Err(Error::InvalidConfiguration)
        ));
    }

    #[test]
    fn resume_codecs_round_trip() {
        let checkpointed = units([1, 2, 4, 7, 8]);
        let mut encoded_ranges = Vec::new();
        encode_ranges(&checkpointed, &mut encoded_ranges);
        let mut range_decoder = Decoder::new(&encoded_ranges);
        let decoded_ranges = decode_ranges(&mut range_decoder, 9).unwrap();
        assert!(range_decoder.is_empty());
        assert_eq!(decoded_ranges, checkpointed);
        assert_eq!(checkpointed.run_count(), 3);
        assert_eq!(encoded_ranges.first().copied(), Some(3));

        let mut encoded_varint = Vec::new();
        encode_uvarint(128, &mut encoded_varint);
        assert_eq!(encoded_varint, [0x80, 0x01]);
        encoded_varint.clear();
        encode_uvarint(255, &mut encoded_varint);
        assert_eq!(encoded_varint, [0xff, 0x01]);
        let mut valid_u64 = vec![0x80; 9];
        valid_u64.push(0x01);
        assert_eq!(Decoder::new(&valid_u64).uvar().unwrap(), 1_u64 << 63);
        let mut invalid_u64 = vec![0x80; 9];
        invalid_u64.push(0x02);
        assert!(matches!(
            Decoder::new(&invalid_u64).uvar(),
            Err(Error::Corrupt)
        ));

        let mut snapshot_objects = BTreeMap::new();
        snapshot_objects.insert(
            subject(11),
            StoredObject {
                total_units: 9,
                checkpointed: checkpointed.clone(),
            },
        );
        let snapshot = encode_snapshot(&snapshot_objects).unwrap();
        assert_eq!(snapshot.first().copied(), Some(SNAPSHOT_RECORD));
        let mut replayed_snapshot = BTreeMap::new();
        apply_record(&snapshot, &mut replayed_snapshot).unwrap();
        assert_eq!(settle(replayed_snapshot).unwrap(), snapshot_objects);

        let reserve = encode_reserve(subject(12), 42).unwrap();
        assert_eq!(reserve.first().copied(), Some(RESERVE_RECORD));
        let mut replayed_reserve = BTreeMap::new();
        apply_record(&reserve, &mut replayed_reserve).unwrap();
        assert_eq!(replayed_reserve[&subject(12)].total_units, 42);
        let conflicting_reserve = encode_reserve(subject(12), 43).unwrap();
        assert!(matches!(
            apply_record(&conflicting_reserve, &mut replayed_reserve),
            Err(Error::Corrupt)
        ));
    }

    #[test]
    fn resume_append_log_replays_and_preserves_errors() {
        let compact_path = temp_path("compact-codecs");
        let mut compact_objects = BTreeMap::new();
        compact_objects.insert(
            subject(14),
            StoredObject {
                total_units: 2,
                checkpointed: units([0]),
            },
        );
        ResumeStore::compact(&compact_path, &compact_objects).unwrap();
        assert!(compact_path.exists());
        assert_eq!(
            ResumeStore::open(&compact_path)
                .unwrap()
                .checkpointed(subject(14))
                .unwrap(),
            &units([0])
        );
        fs::remove_file(&compact_path).unwrap();

        let path = temp_path("append-codecs");
        let reserve = encode_reserve(subject(12), 42).unwrap();
        append_record(&path, &reserve).unwrap();
        let checkpoint = encode_checkpoint(subject(12), 42, &units([3])).unwrap();
        append_record(&path, &checkpoint).unwrap();
        let decoded_store = decode_store(&path).unwrap();
        assert_eq!(decoded_store[&subject(12)].checkpointed, units([3]));
        fs::remove_file(&path).unwrap();

        let alternating = units([0, 2, 4, 6, 8]);
        assert_eq!(alternating.run_count(), 5);
        let mut encoded_alternating = Vec::new();
        encode_ranges(&alternating, &mut encoded_alternating);
        assert_eq!(
            decode_ranges(&mut Decoder::new(&encoded_alternating), 9).unwrap(),
            alternating
        );

        let mut over_count = Vec::new();
        encode_uvarint(6, &mut over_count);
        assert!(matches!(
            decode_ranges(&mut Decoder::new(&over_count), 9),
            Err(Error::Corrupt)
        ));
        let mut absurd_count = Vec::new();
        encode_uvarint(u64::MAX, &mut absurd_count);
        assert!(matches!(
            decode_ranges(&mut Decoder::new(&absurd_count), 4),
            Err(Error::Corrupt)
        ));

        for malformed in [&[1, 0, 0][..], &[2, 0, 2, 1, 1][..]] {
            let mut malformed_decoder = Decoder::new(malformed);
            assert!(matches!(
                decode_ranges(&mut malformed_decoder, 4),
                Err(Error::Corrupt)
            ));
        }

        let file_path = temp_path("file-len");
        assert_eq!(file_len(&file_path).unwrap(), 0);
        fs::write(&file_path, b"abc").unwrap();
        assert_eq!(file_len(&file_path).unwrap(), 3);
        fs::remove_file(&file_path).unwrap();
        assert!(matches!(
            file_len(Path::new("\0")),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));

        let reserve_many_path = temp_path("reserve-many-identity");
        let mut reserve_many_store = ResumeStore::open(&reserve_many_path).unwrap();
        reserve_many_store.reserve_many([(subject(16), 2)]).unwrap();
        assert!(matches!(
            reserve_many_store.reserve_many([(subject(16), 3)]),
            Err(Error::IdentityMismatch)
        ));
        fs::remove_file(&reserve_many_path).unwrap();
        fs::remove_file(lock_path(&reserve_many_path).unwrap()).unwrap();

        let no_op_path = temp_path("no-op-checkpoint");
        let mut store = ResumeStore::open(&no_op_path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(13), 2, 1).unwrap();
        let before = file_len(&no_op_path).unwrap();
        tracker.checkpoint(&mut store).unwrap();
        assert_eq!(file_len(&no_op_path).unwrap(), before);
        fs::remove_file(&no_op_path).unwrap();
        fs::remove_file(lock_path(&no_op_path).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn replaying_many_checkpoint_records_stays_linear() {
        let path = temp_path("replay-many-checkpoints");
        let object = subject(21);
        let total_units = 100_000;
        append_record(&path, &encode_reserve(object, total_units).unwrap()).unwrap();
        for index in (0..20_000).rev() {
            let record = encode_checkpoint(object, total_units, &units([index * 2])).unwrap();
            append_record(&path, &record).unwrap();
        }

        let reopened = ResumeStore::open(&path).unwrap();
        let held = reopened.checkpointed(object).unwrap();
        assert_eq!(held.count(), 20_000);
        assert_eq!(held.run_count(), 20_000);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn a_large_contiguous_object_costs_one_run_in_memory() {
        let path = temp_path("run-length-memory");
        let subject = SubjectId::new(1, [0x5c; 32], MAX_UNITS_PER_OBJECT * 65_536).unwrap();
        let mut store = ResumeStore::open(&path).unwrap();
        store
            .reserve_many([(subject, MAX_UNITS_PER_OBJECT)])
            .unwrap();
        store
            .save_object(subject, MAX_UNITS_PER_OBJECT, &units(0..250_000))
            .unwrap();
        let held = store.checkpointed(subject).unwrap();
        assert_eq!(held.count(), 250_000);
        assert_eq!(held.run_count(), 1);

        let mut fragmented = units(0..250_000);
        fragmented.extend_units([250_001]);
        store
            .save_object(subject, MAX_UNITS_PER_OBJECT, &fragmented)
            .unwrap();
        let held = store.checkpointed(subject).unwrap();
        assert_eq!(held.count(), 250_001);
        assert_eq!(held.run_count(), 2);

        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject).unwrap().run_count(), 2);
        assert_eq!(reopened.checkpointed(subject).unwrap(), &fragmented);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn resume_store_handles_million_small_file_workload() {
        let path = temp_path("million-small-files");
        let subject_for = |index: u32| {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&index.to_be_bytes());
            SubjectId::new(1, root, 1).unwrap()
        };
        let large_subject = SubjectId::new(1, [0xaa; 32], 100 * 65_536).unwrap();
        let mut store = ResumeStore::open(&path).unwrap();
        store
            .reserve_many(
                (0_u32..1_000_000)
                    .map(|index| (subject_for(index), 1))
                    .chain(std::iter::once((large_subject, 100))),
            )
            .unwrap();

        let mut tracker = ResumeTracker::discover(&mut store, large_subject, 100, 3).unwrap();
        for unit in 0..3 {
            tracker.begin_unit(unit).unwrap();
            assert_eq!(tracker.complete_unit(unit).unwrap(), unit == 2);
        }
        tracker.checkpoint(&mut store).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert!(reopened.checkpointed(subject_for(0)).is_some());
        assert!(reopened.checkpointed(subject_for(999_999)).is_some());
        assert_eq!(
            reopened.checkpointed(large_subject).unwrap(),
            &units([0, 1, 2])
        );
        assert!(file_len(&path).unwrap() < MAX_STORE_BYTES);
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "scale test, run with --ignored"]
    fn fully_checkpointed_million_object_snapshot_fits_the_store() {
        let path = temp_path("million-checkpointed");
        let subject_for = |index: u32| {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&index.to_be_bytes());
            SubjectId::new(1, root, 1).unwrap()
        };
        let large_subject = SubjectId::new(1, [0xaa; 32], 100 * 65_536).unwrap();

        let mut objects = BTreeMap::new();
        for index in 0..1_000_000_u32 {
            objects.insert(
                subject_for(index),
                StoredObject {
                    total_units: 1,
                    checkpointed: units([0]),
                },
            );
        }
        objects.insert(
            large_subject,
            StoredObject {
                total_units: 100,
                checkpointed: units(0..100),
            },
        );

        validate_reserved_capacity(&objects).unwrap();
        ResumeStore::compact(&path, &objects).unwrap();

        let reopened = ResumeStore::open(&path).unwrap();
        assert_eq!(reopened.checkpointed(subject_for(0)).unwrap(), &units([0]));
        assert_eq!(
            reopened.checkpointed(subject_for(999_999)).unwrap(),
            &units([0])
        );
        assert_eq!(
            reopened.checkpointed(large_subject).unwrap(),
            &units(0..100)
        );

        let length = file_len(&path).unwrap();
        let headroom = MAX_STORE_BYTES - length;
        assert!(
            headroom >= 16 * 1024 * 1024,
            "fully checkpointed snapshot is {length} bytes, leaving only {headroom} bytes"
        );
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn decoder_rejects_malformed_records_and_accepts_empty_log() {
        let path = temp_path("raw");

        let mut trailing = encode_reserve(subject(1), 1).unwrap();
        trailing.push(0xff);
        write_raw(&path, &trailing);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        let malformed_range = encode_checkpoint(subject(1), 1, &units([1])).unwrap();
        write_raw(&path, &malformed_range);
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        let mut bytes = MAGIC.to_vec();
        let mut record = encode_record(&encode_reserve(subject(2), 1).unwrap()).unwrap();
        let last = record.len() - 1;
        record[last] ^= 1;
        bytes.extend_from_slice(&record);
        fs::write(&path, bytes).unwrap();
        assert!(matches!(ResumeStore::open(&path), Err(Error::Corrupt)));

        fs::write(&path, MAGIC).unwrap();
        assert!(ResumeStore::open(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn compaction_collision_preserves_the_real_error_kind() {
        let path = temp_path("temporary-collision");
        let temporary = temporary_path(&path).unwrap();
        fs::create_dir(&temporary).unwrap();
        let error = ResumeStore::compact(&path, &BTreeMap::new()).unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected I/O error");
        };
        assert_ne!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir(temporary).unwrap();
    }

    #[test]
    fn quic_to_tcp_preserves_verified_and_durable_state() {
        let mut state = CarrierNeutralState::new(Carrier::Quic, 1);
        state.verified(3);
        state.durable(3).unwrap();
        assert!(matches!(state.durable(4), Err(Error::InvalidUnit)));
        state.switch(Carrier::TlsTcp, 2);
        assert_eq!(state.carrier(), Carrier::TlsTcp);
        assert!(state.is_verified(3));
        assert!(state.is_durable(3));
        assert!(!state.is_verified(4));
        assert!(!state.is_durable(4));
    }

    #[test]
    fn stale_path_state_not_reused_unsafely() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [2; 16],
            dscp: 0,
        };
        let observation = Observation {
            saved_cwnd: 1_000_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 7,
        };
        let input = Reconnaissance {
            now: 500,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 7,
            max_jump: 400_000,
        };
        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert_eq!(permit.jump_cwnd, 400_000);
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::AlreadyInUse)
        );
        assert!(cache.release(endpoint, &permit, false));
        let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(cache.release(endpoint, &permit, true));
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::Unknown)
        );
        cache.observe(endpoint, observation).unwrap();

        let changed = RemoteEndpoint {
            interface: 9,
            ..endpoint
        };
        assert_eq!(
            cache.reconnoitre(endpoint, changed, input),
            Err(PathReject::PathChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, Reconnaissance { ..input }),
            Err(PathReject::Unknown)
        );

        cache.observe(endpoint, observation).unwrap();
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    local_path_changed: true,
                    ..input
                }
            ),
            Err(PathReject::PathChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::Unknown)
        );
    }

    #[test]
    fn reconnaissance_congestion_discards_saved_state() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [8; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let mut cache = CarefulResumeCache::default();
        for initial_flight_acknowledged in [false, true] {
            let input = Reconnaissance {
                now: 1,
                current_min_rtt: 100,
                initial_flight_acknowledged,
                congestion_detected: true,
                local_path_changed: false,
                configuration_epoch: 4,
                max_jump: 900,
            };
            cache.observe(endpoint, observation).unwrap();
            assert_eq!(
                cache.reconnoitre(endpoint, endpoint, input),
                Err(PathReject::Congestion)
            );
            assert_eq!(
                cache.reconnoitre(
                    endpoint,
                    endpoint,
                    Reconnaissance {
                        initial_flight_acknowledged: true,
                        congestion_detected: false,
                        ..input
                    }
                ),
                Err(PathReject::Unknown)
            );
        }
    }

    #[test]
    fn active_careful_resume_observation_cannot_be_replaced() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [9; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let input = Reconnaissance {
            now: 1,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        let invalidations = [
            (
                RemoteEndpoint {
                    interface: 2,
                    ..endpoint
                },
                input,
            ),
            (
                endpoint,
                Reconnaissance {
                    local_path_changed: true,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    congestion_detected: true,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    now: observation.expires_at,
                    ..input
                },
            ),
            (
                endpoint,
                Reconnaissance {
                    configuration_epoch: observation.configuration_epoch + 1,
                    ..input
                },
            ),
        ];
        for (current_endpoint, invalidation) in invalidations {
            let mut cache = CarefulResumeCache::default();
            cache.observe(endpoint, observation).unwrap();
            let permit = cache.reconnoitre(endpoint, endpoint, input).unwrap();
            assert_eq!(
                cache.observe(
                    endpoint,
                    Observation {
                        saved_cwnd: 2_000,
                        ..observation
                    }
                ),
                Err(PathReject::AlreadyInUse)
            );
            assert_eq!(
                cache.reconnoitre(endpoint, current_endpoint, invalidation),
                Err(PathReject::AlreadyInUse)
            );
            assert!(cache.release(endpoint, &permit, false));
            assert_eq!(
                cache.reconnoitre(endpoint, endpoint, input),
                Err(PathReject::Unknown)
            );
        }
    }

    #[test]
    fn delayed_release_cannot_clear_a_newer_permit_owner() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [10; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let input = Reconnaissance {
            now: 1,
            current_min_rtt: 100,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let first = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(cache.release(endpoint, &first, false));
        let second = cache.reconnoitre(endpoint, endpoint, input).unwrap();
        assert!(!cache.release(endpoint, &first, false));
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, input),
            Err(PathReject::AlreadyInUse)
        );
        assert!(cache.release(endpoint, &second, false));
        assert!(cache.reconnoitre(endpoint, endpoint, input).is_ok());
    }

    #[test]
    fn careful_resume_rejects_each_condition_and_accepts_exact_rtt_edge() {
        let endpoint = RemoteEndpoint {
            interface: 1,
            destination: [8; 16],
            dscp: 1,
        };
        let observation = Observation {
            saved_cwnd: 1_000,
            saved_rtt: 100,
            expires_at: 1_000,
            configuration_epoch: 4,
        };
        let base = Reconnaissance {
            now: 1,
            current_min_rtt: 1_000,
            initial_flight_acknowledged: true,
            congestion_detected: false,
            local_path_changed: false,
            configuration_epoch: 4,
            max_jump: 900,
        };
        for invalid in [
            Observation {
                saved_cwnd: 0,
                ..observation
            },
            Observation {
                saved_rtt: 0,
                ..observation
            },
            Observation {
                expires_at: 0,
                ..observation
            },
        ] {
            assert_eq!(
                CarefulResumeCache::default().observe(endpoint, invalid),
                Err(PathReject::InvalidObservation)
            );
        }

        let mut cache = CarefulResumeCache::default();
        cache.observe(endpoint, observation).unwrap();
        let permit = cache.reconnoitre(endpoint, endpoint, base).unwrap();
        assert_eq!(permit.jump_cwnd, 500);
        assert!(cache.release(endpoint, &permit, false));
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    current_min_rtt: 1_001,
                    ..base
                }
            ),
            Err(PathReject::RttTooLarge)
        );
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    initial_flight_acknowledged: false,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::InitialFlightUnacknowledged)
        );
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    congestion_detected: true,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::Congestion)
        );
        cache.observe(endpoint, observation).unwrap();
        assert_eq!(
            cache.reconnoitre(
                endpoint,
                endpoint,
                Reconnaissance {
                    configuration_epoch: 5,
                    current_min_rtt: 100,
                    ..base
                }
            ),
            Err(PathReject::ConfigurationChanged)
        );
        assert_eq!(
            cache.reconnoitre(endpoint, endpoint, base),
            Err(PathReject::Unknown)
        );
    }
}
