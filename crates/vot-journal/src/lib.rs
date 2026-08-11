//! Checksummed append-only journal for VOT commit transitions.

#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

use std::io;

mod crc32c;
mod format;
mod io_impl;

pub use crc32c::*;
pub use format::*;
pub use io_impl::*;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Poisoned,
    PayloadTooLarge,
    InvalidHeader,
    Checksum,
    SequenceGap,
    SequenceConflict,
    StaleIncarnation,
    InvalidState,
    Empty,
    /// Another writer holds this journal's lease.
    Locked,
    /// The journal is larger than a replay will hold.
    TooLarge,
    /// One more record would carry the journal past what a replay will hold.
    /// Check point it, which replaces it with one record.
    Full,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::Path;

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A journal path that takes its private directory with it.
    ///
    /// Cleaning up in a `Drop` is the only version a later test cannot
    /// forget. A sweep runs the suite once per mutant, so one file per test
    /// per mutant is thousands in the shared temp directory, which is what
    /// has killed mutation runners here before.
    struct TempJournal {
        path: std::path::PathBuf,
        directory: std::path::PathBuf,
    }

    impl std::ops::Deref for TempJournal {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.path
        }
    }

    impl AsRef<Path> for TempJournal {
        fn as_ref(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn temp_path(name: &str) -> TempJournal {
        let directory = std::env::temp_dir().join(format!(
            "vot-journal-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&directory).unwrap();
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&directory).unwrap();
        TempJournal {
            path: directory.join("journal"),
            directory,
        }
    }

    #[test]
    fn durable_records_replay_in_order() {
        let path = temp_path("ordered");
        let incarnation = [7; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        assert_eq!(journal.append_durable(1, b"admitted").unwrap(), 0);
        assert_eq!(journal.append_durable(2, b"verified").unwrap(), 1);
        drop(journal);
        let replayed = replay(&path, incarnation).unwrap();
        assert_eq!(replayed.records.len(), 2);
        assert!(replayed.records.iter().all(|record| !record.checkpoint));
        assert!(!replayed.torn_tail);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bare_relative_journal_uses_current_directory_for_durability() {
        assert_eq!(parent_directory(Path::new("journal")), Path::new("."));
        assert_eq!(
            parent_directory(Path::new("nested/journal")),
            Path::new("nested")
        );
    }

    #[test]
    fn crash_at_every_tail_byte_never_invents_transition() {
        let path = temp_path("source");
        let incarnation = [8; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        journal.append_durable(1, b"one").unwrap();
        journal.append_durable(2, b"two").unwrap();
        drop(journal);
        let complete = std::fs::read(&path).unwrap();
        for length in 0..complete.len() {
            let truncated = temp_path(format!("tail-{length}").as_str());
            std::fs::write(&truncated, &complete[..length]).unwrap();
            let recovered = replay(&truncated, incarnation).unwrap();
            assert!(recovered.records.len() <= 2);
            assert!(
                recovered
                    .records
                    .iter()
                    .enumerate()
                    .all(|(index, record)| record.sequence == index as u64)
            );
            std::fs::remove_file(truncated).unwrap();
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn corruption_and_stale_incarnation_fail() {
        let path = temp_path("corrupt");
        let incarnation = [9; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        journal.append_durable(1, b"record").unwrap();
        drop(journal);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(replay(&path, incarnation), Err(Error::Checksum)));
        assert!(matches!(
            replay(&path, [3; 16]),
            Err(Error::StaleIncarnation)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn a_combined_crc_is_the_one_the_bytes_would_have_given() {
        let whole: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        for split in [0, 1, 2, 255, 256, 257, 499, 500, 998, 999, 1000] {
            let (head, tail) = whole.split_at(split);
            assert_eq!(
                crc32c_combine(crc32c(head), crc32c(tail), tail.len() as u64),
                crc32c(&whole),
                "split at {split}"
            );
        }

        // A tail the size of a real object-store part. Those are 5 MiB and
        // up, which is 23 or more significant bits of the length, where the
        // splits above reach ten: a defect in the upper iterations of the
        // squaring loop would pass every case above and fail every real
        // upload.
        let part: Vec<u8> = (0..=255_u8).cycle().take(5 * 1024 * 1024).collect();
        let head = b"the part before it";
        let mut joined = head.to_vec();
        joined.extend_from_slice(&part);
        assert_eq!(
            crc32c_combine(crc32c(head), crc32c(&part), part.len() as u64),
            crc32c(&joined)
        );

        // Folded piece by piece, the way a multipart completion folds parts.
        let (a, rest) = whole.split_at(300);
        let (b, c) = rest.split_at(300);
        let folded = [a, b, c].into_iter().fold(CRC32C_EMPTY, |running, piece| {
            crc32c_combine(running, crc32c(piece), piece.len() as u64)
        });
        assert_eq!(folded, crc32c(&whole));
    }

    #[test]
    fn a_running_crc_matches_one_taken_over_the_whole() {
        assert_eq!(crc32c_update(CRC32C_EMPTY, b""), crc32c(b""));
        let whole = b"123456789";
        for split in 0..=whole.len() {
            let (head, tail) = whole.split_at(split);
            assert_eq!(
                crc32c_update(crc32c_update(CRC32C_EMPTY, head), tail),
                crc32c(whole),
                "split at {split}"
            );
        }
    }

    #[test]
    fn checkpoint_bounds_recovery_to_checkpoint_and_active_records() {
        let path = temp_path("checkpoint");
        let incarnation = [5; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        for sequence in 0..100 {
            journal.append_durable(1, &[sequence]).unwrap();
        }
        journal.compact_checkpoint(2, b"sealed-through=99").unwrap();
        journal.append_durable(3, b"active-100").unwrap();
        journal.append_durable(3, b"active-101").unwrap();
        drop(journal);
        let recovered = replay(&path, incarnation).unwrap();
        assert_eq!(recovered.records.len(), 3);
        assert!(recovered.records[0].checkpoint);
        assert_eq!(recovered.records[0].sequence, 99);
        assert_eq!(recovered.records[2].sequence, 101);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reopening_truncates_torn_tail_before_new_append() {
        let path = temp_path("resume-torn");
        let incarnation = [6; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        journal.append_durable(1, b"complete").unwrap();
        journal.append_durable(2, b"torn").unwrap();
        drop(journal);
        let length = std::fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length - 2)
            .unwrap();
        let (mut journal, recovered) = Journal::open_current(&path, incarnation).unwrap();
        assert!(recovered.torn_tail);
        assert_eq!(recovered.records.len(), 1);
        journal.append_durable(3, b"replacement").unwrap();
        drop(journal);
        let recovered = replay(&path, incarnation).unwrap();
        assert!(!recovered.torn_tail);
        assert_eq!(recovered.records.len(), 2);
        assert_eq!(recovered.records[1].state, 3);
        assert_eq!(recovered.records[1].sequence, 1);
        std::fs::remove_file(path).unwrap();
    }

    fn record(sequence: u64, state: u8, payload: Vec<u8>, checkpoint: bool) -> Record {
        Record {
            incarnation: [2; 16],
            sequence,
            state,
            payload,
            checkpoint,
        }
    }

    #[test]
    fn payload_bounds_are_exact_for_append_encode_and_checkpoint() {
        let path = temp_path("payload-bounds");
        let mut journal = Journal::create(&path, [2; 16]).unwrap();
        let maximum = vec![0; MAX_PAYLOAD];
        let oversized = vec![0; MAX_PAYLOAD + 1];
        assert_eq!(journal.append_durable(1, &maximum).unwrap(), 0);
        assert!(matches!(
            journal.append_durable(1, &oversized),
            Err(Error::PayloadTooLarge)
        ));

        assert!(encode(&record(0, 1, maximum.clone(), false)).is_ok());
        assert!(matches!(
            encode(&record(0, 1, oversized.clone(), false)),
            Err(Error::PayloadTooLarge)
        ));
        assert!(matches!(
            encode(&record(0, CHECKPOINT_FLAG, Vec::new(), false)),
            Err(Error::InvalidState)
        ));

        journal.compact_checkpoint(2, &maximum).unwrap();
        assert!(matches!(
            journal.compact_checkpoint(2, &oversized),
            Err(Error::PayloadTooLarge)
        ));
        // A rejected compaction leaves a journal that still writes.
        assert_eq!(journal.append_durable(1, b"after").unwrap(), 1);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn one_writer_holds_the_journal_and_the_next_is_refused() {
        let path = temp_path("one-writer");
        let held = Journal::create(&path, [3; 16]).unwrap();
        assert!(matches!(
            Journal::open_current(&path, [3; 16]),
            Err(Error::Locked)
        ));
        // A second create never reaches the claim: the journal is already
        // there, and `create_new` says so.
        assert!(matches!(
            Journal::create(&path, [3; 16]),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));

        // A second name for the same journal is the same claim, which a lock
        // file named from the path could not manage: it would have produced
        // two names, two locks, and two writers each believing it was alone.
        let alias = path.with_file_name("one-writer-alias");
        let _ = std::fs::remove_file(&alias);
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            Journal::open_current(&alias, [3; 16]),
            Err(Error::Locked)
        ));
        std::fs::remove_file(&alias).unwrap();

        drop(held);
        let (reopened, _) = Journal::open_current(&path, [3; 16]).unwrap();
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_last_sequence_is_refused_before_anything_is_written() {
        let path = temp_path("last-sequence");
        // A checkpoint is the one record that may open a journal at a
        // sequence other than zero.
        std::fs::write(
            &path,
            encode(&record(u64::MAX, 2, Vec::new(), true)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Journal::open_current(&path, [2; 16]),
            Err(Error::SequenceGap)
        ));

        // And a record after it is a gap, not an overflow.
        let mut bytes = encode(&record(u64::MAX, 2, Vec::new(), true)).unwrap();
        bytes.extend_from_slice(&encode(&record(0, 1, Vec::new(), false)).unwrap());
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(replay(&path, [2; 16]), Err(Error::SequenceGap)));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_append_at_the_last_sequence_writes_nothing() {
        let path = temp_path("append-last-sequence");
        let mut journal = Journal::create(&path, [3; 16]).unwrap();
        journal.next_sequence = u64::MAX;
        assert!(matches!(
            journal.append_durable(1, b"never"),
            Err(Error::SequenceGap)
        ));
        assert!(!journal.is_poisoned());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "nothing landed");
        drop(journal);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_ceiling_admits_exactly_itself_and_no_more() {
        assert_eq!(grown_within_ceiling(0, 0).unwrap(), 0);
        assert_eq!(
            grown_within_ceiling(MAX_JOURNAL_BYTES - 1, 1).unwrap(),
            MAX_JOURNAL_BYTES
        );
        assert_eq!(
            grown_within_ceiling(0, MAX_JOURNAL_BYTES).unwrap(),
            MAX_JOURNAL_BYTES
        );
        assert!(matches!(
            grown_within_ceiling(MAX_JOURNAL_BYTES, 1),
            Err(Error::Full)
        ));
        assert!(matches!(
            grown_within_ceiling(MAX_JOURNAL_BYTES - 1, 2),
            Err(Error::Full)
        ));
        assert!(matches!(
            grown_within_ceiling(u64::MAX, 1),
            Err(Error::Full)
        ));
    }

    #[test]
    fn a_full_journal_refuses_the_append_and_check_points_out_of_it() {
        let path = temp_path("full");
        let mut journal = Journal::create(&path, [3; 16]).unwrap();
        // Fill it to just under the ceiling with the largest records it takes.
        let payload = vec![0; MAX_PAYLOAD];
        let mut written = 0;
        while journal.append_durable(1, &payload).is_ok() {
            written += 1;
            assert!(written < 100, "the ceiling never arrived");
        }
        assert!(matches!(
            journal.append_durable(1, &payload),
            Err(Error::Full)
        ));
        assert!(!journal.is_poisoned(), "a full journal is not a broken one");
        assert!(journal.bytes <= MAX_JOURNAL_BYTES);

        // The way out is the one operation that shrinks it, and it works on a
        // journal this size because it no longer replays to find its place.
        journal.compact_checkpoint(2, b"sealed").unwrap();
        assert!(journal.bytes < u64::from(u16::MAX), "still one record");
        assert_eq!(journal.append_durable(1, b"after").unwrap(), written);

        drop(journal);
        let (reopened, replayed) = Journal::open_current(&path, [3; 16]).unwrap();
        assert_eq!(
            replayed.records.len(),
            2,
            "the checkpoint and what followed"
        );
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_compaction_that_cannot_adopt_what_it_renamed_poisons() {
        /// A handle over bytes that stand in for what a rename put in place.
        fn landed(path: &Path, bytes: &[u8]) -> File {
            std::fs::write(path, bytes).unwrap();
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap()
        }

        let path = temp_path("compaction-unreadable");
        let mut journal = Journal::create(&path, [2; 16]).unwrap();
        journal.append_durable(1, b"one").unwrap();

        // A rename that landed something unreadable. Adopting it unread would
        // report success and the corruption would surface only at recovery.
        let landed_path = temp_path("compaction-landed");
        let file = landed(&landed_path, b"not a journal at all");
        assert!(journal.finish_compaction(file, 2).is_err());

        // One record is what a checkpoint leaves. Two means the rename put
        // something there this compaction did not write.
        let mut bytes = encode(&record(0, 1, Vec::new(), true)).unwrap();
        bytes.extend_from_slice(&encode(&record(1, 1, Vec::new(), false)).unwrap());
        let file = landed(&landed_path, &bytes);
        assert!(matches!(
            journal.finish_compaction(file, 2),
            Err(Error::InvalidHeader)
        ));

        // A tail that stops mid-record is one record and torn, so both arms
        // of the check have to hold on their own.
        bytes.truncate(encode(&record(0, 1, Vec::new(), true)).unwrap().len() + 4);
        let file = landed(&landed_path, &bytes);
        assert!(matches!(
            journal.finish_compaction(file, 1),
            Err(Error::InvalidHeader)
        ));
        std::fs::remove_file(&landed_path).unwrap();

        // Failing before the rename changes nothing, which is the half of the
        // contract that still holds.
        let mut early = Journal::create(&temp_path("compaction-early"), [2; 16]).unwrap();
        early.append_durable(1, b"one").unwrap();
        let vanished = early.path.with_file_name("no-such-directory/j");
        let kept = early.path.clone();
        early.path = vanished;
        assert!(early.compact_checkpoint(2, b"sealed").is_err());
        assert!(!early.is_poisoned());
        early.path = kept;

        drop(journal);
        drop(early);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_journal_past_the_ceiling_is_refused_rather_than_read() {
        let path = temp_path("oversized");
        let mut bytes = encode(&record(0, 1, vec![0; MAX_PAYLOAD], false)).unwrap();
        bytes.resize(usize::try_from(MAX_JOURNAL_BYTES).unwrap() + 1, 0);
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(replay(&path, [2; 16]), Err(Error::TooLarge)));

        bytes.truncate(usize::try_from(MAX_JOURNAL_BYTES).unwrap());
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            !matches!(replay(&path, [2; 16]), Err(Error::TooLarge)),
            "exactly the ceiling is inside it"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn poison_status_is_observable_and_blocks_appends() {
        let path = temp_path("poison-status");
        let mut journal = Journal::create(&path, [2; 16]).unwrap();
        assert!(!journal.is_poisoned());
        journal.poisoned = true;
        assert!(journal.is_poisoned());
        assert!(matches!(
            journal.append_durable(1, &[]),
            Err(Error::Poisoned)
        ));
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn create_rejects_unsafe_parent_before_creating_a_journal() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory =
            std::env::temp_dir().join(format!("vot-journal-unsafe-parent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("journal");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            Journal::create(&path, [2; 16]),
            Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
        assert!(!path.exists());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_poisoned_writer_repairs_its_held_file_before_appending() {
        let path = temp_path("repair-poisoned");
        let mut journal = Journal::create(&path, [2; 16]).unwrap();
        journal.append_durable(1, b"before").unwrap();
        journal.poisoned = true;
        let replay = journal.repair_poisoned().unwrap();
        assert_eq!(replay.records.len(), 1);
        assert!(!journal.is_poisoned());
        assert_eq!(journal.append_durable(2, b"after").unwrap(), 1);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn repair_keeps_a_complete_record_poisoned_until_resync_succeeds() {
        let path = temp_path("repair-resync");
        let mut journal = Journal::create(&path, [2; 16]).unwrap();
        journal.append_durable(1, b"complete").unwrap();
        journal.poisoned = true;
        journal.fail_next_repair_sync = true;
        assert!(matches!(journal.repair_poisoned(), Err(Error::Io(_))));
        assert!(journal.is_poisoned());
        assert_eq!(replay(&path, [2; 16]).unwrap().records.len(), 1);
        assert_eq!(journal.repair_poisoned().unwrap().records.len(), 1);
        assert!(!journal.is_poisoned());
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn owned_removal_preserves_a_substituted_name() {
        let path = temp_path("owned-removal");
        let held = path.with_extension("held");
        let journal = Journal::create(&path, [2; 16]).unwrap();
        std::fs::rename(&path, &held).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(journal.remove_owned().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(held).unwrap();
    }

    #[test]
    fn minimum_record_and_header_fields_are_validated_independently() {
        let encoded = encode(&record(0, 1, Vec::new(), false)).unwrap();
        // Both literal: HEADER_LEN feeds the encoder's buffer size, so a
        // drifted constant would produce a self-consistent wrong format.
        assert_eq!(HEADER_LEN, 34);
        assert_eq!(encoded.len(), 38);
        let mut reader = encoded.as_slice();
        assert_eq!(
            replay_reader(&mut reader, [2; 16]).unwrap().records.len(),
            1
        );

        for index in [0, 4] {
            let mut corrupted = encoded.clone();
            corrupted[index] ^= 1;
            let mut reader = corrupted.as_slice();
            assert!(matches!(
                replay_reader(&mut reader, [2; 16]),
                Err(Error::InvalidHeader)
            ));
        }
    }

    #[test]
    fn declared_payload_bounds_are_checked_before_tail_handling() {
        for (declared, expected_too_large) in [
            (u32::try_from(MAX_PAYLOAD).unwrap(), false),
            (u32::try_from(MAX_PAYLOAD + 1).unwrap(), true),
        ] {
            let mut bytes = encode(&record(0, 1, Vec::new(), false)).unwrap();
            bytes[30..34].copy_from_slice(&declared.to_le_bytes());
            let mut reader = bytes.as_slice();
            let result = replay_reader(&mut reader, [2; 16]);
            if expected_too_large {
                assert!(matches!(result, Err(Error::PayloadTooLarge)));
            } else {
                assert!(result.unwrap().torn_tail);
            }
        }
    }

    #[test]
    fn duplicate_sequence_must_be_byte_identical() {
        let first = encode(&record(0, 1, b"same".to_vec(), false)).unwrap();
        let mut identical = first.clone();
        identical.extend_from_slice(&first);
        let mut reader = identical.as_slice();
        assert_eq!(
            replay_reader(&mut reader, [2; 16]).unwrap().records.len(),
            1
        );

        let second = encode(&record(0, 2, b"different".to_vec(), false)).unwrap();
        let mut conflicting = first;
        conflicting.extend_from_slice(&second);
        let mut reader = conflicting.as_slice();
        assert!(matches!(
            replay_reader(&mut reader, [2; 16]),
            Err(Error::SequenceConflict)
        ));
    }
}
