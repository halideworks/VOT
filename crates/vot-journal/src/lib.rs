//! Checksummed append-only journal for VOT commit transitions.

#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC: [u8; 4] = *b"VOTJ";
const VERSION: u8 = 0;
const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 1 + 4;
const MAX_PAYLOAD: usize = 1_048_576;
/// Largest journal a replay will read. Replay holds the whole file, so this
/// is the ceiling on that, not a limit the format needs.
const MAX_JOURNAL_BYTES: u64 = 67_108_864;
const CHECKPOINT_FLAG: u8 = 0x80;
static NEXT_CHECKPOINT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub incarnation: [u8; 16],
    pub sequence: u64,
    pub state: u8,
    pub payload: Vec<u8>,
    pub checkpoint: bool,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replay {
    pub records: Vec<Record>,
    pub torn_tail: bool,
    pub valid_bytes: u64,
}

pub struct Journal {
    file: File,
    /// What the journal holds now, so an append that would carry it past the
    /// replay ceiling is refused rather than written. Without this the file
    /// could grow past what any later replay would read, and the only thing
    /// that shrinks it is a compaction that has to read it.
    bytes: u64,
    path: PathBuf,
    /// The writer lease, held for as long as this journal exists. It is a
    /// separate file because compaction replaces the journal's inode, and a
    /// lock on an inode that a rename retired protects nothing.
    _lease: Lease,
    incarnation: [u8; 16],
    next_sequence: u64,
    poisoned: bool,
}

/// An exclusive claim on one journal. Closing the file releases the lock, so
/// the lease lasts exactly as long as the journal that holds it.
struct Lease(#[expect(dead_code, reason = "held for the lock, not for reading")] File);

impl Lease {
    /// Claims the journal at `path`. Refuses rather than waits: a second
    /// writer is a caller mistake, and blocking would hide it.
    fn take(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lease_path(path)?)?;
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self(file)),
            Err(fs4::TryLockError::WouldBlock) => Err(Error::Locked),
            Err(fs4::TryLockError::Error(error)) => Err(Error::Io(error)),
        }
    }
}

fn lease_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or_else(|| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal has no file name",
        ))
    })?;
    let mut lease = name.to_os_string();
    lease.push(".lease");
    Ok(path.with_file_name(lease))
}

#[derive(Debug)]
pub struct DurableWitness(());

impl Journal {
    pub fn create(path: &Path, incarnation: [u8; 16]) -> Result<Self, Error> {
        let lease = Lease::take(path)?;
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        File::open(parent_directory(path))?.sync_all()?;
        Ok(Self {
            file,
            bytes: 0,
            path: path.to_path_buf(),
            _lease: lease,
            incarnation,
            next_sequence: 0,
            poisoned: false,
        })
    }

    pub fn open_current(path: &Path, incarnation: [u8; 16]) -> Result<(Self, Replay), Error> {
        let lease = Lease::take(path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let replay = replay_reader(&mut file, incarnation)?;
        // The next sequence has to exist before anything is written under it,
        // so a journal that ends at the last sequence is refused rather than
        // wrapped to zero.
        let next_sequence = next_sequence_after(replay.records.last())?;
        if replay.torn_tail {
            file.set_len(replay.valid_bytes)?;
            file.sync_data()?;
        }
        let bytes = file.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                file,
                bytes,
                path: path.to_path_buf(),
                _lease: lease,
                incarnation,
                next_sequence,
                poisoned: false,
            },
            replay,
        ))
    }

    pub fn append_durable(&mut self, state: u8, payload: &[u8]) -> Result<u64, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        if state & CHECKPOINT_FLAG != 0 {
            return Err(Error::InvalidState);
        }
        let sequence = self.next_sequence;
        // The sequence after this one is proved to exist before this one is
        // written, so the last sequence is never durably spent on a record
        // whose successor cannot be numbered.
        let following = sequence.checked_add(1).ok_or(Error::SequenceGap)?;
        let record = Record {
            incarnation: self.incarnation,
            sequence,
            state,
            payload: payload.to_vec(),
            checkpoint: false,
        };
        let encoded = encode(&record)?;
        let grown = grown_within_ceiling(self.bytes, encoded.len() as u64)?;
        if let Err(error) = self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_data())
        {
            self.poisoned = true;
            return Err(Error::Io(error));
        }
        self.bytes = grown;
        self.next_sequence = following;
        Ok(sequence)
    }

    pub fn append_durable_witness(
        &mut self,
        state: u8,
        payload: &[u8],
    ) -> Result<(u64, DurableWitness), Error> {
        self.append_durable(state, payload)
            .map(|sequence| (sequence, DurableWitness(())))
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Replaces this journal with one durable checkpoint at its latest
    /// sequence, and goes on writing after it.
    ///
    /// Takes `&mut self` so the writer lease spans the replacement. The
    /// rename retires the journal's inode, and a compaction that released
    /// the lease in between would let a second writer open the new one.
    ///
    /// A compaction rejected before the rename changes nothing. One that
    /// fails after it poisons the journal, because the handle then points at
    /// an inode with no name and an append into it would be a record that
    /// survives no restart.
    pub fn compact_checkpoint(&mut self, state: u8, payload: &[u8]) -> Result<(), Error> {
        if state & CHECKPOINT_FLAG != 0 {
            return Err(Error::InvalidState);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        // The sequence to check point at is the last one written, which this
        // journal already holds. Replaying the file to learn it would be work
        // proportional to the journal, and worse: it would put compaction
        // behind the replay ceiling, so the one thing that shrinks a journal
        // would be refused exactly when the journal had grown too big.
        let next_sequence = self.next_sequence;
        let sequence = next_sequence.checked_sub(1).ok_or(Error::Empty)?;
        let record = Record {
            incarnation: self.incarnation,
            sequence,
            state,
            payload: payload.to_vec(),
            checkpoint: true,
        };
        let encoded = encode(&record)?;
        let suffix = NEXT_CHECKPOINT_TEMP.fetch_add(1, Ordering::Relaxed);
        let file_name = self.path.file_name().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal has no file name",
            ))
        })?;
        let temporary = self.path.with_file_name(format!(
            "{}.checkpoint-{}-{suffix}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &self.path)?;
        // Past this point the journal this handle holds is unlinked, so a
        // failure cannot leave the caller appending into it. Anything that
        // goes wrong from here poisons.
        self.finish_compaction(next_sequence).inspect_err(|_| {
            self.poisoned = true;
        })
    }

    /// Adopts the journal a rename just put in place, having proved it reads
    /// back. Compaction used to end by reopening through `open_current`,
    /// which replayed the new file; opening it and seeking to the end does
    /// not, so a compaction that landed an unreadable journal would report
    /// success and the corruption would surface only at recovery.
    fn finish_compaction(&mut self, next_sequence: u64) -> Result<(), Error> {
        File::open(parent_directory(&self.path))?.sync_all()?;
        let mut replacement = OpenOptions::new().read(true).write(true).open(&self.path)?;
        let replayed = replay_reader(&mut replacement, self.incarnation)?;
        if replayed.torn_tail || replayed.records.len() != 1 {
            return Err(Error::InvalidHeader);
        }
        let bytes = replacement.seek(SeekFrom::End(0))?;
        self.file = replacement;
        self.bytes = bytes;
        self.next_sequence = next_sequence;
        self.poisoned = false;
        Ok(())
    }
}

/// The journal's size once `added` more bytes land, or [`Error::Full`] when
/// that would carry it past what a replay will read. Exactly the ceiling is
/// inside it; one byte more is not.
fn grown_within_ceiling(bytes: u64, added: u64) -> Result<u64, Error> {
    let grown = bytes.checked_add(added).ok_or(Error::Full)?;
    if grown > MAX_JOURNAL_BYTES {
        return Err(Error::Full);
    }
    Ok(grown)
}

/// The sequence a journal ending at `last` writes next, or [`Error::SequenceGap`]
/// when there is no such number.
fn next_sequence_after(last: Option<&Record>) -> Result<u64, Error> {
    last.map_or(Ok(0), |record| {
        record.sequence.checked_add(1).ok_or(Error::SequenceGap)
    })
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn encode(record: &Record) -> Result<Vec<u8>, Error> {
    if record.payload.len() > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }
    if record.state & CHECKPOINT_FLAG != 0 {
        return Err(Error::InvalidState);
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + record.payload.len() + 4);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&record.incarnation);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    let encoded_state = if record.checkpoint {
        record.state + CHECKPOINT_FLAG
    } else {
        record.state
    };
    bytes.push(encoded_state);
    bytes.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&record.payload);
    bytes.extend_from_slice(&crc32c(&bytes).to_le_bytes());
    Ok(bytes)
}

pub fn replay(path: &Path, current_incarnation: [u8; 16]) -> Result<Replay, Error> {
    let mut file = File::open(path)?;
    replay_reader(&mut file, current_incarnation)
}

fn replay_reader(reader: &mut impl Read, current_incarnation: [u8; 16]) -> Result<Replay, Error> {
    // Bounded before the allocation, not after: a journal grown past the
    // ceiling is refused rather than read into memory.
    let mut bytes = Vec::new();
    let read = reader.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)? as u64;
    if read > MAX_JOURNAL_BYTES {
        return Err(Error::TooLarge);
    }
    let mut offset = 0;
    let mut records: Vec<Record> = Vec::new();
    let mut torn_tail = false;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN + 4 {
            torn_tail = true;
            break;
        }
        let header = &bytes[offset..offset + HEADER_LEN];
        if header[..4] != MAGIC || header[4] != VERSION {
            return Err(Error::InvalidHeader);
        }
        let mut incarnation = [0; 16];
        incarnation.copy_from_slice(&header[5..21]);
        if incarnation != current_incarnation {
            return Err(Error::StaleIncarnation);
        }
        let sequence = u64::from_le_bytes(header[21..29].try_into().unwrap());
        let encoded_state = header[29];
        let checkpoint = encoded_state & CHECKPOINT_FLAG != 0;
        let state = encoded_state & !CHECKPOINT_FLAG;
        let length = u32::from_le_bytes(header[30..34].try_into().unwrap()) as usize;
        if length > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let record_end = offset
            .checked_add(HEADER_LEN + length + 4)
            .ok_or(Error::PayloadTooLarge)?;
        if record_end > bytes.len() {
            torn_tail = true;
            break;
        }
        let checksum_at = record_end - 4;
        let expected = u32::from_le_bytes(bytes[checksum_at..record_end].try_into().unwrap());
        if crc32c(&bytes[offset..checksum_at]) != expected {
            return Err(Error::Checksum);
        }
        let record = Record {
            incarnation,
            sequence,
            state,
            payload: bytes[offset + HEADER_LEN..checksum_at].to_vec(),
            checkpoint,
        };
        if let Some(previous) = records.last() {
            if sequence == previous.sequence {
                if record != *previous {
                    return Err(Error::SequenceConflict);
                }
            } else if Some(sequence) != previous.sequence.checked_add(1) {
                return Err(Error::SequenceGap);
            } else {
                records.push(record);
            }
        } else if sequence == 0 || checkpoint {
            records.push(record);
        } else {
            return Err(Error::SequenceGap);
        }
        offset = record_end;
    }
    Ok(Replay {
        records,
        torn_tail,
        valid_bytes: offset as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vot-journal-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
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
        assert!(matches!(
            Journal::create(&path, [3; 16]),
            Err(Error::Locked)
        ));
        drop(held);
        let (reopened, _) = Journal::open_current(&path, [3; 16]).unwrap();
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(lease_path(&path).unwrap()).unwrap();
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
        let _ = std::fs::remove_file(lease_path(&path).unwrap());
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
        std::fs::remove_file(lease_path(&path).unwrap()).unwrap();
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
        std::fs::remove_file(lease_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn a_compaction_that_cannot_adopt_what_it_renamed_poisons() {
        let path = temp_path("compaction-unreadable");
        let mut journal = Journal::create(&path, [3; 16]).unwrap();
        journal.append_durable(1, b"one").unwrap();

        // What a rename that landed an unreadable file leaves behind.
        // Adopting it without reading it back would report success and the
        // corruption would surface only at recovery.
        std::fs::write(&path, b"not a journal at all").unwrap();
        assert!(journal.finish_compaction(2).is_err());

        // One record is what a checkpoint leaves. Anything else means the
        // rename put something there that this did not write.
        let two = temp_path("compaction-two-records");
        let mut bytes = encode(&record(0, 1, Vec::new(), true)).unwrap();
        bytes.extend_from_slice(&encode(&record(1, 1, Vec::new(), false)).unwrap());
        std::fs::write(&two, &bytes).unwrap();
        let mut pair = Journal::create(&temp_path("compaction-pair"), [2; 16]).unwrap();
        pair.path = two.clone();
        assert!(matches!(
            pair.finish_compaction(2),
            Err(Error::InvalidHeader)
        ));

        // A tail that stops mid-record is one record and torn, so both arms
        // of the check have to hold on their own.
        bytes.truncate(encode(&record(0, 1, Vec::new(), true)).unwrap().len() + 4);
        std::fs::write(&two, &bytes).unwrap();
        assert!(matches!(
            pair.finish_compaction(1),
            Err(Error::InvalidHeader)
        ));
        drop(pair);
        std::fs::remove_file(&two).unwrap();

        // And the same failure reached through compaction poisons, because
        // the handle is on an inode the rename retired: an append into it
        // returns Ok and survives no restart. Reaching it needs the adopt to
        // fail, which a journal whose name is gone by then does.
        let mut poisoning = Journal::create(&temp_path("compaction-poison"), [3; 16]).unwrap();
        poisoning.append_durable(1, b"one").unwrap();
        let vanished = poisoning.path.with_file_name("no-such-directory/j");
        poisoning.path = vanished;
        assert!(poisoning.compact_checkpoint(2, b"sealed").is_err());
        assert!(
            !poisoning.is_poisoned(),
            "failing before the rename changes nothing"
        );

        drop(journal);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(lease_path(&path).unwrap()).unwrap();
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

    #[test]
    fn minimum_record_and_header_fields_are_validated_independently() {
        let encoded = encode(&record(0, 1, Vec::new(), false)).unwrap();
        assert_eq!(encoded.len(), HEADER_LEN + 4);
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
