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
    /// The journal, and the claim on it: the lock is held on this handle for
    /// as long as it lives.
    file: File,
    /// What the journal holds now, so an append that would carry it past the
    /// replay ceiling is refused rather than written. Without this the file
    /// could grow past what any later replay would read, and the only thing
    /// that shrinks it is a compaction that has to read it.
    bytes: u64,
    path: PathBuf,
    incarnation: [u8; 16],
    next_sequence: u64,
    poisoned: bool,
}

/// Claims a journal for one writer, on the journal itself.
///
/// Not on a sibling lock file. A sibling has to be named from the journal's
/// path, which makes the claim lexical: two names for one journal, a hardlink
/// or a symlink, produce two lock files and both writers win, which is the
/// outcome the claim exists to prevent. It also has to be left behind, since
/// unlinking a name somebody may be holding is the hazard in the other
/// direction. Locking the inode has neither problem: two names for it are one
/// lock, and there is no extra file to leave.
///
/// Refuses rather than waits. A second writer is a caller mistake, and
/// blocking would hide it.
///
/// # Errors
/// Reports [`Error::Locked`] when another writer holds the journal.
fn claim(file: &File) -> Result<(), Error> {
    match fs4::FileExt::try_lock(file) {
        Ok(()) => Ok(()),
        Err(fs4::TryLockError::WouldBlock) => Err(Error::Locked),
        Err(fs4::TryLockError::Error(error)) => Err(Error::Io(error)),
    }
}

#[derive(Debug)]
pub struct DurableWitness(());

impl Journal {
    pub fn create(path: &Path, incarnation: [u8; 16]) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        claim(&file)?;
        File::open(parent_directory(path))?.sync_all()?;
        Ok(Self {
            file,
            bytes: 0,
            path: path.to_path_buf(),
            incarnation,
            next_sequence: 0,
            poisoned: false,
        })
    }

    pub fn open_current(path: &Path, incarnation: [u8; 16]) -> Result<(Self, Replay), Error> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        claim(&file)?;
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
        let following = successor(sequence)?;
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
            .read(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        // Claimed before it has the journal's name, so there is no moment in
        // which the inode that is about to become the journal is unclaimed.
        // Holding both across the rename is what lets the claim live on the
        // journal itself rather than on a sibling that has to be named from
        // its path and left behind.
        claim(&file)?;
        fs::rename(&temporary, &self.path)?;
        // Past this point the journal this handle holds is unlinked, so a
        // failure cannot leave the caller appending into it. Anything that
        // goes wrong from here poisons.
        self.finish_compaction(file, next_sequence)
            .inspect_err(|_| {
                self.poisoned = true;
            })
    }

    /// Adopts the journal a rename just put in place, having proved it reads
    /// back.
    ///
    /// `replacement` is the handle that wrote it and holds the claim on it,
    /// not a reopen by path: reopening would take a second handle to the same
    /// inode without the claim, and would read whatever the name points at
    /// now rather than what this compaction wrote.
    ///
    /// Compaction used to end by reopening through `open_current`, which
    /// replayed the new file. Adopting it unread would let a compaction that
    /// landed an unreadable journal report success, with the corruption
    /// surfacing only at recovery.
    fn finish_compaction(
        &mut self,
        mut replacement: File,
        next_sequence: u64,
    ) -> Result<(), Error> {
        File::open(parent_directory(&self.path))?.sync_all()?;
        replacement.seek(SeekFrom::Start(0))?;
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

/// The sequence after `sequence`, or [`Error::SequenceGap`] when there is no
/// such number. One home for the rule, so a change to what happens at the top
/// cannot be made in one place and missed in another.
fn successor(sequence: u64) -> Result<u64, Error> {
    sequence.checked_add(1).ok_or(Error::SequenceGap)
}

/// The sequence a journal ending at `last` writes next.
fn next_sequence_after(last: Option<&Record>) -> Result<u64, Error> {
    last.map_or(Ok(0), |record| successor(record.sequence))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c_update(CRC32C_EMPTY, bytes)
}

/// The CRC of nothing, which is what a running checksum starts from.
pub const CRC32C_EMPTY: u32 = 0;

/// Extends a CRC over more bytes, so a checksum can be computed from a stream
/// without holding what it covers.
///
/// `crc32c_update(crc32c_update(CRC32C_EMPTY, a), b)` equals
/// `crc32c([a, b].concat())`.
#[must_use]
pub fn crc32c_update(crc: u32, bytes: &[u8]) -> u32 {
    let mut running = !crc;
    for byte in bytes {
        running ^= u32::from(*byte);
        for _ in 0..8 {
            running = (running >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(running & 1));
        }
    }
    !running
}

/// The CRC of `a` followed by `b`, given each one's CRC and the length of
/// `b`. zlib's `crc32_combine` over the CRC-32C polynomial: advancing `a`'s
/// remainder by `len_b` zero bytes is a linear map over GF(2), so squaring
/// the operator gets there in a logarithmic number of steps rather than one
/// per byte.
#[must_use]
pub fn crc32c_combine(a: u32, b: u32, len_b: u64) -> u32 {
    if len_b == 0 {
        return a;
    }
    let mut odd = [0_u32; 32];
    // The operator for one zero bit: the polynomial, then the identity.
    odd[0] = 0x82f6_3b78;
    let mut row = 1_u32;
    for entry in odd.iter_mut().skip(1) {
        *entry = row;
        row <<= 1;
    }
    let mut even = [0_u32; 32];
    square(&mut even, &odd); // two zero bits
    square(&mut odd, &even); // four, which is half a byte

    let mut advanced = a;
    let mut remaining = len_b;
    // One pass per bit of the length, counted, because a shift that stopped
    // shrinking would otherwise spin rather than answer wrongly.
    for _ in 0..u64::BITS {
        if remaining == 0 {
            break;
        }
        square(&mut even, &odd);
        if remaining & 1 != 0 {
            advanced = apply(&even, advanced);
        }
        remaining >>= 1;
        std::mem::swap(&mut even, &mut odd);
    }
    advanced ^ b
}

/// One GF(2) matrix applied to a vector, both of them 32 bits wide. The sum
/// of the columns the vector selects.
fn apply(matrix: &[u32; 32], vector: u32) -> u32 {
    let mut sum = 0;
    for (index, column) in matrix.iter().enumerate() {
        if vector >> index & 1 != 0 {
            sum ^= *column;
        }
    }
    sum
}

/// The operator that does what `matrix` does twice.
fn square(into: &mut [u32; 32], matrix: &[u32; 32]) {
    for (slot, column) in into.iter_mut().zip(matrix.iter()) {
        *slot = apply(matrix, *column);
    }
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
            } else if successor(previous.sequence).ok() != Some(sequence) {
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

    /// A journal path that takes its file with it.
    ///
    /// Cleaning up in a `Drop` is the only version a later test cannot
    /// forget. A sweep runs the suite once per mutant, so one file per test
    /// per mutant is thousands in the shared temp directory, which is what
    /// has killed mutation runners here before.
    struct TempJournal(std::path::PathBuf);

    impl std::ops::Deref for TempJournal {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for TempJournal {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn temp_path(name: &str) -> TempJournal {
        TempJournal(std::env::temp_dir().join(format!(
            "vot-journal-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
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
