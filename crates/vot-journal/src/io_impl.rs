//! Append, replay, and compaction, with the syscall ordering visible.

use super::{CHECKPOINT_FLAG, Error, HEADER_LEN, Header, MAX_PAYLOAD, Record, crc32c, encode, io};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Largest journal a replay will read. Replay holds the whole file, so this
/// is the ceiling on that, not a limit the format needs.
pub(super) const MAX_JOURNAL_BYTES: u64 = 67_108_864;
pub(super) static NEXT_CHECKPOINT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replay {
    pub records: Vec<Record>,
    pub torn_tail: bool,
    pub valid_bytes: u64,
}

pub struct Journal {
    /// The journal, and the claim on it: the lock is held on this handle for
    /// as long as it lives.
    pub(super) file: File,
    /// What the journal holds now, so an append that would carry it past the
    /// replay ceiling is refused rather than written. Without this the file
    /// could grow past what any later replay would read, and the only thing
    /// that shrinks it is a compaction that has to read it.
    pub(super) bytes: u64,
    pub(super) path: PathBuf,
    pub(super) incarnation: [u8; 16],
    pub(super) next_sequence: u64,
    pub(super) poisoned: bool,
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
pub(super) fn claim(file: &File) -> Result<(), Error> {
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
    pub(super) fn finish_compaction(
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
pub(super) fn grown_within_ceiling(bytes: u64, added: u64) -> Result<u64, Error> {
    let grown = bytes.checked_add(added).ok_or(Error::Full)?;
    if grown > MAX_JOURNAL_BYTES {
        return Err(Error::Full);
    }
    Ok(grown)
}

/// The sequence after `sequence`, or [`Error::SequenceGap`] when there is no
/// such number. One home for the rule, so a change to what happens at the top
/// cannot be made in one place and missed in another.
pub(super) fn successor(sequence: u64) -> Result<u64, Error> {
    sequence.checked_add(1).ok_or(Error::SequenceGap)
}

/// The sequence a journal ending at `last` writes next.
pub(super) fn next_sequence_after(last: Option<&Record>) -> Result<u64, Error> {
    last.map_or(Ok(0), |record| successor(record.sequence))
}

pub(super) fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub fn replay(path: &Path, current_incarnation: [u8; 16]) -> Result<Replay, Error> {
    let mut file = File::open(path)?;
    replay_reader(&mut file, current_incarnation)
}

pub(super) fn replay_reader(
    reader: &mut impl Read,
    current_incarnation: [u8; 16],
) -> Result<Replay, Error> {
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
        let header = Header::decode(&bytes[offset..offset + HEADER_LEN])?;
        if header.incarnation != current_incarnation {
            return Err(Error::StaleIncarnation);
        }
        if header.payload_length > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let record_end = offset
            .checked_add(HEADER_LEN + header.payload_length + 4)
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
            incarnation: header.incarnation,
            sequence: header.sequence,
            state: header.state,
            payload: bytes[offset + HEADER_LEN..checksum_at].to_vec(),
            checkpoint: header.checkpoint,
        };
        if let Some(previous) = records.last() {
            if header.sequence == previous.sequence {
                if record != *previous {
                    return Err(Error::SequenceConflict);
                }
            } else if successor(previous.sequence).ok() != Some(header.sequence) {
                return Err(Error::SequenceGap);
            } else {
                records.push(record);
            }
        } else if header.sequence == 0 || header.checkpoint {
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
