//! Bounded mutable disk staging for canonical object checkpoints.
//!
//! The containing directory and all same-user access must remain exclusive to
//! this owner. Advisory locks do not prevent unrelated code from writing bytes.

use std::ffi::OsStr;
use std::fs::{File, TryLockError};
use std::io;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use vot_journal::Journal;
use vot_platform_fs::{Directory, FileLocation};
use vot_sdk::object::{ObjectId, Suite};
use vot_sdk::verify::{RetainedRange, VerifiedSlice};

use super::{Error, ErrorKind, map_journal};
use state::{
    COMMIT, Group, INVALIDATE, REUSE, SELECT, SNAPSHOT, State, encode_object, group_length,
    validate_object,
};

mod state;
#[cfg(test)]
mod tests;

const GROUP: u64 = 65_536;
/// Full snapshots fit the existing journal's 1 MiB record limit.
pub const MAX_CAPTURE_GROUPS: usize = 8_192;

/// Durable local capture bookkeeping, not a publication or at-rest receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgress {
    pub object: ObjectId,
    pub sequence: u64,
    pub covered_bytes: u64,
    pub cached_groups: usize,
}

/// One serial writer of a private payload and checksummed journal on Unix.
///
/// Dropping preserves both files for recovery. No writable handle escapes.
/// Recovery reads and checks every surviving cached group before reporting
/// coverage. The group budget bounds metadata; 8,192 groups fully cover 512 MiB.
/// Larger sparse objects are allowed, but their full coverage needs more than
/// this prototype's bounded snapshot. Disk-space quotas belong to the caller.
pub struct CaptureFile {
    file: File,
    data_location: FileLocation,
    journal_location: FileLocation,
    journal_identity: (u64, u64),
    journal: Journal,
    state: State,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Boundary>,
    #[cfg(test)]
    trace: Vec<Boundary>,
}

impl CaptureFile {
    /// Creates `capture.data` and `capture.journal` in an existing owner-only
    /// local directory. Existing names are refused. `incarnation` is a stable
    /// caller-owned capture identifier, separate from changing object roots.
    pub fn create(
        path: impl AsRef<Path>,
        incarnation: [u8; 16],
        object: &ObjectId,
        max_groups: usize,
    ) -> Result<Self, Error> {
        let directory = Directory::open(path.as_ref()).map_err(Error::io)?;
        directory.require_private().map_err(Error::io)?;
        let mut state = State::new([0; 4], max_groups, object.clone())?;
        let data_location = directory
            .entry(OsStr::new("capture.data"))
            .map_err(Error::io)?;
        let journal_location = directory
            .entry(OsStr::new("capture.journal"))
            .map_err(Error::io)?;
        let file = data_location.create().map_err(Error::io)?;
        let prepared = (|| {
            claim(&file)?;
            state.binding = binding(&file, &data_location)?;
            file.set_len(object.length).map_err(Error::io)?;
            file.sync_all().map_err(Error::io)?;
            let mut journal =
                Journal::create_at(journal_location.clone(), incarnation).map_err(map_journal)?;
            if let Err(error) = journal.append_durable(SNAPSHOT, &state.snapshot()) {
                let _ = journal.remove_owned();
                return Err(map_journal(error));
            }
            Ok(journal)
        })();
        let journal = match prepared {
            Ok(journal) => journal,
            Err(error) => {
                let _ = data_location.remove_owned(&file);
                return Err(error);
            }
        };
        let journal_identity = journal_location.identity().map_err(Error::io)?;
        Ok(Self {
            file,
            data_location,
            journal_location,
            journal_identity,
            journal,
            state,
            poisoned: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            trace: Vec::new(),
        })
    }

    /// Reopens the same private pair, repairs a torn journal tail, and reads
    /// back surviving groups. Corrupt or shortened groups become durably
    /// invalid; unaffected groups remain reusable. Other I/O errors refuse open.
    pub fn open(path: impl AsRef<Path>, incarnation: [u8; 16]) -> Result<Self, Error> {
        let directory = Directory::open(path.as_ref()).map_err(Error::io)?;
        directory.require_private().map_err(Error::io)?;
        let data_location = directory
            .entry(OsStr::new("capture.data"))
            .map_err(Error::io)?;
        let journal_location = directory
            .entry(OsStr::new("capture.journal"))
            .map_err(Error::io)?;
        let file = data_location.open_write().map_err(Error::io)?;
        claim(&file)?;
        let actual_binding = binding(&file, &data_location)?;
        let (journal, replay) =
            Journal::open_at(journal_location.clone(), incarnation).map_err(map_journal)?;
        let first = replay.records.first().ok_or_else(invalid)?;
        let mut state = State::restore(first)?;
        if state.binding != actual_binding {
            return Err(invalid());
        }
        for record in &replay.records[1..] {
            if record.checkpoint {
                return Err(invalid());
            }
            state.apply(record.sequence, record.state, &record.payload)?;
        }
        let journal_identity = journal_location.identity().map_err(Error::io)?;
        let mut capture = Self {
            file,
            data_location,
            journal_location,
            journal_identity,
            journal,
            state,
            poisoned: true,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            trace: Vec::new(),
        };
        capture.sync_recovery_journal()?;
        let suite = validate_object(&capture.state.object)?;
        let mut invalidated = Vec::new();
        for group in capture.state.groups.values() {
            let mut bytes = vec![0; usize::try_from(group.length).map_err(|_| invalid())?];
            if complete_read(capture.file.read_exact_at(&mut bytes, group.offset))? {
                if Group::from_bytes(suite, group.offset, &bytes, group.generation)? != *group {
                    invalidated.push(group.offset);
                }
            } else {
                invalidated.push(group.offset);
            }
        }
        for offset in invalidated {
            capture.record(INVALIDATE, &offset.to_le_bytes())?;
        }
        capture.resize()?;
        capture.poisoned = false;
        Ok(capture)
    }

    /// Selects a new canonical checkpoint, retiring previous coverage while
    /// retaining unchanged group commitments for explicit proof-based reuse.
    /// Truncation discards shortened and removed groups before shrinking bytes.
    pub fn select(&mut self, object: &ObjectId) -> Result<CaptureProgress, Error> {
        self.ready()?;
        validate_object(object)?;
        if object.suite != self.state.object.suite {
            return Err(invalid());
        }
        self.poisoned = true;
        self.record(SELECT, &encode_object(object))?;
        self.resize()?;
        self.poisoned = false;
        self.progress()
    }

    /// Replaces one complete authenticated group. Invalidation is durable
    /// before the write; data is flushed before the verified record is durable.
    /// Any ambiguous write or barrier error requires dropping and reopening.
    pub fn accept(&mut self, verified: &VerifiedSlice<'_>) -> Result<CaptureProgress, Error> {
        self.ready()?;
        if verified.object_id() != self.state.object {
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        let offset = verified.covered_offset();
        if verified.data().len() as u64 != group_length(self.state.object.length, offset)? {
            return Err(invalid());
        }
        if !self.state.groups.contains_key(&offset) && self.state.groups.len() >= self.state.limit {
            return Err(Error::plain(ErrorKind::ResourceExhausted));
        }
        let group = Group::from_bytes(
            validate_object(&self.state.object)?,
            offset,
            verified.data(),
            self.state.generation,
        )?;
        self.poisoned = true;
        self.record(INVALIDATE, &offset.to_le_bytes())?;
        #[cfg(test)]
        if self.fault == Some(Boundary::PartialWrite) {
            self.file
                .write_all_at(
                    &verified.data()[..verified.data().len().div_ceil(2)],
                    offset,
                )
                .map_err(Error::io)?;
            return Err(Error::io(io::Error::other(
                "injected partial capture write",
            )));
        }
        self.file
            .write_all_at(verified.data(), offset)
            .map_err(Error::io)?;
        #[cfg(test)]
        self.boundary(Boundary::Written)?;
        self.sync_data()?;
        self.record(COMMIT, &group.encode())?;
        self.poisoned = false;
        self.progress()
    }

    /// Authenticates one cached group's exact bytes under the selected root,
    /// without reading payload, and durably records the new coverage.
    pub fn reuse(&mut self, offset: u64, proof: &[u8]) -> Result<CaptureProgress, Error> {
        self.ready()?;
        let group = self.state.groups.get(&offset).ok_or_else(invalid)?;
        group.verify(&self.state.object, proof)?;
        self.poisoned = true;
        self.record(REUSE, &offset.to_le_bytes())?;
        self.poisoned = false;
        self.progress()
    }

    /// Releases one cached group and its coverage while preserving payload.
    pub fn invalidate(&mut self, offset: u64) -> Result<CaptureProgress, Error> {
        self.ready()?;
        group_length(self.state.object.length, offset)?;
        self.poisoned = true;
        self.record(INVALIDATE, &offset.to_le_bytes())?;
        self.poisoned = false;
        self.progress()
    }

    /// Reads one group and verifies it against the selected root and proof.
    /// A byte witness is returned only after fresh payload verification.
    pub fn read(&mut self, offset: u64, proof: &[u8]) -> Result<RetainedRange, Error> {
        self.ready()?;
        let group = self.state.groups.get(&offset).ok_or_else(invalid)?.clone();
        let mut bytes = vec![0; usize::try_from(group.length).map_err(|_| invalid())?];
        match self.file.read_exact_at(&mut bytes, offset) {
            Ok(()) => {}
            Err(error) => {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    self.invalidate(offset)?;
                }
                return Err(Error::io(error));
            }
        }
        if Group::from_bytes(
            validate_object(&self.state.object)?,
            offset,
            &bytes,
            group.generation,
        )? != group
        {
            self.invalidate(offset)?;
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        vot_sdk::verify::verify_range(&self.state.object, offset, &bytes, proof)
            .map(VerifiedSlice::retain)
            .map_err(|error| super::map_sdk_code(error.code()))
    }

    /// Compacts the complete admission, target, cached groups and pending
    /// invalidation into one durable snapshot without releasing writer locks.
    pub fn checkpoint(&mut self) -> Result<CaptureProgress, Error> {
        self.ready()?;
        self.poisoned = true;
        self.compact()?;
        self.poisoned = false;
        self.progress()
    }

    pub fn progress(&self) -> Result<CaptureProgress, Error> {
        self.ready()?;
        Ok(CaptureProgress {
            object: self.state.object.clone(),
            sequence: self.state.sequence,
            covered_bytes: self.state.covered_bytes(),
            cached_groups: self.state.groups.len(),
        })
    }

    fn ready(&self) -> Result<(), Error> {
        if self.poisoned
            || !self
                .data_location
                .same_file(&self.file)
                .map_err(Error::io)?
            || self.journal_location.identity().map_err(Error::io)? != self.journal_identity
            || binding(&self.file, &self.data_location)? != self.state.binding
        {
            return Err(invalid());
        }
        self.data_location
            .directory()
            .require_private()
            .map_err(Error::io)
    }

    fn resize(&mut self) -> Result<(), Error> {
        self.file
            .set_len(self.state.object.length)
            .map_err(Error::io)?;
        #[cfg(test)]
        self.boundary(Boundary::Resized)?;
        self.sync_data()
    }

    fn sync_data(&mut self) -> Result<(), Error> {
        #[cfg(test)]
        self.boundary(Boundary::BeforeDataSync)?;
        self.file.sync_all().map_err(Error::io)?;
        #[cfg(test)]
        self.boundary(Boundary::DataSynced)?;
        Ok(())
    }

    fn sync_recovery_journal(&mut self) -> Result<(), Error> {
        self.journal.sync_replay().map_err(map_journal)?;
        #[cfg(test)]
        self.boundary(Boundary::JournalSynced)?;
        #[cfg(test)]
        self.boundary(Boundary::BeforeParentSync)?;
        self.journal_location.sync_parent().map_err(Error::io)?;
        #[cfg(test)]
        self.boundary(Boundary::ParentSynced)?;
        Ok(())
    }

    fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Error> {
        #[cfg(test)]
        self.boundary(Boundary::BeforeRecord(kind))?;
        let sequence = match self.append(kind, payload) {
            Err(vot_journal::Error::Full) => {
                self.compact()?;
                self.journal
                    .append_durable(kind, payload)
                    .map_err(map_journal)?
            }
            result => result.map_err(map_journal)?,
        };
        self.state.apply(sequence, kind, payload)?;
        #[cfg(test)]
        self.boundary(Boundary::Recorded(kind))?;
        Ok(())
    }

    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<u64, vot_journal::Error> {
        #[cfg(test)]
        if self.fault == Some(Boundary::JournalFull(kind)) {
            self.fault = None;
            return Err(vot_journal::Error::Full);
        }
        self.journal.append_durable(kind, payload)
    }

    fn compact(&mut self) -> Result<(), Error> {
        self.journal
            .compact_checkpoint(SNAPSHOT, &self.state.snapshot())
            .map_err(map_journal)?;
        self.journal_identity = self.journal_location.identity().map_err(Error::io)?;
        Ok(())
    }
}

fn claim(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(invalid()),
        Err(TryLockError::Error(error)) => Err(Error::io(error)),
    }
}

fn binding(file: &File, location: &FileLocation) -> Result<[u64; 4], Error> {
    let data = file.metadata().map_err(Error::io)?;
    let parent = location.directory().file().metadata().map_err(Error::io)?;
    if data.nlink() != 1 {
        return Err(invalid());
    }
    Ok([data.dev(), data.ino(), parent.dev(), parent.ino()])
}

fn complete_read(result: io::Result<()>) -> Result<bool, Error> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(Error::io(error)),
    }
}

fn invalid() -> Error {
    Error::plain(ErrorKind::StateConflict)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    JournalSynced,
    ParentSynced,
    BeforeParentSync,
    JournalFull(u8),
    BeforeRecord(u8),
    Recorded(u8),
    PartialWrite,
    Written,
    BeforeDataSync,
    DataSynced,
    Resized,
}

#[cfg(test)]
impl CaptureFile {
    fn boundary(&mut self, boundary: Boundary) -> Result<(), Error> {
        self.trace.push(boundary);
        if self.fault == Some(boundary) {
            return Err(Error::io(io::Error::other(
                "injected capture boundary failure",
            )));
        }
        Ok(())
    }
}
