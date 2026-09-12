//! Bounded mutable disk staging for canonical object checkpoints.
//!
//! The containing directory and all same-user access must remain exclusive to
//! this owner. Unix advisory locks cannot prevent writes by unrelated code.

use std::ffi::OsStr;
use std::fs::File;
#[cfg(unix)]
use std::fs::TryLockError;
use std::io;
use std::path::Path;

use vot_journal::Journal;
use vot_platform_fs::{
    Directory, FileLocation, file_identity, identity_and_links, read_exact_at, write_all_at,
};
use vot_sdk::object::{ObjectId, Suite};
use vot_sdk::verify::{RetainedRange, VerifiedSlice};

use super::{Error, ErrorKind, map_journal};
use state::{
    COMMIT, Effect, Group, INVALIDATE, REUSE, SELECT, SNAPSHOT, State, encode_object, group_length,
    validate_object,
};

mod state;
mod table;
use table::Table;
#[cfg(test)]
mod tests;

const GROUP: u64 = 65_536;
/// Maximum groups in a canonical object; metadata is paged independently of this limit.
pub const MAX_CAPTURE_GROUPS: u64 = vot_sdk::object::MAX_OBJECT_LENGTH.div_ceil(GROUP);

/// Durable local capture bookkeeping, not a publication or at-rest receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgress {
    pub object: ObjectId,
    pub sequence: u64,
    pub covered_bytes: u64,
    pub cached_groups: u64,
}

/// One serial writer of private payload, metadata and journal files on Unix or local NTFS.
///
/// Dropping preserves the files for recovery. No writable handle escapes.
/// Recovery reads and checks every surviving cached group before reporting
/// coverage. Group metadata uses one 48 KiB page in memory. The caller chooses
/// the cached-group budget and owns disk-space quotas. The replay journal has
/// its existing independent 64 MiB bound.
pub struct CaptureFile {
    file: File,
    data_location: FileLocation,
    journal_location: FileLocation,
    journal_identity: (u64, u64),
    journal: Journal,
    state: State,
    table: Table,
    cached_groups: u64,
    covered_bytes: u64,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Boundary>,
    #[cfg(test)]
    trace: Vec<Boundary>,
}

impl CaptureFile {
    /// Creates `capture.data`, `capture.groups` and `capture.journal` in an owner-only
    /// local directory. Existing names are refused. `incarnation` is a stable
    /// caller-owned capture identifier, separate from changing object roots.
    pub fn create(
        path: impl AsRef<Path>,
        incarnation: [u8; 16],
        object: &ObjectId,
        max_groups: u64,
    ) -> Result<Self, Error> {
        let directory = Directory::open(path.as_ref()).map_err(Error::io)?;
        directory.require_private().map_err(Error::io)?;
        let mut state = State::new([0; 6], max_groups, object.clone())?;
        let data_location = directory
            .entry(OsStr::new("capture.data"))
            .map_err(Error::io)?;
        let journal_location = directory
            .entry(OsStr::new("capture.journal"))
            .map_err(Error::io)?;
        let metadata_location = directory
            .entry(OsStr::new("capture.groups"))
            .map_err(Error::io)?;
        let file = data_location.create_owned().map_err(Error::io)?;
        let table = match metadata_location.create_owned() {
            Ok(metadata) => Table::new(metadata, metadata_location),
            Err(error) => {
                let _ = data_location.remove_owned(&file);
                return Err(Error::io(error));
            }
        };
        let prepared = (|| {
            #[cfg(unix)]
            claim(&file)?;
            state.binding = binding(&file, &data_location, &table.file)?;
            file.set_len(object.length).map_err(Error::io)?;
            file.sync_all().map_err(Error::io)?;
            table.file.sync_all().map_err(Error::io)?;
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
                let _ = table.location.remove_owned(&table.file);
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
            table,
            cached_groups: 0,
            covered_bytes: 0,
            poisoned: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            trace: Vec::new(),
        })
    }

    /// Reopens the same private files, repairs a torn journal tail, and reads
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
        let file = data_location.open_owned().map_err(Error::io)?;
        #[cfg(unix)]
        claim(&file)?;
        let metadata_location = directory
            .entry(OsStr::new("capture.groups"))
            .map_err(Error::io)?;
        let table = Table::new(
            metadata_location.open_owned().map_err(Error::io)?,
            metadata_location,
        );
        let actual_binding = binding(&file, &data_location, &table.file)?;
        let (journal, replay) =
            Journal::open_at(journal_location.clone(), incarnation).map_err(map_journal)?;
        let first = replay.records.first().ok_or_else(invalid)?;
        let state = State::restore(first)?;
        if state.binding != actual_binding {
            return Err(invalid());
        }
        let journal_identity = journal_location.identity().map_err(Error::io)?;
        let mut capture = Self {
            file,
            data_location,
            journal_location,
            journal_identity,
            journal,
            state,
            table,
            cached_groups: 0,
            covered_bytes: 0,
            poisoned: true,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            trace: Vec::new(),
        };
        capture.sync_recovery_journal()?;
        for record in &replay.records[1..] {
            if record.checkpoint {
                return Err(invalid());
            }
            let effect = capture
                .state
                .apply(record.sequence, record.state, &record.payload)?;
            capture.apply_table(effect, false)?;
        }
        capture
            .table
            .extent(capture.state.object.length.div_ceil(GROUP))?;
        let suite = validate_object(&capture.state.object)?;
        let mut cursor = 0;
        let mut buffer = vec![0; usize::try_from(GROUP).map_err(|_| invalid())?];
        while let Some(group) = capture.table.next(&mut cursor)? {
            group.validate(&capture.state)?;
            capture.tally(&group, true)?;
            let bytes = &mut buffer[..usize::try_from(group.length).map_err(|_| invalid())?];
            if !complete_read(read_exact_at(&capture.file, bytes, group.offset))?
                || Group::from_bytes(suite, group.offset, bytes, group.generation)? != group
            {
                capture.record(INVALIDATE, &group.offset.to_le_bytes())?;
            }
        }
        if capture.cached_groups > capture.state.limit {
            return Err(invalid());
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
        if self.table.get(offset)?.is_none() && self.cached_groups >= self.state.limit {
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
            write_all_at(
                &self.file,
                &verified.data()[..verified.data().len().div_ceil(2)],
                offset,
            )
            .map_err(Error::io)?;
            return Err(Error::io(io::Error::other(
                "injected partial capture write",
            )));
        }
        write_all_at(&self.file, verified.data(), offset).map_err(Error::io)?;
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
        let mut group = self.table.get(offset)?.ok_or_else(invalid)?;
        group.verify(&self.state.object, proof)?;
        group.generation = self.state.generation;
        self.poisoned = true;
        self.record(REUSE, &group.encode())?;
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
        let group = self.table.get(offset)?.ok_or_else(invalid)?;
        let mut bytes = vec![0; usize::try_from(group.length).map_err(|_| invalid())?];
        match read_exact_at(&self.file, &mut bytes, offset) {
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

    /// Flushes group metadata before compacting admission, target and pending
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
            covered_bytes: self.covered_bytes,
            cached_groups: self.cached_groups,
        })
    }

    fn ready(&self) -> Result<(), Error> {
        if self.poisoned
            || !self
                .data_location
                .same_file(&self.file)
                .map_err(Error::io)?
            || self.journal_location.identity().map_err(Error::io)? != self.journal_identity
            || !self
                .table
                .location
                .same_file(&self.table.file)
                .map_err(Error::io)?
            || binding(&self.file, &self.data_location, &self.table.file)? != self.state.binding
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
        #[cfg(test)]
        self.boundary(Boundary::JournalAppended(kind))?;
        let effect = self.state.apply(sequence, kind, payload)?;
        self.apply_table(effect, true)?;
        #[cfg(test)]
        self.boundary(Boundary::Recorded(kind))?;
        Ok(())
    }

    fn apply_table(&mut self, effect: Effect, tally: bool) -> Result<(), Error> {
        match effect {
            Effect::Select => {
                self.table.select(self.state.object.length)?;
                if tally {
                    // ponytail: target selection scans metadata; add page summaries if this dominates.
                    self.cached_groups = 0;
                    self.covered_bytes = 0;
                    let mut cursor = 0;
                    while let Some(group) = self.table.next(&mut cursor)? {
                        group.validate(&self.state)?;
                        self.tally(&group, true)?;
                    }
                }
            }
            Effect::Store { offset, group } => {
                if tally && let Some(old) = self.table.get(offset)? {
                    self.tally(&old, false)?;
                }
                #[cfg(test)]
                self.boundary(Boundary::BeforeMetadataWrite)?;
                self.table.put(offset, group.as_ref())?;
                #[cfg(test)]
                self.boundary(Boundary::MetadataWritten)?;
                if tally && let Some(group) = group {
                    self.tally(&group, true)?;
                }
            }
        }
        Ok(())
    }

    fn tally(&mut self, group: &Group, add: bool) -> Result<(), Error> {
        self.cached_groups = if add {
            self.cached_groups.checked_add(1)
        } else {
            self.cached_groups.checked_sub(1)
        }
        .ok_or_else(invalid)?;
        if group.generation == self.state.generation {
            self.covered_bytes = if add {
                self.covered_bytes.checked_add(group.length)
            } else {
                self.covered_bytes.checked_sub(group.length)
            }
            .ok_or_else(invalid)?;
        }
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
        #[cfg(test)]
        self.boundary(Boundary::BeforeMetadataSync)?;
        self.table.file.sync_all().map_err(Error::io)?;
        #[cfg(test)]
        self.boundary(Boundary::MetadataSynced)?;
        self.journal
            .compact_checkpoint(SNAPSHOT, &self.state.snapshot())
            .map_err(map_journal)?;
        self.journal_identity = self.journal_location.identity().map_err(Error::io)?;
        Ok(())
    }
}

#[cfg(unix)]
fn claim(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(invalid()),
        Err(TryLockError::Error(error)) => Err(Error::io(error)),
    }
}

fn binding(file: &File, location: &FileLocation, metadata: &File) -> Result<[u64; 6], Error> {
    let (data, data_links) = identity_and_links(file).map_err(Error::io)?;
    let parent = file_identity(location.directory().file()).map_err(Error::io)?;
    let (metadata, metadata_links) = identity_and_links(metadata).map_err(Error::io)?;
    if data_links != 1 || metadata_links != 1 {
        return Err(invalid());
    }
    Ok([data.0, data.1, parent.0, parent.1, metadata.0, metadata.1])
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
    BeforeMetadataWrite,
    MetadataWritten,
    BeforeMetadataSync,
    MetadataSynced,
    JournalAppended(u8),
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
