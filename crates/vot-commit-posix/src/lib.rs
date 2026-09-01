//! POSIX VOT commit provider with no-overwrite publication and durable namespace ordering.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use vot_commit_model::{Assurance, Event, Machine, Profile, State};
use vot_commit_strict::{LinuxDirectReader, ReadBack, Suite};
use vot_journal::Journal;

const JOURNAL_ADMITTED: u8 = 1;
const JOURNAL_TRANSIT_VERIFIED: u8 = 2;
const JOURNAL_DURABLE: u8 = 3;
const JOURNAL_AT_REST_VERIFIED: u8 = 4;
const JOURNAL_NAMESPACE_LINKED: u8 = 5;
const JOURNAL_PUBLISHED: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    Write,
    DataFlush,
    JournalFlush,
    NamespaceLink,
    DirectoryFlush,
}

pub trait FaultInjector {
    fn check(&mut self, point: FaultPoint) -> io::Result<()>;
}

#[derive(Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn check(&mut self, _point: FaultPoint) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceEvent {
    Admitted,
    TransitVerified,
    DataFlushed,
    JournalDurable,
    AtRestVerified,
    NamespaceLinked,
    DirectoryFlushed,
    ReceiptEmitted,
    Poisoned,
    MissingObservation,
    RecoveryRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub level: Assurance,
    pub profile: Profile,
    pub incarnation: [u8; 16],
    pub sequence: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Journal(vot_journal::Error),
    Model(vot_commit_model::Error),
    Strict(vot_commit_strict::Error),
    StrictUnsupported,
    UnsupportedProfile,
    Poisoned,
    MissingObservation,
    DestinationIdentityMismatch,
    StagingIdentityMismatch,
    StrictIdentityMismatch,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vot_journal::Error> for Error {
    fn from(error: vot_journal::Error) -> Self {
        Self::Journal(error)
    }
}

impl From<vot_commit_model::Error> for Error {
    fn from(error: vot_commit_model::Error) -> Self {
        Self::Model(error)
    }
}

/// A filesystem object, as `(device, inode)`.
///
/// Not the length. The Fast profile makes no durability claim before
/// publication, so after a crash the size on disk need not be the size that
/// was linked, and comparing it would make recovery reject this provider's
/// own object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity([u8; 16]);

impl Identity {
    fn of_path(path: &Path) -> Result<Self, Error> {
        Ok(Self::of_metadata(&fs::metadata(path)?))
    }

    fn of_file(file: &File) -> Result<Self, Error> {
        Ok(Self::of_metadata(&file.metadata()?))
    }

    fn of_metadata(metadata: &fs::Metadata) -> Self {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
        bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
        Self(bytes)
    }

    /// The identity a journal record carries, or nothing for a record from
    /// before publication recorded one.
    fn from_payload(payload: &[u8]) -> Option<Self> {
        payload.try_into().ok().map(Self)
    }
}

/// The staging object. Sealing drops the write capability, so no writable
/// handle reaches publication.
enum Staging {
    Open(File),
    Sealed(File),
}

impl Staging {
    const fn handle(&self) -> &File {
        match self {
            Self::Open(file) | Self::Sealed(file) => file,
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Open(file) => file.write_all(bytes),
            Self::Sealed(_) => Err(io::Error::other("staging is sealed")),
        }
    }

    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Open(file) => file.write_all_at(bytes, offset),
            Self::Sealed(_) => Err(io::Error::other("staging is sealed")),
        }
    }

    fn set_len(&mut self, length: u64) -> io::Result<()> {
        match self {
            Self::Open(file) => file.set_len(length),
            Self::Sealed(_) => Err(io::Error::other("staging is sealed")),
        }
    }

    /// Reopens `path` read only and proves it is the inode this staging
    /// already holds, then drops the writable handle. Sealing claims nothing
    /// about durability, so the Fast profile can seal without a sync.
    fn seal(&mut self, path: &Path) -> Result<(), Error> {
        if matches!(self, Self::Sealed(_)) {
            return Ok(());
        }
        let read_only = File::open(path)?;
        if Identity::of_file(&read_only)? != Identity::of_file(self.handle())? {
            return Err(Error::StagingIdentityMismatch);
        }
        *self = Self::Sealed(read_only);
        Ok(())
    }
}

pub struct PosixCommit<F> {
    profile: Profile,
    incarnation: [u8; 16],
    machine: Machine,
    staging: Staging,
    staging_path: PathBuf,
    destination: PathBuf,
    journal: Journal,
    faults: F,
    trace: Vec<TraceEvent>,
}

impl<F: FaultInjector> PosixCommit<F> {
    /// Creates a commit only when the staging and journal parents satisfy the
    /// portable Unix removal precondition: effective-user ownership, no group
    /// or other writes, and caller serialization of same-user mutation.
    pub fn create(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: PathBuf,
        destination: PathBuf,
        journal_path: &Path,
        faults: F,
    ) -> Result<Self, Error> {
        vot_platform_fs::validate_removal_parent(&staging_path)?;
        vot_platform_fs::validate_removal_parent(journal_path)?;
        let staging = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&staging_path)?;
        let journal = match Journal::create(journal_path, incarnation) {
            Ok(journal) => journal,
            Err(error) => {
                let _ = vot_platform_fs::remove_file_handle(&staging, &staging_path);
                return Err(Error::Journal(error));
            }
        };
        let mut commit = Self {
            profile,
            incarnation,
            machine: Machine::new(profile),
            staging: Staging::Open(staging),
            staging_path,
            destination,
            journal,
            faults,
            trace: Vec::new(),
        };
        let admission = commit
            .machine
            .apply(Event::Admit)
            .map_err(Error::Model)
            .and_then(|_| {
                commit
                    .journal
                    .append_durable(JOURNAL_ADMITTED, &[])
                    .map(|_| ())
                    .map_err(Error::Journal)
            });
        if let Err(error) = admission {
            let _ = commit.remove_owned_names();
            return Err(error);
        }
        commit.trace.push(TraceEvent::Admitted);
        Ok(commit)
    }

    pub fn write_transit_verified(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.ensure_admitted()?;
        if let Err(error) = self
            .faults
            .check(FaultPoint::Write)
            .and_then(|()| self.staging.write_all(bytes))
        {
            return Err(self.fail(
                Event::DataFlushFailed,
                TraceEvent::Poisoned,
                Error::Io(error),
            ));
        }
        self.finish_transit_verified()
    }

    /// Sizes staging before verified positional range placement.
    pub fn set_len(&mut self, length: u64) -> Result<(), Error> {
        self.ensure_admitted()?;
        if let Err(error) = self
            .faults
            .check(FaultPoint::Write)
            .and_then(|()| self.staging.set_len(length))
        {
            return Err(self.fail(
                Event::DataFlushFailed,
                TraceEvent::Poisoned,
                Error::Io(error),
            ));
        }
        Ok(())
    }

    /// Places one transit-verified range without advancing global coverage.
    pub fn write_verified_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Error> {
        self.ensure_admitted()?;
        if let Err(error) = self
            .faults
            .check(FaultPoint::Write)
            .and_then(|()| self.staging.write_all_at(offset, bytes))
        {
            return Err(self.fail(
                Event::DataFlushFailed,
                TraceEvent::Poisoned,
                Error::Io(error),
            ));
        }
        Ok(())
    }

    /// A second handle to open staging for positional writes performed
    /// outside this commit's exclusive borrow (ADR-0046). The caller owns
    /// the ordering: it must observe [`Self::state`] before counting any
    /// such write, and report a failed write through
    /// [`Self::poison_write_failure`]. Refused once staging is sealed.
    pub fn try_clone_staging(&self) -> Result<File, Error> {
        match &self.staging {
            Staging::Open(file) => Ok(file.try_clone()?),
            Staging::Sealed(_) => Err(Error::Io(io::Error::other("staging is sealed"))),
        }
    }

    /// Drives the poison transition for a positional write that failed
    /// outside this commit, returning the error the caller reports. The
    /// state machine advances exactly as if [`Self::write_verified_at`] had
    /// performed the write itself.
    pub fn poison_write_failure(&mut self, error: io::Error) -> Error {
        // Concurrent writes can fail together; the loser of the relock race
        // finds the machine already poisoned and still reports its own
        // write error, never a model refusal.
        if self.machine.state() == State::Poisoned {
            return Error::Io(error);
        }
        self.fail(
            Event::DataFlushFailed,
            TraceEvent::Poisoned,
            Error::Io(error),
        )
    }

    /// Records that every staged byte has been transit verified.
    pub fn finish_transit_verified(&mut self) -> Result<(), Error> {
        self.ensure_admitted()?;
        self.machine.apply(Event::TransitVerified)?;
        if let Err(error) = self.journal.append_durable(JOURNAL_TRANSIT_VERIFIED, &[]) {
            return Err(self.fail(
                Event::JournalFlushFailed,
                TraceEvent::Poisoned,
                Error::Journal(error),
            ));
        }
        self.trace.push(TraceEvent::TransitVerified);
        Ok(())
    }

    fn ensure_admitted(&self) -> Result<(), Error> {
        if self.machine.state() == State::Poisoned {
            return Err(Error::Poisoned);
        }
        if self.machine.state() != State::Admitted {
            return Err(Error::Model(vot_commit_model::Error::InvalidTransition));
        }
        Ok(())
    }

    /// Applies a failure event, records its trace, and hands back the error
    /// to return. The call site chooses all three; this only keeps the
    /// three-step order, and an event the model refuses is reported instead
    /// of the mapped error, with no trace recorded, as before.
    fn fail(&mut self, event: Event, trace: TraceEvent, error: Error) -> Error {
        if let Err(model) = self.machine.apply(event) {
            return model.into();
        }
        self.trace.push(trace);
        error
    }

    pub fn publish(&mut self) -> Result<Receipt, Error> {
        if self.profile == Profile::Strict {
            return Err(Error::UnsupportedProfile);
        }
        if self.profile == Profile::Balanced {
            self.prepare_durable()?;
        }
        self.staging.seal(&self.staging_path)?;
        self.publish_namespace()
    }

    /// Resumes an ambiguous namespace publication from its saved state.
    pub fn retry_publication(&mut self) -> Result<Receipt, Error> {
        let repaired_published = if self.journal.is_poisoned() {
            self.journal
                .repair_poisoned()?
                .records
                .last()
                .and_then(|record| published_identity(record.state, &record.payload))
        } else {
            None
        };
        self.machine.apply(Event::Recover)?;
        if let Some(recorded) = repaired_published {
            return self.finish_published_replay(recorded);
        }
        self.publish_namespace()
    }

    fn finish_published_replay(&mut self, recorded: Identity) -> Result<Receipt, Error> {
        let sealed = Identity::of_file(self.staging.handle())?;
        validate_published_replay(recorded, sealed, &self.destination)?;
        let observation = self
            .machine
            .apply(Event::NamespaceDurable)?
            .ok_or(Error::MissingObservation)?;
        self.trace.push(TraceEvent::ReceiptEmitted);
        Ok(Receipt {
            level: observation.level,
            profile: self.profile,
            incarnation: self.incarnation,
            sequence: observation.sequence,
        })
    }

    pub fn publish_strict(
        &mut self,
        suite: Suite,
        expected: &[u8; 32],
        alignment: usize,
    ) -> Result<Receipt, Error> {
        if self.profile != Profile::Strict {
            return Err(Error::UnsupportedProfile);
        }
        self.prepare_durable()?;
        self.staging.seal(&self.staging_path)?;
        let logical_length = self.staging.handle().metadata()?.len();
        let reader = LinuxDirectReader::open(&self.staging_path, logical_length, alignment)
            .map_err(Error::Strict)?;
        match reader
            .identity(self.staging.handle())
            .map_err(Error::Strict)?
        {
            vot_commit_strict::DirectIdentity::Match
            | vot_commit_strict::DirectIdentity::Unsupported => {}
            vot_commit_strict::DirectIdentity::Mismatch => {
                return Err(Error::StrictIdentityMismatch);
            }
        }
        self.finish_strict(&reader, suite, expected)
    }

    fn finish_strict<R: ReadBack>(
        &mut self,
        reader: &R,
        suite: Suite,
        expected: &[u8; 32],
    ) -> Result<Receipt, Error> {
        let verification =
            vot_commit_strict::verify_and_advance(&mut self.machine, reader, suite, expected)
                .map_err(Error::Strict)?;
        match verification {
            vot_commit_strict::VerificationOutcome::Verified => {}
            vot_commit_strict::VerificationOutcome::Unsupported => {
                return Err(Error::StrictUnsupported);
            }
            vot_commit_strict::VerificationOutcome::Mismatch => {
                self.trace.push(TraceEvent::Poisoned);
                return Err(Error::Strict(vot_commit_strict::Error::HashMismatch));
            }
        }
        if let Err(error) = self.journal.append_durable(JOURNAL_AT_REST_VERIFIED, &[]) {
            return Err(self.fail(
                Event::JournalFlushFailed,
                TraceEvent::Poisoned,
                Error::Journal(error),
            ));
        }
        self.trace.push(TraceEvent::AtRestVerified);
        self.publish_namespace()
    }

    #[cfg(test)]
    fn publish_strict_with_test_reader<R: ReadBack>(
        &mut self,
        reader: &R,
        suite: Suite,
        expected: &[u8; 32],
    ) -> Result<Receipt, Error> {
        if self.profile != Profile::Strict {
            return Err(Error::UnsupportedProfile);
        }
        self.prepare_durable()?;
        self.staging.seal(&self.staging_path)?;
        self.finish_strict(reader, suite, expected)
    }

    fn prepare_durable(&mut self) -> Result<(), Error> {
        if let Err(error) = self
            .faults
            .check(FaultPoint::DataFlush)
            .and_then(|()| self.staging.handle().sync_all())
        {
            return Err(self.fail(
                Event::DataFlushFailed,
                TraceEvent::Poisoned,
                Error::Io(error),
            ));
        }
        self.machine.apply(Event::DataFlushSucceeded)?;
        self.trace.push(TraceEvent::DataFlushed);
        if let Err(error) = self.faults.check(FaultPoint::JournalFlush) {
            return Err(self.fail(
                Event::JournalFlushFailed,
                TraceEvent::Poisoned,
                Error::Io(error),
            ));
        }
        if let Err(error) = self.journal.append_durable(JOURNAL_DURABLE, &[]) {
            return Err(self.fail(
                Event::JournalFlushFailed,
                TraceEvent::Poisoned,
                Error::Journal(error),
            ));
        }
        self.machine.apply(Event::JournalFlushSucceeded)?;
        self.trace.push(TraceEvent::JournalDurable);
        Ok(())
    }

    fn publish_namespace(&mut self) -> Result<Receipt, Error> {
        let sealed = match Identity::of_file(self.staging.handle()) {
            Ok(sealed) => sealed,
            Err(error) => {
                return Err(self.fail(
                    Event::NamespaceLinkAmbiguous,
                    TraceEvent::RecoveryRequired,
                    error,
                ));
            }
        };
        if self.machine.state() == State::NamespaceLinked {
            if !Identity::of_path(&self.destination).is_ok_and(|found| found == sealed) {
                return Err(self.fail(
                    Event::NamespaceFlushFailed,
                    TraceEvent::RecoveryRequired,
                    Error::DestinationIdentityMismatch,
                ));
            }
        } else {
            if let Err(error) = self.link_destination(sealed) {
                return Err(match error {
                    LinkError::Safe(error) => error,
                    LinkError::Ambiguous(error) => self.fail(
                        Event::NamespaceLinkAmbiguous,
                        TraceEvent::RecoveryRequired,
                        error,
                    ),
                });
            }
            self.machine.apply(Event::NamespaceLinked)?;
            if let Err(error) = self
                .journal
                .append_durable(JOURNAL_NAMESPACE_LINKED, &sealed.0)
            {
                return Err(self.fail(
                    Event::NamespaceFlushFailed,
                    TraceEvent::RecoveryRequired,
                    Error::Journal(error),
                ));
            }
            self.trace.push(TraceEvent::NamespaceLinked);
        }

        if let Err(error) = self.seal_namespace(sealed) {
            return Err(self.fail(
                Event::NamespaceFlushFailed,
                TraceEvent::RecoveryRequired,
                error,
            ));
        }
        self.trace.push(TraceEvent::DirectoryFlushed);
        let published = self
            .faults
            .check(FaultPoint::JournalFlush)
            .map_err(Error::Io)
            .and_then(|()| {
                self.journal
                    .append_durable(JOURNAL_PUBLISHED, &sealed.0)
                    .map(|_| ())
                    .map_err(Error::Journal)
            });
        if let Err(error) = published {
            return Err(self.fail(
                Event::NamespaceFlushFailed,
                TraceEvent::RecoveryRequired,
                error,
            ));
        }
        let observation = self
            .machine
            .apply(Event::NamespaceDurable)?
            .ok_or(Error::MissingObservation)?;
        self.trace.push(TraceEvent::ReceiptEmitted);
        Ok(Receipt {
            level: observation.level,
            profile: self.profile,
            incarnation: self.incarnation,
            sequence: observation.sequence,
        })
    }

    /// Links the destination to the sealed object, and proves it.
    ///
    /// The link goes by name because that is the only portable way to make
    /// one, but a name is not what was sealed. Anything could have replaced
    /// the staging name since, and on the Strict profile the window is the
    /// whole at-rest read. So the destination is compared against the handle
    /// that was actually sealed, and a destination that is anything else is
    /// unlinked again rather than published.
    ///
    /// A destination that is already the sealed object is this same call
    /// having run before, which makes publication retryable after a later
    /// step failed.
    fn link_destination(&mut self, sealed: Identity) -> Result<(), LinkError> {
        match Identity::of_path(&self.staging_path) {
            Ok(found) if found == sealed => {}
            Ok(_) => return Err(LinkError::Safe(Error::StagingIdentityMismatch)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LinkError::Safe(Error::StagingIdentityMismatch));
            }
            Err(error) => return Err(LinkError::Ambiguous(error)),
        }
        if let Err(error) = fs::hard_link(&self.staging_path, &self.destination) {
            // Why it failed does not decide anything; whether the destination
            // is already the sealed object does. That is this call having run
            // before, whatever the link says about it now.
            return classify_failed_link(error, Identity::of_path(&self.destination), sealed);
        }
        self.faults
            .check(FaultPoint::NamespaceLink)
            .map_err(|error| LinkError::Ambiguous(Error::Io(error)))?;
        if Identity::of_path(&self.destination).map_err(LinkError::Ambiguous)? == sealed {
            return Ok(());
        }
        Err(LinkError::Ambiguous(Error::StagingIdentityMismatch))
    }

    /// Makes the destination link durable, then removes the staging name so
    /// nothing can reach the published inode through it, then makes that
    /// removal durable too. The order never leaves the object unreachable:
    /// a crash before the unlink finds both names, a crash after it finds the
    /// destination.
    fn seal_namespace(&mut self, sealed: Identity) -> Result<(), Error> {
        let (destination_parent, staging_parent) =
            flushed_directories(&self.destination, &self.staging_path)?;
        self.faults
            .check(FaultPoint::DirectoryFlush)
            .and_then(|()| File::open(destination_parent)?.sync_all())?;
        if Identity::of_path(&self.destination)? != sealed {
            return Err(Error::DestinationIdentityMismatch);
        }
        remove_alias(self.staging.handle(), &self.staging_path)?;
        // Always, not only when the two differ. When they are one directory
        // the sync above happened before the unlink, so without this the
        // removal is only in the page cache and a power loss brings the alias
        // back, still linked to the published inode.
        File::open(staging_parent)?.sync_all()?;
        Ok(())
    }

    #[must_use]
    pub fn trace(&self) -> &[TraceEvent] {
        &self.trace
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.machine.state()
    }

    /// Abandons an unpublished commit without removing substituted names.
    pub fn cancel(self) -> Result<(), Error> {
        self.remove_owned_names()
    }

    /// Removes the journal after publication while retaining its owner handle.
    pub fn cleanup_published(self) -> Result<(), Error> {
        self.journal.remove_owned().map_err(Error::Journal)
    }

    fn remove_owned_names(self) -> Result<(), Error> {
        let staging =
            vot_platform_fs::remove_file_handle(self.staging.handle(), &self.staging_path)
                .map_err(Error::Io);
        let journal = self.journal.remove_owned().map_err(Error::Journal);
        staging.and(journal)
    }
}

fn classify_failed_link(
    link_error: io::Error,
    destination: Result<Identity, Error>,
    sealed: Identity,
) -> Result<(), LinkError> {
    match destination {
        Ok(found) if found == sealed => Ok(()),
        Ok(_) => Err(LinkError::Safe(Error::Io(link_error))),
        Err(Error::Io(lookup)) if lookup.kind() == io::ErrorKind::NotFound => {
            Err(LinkError::Safe(Error::Io(link_error)))
        }
        Err(lookup) => Err(LinkError::Ambiguous(lookup)),
    }
}

fn published_identity(state: u8, payload: &[u8]) -> Option<Identity> {
    (state == JOURNAL_PUBLISHED)
        .then(|| Identity::from_payload(payload))
        .flatten()
}

fn validate_published_replay(
    recorded: Identity,
    sealed: Identity,
    destination: &Path,
) -> Result<(), Error> {
    if recorded != sealed {
        return Err(Error::DestinationIdentityMismatch);
    }
    if Identity::of_path(destination)? != sealed {
        return Err(Error::DestinationIdentityMismatch);
    }
    Ok(())
}

#[derive(Debug)]
enum LinkError {
    Safe(Error),
    Ambiguous(Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    ResumeStaging,
    FinishDirectoryFlush,
    AlreadyPublished,
}

pub fn recover(
    journal_path: &Path,
    incarnation: [u8; 16],
    staging_path: &Path,
    destination: &Path,
) -> Result<RecoveryDisposition, Error> {
    let replay = vot_journal::replay(journal_path, incarnation)?;
    let last = replay.records.last();
    if destination.exists() {
        let found = Identity::of_path(destination)?;
        let linked = last
            .filter(|record| matches!(record.state, JOURNAL_NAMESPACE_LINKED | JOURNAL_PUBLISHED));
        // The link happens before the record of it, so a crash in that window
        // leaves a destination this incarnation did link and a journal that
        // does not say so. The staging alias is still there in that window and
        // is the evidence: the two names share an inode. It also covers a
        // journal written before publication recorded an identity at all.
        let Some(record) = linked else {
            return if same_file(staging_path, destination)? {
                Ok(RecoveryDisposition::FinishDirectoryFlush)
            } else {
                Err(Error::DestinationIdentityMismatch)
            };
        };
        // A record from before publication carried an identity has none to
        // compare, and falls back to the alias the same way.
        let agrees = match Identity::from_payload(&record.payload) {
            Some(recorded) => recorded == found,
            None => same_file(staging_path, destination)?,
        };
        if !agrees {
            return Err(Error::DestinationIdentityMismatch);
        }
        return Ok(if record.state == JOURNAL_PUBLISHED {
            RecoveryDisposition::AlreadyPublished
        } else {
            RecoveryDisposition::FinishDirectoryFlush
        });
    }
    if staging_path.exists() {
        return Ok(RecoveryDisposition::ResumeStaging);
    }
    Err(Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "no recoverable object",
    )))
}

/// The parents of the two names publication changes. Both are synced, and
/// both are synced even when they are the same directory: the destination's
/// sync happens before the staging unlink, so that one cannot cover it.
fn flushed_directories<'a>(
    destination: &'a Path,
    staging: &'a Path,
) -> Result<(&'a Path, &'a Path), Error> {
    Ok((parent_of(destination)?, parent_of(staging)?))
}

/// The directory holding `path`. A bare relative name lives in the current
/// directory, which `Path::parent` reports as the empty path, and opening
/// that fails.
/// Whether two names are one file. A name that is not there is not it.
fn same_file(left: &Path, right: &Path) -> Result<bool, Error> {
    match (fs::metadata(left), fs::metadata(right)) {
        (Ok(left), Ok(right)) => Ok(Identity::of_metadata(&left) == Identity::of_metadata(&right)),
        (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        (Err(error), _) | (_, Err(error)) => Err(Error::Io(error)),
    }
}

fn parent_of(path: &Path) -> Result<&Path, Error> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .or_else(|| path.file_name().map(|_| Path::new(".")))
        .ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path has no parent",
            ))
        })
}

/// Removes a name that is already published under another. A name somebody
/// else removed first is the outcome this wanted.
fn remove_alias(file: &File, path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::Io(error)),
        Ok(_) => {}
    }
    vot_platform_fs::remove_file_handle(file, path).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vot_commit_strict::{DirectHash, Error as StrictError};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct OneFault(Option<FaultPoint>);

    impl FaultInjector for OneFault {
        fn check(&mut self, point: FaultPoint) -> io::Result<()> {
            if self.0 == Some(point) {
                self.0 = None;
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        }
    }

    fn directory(name: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;

        let path = std::env::temp_dir().join(format!(
            "vot-posix-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        path
    }

    fn provider(
        directory: &Path,
        profile: Profile,
        fault: Option<FaultPoint>,
    ) -> PosixCommit<OneFault> {
        PosixCommit::create(
            profile,
            [4; 16],
            directory.join("stage"),
            directory.join("object"),
            &directory.join("journal"),
            OneFault(fault),
        )
        .unwrap()
    }

    #[test]
    fn a_second_write_failure_after_poison_reports_its_own_error() {
        let directory = directory("double-poison");
        let mut commit = provider(&directory, Profile::Fast, None);
        let first = commit.poison_write_failure(io::Error::other("first failure"));
        assert!(matches!(first, Error::Io(_)));
        assert_eq!(commit.state(), State::Poisoned);
        let trace_len = commit.trace().len();
        // The loser of the relock race still reports its own write error,
        // never a model refusal, and adds nothing to the trace.
        let second = commit.poison_write_failure(io::Error::other("second failure"));
        assert!(matches!(second, Error::Io(_)), "{second:?}");
        assert_eq!(commit.trace().len(), trace_len);
        assert_eq!(commit.state(), State::Poisoned);
    }

    #[test]
    fn balanced_receipt_follows_directory_flush() {
        let directory = directory("balanced");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"verified bytes").unwrap();
        let receipt = commit.publish().unwrap();
        assert_eq!(receipt.level, Assurance::Published);
        let trace = commit.trace();
        assert!(
            trace
                .iter()
                .position(|event| *event == TraceEvent::DirectoryFlushed)
                .unwrap()
                < trace
                    .iter()
                    .position(|event| *event == TraceEvent::ReceiptEmitted)
                    .unwrap()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_flush_poison_cannot_retry() {
        let directory = directory("poison");
        let mut commit = provider(&directory, Profile::Balanced, Some(FaultPoint::DataFlush));
        commit.write_transit_verified(b"bytes").unwrap();
        assert!(commit.publish().is_err());
        assert_eq!(commit.state(), State::Poisoned);
        assert!(matches!(
            commit.publish(),
            Err(Error::Model(vot_commit_model::Error::Terminal))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn directory_failure_never_emits_receipt_and_recovers() {
        let directory = directory("directory-fault");
        let mut commit = provider(&directory, Profile::Fast, Some(FaultPoint::DirectoryFlush));
        commit.write_transit_verified(b"bytes").unwrap();
        assert!(commit.publish().is_err());
        assert!(!commit.trace().contains(&TraceEvent::ReceiptEmitted));
        assert_eq!(
            recover(
                &directory.join("journal"),
                [4; 16],
                &directory.join("stage"),
                &directory.join("object")
            )
            .unwrap(),
            RecoveryDisposition::FinishDirectoryFlush
        );
        commit.retry_publication().unwrap();
        assert_eq!(commit.state(), State::Published);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn namespace_link_failure_retries_from_its_predecessor() {
        let directory = directory("link-retry");
        let mut commit = provider(&directory, Profile::Fast, Some(FaultPoint::NamespaceLink));
        commit.write_transit_verified(b"bytes").unwrap();
        assert!(commit.publish().is_err());
        assert_eq!(commit.state(), State::RecoveryRequired);
        commit.retry_publication().unwrap();
        assert_eq!(commit.state(), State::Published);
        assert_eq!(fs::read(directory.join("object")).unwrap(), b"bytes");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn owned_cleanup_removes_both_names() {
        let directory = directory("admission-cleanup");
        let commit = provider(&directory, Profile::Fast, None);
        commit.cancel().unwrap();
        assert!(!directory.join("stage").exists());
        assert!(!directory.join("journal").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unsafe_parent_is_rejected_before_staging_or_admission() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = directory("unsafe-parent");
        let staging = directory.join("stage");
        let journal = directory.join("journal");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let Err(error) = PosixCommit::create(
            Profile::Fast,
            [4; 16],
            staging.clone(),
            directory.join("object"),
            &journal,
            NoFaults,
        ) else {
            panic!("unsafe parent admitted");
        };
        assert!(matches!(
            error,
            Error::Io(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(!staging.exists());
        assert!(!journal.exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn published_record_failure_remains_retryable() {
        let directory = directory("published-record-retry");
        let mut commit = provider(&directory, Profile::Fast, Some(FaultPoint::JournalFlush));
        commit.write_transit_verified(b"bytes").unwrap();
        assert!(commit.publish().is_err());
        assert_eq!(commit.state(), State::RecoveryRequired);
        assert!(!commit.trace().contains(&TraceEvent::ReceiptEmitted));
        commit.retry_publication().unwrap();
        assert_eq!(commit.state(), State::Published);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn no_overwrite_publication_is_enforced() {
        let directory = directory("no-overwrite");
        fs::write(directory.join("object"), b"existing").unwrap();
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"new").unwrap();
        assert!(commit.publish().is_err());
        assert_eq!(fs::read(directory.join("object")).unwrap(), b"existing");
        assert!(!commit.trace().contains(&TraceEvent::ReceiptEmitted));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn repeated_verified_write_cannot_mutate_published_bytes() {
        let directory = directory("repeat-write");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"first").unwrap();
        assert!(matches!(
            commit.write_transit_verified(b"second"),
            Err(Error::Model(vot_commit_model::Error::InvalidTransition))
        ));
        commit.publish().unwrap();
        assert_eq!(fs::read(directory.join("object")).unwrap(), b"first");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn positional_verified_writes_advance_only_after_completion() {
        let directory = directory("positional-write");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.set_len(6).unwrap();
        assert_eq!(commit.staging.handle().metadata().unwrap().len(), 6);
        commit.write_verified_at(3, b"def").unwrap();
        commit.write_verified_at(0, b"abc").unwrap();
        assert_eq!(commit.state(), State::Admitted);
        commit.finish_transit_verified().unwrap();
        assert_eq!(commit.state(), State::TransitVerified);
        assert!(matches!(
            commit.write_verified_at(0, b"bad"),
            Err(Error::Model(vot_commit_model::Error::InvalidTransition))
        ));
        commit.publish().unwrap();
        assert_eq!(fs::read(directory.join("object")).unwrap(), b"abcdef");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_rejects_unrelated_destination_identity() {
        let directory = directory("recovery-identity");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"staged").unwrap();
        fs::write(directory.join("object"), b"unrelated").unwrap();
        assert!(matches!(
            recover(
                &directory.join("journal"),
                [4; 16],
                &directory.join("stage"),
                &directory.join("object")
            ),
            Err(Error::DestinationIdentityMismatch)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn both_parents_are_flushed_even_when_they_are_one_directory() {
        // Named separately even when equal: the destination's sync happens
        // before the staging unlink, so it cannot stand in for the staging
        // one afterwards.
        assert_eq!(
            flushed_directories(Path::new("/a/object"), Path::new("/a/stage")).unwrap(),
            (Path::new("/a"), Path::new("/a"))
        );
        assert_eq!(
            flushed_directories(Path::new("/a/object"), Path::new("/b/stage")).unwrap(),
            (Path::new("/a"), Path::new("/b"))
        );
        // A bare relative name lives in the current directory.
        assert_eq!(
            flushed_directories(Path::new("object"), Path::new("stage")).unwrap(),
            (Path::new("."), Path::new("."))
        );
        assert!(matches!(
            flushed_directories(Path::new("/"), Path::new("/a/stage")),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn removing_an_alias_tolerates_absence_but_not_failure() {
        let directory = directory("remove-alias");
        let name = directory.join("present");
        fs::write(&name, b"gone soon").unwrap();
        let file = File::open(&name).unwrap();
        remove_alias(&file, &directory.join("never-existed")).unwrap();
        remove_alias(&file, &name).unwrap();
        assert!(!name.exists());
        // A directory is not an alias, and the failure must surface.
        assert!(matches!(remove_alias(&file, &directory), Err(Error::Io(_))));
        // NotFound is the only ignorable lookup result. A path that traverses
        // a regular file fails before unlink and must not be read as absence.
        fs::write(directory.join("component"), b"not a directory").unwrap();
        assert!(matches!(
            remove_alias(&file, &directory.join("component/child")),
            Err(Error::Io(error)) if error.kind() != io::ErrorKind::NotFound
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn published_replay_requires_marker_and_both_identities() {
        let directory = directory("published-replay-identity");
        let staged = directory.join("staged");
        let destination = directory.join("destination");
        let unrelated = directory.join("unrelated");
        fs::write(&staged, b"sealed").unwrap();
        fs::hard_link(&staged, &destination).unwrap();
        fs::write(&unrelated, b"other").unwrap();
        let sealed = Identity::of_path(&staged).unwrap();
        let other = Identity::of_path(&unrelated).unwrap();

        assert_eq!(
            published_identity(JOURNAL_PUBLISHED, &sealed.0),
            Some(sealed)
        );
        assert_eq!(
            published_identity(JOURNAL_NAMESPACE_LINKED, &sealed.0),
            None
        );
        assert!(validate_published_replay(sealed, sealed, &destination).is_ok());
        assert!(matches!(
            validate_published_replay(other, sealed, &destination),
            Err(Error::DestinationIdentityMismatch)
        ));
        assert!(matches!(
            validate_published_replay(sealed, sealed, &unrelated),
            Err(Error::DestinationIdentityMismatch)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn published_cleanup_refuses_a_substituted_journal_name() {
        let directory = directory("published-cleanup-substitution");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"bytes").unwrap();
        commit.publish().unwrap();
        let journal = directory.join("journal");
        let held = directory.join("held-journal");
        fs::rename(&journal, &held).unwrap();
        fs::write(&journal, b"replacement").unwrap();

        assert!(commit.cleanup_published().is_err());
        assert_eq!(fs::read(&journal).unwrap(), b"replacement");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn published_object_has_no_writable_staging_alias() {
        let directory = directory("no-alias");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"published bytes").unwrap();
        commit.publish().unwrap();

        let staging = directory.join("stage");
        assert!(!staging.exists(), "the staging name outlived publication");
        assert!(matches!(commit.staging, Staging::Sealed(_)));
        assert_eq!(
            commit.staging.write_all(b"more").unwrap_err().kind(),
            io::ErrorKind::Other
        );

        // The staging name is claimable again, and what lands there is a
        // different inode that cannot reach the published object.
        fs::write(&staging, b"impostor").unwrap();
        assert_eq!(
            fs::read(directory.join("object")).unwrap(),
            b"published bytes"
        );
        assert_ne!(
            Identity::of_path(&staging).unwrap(),
            Identity::of_path(&directory.join("object")).unwrap()
        );
        drop(commit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn publication_across_directories_removes_the_alias() {
        use std::os::unix::fs::DirBuilderExt as _;

        let directory = directory("cross-directory");
        let staging_directory = directory.join("staging");
        let namespace = directory.join("namespace");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&staging_directory).unwrap();
        builder.mode(0o700).create(&namespace).unwrap();
        let mut commit = PosixCommit::create(
            Profile::Balanced,
            [4; 16],
            staging_directory.join("stage"),
            namespace.join("object"),
            &directory.join("journal"),
            OneFault(None),
        )
        .unwrap();
        commit.write_transit_verified(b"crossing").unwrap();
        commit.publish().unwrap();
        assert!(!staging_directory.join("stage").exists());
        assert_eq!(fs::read(namespace.join("object")).unwrap(), b"crossing");
        drop(commit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_rejects_a_published_marker_for_an_unrelated_destination() {
        let directory = directory("forged-published");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"published bytes").unwrap();
        commit.publish().unwrap();
        drop(commit);

        // The journal still ends in PUBLISHED, but this destination holds a
        // file the incarnation never linked. Visibility is not publication.
        let unrelated = directory.join("unrelated");
        fs::write(&unrelated, b"someone else").unwrap();
        assert!(matches!(
            recover(
                &directory.join("journal"),
                [4; 16],
                &directory.join("stage"),
                &unrelated
            ),
            Err(Error::DestinationIdentityMismatch)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_finishes_a_link_whose_alias_is_already_gone() {
        let directory = directory("alias-gone");
        let mut commit = provider(&directory, Profile::Fast, Some(FaultPoint::DirectoryFlush));
        commit.write_transit_verified(b"linked").unwrap();
        assert!(commit.publish().is_err());
        drop(commit);
        // The crash cut between the destination flush and the staging flush:
        // the alias is unlinked but the journal has not reached PUBLISHED.
        fs::remove_file(directory.join("stage")).unwrap();
        assert_eq!(
            recover(
                &directory.join("journal"),
                [4; 16],
                &directory.join("stage"),
                &directory.join("object")
            )
            .unwrap(),
            RecoveryDisposition::FinishDirectoryFlush
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn same_file_answers_only_for_two_names_it_could_read() {
        let directory = directory("same-file");
        let one = directory.join("one");
        let two = directory.join("two");
        fs::write(&one, b"x").unwrap();
        fs::write(&two, b"x").unwrap();
        let linked = directory.join("linked");
        fs::hard_link(&one, &linked).unwrap();

        assert!(same_file(&one, &linked).unwrap(), "two names, one inode");
        assert!(!same_file(&one, &two).unwrap(), "same bytes, two inodes");
        // A name that is not there is not the other one, either way round.
        let missing = directory.join("missing");
        assert!(!same_file(&one, &missing).unwrap());
        assert!(!same_file(&missing, &one).unwrap());
        // Anything else is the filesystem failing and has to surface. An
        // interior NUL is invalid input on every platform, where "a component
        // of the path is a file" is NotADirectory on Unix and NotFound on
        // Windows, and NotFound is the arm this is ruling out.
        let unreadable = Path::new("vot-posix-\0-name");
        assert!(matches!(same_file(unreadable, &one), Err(Error::Io(_))));
        assert!(matches!(same_file(&one, unreadable), Err(Error::Io(_))));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_link_that_fails_for_another_reason_is_not_read_as_a_retry() {
        let directory = directory("link-failure");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"bytes").unwrap();
        commit.staging.seal(&directory.join("stage")).unwrap();
        let sealed = Identity::of_file(commit.staging.handle()).unwrap();
        // A destination whose parent does not exist fails with NotFound, not
        // AlreadyExists, so it is a failure rather than this call having run
        // before.
        commit.destination = directory.join("absent").join("object");
        assert!(matches!(
            commit.link_destination(sealed),
            Err(LinkError::Safe(Error::Io(error))) if error.kind() == io::ErrorKind::NotFound
        ));
        drop(commit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_name_swapped_after_sealing_is_never_published() {
        let directory = directory("swapped-after-seal");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit
            .write_transit_verified(b"the verified bytes")
            .unwrap();
        // Seal, which is what publish does first, then take the name away.
        // On Strict the window between these two is the whole at-rest read.
        commit.staging.seal(&directory.join("stage")).unwrap();
        fs::remove_file(directory.join("stage")).unwrap();
        fs::write(directory.join("stage"), b"somebody else's file").unwrap();

        assert!(
            matches!(commit.publish(), Err(Error::StagingIdentityMismatch)),
            "a swapped name published"
        );
        assert!(
            !directory.join("object").exists(),
            "the impostor reached the destination"
        );
        drop(commit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn publication_is_retryable_once_the_destination_is_the_sealed_object() {
        let clash_directory = directory("retry-publish-clash");
        let directory = directory("retry-publish");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"linked once").unwrap();
        commit.staging.seal(&directory.join("stage")).unwrap();
        let sealed = Identity::of_file(commit.staging.handle()).unwrap();
        // The link is already in place, as it would be after a failure in a
        // later step. Linking again gives AlreadyExists, and the destination
        // being the sealed object is what makes that the same call succeeding
        // rather than somebody else's file.
        fs::hard_link(directory.join("stage"), directory.join("object")).unwrap();
        commit.link_destination(sealed).expect("its own link");

        // A destination that exists and is somebody else's is a conflict, not
        // a retry.
        let mut clash = provider(&clash_directory, Profile::Balanced, None);
        clash.write_transit_verified(b"clashing").unwrap();
        clash.staging.seal(&clash_directory.join("stage")).unwrap();
        let clash_sealed = Identity::of_file(clash.staging.handle()).unwrap();
        fs::write(clash_directory.join("object"), b"not ours").unwrap();
        assert!(matches!(
            clash.link_destination(clash_sealed),
            Err(LinkError::Safe(Error::Io(error))) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        drop(commit);
        drop(clash);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(clash_directory).unwrap();
    }

    #[test]
    fn linking_distinguishes_every_namespace_identity_branch() {
        let primary_directory = directory("link-identity-branches");
        let mut commit = provider(&primary_directory, Profile::Fast, None);
        commit.write_transit_verified(b"sealed").unwrap();
        commit
            .staging
            .seal(&primary_directory.join("stage"))
            .unwrap();
        let sealed = Identity::of_file(commit.staging.handle()).unwrap();

        commit.link_destination(sealed).expect("fresh link");
        commit.link_destination(sealed).expect("idempotent link");

        let other = primary_directory.join("other");
        fs::write(&other, b"other").unwrap();
        let other_identity = Identity::of_path(&other).unwrap();
        assert!(matches!(
            commit.link_destination(other_identity),
            Err(LinkError::Safe(Error::StagingIdentityMismatch))
        ));

        let clash_directory = directory("link-identity-clash");
        let mut clash = provider(&clash_directory, Profile::Fast, None);
        clash.write_transit_verified(b"sealed").unwrap();
        clash.staging.seal(&clash_directory.join("stage")).unwrap();
        let clash_sealed = Identity::of_file(clash.staging.handle()).unwrap();
        fs::write(clash_directory.join("object"), b"competitor").unwrap();
        assert!(matches!(
            clash.link_destination(clash_sealed),
            Err(LinkError::Safe(Error::Io(error)))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));

        let missing_directory = directory("link-identity-missing");
        let mut missing = provider(&missing_directory, Profile::Fast, None);
        missing.write_transit_verified(b"sealed").unwrap();
        missing
            .staging
            .seal(&missing_directory.join("stage"))
            .unwrap();
        let missing_sealed = Identity::of_file(missing.staging.handle()).unwrap();
        fs::remove_file(missing_directory.join("stage")).unwrap();
        assert!(matches!(
            missing.link_destination(missing_sealed),
            Err(LinkError::Safe(Error::StagingIdentityMismatch))
        ));

        let ambiguous_directory = directory("link-identity-ambiguous");
        let mut ambiguous = provider(&ambiguous_directory, Profile::Fast, None);
        ambiguous.write_transit_verified(b"sealed").unwrap();
        ambiguous
            .staging
            .seal(&ambiguous_directory.join("stage"))
            .unwrap();
        let ambiguous_sealed = Identity::of_file(ambiguous.staging.handle()).unwrap();
        fs::write(ambiguous_directory.join("component"), b"not a directory").unwrap();
        ambiguous.staging_path = ambiguous_directory.join("component/child");
        assert!(matches!(
            ambiguous.link_destination(ambiguous_sealed),
            Err(LinkError::Ambiguous(Error::Io(error)))
                if error.kind() != io::ErrorKind::NotFound
        ));

        drop(commit);
        drop(clash);
        drop(missing);
        drop(ambiguous);
        fs::remove_dir_all(primary_directory).unwrap();
        fs::remove_dir_all(clash_directory).unwrap();
        fs::remove_dir_all(missing_directory).unwrap();
        fs::remove_dir_all(ambiguous_directory).unwrap();
    }

    #[test]
    fn failed_link_classification_distinguishes_absence_from_ambiguity() {
        let directory = directory("failed-link-classification");
        let sealed_path = directory.join("sealed");
        let other_path = directory.join("other");
        fs::write(&sealed_path, b"sealed").unwrap();
        fs::write(&other_path, b"other").unwrap();
        let sealed = Identity::of_path(&sealed_path).unwrap();
        let other = Identity::of_path(&other_path).unwrap();

        assert!(
            classify_failed_link(io::ErrorKind::AlreadyExists.into(), Ok(sealed), sealed).is_ok()
        );
        assert!(matches!(
            classify_failed_link(io::ErrorKind::AlreadyExists.into(), Ok(other), sealed),
            Err(LinkError::Safe(Error::Io(error)))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(matches!(
            classify_failed_link(
                io::ErrorKind::AlreadyExists.into(),
                Err(Error::Io(io::ErrorKind::NotFound.into())),
                sealed
            ),
            Err(LinkError::Safe(Error::Io(error)))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(matches!(
            classify_failed_link(
                io::ErrorKind::AlreadyExists.into(),
                Err(Error::Io(io::ErrorKind::PermissionDenied.into())),
                sealed
            ),
            Err(LinkError::Ambiguous(Error::Io(error)))
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_finishes_a_link_the_journal_never_recorded() {
        let directory = directory("link-before-record");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"linked").unwrap();
        commit.staging.seal(&directory.join("stage")).unwrap();
        // The crash window between the hard link and the record of it. The
        // journal's last state is TRANSIT_VERIFIED, and the two names sharing
        // an inode is the evidence recovery has.
        fs::hard_link(directory.join("stage"), directory.join("object")).unwrap();
        drop(commit);
        assert_eq!(
            recover(
                &directory.join("journal"),
                [4; 16],
                &directory.join("stage"),
                &directory.join("object")
            )
            .unwrap(),
            RecoveryDisposition::FinishDirectoryFlush
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sealing_refuses_a_staging_name_that_was_swapped() {
        let directory = directory("swapped-staging");
        let mut commit = provider(&directory, Profile::Fast, None);
        commit.write_transit_verified(b"staged").unwrap();
        fs::remove_file(directory.join("stage")).unwrap();
        fs::write(directory.join("stage"), b"substitute").unwrap();
        assert!(matches!(
            commit.publish(),
            Err(Error::StagingIdentityMismatch)
        ));
        assert!(!directory.join("object").exists());
        drop(commit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn every_injected_commit_fault_emits_no_false_receipt() {
        let faults = [
            FaultPoint::Write,
            FaultPoint::DataFlush,
            FaultPoint::JournalFlush,
            FaultPoint::NamespaceLink,
            FaultPoint::DirectoryFlush,
        ];
        for fault in faults {
            let directory = directory("fault-campaign");
            let mut commit = provider(&directory, Profile::Balanced, Some(fault));
            let result = commit
                .write_transit_verified(b"bytes")
                .and_then(|()| commit.publish().map(|_| ()));
            assert!(result.is_err(), "fault {fault:?} unexpectedly succeeded");
            assert!(!commit.trace().contains(&TraceEvent::ReceiptEmitted));
            let expected_state = match fault {
                FaultPoint::Write | FaultPoint::DataFlush | FaultPoint::JournalFlush => {
                    State::Poisoned
                }
                FaultPoint::NamespaceLink | FaultPoint::DirectoryFlush => State::RecoveryRequired,
            };
            assert_eq!(commit.state(), expected_state);
            let expected_recovery = if matches!(
                fault,
                FaultPoint::NamespaceLink | FaultPoint::DirectoryFlush
            ) {
                RecoveryDisposition::FinishDirectoryFlush
            } else {
                RecoveryDisposition::ResumeStaging
            };
            assert_eq!(
                recover(
                    &directory.join("journal"),
                    [4; 16],
                    &directory.join("stage"),
                    &directory.join("object")
                )
                .unwrap(),
                expected_recovery
            );
            drop(commit);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn recovery_distinguishes_staging_linked_and_published_crashes() {
        let staging = directory("crash-staging");
        let commit = provider(&staging, Profile::Balanced, None);
        assert_eq!(
            recover(
                &staging.join("journal"),
                [4; 16],
                &staging.join("stage"),
                &staging.join("object")
            )
            .unwrap(),
            RecoveryDisposition::ResumeStaging
        );
        drop(commit);
        fs::remove_dir_all(staging).unwrap();

        let verified = directory("crash-verified");
        let mut commit = provider(&verified, Profile::Balanced, None);
        commit.write_transit_verified(b"bytes").unwrap();
        assert_eq!(
            recover(
                &verified.join("journal"),
                [4; 16],
                &verified.join("stage"),
                &verified.join("object")
            )
            .unwrap(),
            RecoveryDisposition::ResumeStaging
        );
        drop(commit);
        fs::remove_dir_all(verified).unwrap();

        let published = directory("crash-published");
        let mut commit = provider(&published, Profile::Balanced, None);
        commit.write_transit_verified(b"bytes").unwrap();
        commit.publish().unwrap();
        assert_eq!(
            recover(
                &published.join("journal"),
                [4; 16],
                &published.join("stage"),
                &published.join("object")
            )
            .unwrap(),
            RecoveryDisposition::AlreadyPublished
        );
        drop(commit);
        fs::remove_dir_all(published).unwrap();
    }

    struct MemoryReader(DirectHash);

    impl ReadBack for MemoryReader {
        fn hash(&self, _suite: Suite) -> Result<DirectHash, StrictError> {
            Ok(self.0)
        }
    }

    #[test]
    fn strict_posix_verification_precedes_publication() {
        let bytes = b"strict verified bytes".to_vec();
        let expected = *blake3::hash(&bytes).as_bytes();

        {
            let directory = directory("strict-success");
            let mut commit = provider(&directory, Profile::Strict, None);
            commit.write_transit_verified(&bytes).unwrap();
            let receipt = commit
                .publish_strict_with_test_reader(
                    &MemoryReader(DirectHash::Supported(expected)),
                    Suite::Blake3Bao64,
                    &expected,
                )
                .unwrap();
            assert_eq!(receipt.profile, Profile::Strict);
            let trace = commit.trace();
            assert!(
                trace
                    .iter()
                    .position(|event| *event == TraceEvent::AtRestVerified)
                    .unwrap()
                    < trace
                        .iter()
                        .position(|event| *event == TraceEvent::NamespaceLinked)
                        .unwrap()
            );
            drop(commit);
            fs::remove_dir_all(directory).unwrap();
        }

        {
            let directory = directory("strict-corruption");
            let mut commit = provider(&directory, Profile::Strict, None);
            commit.write_transit_verified(&bytes).unwrap();
            let mut corrupted_hash = expected;
            corrupted_hash[0] ^= 1;
            assert!(matches!(
                commit.publish_strict_with_test_reader(
                    &MemoryReader(DirectHash::Supported(corrupted_hash)),
                    Suite::Blake3Bao64,
                    &expected,
                ),
                Err(Error::Strict(StrictError::HashMismatch))
            ));
            assert_eq!(commit.state(), State::Poisoned);
            assert!(commit.trace().contains(&TraceEvent::Poisoned));
            assert!(!directory.join("object").exists());
            drop(commit);
            fs::remove_dir_all(directory).unwrap();
        }

        {
            let directory = directory("strict-unsupported");
            let mut commit = provider(&directory, Profile::Strict, None);
            commit.write_transit_verified(b"bytes").unwrap();
            assert!(matches!(
                commit.publish_strict_with_test_reader(
                    &MemoryReader(DirectHash::Unsupported),
                    Suite::Blake3Bao64,
                    &blake3::hash(b"bytes").into(),
                ),
                Err(Error::StrictUnsupported)
            ));
            assert!(!directory.join("object").exists());
            drop(commit);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn strict_public_api_reads_back_its_own_staging_file() {
        let directory = directory("strict-bound-reader");
        let bytes = b"provider-owned strict reader";
        let expected = *blake3::hash(bytes).as_bytes();
        let mut commit = provider(&directory, Profile::Strict, None);
        commit.write_transit_verified(bytes).unwrap();
        match commit.publish_strict(Suite::Blake3Bao64, &expected, 4096) {
            Ok(receipt) => assert_eq!(receipt.level, Assurance::Published),
            Err(Error::StrictUnsupported) => assert!(!directory.join("object").exists()),
            Err(error) => panic!("unexpected Strict result: {error:?}"),
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
