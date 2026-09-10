//! POSIX VOT commit provider with no-overwrite publication and durable namespace ordering.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use vot_platform_fs::{FileLocation, NasContract};

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
    /// The journal replays to a state other than freshly admitted, so the
    /// object belongs to [`recover`], not to a resume.
    NotAdmitted,
    AdmissionMismatch,
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
    /// The journal replays to a state other than freshly admitted, so the
    /// object belongs to [`recover`], not to a resume.
    NotAdmitted,
    AdmissionMismatch,
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
    #[cfg(test)]
    fn of_path(path: &Path) -> Result<Self, Error> {
        Self::of_location(&FileLocation::from_path(path)?)
    }

    fn of_location(location: &FileLocation) -> Result<Self, Error> {
        let (device, inode) = location.identity()?;
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&device.to_le_bytes());
        bytes[8..].copy_from_slice(&inode.to_le_bytes());
        Ok(Self(bytes))
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
    fn seal(&mut self, path: &FileLocation) -> Result<(), Error> {
        if matches!(self, Self::Sealed(_)) {
            return Ok(());
        }
        let read_only = path.open_read()?;
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
    staging_path: FileLocation,
    destination: FileLocation,
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
        staging_path: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        journal_path: &Path,
        faults: F,
    ) -> Result<Self, Error> {
        Self::create_at(
            profile,
            incarnation,
            FileLocation::from_path(staging_path.as_ref())?,
            FileLocation::from_path(destination.as_ref())?,
            FileLocation::from_path(journal_path)?,
            NasContract::Unqualified,
            faults,
        )
    }

    pub fn create_at(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: FileLocation,
        destination: FileLocation,
        journal_path: FileLocation,
        nas_contract: NasContract,
        faults: F,
    ) -> Result<Self, Error> {
        validate_contract_platform(nas_contract, cfg!(target_os = "linux"))?;
        staging_path.require_removal_parent()?;
        journal_path.require_removal_parent()?;
        let staging = staging_path.create()?;
        #[cfg(target_os = "linux")]
        if let Err(error) = validate_filesystem_profile(&staging, profile, nas_contract) {
            let _ = staging_path.remove_owned(&staging);
            return Err(error);
        }
        let journal = match Journal::create_at(journal_path, incarnation) {
            Ok(journal) => journal,
            Err(error) => {
                let _ = staging_path.remove_owned(&staging);
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
                let payload = admission_payload(
                    profile,
                    nas_contract,
                    commit.staging.handle(),
                    &commit.staging_path,
                    &commit.destination,
                )?;
                commit
                    .journal
                    .append_durable(JOURNAL_ADMITTED, &payload)
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

    /// Reopens an admitted staging file and its journal for a receiver
    /// that restarted (ADR-0047). Refuses with [`Error::NotAdmitted`]
    /// unless the journal replays, under the supplied incarnation, to
    /// exactly the admission record. The profile, NAS contract, retained
    /// directory identities, staging identity and destination name must match
    /// the admission payload. Later states belong to [`recover`].
    pub fn reattach(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        journal_path: &Path,
        faults: F,
    ) -> Result<Self, Error> {
        Self::reattach_at(
            profile,
            incarnation,
            FileLocation::from_path(staging_path.as_ref())?,
            FileLocation::from_path(destination.as_ref())?,
            FileLocation::from_path(journal_path)?,
            NasContract::Unqualified,
            faults,
        )
    }

    pub fn reattach_at(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: FileLocation,
        destination: FileLocation,
        journal_path: FileLocation,
        nas_contract: NasContract,
        faults: F,
    ) -> Result<Self, Error> {
        validate_contract_platform(nas_contract, cfg!(target_os = "linux"))?;
        staging_path.require_removal_parent()?;
        journal_path.require_removal_parent()?;
        // The journal is read before staging is opened: a published or
        // sealed transfer answers NotAdmitted even after publication
        // consumed the staging name.
        let (journal, replay) = Journal::open_at(journal_path, incarnation)?;
        let admitted = replay
            .records
            .last()
            .is_some_and(|record| record.state == JOURNAL_ADMITTED)
            && replay
                .records
                .iter()
                .all(|record| record.state == JOURNAL_ADMITTED);
        if !admitted {
            return Err(Error::NotAdmitted);
        }
        let staging = staging_path.open_write()?;
        let expected =
            admission_payload(profile, nas_contract, &staging, &staging_path, &destination)?;
        if replay
            .records
            .iter()
            .any(|record| record.payload != expected)
        {
            return Err(Error::AdmissionMismatch);
        }
        #[cfg(target_os = "linux")]
        validate_filesystem_profile(&staging, profile, nas_contract)?;
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
        // The journal already holds the admission record; only the
        // in-memory machine replays it.
        commit.machine.apply(Event::Admit)?;
        commit.trace.push(TraceEvent::Admitted);
        Ok(commit)
    }

    /// The identity this commit's journal is claimed under, for a caller
    /// that persists it to [`Self::reattach`] later (ADR-0047).
    #[must_use]
    pub const fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    /// Reclaims a publication whose final name already exists. The consumer must
    /// verify its bytes before finishing; failure leaves all recovery names intact.
    pub fn reopen_publication_at(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: FileLocation,
        destination: FileLocation,
        journal_path: FileLocation,
        nas_contract: NasContract,
        faults: F,
    ) -> Result<Self, Error> {
        let (journal, replay) = Journal::open_at(journal_path, incarnation)?;
        let file = destination.open_read()?;
        #[cfg(target_os = "linux")]
        validate_filesystem_profile(&file, profile, nas_contract)?;
        validate_contract_platform(nas_contract, cfg!(target_os = "linux"))?;
        let expected =
            admission_payload(profile, nas_contract, &file, &staging_path, &destination)?;
        let identity = Identity::of_file(&file)?;
        let machine = replay_publication(profile, &replay.records, &expected, identity)?;
        validate_publication_alias(
            Identity::of_location(&staging_path),
            identity,
            machine.state(),
        )?;
        Ok(Self {
            profile,
            incarnation,
            machine,
            staging: Staging::Sealed(file),
            staging_path,
            destination,
            journal,
            faults,
            trace: Vec::new(),
        })
    }

    /// The retained read-only object to verify during uncertain recovery.
    #[must_use]
    pub fn recovery_file(&self) -> &File {
        self.staging.handle()
    }

    /// Restores file, journal and namespace durability before returning evidence.
    pub fn finish_recovered_publication(&mut self) -> Result<Receipt, Error> {
        if !matches!(self.staging, Staging::Sealed(_)) {
            return Err(Error::NotAdmitted);
        }
        if self.profile != Profile::Fast {
            self.faults.check(FaultPoint::DataFlush)?;
            self.staging.handle().sync_all()?;
        }
        self.faults.check(FaultPoint::JournalFlush)?;
        self.journal.sync_replay()?;
        if self.machine.state() != State::Published {
            return self.publish_namespace();
        }
        self.seal_namespace(Identity::of_file(self.staging.handle())?)?;
        Ok(Receipt {
            level: Assurance::Published,
            profile: self.profile,
            incarnation: self.incarnation,
            sequence: self.machine.sequence(),
        })
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

    /// Opens staging read only and proves it is the retained file.
    pub fn read_staging(&self) -> Result<File, Error> {
        let file = self.staging_path.open_read()?;
        if Identity::of_file(&file)? != Identity::of_file(self.staging.handle())? {
            return Err(Error::StagingIdentityMismatch);
        }
        Ok(file)
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
        let reader = LinuxDirectReader::open_at(&self.staging_path, logical_length, alignment)
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
            if !Identity::of_location(&self.destination).is_ok_and(|found| found == sealed) {
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
    /// whole at-rest read. The destination is compared against the sealed
    /// handle. A mismatched name remains untouched and emits no receipt.
    ///
    /// A destination that is already the sealed object is this same call
    /// having run before, which makes publication retryable after a later
    /// step failed.
    fn link_destination(&mut self, sealed: Identity) -> Result<(), LinkError> {
        match Identity::of_location(&self.staging_path) {
            Ok(found) if found == sealed => {}
            Ok(_) => return Err(LinkError::Safe(Error::StagingIdentityMismatch)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LinkError::Safe(Error::StagingIdentityMismatch));
            }
            Err(error) => return Err(LinkError::Ambiguous(error)),
        }
        if let Err(error) = self
            .staging_path
            .link_to(self.staging.handle(), &self.destination)
        {
            // Why it failed does not decide anything; whether the destination
            // is already the sealed object does. That is this call having run
            // before, whatever the link says about it now.
            return classify_failed_link(error, Identity::of_location(&self.destination), sealed);
        }
        self.faults
            .check(FaultPoint::NamespaceLink)
            .map_err(|error| LinkError::Ambiguous(Error::Io(error)))?;
        if Identity::of_location(&self.destination).map_err(LinkError::Ambiguous)? == sealed {
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
        self.faults
            .check(FaultPoint::DirectoryFlush)
            .and_then(|()| self.destination.sync_parent())?;
        if Identity::of_location(&self.destination)? != sealed {
            return Err(Error::DestinationIdentityMismatch);
        }
        remove_alias(self.staging.handle(), &self.staging_path)?;
        // Always, not only when the two differ. When they are one directory
        // the sync above happened before the unlink, so without this the
        // removal is only in the page cache and a power loss brings the alias
        // back, still linked to the published inode.
        self.staging_path.sync_parent()?;
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
        if self.machine.state() != State::Published {
            return Err(Error::MissingObservation);
        }
        self.journal.remove_owned().map_err(Error::Journal)
    }

    fn remove_owned_names(self) -> Result<(), Error> {
        let staging = self
            .staging_path
            .remove_owned(self.staging.handle())
            .map_err(Error::Io);
        let journal = self.journal.remove_owned().map_err(Error::Journal);
        staging.and(journal)
    }
}

fn validate_contract_platform(contract: NasContract, supported: bool) -> Result<(), Error> {
    if !supported && contract != NasContract::Unqualified {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

fn validate_publication_alias(
    found: Result<Identity, Error>,
    expected: Identity,
    state: State,
) -> Result<(), Error> {
    match found {
        Ok(identity) if identity == expected => Ok(()),
        Err(Error::Io(error))
            if error.kind() == io::ErrorKind::NotFound
                && matches!(state, State::NamespaceLinked | State::Published) =>
        {
            Ok(())
        }
        _ => Err(Error::StagingIdentityMismatch),
    }
}

fn replay_publication(
    profile: Profile,
    records: &[vot_journal::Record],
    admission: &[u8],
    identity: Identity,
) -> Result<Machine, Error> {
    let mut machine = Machine::new(profile);
    for record in records {
        let events: &[Event] = match record.state {
            JOURNAL_ADMITTED if record.payload == admission => &[Event::Admit],
            JOURNAL_TRANSIT_VERIFIED if record.payload.is_empty() => &[Event::TransitVerified],
            JOURNAL_DURABLE if record.payload.is_empty() => {
                &[Event::DataFlushSucceeded, Event::JournalFlushSucceeded]
            }
            JOURNAL_AT_REST_VERIFIED if record.payload.is_empty() => &[Event::AtRestVerified],
            JOURNAL_NAMESPACE_LINKED if record.payload == identity.0 => &[Event::NamespaceLinked],
            JOURNAL_PUBLISHED if record.payload == identity.0 => &[Event::NamespaceDurable],
            _ => return Err(Error::AdmissionMismatch),
        };
        for event in events {
            machine.apply(*event)?;
        }
    }
    let ready = match profile {
        Profile::Fast => State::TransitVerified,
        Profile::Balanced => State::Durable,
        Profile::Strict => State::AtRestVerified,
    };
    if machine.state() != ready
        && !matches!(machine.state(), State::NamespaceLinked | State::Published)
    {
        return Err(Error::NotAdmitted);
    }
    Ok(machine)
}

fn admission_payload(
    profile: Profile,
    nas_contract: NasContract,
    staging: &File,
    staging_path: &FileLocation,
    destination: &FileLocation,
) -> Result<Vec<u8>, Error> {
    let profile = match profile {
        Profile::Fast => 0,
        Profile::Balanced => 1,
        Profile::Strict => 2,
    };
    let nas = match nas_contract {
        NasContract::Unqualified => 0,
        NasContract::ServerAcknowledged => 1,
    };
    let mut payload = Vec::with_capacity(83);
    payload.extend_from_slice(&[1, profile, nas]);
    for file in [
        staging,
        staging_path.directory().file(),
        destination.directory().file(),
    ] {
        payload.extend_from_slice(&Identity::of_file(file)?.0);
    }
    payload.extend_from_slice(blake3::hash(destination.name().as_bytes()).as_bytes());
    Ok(payload)
}

fn classify_failed_link(
    link_error: io::Error,
    destination: Result<Identity, Error>,
    sealed: Identity,
) -> Result<(), LinkError> {
    match destination {
        Ok(found) if found == sealed => Ok(()),
        Ok(_) => Err(LinkError::Safe(Error::Io(link_error))),
        Err(Error::Io(lookup))
            if matches!(
                lookup.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::AlreadyExists
            ) =>
        {
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
    destination: &FileLocation,
) -> Result<(), Error> {
    if recorded != sealed {
        return Err(Error::DestinationIdentityMismatch);
    }
    if Identity::of_location(destination)? != sealed {
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
    recover_at(
        &FileLocation::from_path(journal_path)?,
        incarnation,
        &FileLocation::from_path(staging_path)?,
        &FileLocation::from_path(destination)?,
    )
}

pub fn recover_at(
    journal_path: &FileLocation,
    incarnation: [u8; 16],
    staging_path: &FileLocation,
    destination: &FileLocation,
) -> Result<RecoveryDisposition, Error> {
    let replay = vot_journal::replay_at(journal_path, incarnation)?;
    let last = replay.records.last();
    let destination_identity = match Identity::of_location(destination) {
        Ok(identity) => Some(identity),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Some(found) = destination_identity {
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
    if Identity::of_location(staging_path).is_ok() {
        return Ok(RecoveryDisposition::ResumeStaging);
    }
    Err(Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "no recoverable object",
    )))
}

fn same_file(left: &FileLocation, right: &FileLocation) -> Result<bool, Error> {
    match (left.identity(), right.identity()) {
        (Ok(left), Ok(right)) => Ok(left == right),
        (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        (Err(error), _) | (_, Err(error)) => Err(Error::Io(error)),
    }
}

#[cfg(target_os = "linux")]
fn validate_filesystem_profile(
    file: &File,
    profile: Profile,
    nas_contract: NasContract,
) -> Result<(), Error> {
    let remote = vot_platform_fs::is_smb_or_nfs(file)?;
    validate_remote_profile(profile, remote, nas_contract)?;
    if nas_contract == NasContract::ServerAcknowledged {
        vot_platform_fs::validate_nas_mount(file)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_remote_profile(
    profile: Profile,
    remote: bool,
    nas_contract: NasContract,
) -> Result<(), Error> {
    if remote
        && (profile == Profile::Strict
            || (profile == Profile::Balanced && nas_contract != NasContract::ServerAcknowledged))
    {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

/// Removes a name that is already published under another. A name somebody
/// else removed first is the outcome this wanted.
fn remove_alias(file: &File, path: &FileLocation) -> Result<(), Error> {
    match path.identity() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::Io(error)),
        Ok(_) => {}
    }
    path.remove_owned(file).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn remote_filesystems_require_explicit_balanced_qualification_and_refuse_strict() {
        for profile in [
            super::Profile::Fast,
            super::Profile::Balanced,
            super::Profile::Strict,
        ] {
            assert!(
                super::validate_remote_profile(profile, false, NasContract::Unqualified).is_ok()
            );
            assert_eq!(
                super::validate_remote_profile(profile, true, NasContract::Unqualified).is_ok(),
                profile == super::Profile::Fast
            );
            assert_eq!(
                super::validate_remote_profile(profile, true, NasContract::ServerAcknowledged)
                    .is_ok(),
                profile != super::Profile::Strict
            );
            assert!(
                super::validate_remote_profile(profile, false, NasContract::ServerAcknowledged)
                    .is_ok()
            );
        }
    }
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vot_commit_strict::{DirectHash, Error as StrictError};

    fn location(path: &Path) -> FileLocation {
        FileLocation::from_path(path).unwrap()
    }

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
    fn recovery_alias_and_platform_contract_refusals_cover_all_states() {
        for supported in [false, true] {
            for contract in [NasContract::Unqualified, NasContract::ServerAcknowledged] {
                assert_eq!(
                    validate_contract_platform(contract, supported).is_ok(),
                    supported || contract == NasContract::Unqualified
                );
            }
        }
        for state in [
            State::New,
            State::Admitted,
            State::TransitVerified,
            State::DataFlushed,
            State::Durable,
            State::AtRestVerified,
            State::NamespaceLinked,
            State::Published,
            State::RecoveryRequired,
            State::Poisoned,
            State::Aborted,
        ] {
            let expected = Identity([7; 16]);
            assert!(validate_publication_alias(Ok(expected), expected, state).is_ok());
            assert!(validate_publication_alias(Ok(Identity([8; 16])), expected, state).is_err());
            for kind in [
                io::ErrorKind::NotFound,
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::AlreadyExists,
            ] {
                assert_eq!(
                    validate_publication_alias(Err(Error::Io(kind.into())), expected, state)
                        .is_ok(),
                    kind == io::ErrorKind::NotFound
                        && matches!(state, State::NamespaceLinked | State::Published)
                );
            }
            assert!(
                validate_publication_alias(Err(Error::AdmissionMismatch), expected, state).is_err()
            );
        }
    }

    #[test]
    fn recovered_publication_renews_required_barriers_and_retains_the_journal() {
        for profile in [Profile::Fast, Profile::Balanced] {
            for fault in [
                Some(FaultPoint::NamespaceLink),
                Some(FaultPoint::DirectoryFlush),
                None,
            ] {
                let root = directory("recover-publication");
                let mut commit = provider(&root, profile, fault);
                assert!(matches!(
                    commit.finish_recovered_publication(),
                    Err(Error::NotAdmitted)
                ));
                commit.write_transit_verified(b"verified bytes").unwrap();
                assert_eq!(commit.publish().is_err(), fault.is_some());
                drop(commit);
                let mut recovered = PosixCommit::reopen_publication_at(
                    profile,
                    [4; 16],
                    location(&root.join("stage")),
                    location(&root.join("object")),
                    location(&root.join("journal")),
                    NasContract::Unqualified,
                    OneFault(Some(FaultPoint::DataFlush)),
                )
                .unwrap();
                assert_eq!(recovered.recovery_file().metadata().unwrap().len(), 14);
                if profile == Profile::Balanced {
                    assert!(recovered.finish_recovered_publication().is_err());
                }
                let receipt = recovered.finish_recovered_publication().unwrap();
                let again = recovered.finish_recovered_publication().unwrap();
                assert_eq!(receipt.sequence, again.sequence);
                assert_eq!(receipt.level, Assurance::Published);
                assert!(root.join("journal").exists());
                recovered.cleanup_published().unwrap();
                assert!(!root.join("journal").exists());
                assert_eq!(fs::read(root.join("object")).unwrap(), b"verified bytes");
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn readback_cleanup_and_recovery_refuse_replaced_or_unpublished_names() {
        let root = directory("recovery-refusals");
        let commit = provider(&root, Profile::Balanced, None);
        assert!(commit.read_staging().is_ok());
        fs::rename(root.join("stage"), root.join("held")).unwrap();
        fs::write(root.join("stage"), b"unrelated").unwrap();
        assert!(matches!(
            commit.read_staging(),
            Err(Error::StagingIdentityMismatch)
        ));
        assert!(matches!(
            commit.cleanup_published(),
            Err(Error::MissingObservation)
        ));
        fs::create_dir(root.join("object")).unwrap();
        assert!(
            recover(
                &root.join("journal"),
                [4; 16],
                &root.join("stage"),
                &root.join("object")
            )
            .is_err()
        );
        #[cfg(target_os = "linux")]
        {
            let file = File::open(root.join("stage")).unwrap();
            assert!(
                validate_filesystem_profile(&file, Profile::Balanced, NasContract::Unqualified)
                    .is_ok()
            );
            assert!(
                validate_filesystem_profile(
                    &file,
                    Profile::Balanced,
                    NasContract::ServerAcknowledged
                )
                .is_err()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_replay_requires_ordered_predecessors_and_bound_payloads() {
        let admission = vec![1; 83];
        let identity = Identity([4; 16]);
        for profile in [Profile::Fast, Profile::Balanced, Profile::Strict] {
            let mut states = vec![JOURNAL_ADMITTED, JOURNAL_TRANSIT_VERIFIED];
            if profile != Profile::Fast {
                states.push(JOURNAL_DURABLE);
            }
            if profile == Profile::Strict {
                states.push(JOURNAL_AT_REST_VERIFIED);
            }
            let ready = states.len();
            states.extend([JOURNAL_NAMESPACE_LINKED, JOURNAL_PUBLISHED]);
            let records: Vec<_> = states
                .iter()
                .enumerate()
                .map(|(index, state)| vot_journal::Record {
                    incarnation: [4; 16],
                    sequence: index as u64,
                    state: *state,
                    checkpoint: false,
                    payload: match *state {
                        JOURNAL_ADMITTED => admission.clone(),
                        JOURNAL_NAMESPACE_LINKED | JOURNAL_PUBLISHED => identity.0.to_vec(),
                        _ => Vec::new(),
                    },
                })
                .collect();
            for count in 0..=records.len() {
                assert_eq!(
                    replay_publication(profile, &records[..count], &admission, identity).is_ok(),
                    count >= ready
                );
            }
            assert_eq!(
                replay_publication(profile, &records, &admission, identity)
                    .unwrap()
                    .state(),
                State::Published
            );
            for index in 0..records.len() {
                let mut invalid = records.clone();
                invalid[index].payload.push(1);
                assert!(replay_publication(profile, &invalid, &admission, identity).is_err());
                invalid = records.clone();
                invalid[index].state = 255;
                assert!(replay_publication(profile, &invalid, &admission, identity).is_err());
                invalid = records.clone();
                invalid.insert(index, invalid[index].clone());
                assert!(replay_publication(profile, &invalid, &admission, identity).is_err());
            }
        }
    }

    #[test]
    fn reattach_binds_staging_and_both_parent_identities() {
        use std::os::unix::fs::DirBuilderExt as _;

        let root = directory("admission-identities");
        let commit = provider(&root, Profile::Balanced, None);
        drop(commit);
        let other = root.join("other");
        fs::DirBuilder::new().mode(0o700).create(&other).unwrap();
        fs::hard_link(root.join("stage"), other.join("stage")).unwrap();
        for (stage, destination) in [
            (other.join("stage"), root.join("object")),
            (root.join("stage"), other.join("object")),
        ] {
            assert!(matches!(
                PosixCommit::reattach(
                    Profile::Balanced,
                    [4; 16],
                    stage,
                    destination,
                    &root.join("journal"),
                    NoFaults
                ),
                Err(Error::AdmissionMismatch)
            ));
        }
        fs::rename(root.join("stage"), root.join("saved")).unwrap();
        fs::write(root.join("stage"), b"").unwrap();
        assert!(matches!(
            PosixCommit::reattach(
                Profile::Balanced,
                [4; 16],
                root.join("stage"),
                root.join("object"),
                &root.join("journal"),
                NoFaults
            ),
            Err(Error::AdmissionMismatch)
        ));
        assert!(root.join("saved").exists());
        assert!(root.join("journal").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reattach_refuses_a_journal_with_no_admission_record() {
        // A torn tail can truncate the admission record away; zero records
        // must refuse, and vacuous truth over an empty trail must not pass
        // for admission.
        let directory = directory("reattach-empty");
        drop(Journal::create(&directory.join("journal"), [4; 16]).unwrap());
        fs::write(directory.join("stage"), b"").unwrap();
        let refused = PosixCommit::reattach(
            Profile::Fast,
            [4; 16],
            directory.join("stage"),
            directory.join("object"),
            &directory.join("journal"),
            NoFaults,
        );
        assert!(matches!(refused, Err(Error::NotAdmitted)));
    }

    #[test]
    fn reattach_refuses_every_journal_state_past_admission() {
        // Sealed: admission plus the transit-verified record.
        let sealed_dir = directory("reattach-sealed");
        let mut commit = provider(&sealed_dir, Profile::Fast, None);
        commit.write_transit_verified(b"bytes").unwrap();
        drop(commit);
        let sealed = PosixCommit::reattach(
            Profile::Fast,
            [4; 16],
            sealed_dir.join("stage"),
            sealed_dir.join("object"),
            &sealed_dir.join("journal"),
            NoFaults,
        );
        assert!(matches!(sealed, Err(Error::NotAdmitted)));

        // Linked and published: the full publication record trail.
        let published_dir = directory("reattach-published");
        let mut commit = provider(&published_dir, Profile::Fast, None);
        commit.write_transit_verified(b"bytes").unwrap();
        commit.publish().unwrap();
        drop(commit);
        let published = PosixCommit::reattach(
            Profile::Fast,
            [4; 16],
            published_dir.join("stage"),
            published_dir.join("object"),
            &published_dir.join("journal"),
            NoFaults,
        );
        assert!(matches!(published, Err(Error::NotAdmitted)));

        // Freshly admitted: reattach succeeds and the machine accepts work.
        let admitted_dir = directory("reattach-admitted");
        let commit = provider(&admitted_dir, Profile::Fast, None);
        drop(commit);
        let mut resumed = PosixCommit::reattach(
            Profile::Fast,
            [4; 16],
            admitted_dir.join("stage"),
            admitted_dir.join("object"),
            &admitted_dir.join("journal"),
            NoFaults,
        )
        .unwrap();
        assert_eq!(resumed.state(), State::Admitted);
        assert_eq!(resumed.incarnation(), [4; 16]);
        resumed.write_verified_at(0, b"resumed bytes").unwrap();
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
    fn removing_an_alias_tolerates_absence_but_not_failure() {
        let directory = directory("remove-alias");
        let name = directory.join("present");
        fs::write(&name, b"gone soon").unwrap();
        let file = File::open(&name).unwrap();
        remove_alias(&file, &location(&directory.join("never-existed"))).unwrap();
        remove_alias(&file, &location(&name)).unwrap();
        assert!(!name.exists());
        // A directory is not an alias, and the failure must surface.
        assert!(matches!(
            remove_alias(&file, &location(&directory)),
            Err(Error::Io(_))
        ));
        // NotFound is the only ignorable lookup result. A path that traverses
        // a regular file fails before unlink and must not be read as absence.
        fs::write(directory.join("component"), b"not a directory").unwrap();
        assert!(matches!(
            FileLocation::from_path(&directory.join("component/child")).map_err(Error::Io),
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
        assert!(validate_published_replay(sealed, sealed, &location(&destination)).is_ok());
        assert!(matches!(
            validate_published_replay(other, sealed, &location(&destination)),
            Err(Error::DestinationIdentityMismatch)
        ));
        assert!(matches!(
            validate_published_replay(sealed, sealed, &location(&unrelated)),
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

        assert!(
            same_file(&location(&one), &location(&linked)).unwrap(),
            "two names, one inode"
        );
        assert!(
            !same_file(&location(&one), &location(&two)).unwrap(),
            "same bytes, two inodes"
        );
        // A name that is not there is not the other one, either way round.
        let missing = directory.join("missing");
        assert!(!same_file(&location(&one), &location(&missing)).unwrap());
        assert!(!same_file(&location(&missing), &location(&one)).unwrap());
        // A symlink must fail identity lookup even when its target is the held file.
        let unreadable = directory.join("symlink");
        std::os::unix::fs::symlink(&one, &unreadable).unwrap();
        assert!(matches!(
            same_file(&location(&unreadable), &location(&one)),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            same_file(&location(&one), &location(&unreadable)),
            Err(Error::Io(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_link_that_fails_for_another_reason_is_not_read_as_a_retry() {
        let directory = directory("link-failure");
        let mut commit = provider(&directory, Profile::Balanced, None);
        commit.write_transit_verified(b"bytes").unwrap();
        commit
            .staging
            .seal(&location(&directory.join("stage")))
            .unwrap();
        let sealed = Identity::of_file(commit.staging.handle()).unwrap();
        // A destination whose parent does not exist fails with NotFound, not
        // AlreadyExists, so it is a failure rather than this call having run
        // before.
        let absent = directory.join("absent");
        fs::create_dir(&absent).unwrap();
        commit.destination = location(&absent.join("object"));
        fs::remove_dir(&absent).unwrap();
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
        commit
            .staging
            .seal(&location(&directory.join("stage")))
            .unwrap();
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
        commit
            .staging
            .seal(&location(&directory.join("stage")))
            .unwrap();
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
        clash
            .staging
            .seal(&location(&clash_directory.join("stage")))
            .unwrap();
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
            .seal(&location(&primary_directory.join("stage")))
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
        clash
            .staging
            .seal(&location(&clash_directory.join("stage")))
            .unwrap();
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
            .seal(&location(&missing_directory.join("stage")))
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
            .seal(&location(&ambiguous_directory.join("stage")))
            .unwrap();
        let ambiguous_sealed = Identity::of_file(ambiguous.staging.handle()).unwrap();
        std::os::unix::fs::symlink(
            ambiguous_directory.join("stage"),
            ambiguous_directory.join("component"),
        )
        .unwrap();
        ambiguous.staging_path = location(&ambiguous_directory.join("component"));
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
        commit
            .staging
            .seal(&location(&directory.join("stage")))
            .unwrap();
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
