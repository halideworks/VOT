//! POSIX VOT commit provider with no-overwrite publication and durable namespace ordering.

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
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
    pub fn create(
        profile: Profile,
        incarnation: [u8; 16],
        staging_path: PathBuf,
        destination: PathBuf,
        journal_path: &Path,
        faults: F,
    ) -> Result<Self, Error> {
        let staging = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&staging_path)?;
        let journal = Journal::create(journal_path, incarnation)?;
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
        commit.machine.apply(Event::Admit)?;
        commit.journal.append_durable(JOURNAL_ADMITTED, &[])?;
        commit.trace.push(TraceEvent::Admitted);
        Ok(commit)
    }

    pub fn write_transit_verified(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.machine.state() == State::Poisoned {
            return Err(Error::Poisoned);
        }
        if self.machine.state() != State::Admitted {
            return Err(Error::Model(vot_commit_model::Error::InvalidTransition));
        }
        if let Err(error) = self
            .faults
            .check(FaultPoint::Write)
            .and_then(|()| self.staging.write_all(bytes))
        {
            self.machine.apply(Event::DataFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Io(error));
        }
        self.machine.apply(Event::TransitVerified)?;
        if let Err(error) = self.journal.append_durable(JOURNAL_TRANSIT_VERIFIED, &[]) {
            self.machine.apply(Event::JournalFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Journal(error));
        }
        self.trace.push(TraceEvent::TransitVerified);
        Ok(())
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
            self.machine.apply(Event::JournalFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Journal(error));
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
            self.machine.apply(Event::DataFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Io(error));
        }
        self.machine.apply(Event::DataFlushSucceeded)?;
        self.trace.push(TraceEvent::DataFlushed);
        if let Err(error) = self.faults.check(FaultPoint::JournalFlush) {
            self.machine.apply(Event::JournalFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Io(error));
        }
        if let Err(error) = self.journal.append_durable(JOURNAL_DURABLE, &[]) {
            self.machine.apply(Event::JournalFlushFailed)?;
            self.trace.push(TraceEvent::Poisoned);
            return Err(Error::Journal(error));
        }
        self.machine.apply(Event::JournalFlushSucceeded)?;
        self.trace.push(TraceEvent::JournalDurable);
        Ok(())
    }

    fn publish_namespace(&mut self) -> Result<Receipt, Error> {
        let sealed = match Identity::of_file(self.staging.handle()) {
            Ok(sealed) => sealed,
            Err(error) => {
                self.machine.apply(Event::NamespaceLinkAmbiguous)?;
                self.trace.push(TraceEvent::RecoveryRequired);
                return Err(error);
            }
        };
        if let Err(error) = self.link_destination(sealed) {
            self.machine.apply(Event::NamespaceLinkAmbiguous)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(error);
        }
        self.machine.apply(Event::NamespaceLinked)?;
        // Recovery compares this against the destination it finds, so it never
        // has to infer identity from a staging name that publication removes.
        let identity = sealed;
        if let Err(error) = self
            .journal
            .append_durable(JOURNAL_NAMESPACE_LINKED, &identity.0)
        {
            self.machine.apply(Event::NamespaceFlushFailed)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(Error::Journal(error));
        }
        self.trace.push(TraceEvent::NamespaceLinked);

        if let Err(error) = self.seal_namespace() {
            self.machine.apply(Event::NamespaceFlushFailed)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(error);
        }
        self.trace.push(TraceEvent::DirectoryFlushed);
        let observation = self
            .machine
            .apply(Event::NamespaceDurable)?
            .ok_or(Error::MissingObservation)?;
        self.journal
            .append_durable(JOURNAL_PUBLISHED, &identity.0)?;
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
    fn link_destination(&mut self, sealed: Identity) -> Result<(), Error> {
        self.faults.check(FaultPoint::NamespaceLink)?;
        if let Err(error) = fs::hard_link(&self.staging_path, &self.destination) {
            // Why it failed does not decide anything; whether the destination
            // is already the sealed object does. That is this call having run
            // before, whatever the link says about it now.
            return if Identity::of_path(&self.destination).is_ok_and(|found| found == sealed) {
                Ok(())
            } else {
                Err(Error::Io(error))
            };
        }
        if Identity::of_path(&self.destination)? == sealed {
            return Ok(());
        }
        // The name resolved to something else. Take back the link rather than
        // publish and receipt bytes this provider never wrote.
        remove_alias(&self.destination)?;
        Err(Error::StagingIdentityMismatch)
    }

    /// Makes the destination link durable, then removes the staging name so
    /// nothing can reach the published inode through it, then makes that
    /// removal durable too. The order never leaves the object unreachable:
    /// a crash before the unlink finds both names, a crash after it finds the
    /// destination.
    fn seal_namespace(&mut self) -> Result<(), Error> {
        let (destination_parent, staging_parent) =
            flushed_directories(&self.destination, &self.staging_path)?;
        self.faults
            .check(FaultPoint::DirectoryFlush)
            .and_then(|()| File::open(destination_parent)?.sync_all())?;
        remove_alias(&self.staging_path)?;
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
fn remove_alias(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
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
        let path = std::env::temp_dir().join(format!(
            "vot-posix-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
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
        remove_alias(&directory.join("never-existed")).unwrap();
        let name = directory.join("present");
        fs::write(&name, b"gone soon").unwrap();
        remove_alias(&name).unwrap();
        assert!(!name.exists());
        // A directory is not an alias, and the failure must surface.
        assert!(matches!(remove_alias(&directory), Err(Error::Io(_))));
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
        let directory = directory("cross-directory");
        let staging_directory = directory.join("staging");
        let namespace = directory.join("namespace");
        fs::create_dir(&staging_directory).unwrap();
        fs::create_dir(&namespace).unwrap();
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
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound
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
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        drop(commit);
        drop(clash);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(clash_directory).unwrap();
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
            let expected_recovery = if fault == FaultPoint::DirectoryFlush {
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
