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

pub struct PosixCommit<F> {
    profile: Profile,
    incarnation: [u8; 16],
    machine: Machine,
    staging: File,
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
            staging,
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
        let logical_length = self.staging.metadata()?.len();
        let reader = LinuxDirectReader::open(&self.staging_path, logical_length, alignment)
            .map_err(Error::Strict)?;
        match reader.identity(&self.staging).map_err(Error::Strict)? {
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
        self.finish_strict(reader, suite, expected)
    }

    fn prepare_durable(&mut self) -> Result<(), Error> {
        if let Err(error) = self
            .faults
            .check(FaultPoint::DataFlush)
            .and_then(|()| self.staging.sync_all())
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
        if let Err(error) = self
            .faults
            .check(FaultPoint::NamespaceLink)
            .and_then(|()| fs::hard_link(&self.staging_path, &self.destination))
        {
            self.machine.apply(Event::NamespaceLinkAmbiguous)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(Error::Io(error));
        }
        self.machine.apply(Event::NamespaceLinked)?;
        if let Err(error) = self.journal.append_durable(JOURNAL_NAMESPACE_LINKED, &[]) {
            self.machine.apply(Event::NamespaceFlushFailed)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(Error::Journal(error));
        }
        self.trace.push(TraceEvent::NamespaceLinked);

        let parent = self.destination.parent().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination has no parent",
            ))
        })?;
        if let Err(error) = self
            .faults
            .check(FaultPoint::DirectoryFlush)
            .and_then(|()| File::open(parent)?.sync_all())
        {
            self.machine.apply(Event::NamespaceFlushFailed)?;
            self.trace.push(TraceEvent::RecoveryRequired);
            return Err(Error::Io(error));
        }
        self.trace.push(TraceEvent::DirectoryFlushed);
        let observation = self
            .machine
            .apply(Event::NamespaceDurable)?
            .ok_or(Error::MissingObservation)?;
        self.journal.append_durable(JOURNAL_PUBLISHED, &[])?;
        self.trace.push(TraceEvent::ReceiptEmitted);
        Ok(Receipt {
            level: observation.level,
            profile: self.profile,
            incarnation: self.incarnation,
            sequence: observation.sequence,
        })
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
    let last = replay.records.last().map(|record| record.state);
    if destination.exists() {
        if last == Some(JOURNAL_PUBLISHED) {
            return Ok(RecoveryDisposition::AlreadyPublished);
        }
        if !same_file(staging_path, destination)? {
            return Err(Error::DestinationIdentityMismatch);
        }
        return Ok(RecoveryDisposition::FinishDirectoryFlush);
    }
    if staging_path.exists() {
        return Ok(RecoveryDisposition::ResumeStaging);
    }
    Err(Error::Io(io::Error::new(
        io::ErrorKind::NotFound,
        "no recoverable object",
    )))
}

fn same_file(left: &Path, right: &Path) -> Result<bool, Error> {
    let left = fs::metadata(left)?;
    let right = fs::metadata(right)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
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
