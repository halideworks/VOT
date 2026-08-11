//! Native placement of SDK-authenticated ranges with atomic publication.
//!
//! Each [`NativeFile::accept`] call is one bounded cancellation point: it
//! borrows one verified slice, writes it once, and returns current progress.
//! Dropping or cancelling a receiver removes unpublished staging files.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use vot_sdk::coverage::{CoverageCheck, ObjectCoverage};
use vot_sdk::object::ObjectId;
use vot_sdk::verify::VerifiedSlice;

const CREATE_ATTEMPTS: usize = 32;
static NEXT_NAME: AtomicU64 = AtomicU64::new(0);

/// Requested native publication guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitProfile {
    Fast,
    Balanced,
    Strict,
}

/// Stable classification for adapter failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    InvalidDestination,
    AlreadyExists,
    IdentityMismatch,
    Incomplete,
    UnsupportedPlatform,
    UnsupportedProfile,
    ResourceExhausted,
    StateConflict,
    Io,
    Internal,
}

/// Native adapter failure with an optional underlying I/O error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    io: Option<io::Error>,
}

impl Error {
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn io_error(&self) -> Option<&io::Error> {
        self.io.as_ref()
    }

    const fn plain(kind: ErrorKind) -> Self {
        Self { kind, io: None }
    }

    fn io(error: io::Error) -> Self {
        let kind = if error.kind() == io::ErrorKind::AlreadyExists {
            ErrorKind::AlreadyExists
        } else {
            ErrorKind::Io
        };
        Self {
            kind,
            io: Some(error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "VOT native file error: {:?}", self.kind)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// Whether an authenticated range changed accepted coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeStatus {
    Accepted,
    Replay,
}

/// Bounded receive progress after one range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub covered_bytes: u64,
    pub total_bytes: u64,
    pub fragments: usize,
}

/// Result and resulting progress for one authenticated range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acceptance {
    pub status: RangeStatus,
    pub progress: Progress,
}

#[cfg(unix)]
struct Backend {
    commit: vot_commit_posix::PosixCommit<vot_commit_posix::NoFaults>,
}

#[cfg(windows)]
struct Backend {
    sink: vot_scheduler::FileSink,
}

#[cfg(not(any(unix, windows)))]
struct Backend;

/// One native destination receiving authenticated object ranges.
pub struct NativeFile {
    object: ObjectId,
    coverage: ObjectCoverage,
    destination: PathBuf,
    #[cfg_attr(not(windows), allow(dead_code))]
    staging: PathBuf,
    backend: Option<Backend>,
    sealed: bool,
    preserve_recovery: bool,
    published: bool,
    #[cfg(unix)]
    profile: CommitProfile,
    #[cfg(test)]
    publish_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
}

impl NativeFile {
    /// Exclusively creates same-directory staging for one object.
    pub fn create(
        object: &ObjectId,
        destination: impl AsRef<Path>,
        profile: CommitProfile,
    ) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))]
        validate_profile(profile)?;
        let destination = destination.as_ref().to_path_buf();
        let parent = destination_parent(&destination)?;
        reject_existing(&destination)?;

        #[cfg(unix)]
        let (backend, staging, _journal) = create_unix(object, parent, &destination, profile)?;
        #[cfg(windows)]
        let (backend, staging, _journal) = write_all_at_windows_create(object, parent)?;
        #[cfg(not(any(unix, windows)))]
        let (backend, staging, _journal) = {
            let _ = (object, parent);
            return Err(Error::plain(ErrorKind::UnsupportedPlatform));
        };

        Ok(Self {
            object: object.clone(),
            coverage: ObjectCoverage::new(object),
            destination,
            staging,
            backend: Some(backend),
            sealed: false,
            preserve_recovery: false,
            published: false,
            #[cfg(unix)]
            profile,
            #[cfg(test)]
            publish_barrier: None,
        })
    }

    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            covered_bytes: self.coverage.covered_bytes(),
            total_bytes: self.object.length,
            fragments: self.coverage.fragment_count(),
        }
    }

    /// Reports whether cleanup must preserve the files needed for recovery.
    #[must_use]
    pub const fn recovery_required(&self) -> bool {
        self.preserve_recovery
    }

    /// Writes one authenticated range and commits its coverage only after the
    /// positional write succeeds. Callers cancel safely between calls.
    pub fn accept(&mut self, verified: &VerifiedSlice<'_>) -> Result<Acceptance, Error> {
        if self.published || self.sealed {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        let backend = self
            .backend
            .as_mut()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        let checked = self
            .coverage
            .check(verified)
            .map_err(|error| map_sdk_code(error.code()))?;
        let status = match checked {
            CoverageCheck::Replay => RangeStatus::Replay,
            CoverageCheck::New(booking) => {
                write_backend(backend, verified.covered_offset(), verified.data())?;
                booking.commit();
                RangeStatus::Accepted
            }
        };
        Ok(Acceptance {
            status,
            progress: self.progress(),
        })
    }

    /// Publishes complete verified coverage without overwriting a destination.
    pub fn publish(&mut self) -> Result<(), Error> {
        if self.published {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        if !self.coverage.is_complete() {
            return Err(Error::plain(ErrorKind::Incomplete));
        }
        if !self.sealed {
            reject_existing(&self.destination)?;
        }
        #[cfg(test)]
        if let Some(barrier) = &self.publish_barrier {
            barrier.wait();
        }

        #[cfg(unix)]
        self.publish_unix()?;
        #[cfg(windows)]
        self.write_all_at_windows_publish()?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::plain(ErrorKind::UnsupportedPlatform));

        self.published = true;
        self.cleanup_backend();
        Ok(())
    }

    /// Cancels before publication and reports cleanup failures.
    pub fn cancel(mut self) -> Result<(), Error> {
        if self.preserve_recovery || self.published {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        self.remove_backend()
    }

    #[cfg(unix)]
    fn publish_unix(&mut self) -> Result<(), Error> {
        let backend = self
            .backend
            .as_mut()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        if !self.sealed {
            backend
                .commit
                .finish_transit_verified()
                .map_err(map_posix)?;
            self.sealed = true;
        }
        let result = if backend.commit.state() == vot_commit_model::State::RecoveryRequired {
            backend.commit.retry_publication()
        } else {
            match self.profile {
                CommitProfile::Fast | CommitProfile::Balanced => backend.commit.publish(),
                CommitProfile::Strict => {
                    let suite = vot_commit_strict::Suite::try_from(self.object.suite)
                        .map_err(|_| Error::plain(ErrorKind::Internal))?;
                    backend
                        .commit
                        .publish_strict(suite, &self.object.root, 4096)
                }
            }
        };
        self.preserve_recovery =
            backend.commit.state() == vot_commit_model::State::RecoveryRequired;
        result.map(|_| ()).map_err(map_posix)
    }

    #[cfg(windows)]
    fn write_all_at_windows_publish(&mut self) -> Result<(), Error> {
        let backend = self
            .backend
            .as_ref()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        self.sealed = true;
        let result = vot_commit_platform::publish_native_file(
            backend.sink.file(),
            &self.staging,
            &self.destination,
            vot_receipt::CommitProfile::Fast,
        );
        if result.is_err() {
            self.preserve_recovery =
                vot_platform_fs::same_file_handle(backend.sink.file(), &self.destination)
                    .unwrap_or(true);
        }
        result.map(|_| ()).map_err(write_all_at_windows_error)
    }

    fn cleanup_backend(&mut self) {
        let Some(backend) = self.backend.take() else {
            return;
        };
        #[cfg(unix)]
        let _ = backend.commit.cleanup_published();
        #[cfg(not(unix))]
        let _ = backend;
    }

    fn remove_backend(&mut self) -> Result<(), Error> {
        let backend = self
            .backend
            .take()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        #[cfg(unix)]
        return backend.commit.cancel().map_err(map_posix);
        #[cfg(windows)]
        return vot_platform_fs::remove_file_handle(backend.sink.file(), &self.staging)
            .map_err(Error::io);
        #[cfg(not(any(unix, windows)))]
        {
            let _ = backend;
            Err(Error::plain(ErrorKind::UnsupportedPlatform))
        }
    }
}

impl Drop for NativeFile {
    fn drop(&mut self) {
        if !self.preserve_recovery && !self.published {
            let _ = self.remove_backend();
        }
    }
}

fn destination_parent(destination: &Path) -> Result<&Path, Error> {
    if destination.file_name().is_none() {
        return Err(Error::plain(ErrorKind::InvalidDestination));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !fs::metadata(parent).map_err(Error::io)?.is_dir() {
        return Err(Error::plain(ErrorKind::InvalidDestination));
    }
    Ok(parent)
}

fn reject_existing(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::plain(ErrorKind::AlreadyExists)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            destination_parent(path)?;
            Ok(())
        }
        Err(error) => Err(Error::io(error)),
    }
}

fn next_name() -> (String, [u8; 16]) {
    let sequence = NEXT_NAME.fetch_add(1, Ordering::Relaxed);
    let process = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut incarnation = [0; 16];
    incarnation[..8].copy_from_slice(&sequence.to_le_bytes());
    incarnation[8..12].copy_from_slice(&process.to_le_bytes());
    incarnation[12..].copy_from_slice(&nanos.to_le_bytes()[..4]);
    (
        format!(".vot-{process:x}-{sequence:x}-{nanos:x}"),
        incarnation,
    )
}

#[cfg(unix)]
fn create_unix(
    object: &ObjectId,
    parent: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<(Backend, PathBuf, Option<PathBuf>), Error> {
    for _ in 0..CREATE_ATTEMPTS {
        let (name, incarnation) = next_name();
        let staging = parent.join(format!("{name}.stage"));
        let journal = parent.join(format!("{name}.journal"));
        match vot_commit_posix::PosixCommit::create(
            map_profile(profile),
            incarnation,
            staging.clone(),
            destination.to_path_buf(),
            &journal,
            vot_commit_posix::NoFaults,
        ) {
            Ok(mut commit) => {
                if let Err(error) = commit.set_len(object.length) {
                    let _ = commit.cancel();
                    return Err(map_posix(error));
                }
                return Ok((Backend { commit }, staging, Some(journal)));
            }
            Err(error) => classify_creation_error(error)?,
        }
    }
    Err(Error::plain(ErrorKind::ResourceExhausted))
}

#[cfg(unix)]
fn classify_creation_error(error: vot_commit_posix::Error) -> Result<(), Error> {
    match error {
        vot_commit_posix::Error::Io(error)
        | vot_commit_posix::Error::Journal(vot_journal::Error::Io(error)) => {
            classify_creation_io(error)
        }
        vot_commit_posix::Error::Journal(error) => Err(map_journal(error)),
        error => Err(map_posix(error)),
    }
}

#[cfg(unix)]
fn classify_creation_io(error: io::Error) -> Result<(), Error> {
    if error.kind() == io::ErrorKind::AlreadyExists {
        Ok(())
    } else {
        Err(Error::io(error))
    }
}

#[cfg(windows)]
fn write_all_at_windows_create(
    object: &ObjectId,
    parent: &Path,
) -> Result<(Backend, PathBuf, Option<PathBuf>), Error> {
    for _ in 0..CREATE_ATTEMPTS {
        let (name, _) = next_name();
        let staging = parent.join(format!("{name}.stage"));
        match vot_scheduler::FileSink::create_new(&staging, object.length) {
            Ok(sink) => return Ok((Backend { sink }, staging, None)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(Error::io(error)),
        }
    }
    Err(Error::plain(ErrorKind::ResourceExhausted))
}

#[cfg(unix)]
fn write_backend(backend: &mut Backend, offset: u64, data: &[u8]) -> Result<(), Error> {
    backend
        .commit
        .write_verified_at(offset, data)
        .map_err(map_posix)
}

#[cfg(windows)]
fn write_all_at_windows(backend: &mut Backend, offset: u64, data: &[u8]) -> Result<(), Error> {
    use vot_scheduler::RangeSink as _;
    backend
        .sink
        .write_at(offset, data)
        .map_err(|_| Error::plain(ErrorKind::Io))
}

#[cfg(not(any(unix, windows)))]
fn write_all_at_unsupported(
    _backend: &mut Backend,
    _offset: u64,
    _data: &[u8],
) -> Result<(), Error> {
    Err(Error::plain(ErrorKind::UnsupportedPlatform))
}

#[cfg(windows)]
fn write_all_at_windows_validate_profile(profile: CommitProfile) -> Result<(), Error> {
    if profile != CommitProfile::Fast {
        return Err(Error::plain(ErrorKind::UnsupportedProfile));
    }
    Ok(())
}

#[cfg(windows)]
use write_all_at_windows_validate_profile as validate_profile;

#[cfg(all(unix, not(target_os = "linux")))]
fn refuse_fragmentation_macos_profile(profile: CommitProfile) -> Result<(), Error> {
    if profile == CommitProfile::Strict {
        return Err(Error::plain(ErrorKind::UnsupportedProfile));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
use refuse_fragmentation_macos_profile as validate_profile;

#[cfg(not(any(unix, windows)))]
fn write_all_at_unsupported_validate_profile(_profile: CommitProfile) -> Result<(), Error> {
    Err(Error::plain(ErrorKind::UnsupportedPlatform))
}

#[cfg(not(any(unix, windows)))]
use write_all_at_unsupported_validate_profile as validate_profile;

#[cfg(unix)]
const fn map_profile(profile: CommitProfile) -> vot_commit_model::Profile {
    match profile {
        CommitProfile::Fast => vot_commit_model::Profile::Fast,
        CommitProfile::Balanced => vot_commit_model::Profile::Balanced,
        CommitProfile::Strict => vot_commit_model::Profile::Strict,
    }
}

fn map_sdk_code(code: vot_sdk::ErrorCode) -> Error {
    let kind = match code {
        vot_sdk::ErrorCode::IdentityMismatch => ErrorKind::IdentityMismatch,
        vot_sdk::ErrorCode::ResourceExhausted | vot_sdk::ErrorCode::LimitExceeded => {
            ErrorKind::ResourceExhausted
        }
        vot_sdk::ErrorCode::StateConflict => ErrorKind::StateConflict,
        _ => ErrorKind::Internal,
    };
    Error::plain(kind)
}

#[cfg(unix)]
fn map_posix(error: vot_commit_posix::Error) -> Error {
    match error {
        vot_commit_posix::Error::Io(error) => Error::io(error),
        vot_commit_posix::Error::Journal(error) => map_journal(error),
        vot_commit_posix::Error::StrictUnsupported
        | vot_commit_posix::Error::UnsupportedProfile => {
            Error::plain(ErrorKind::UnsupportedProfile)
        }
        vot_commit_posix::Error::DestinationIdentityMismatch
        | vot_commit_posix::Error::StagingIdentityMismatch
        | vot_commit_posix::Error::StrictIdentityMismatch
        | vot_commit_posix::Error::Poisoned => Error::plain(ErrorKind::StateConflict),
        vot_commit_posix::Error::Model(_) | vot_commit_posix::Error::Strict(_) => {
            Error::plain(ErrorKind::Internal)
        }
        vot_commit_posix::Error::MissingObservation => Error::plain(ErrorKind::Internal),
    }
}

#[cfg(unix)]
fn map_journal(error: vot_journal::Error) -> Error {
    match error {
        vot_journal::Error::Io(error) => Error::io(error),
        vot_journal::Error::Full | vot_journal::Error::TooLarge => {
            Error::plain(ErrorKind::ResourceExhausted)
        }
        _ => Error::plain(ErrorKind::Internal),
    }
}

#[cfg(windows)]
fn write_all_at_windows_error(error: vot_commit_platform::Error) -> Error {
    match error {
        vot_commit_platform::Error::Io(error) => Error::io(error),
        vot_commit_platform::Error::UnsupportedPlatform => {
            Error::plain(ErrorKind::UnsupportedPlatform)
        }
        vot_commit_platform::Error::UnsupportedProfile => {
            Error::plain(ErrorKind::UnsupportedProfile)
        }
        vot_commit_platform::Error::InvalidLayout => Error::plain(ErrorKind::InvalidDestination),
    }
}

#[cfg(windows)]
use write_all_at_windows as write_backend;

#[cfg(not(any(unix, windows)))]
use write_all_at_unsupported as write_backend;

#[cfg(test)]
mod tests {
    use super::*;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};

    fn object(bytes: &[u8]) -> vot_sdk::object::InMemoryPreparedObject {
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(bytes).unwrap();
        builder.finish().unwrap()
    }

    fn directory(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("vot-sdk-file-unit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&path).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn io_error_contract_preserves_kind_source_and_display() {
        let error = Error::io(io::Error::from(io::ErrorKind::AlreadyExists));
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            error.io_error().map(io::Error::kind),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(error.to_string(), "VOT native file error: AlreadyExists");
        let other = Error::io(io::Error::other("failure"));
        assert_eq!(other.kind(), ErrorKind::Io);
    }

    #[test]
    fn sealed_and_recovery_states_are_independent() {
        let directory = directory("states");
        let prepared = object(b"bytes");
        let mut file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        assert!(!file.recovery_required());
        file.sealed = true;
        let proof = prepared.prove(0, 1).unwrap();
        let verified = vot_sdk::verify::verify_range(
            prepared.object_id(),
            proof.covered_offset(),
            b"bytes",
            proof.proof(),
        )
        .unwrap();
        assert_eq!(
            file.accept(&verified).unwrap_err().kind(),
            ErrorKind::StateConflict
        );
        file.preserve_recovery = true;
        assert!(file.recovery_required());
        let staging = file.staging.clone();
        assert_eq!(file.cancel().unwrap_err().kind(), ErrorKind::StateConflict);
        assert!(staging.exists(), "recovery state was discarded by Drop");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn destination_admission_distinguishes_absence_conflict_and_lookup_failure() {
        let directory = directory("destination-admission");
        let missing = directory.join("missing");
        reject_existing(&missing).unwrap();
        fs::write(&missing, b"present").unwrap();
        assert_eq!(
            reject_existing(&missing).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            reject_existing(&missing.join("child")).unwrap_err().kind(),
            ErrorKind::InvalidDestination
        );
        assert_eq!(
            reject_existing(Path::new("invalid\0destination"))
                .unwrap_err()
                .kind(),
            ErrorKind::Io
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn creation_retries_only_namespace_collisions() {
        assert!(classify_creation_io(io::ErrorKind::AlreadyExists.into()).is_ok());
        assert_eq!(
            classify_creation_io(io::ErrorKind::PermissionDenied.into())
                .unwrap_err()
                .kind(),
            ErrorKind::Io
        );
        assert!(
            classify_creation_error(vot_commit_posix::Error::Io(
                io::ErrorKind::AlreadyExists.into()
            ))
            .is_ok()
        );
        assert!(
            classify_creation_error(vot_commit_posix::Error::Journal(vot_journal::Error::Io(
                io::ErrorKind::AlreadyExists.into()
            )))
            .is_ok()
        );
        assert_eq!(
            classify_creation_error(vot_commit_posix::Error::Io(
                io::ErrorKind::PermissionDenied.into()
            ))
            .unwrap_err()
            .kind(),
            ErrorKind::Io
        );
        assert_eq!(
            classify_creation_error(vot_commit_posix::Error::Journal(
                vot_journal::Error::Poisoned
            ))
            .unwrap_err()
            .kind(),
            ErrorKind::Internal
        );
    }

    #[test]
    fn sdk_error_mapping_preserves_actionable_classes() {
        assert_eq!(
            map_sdk_code(vot_sdk::ErrorCode::IdentityMismatch).kind(),
            ErrorKind::IdentityMismatch
        );
        assert_eq!(
            map_sdk_code(vot_sdk::ErrorCode::ResourceExhausted).kind(),
            ErrorKind::ResourceExhausted
        );
        assert_eq!(
            map_sdk_code(vot_sdk::ErrorCode::LimitExceeded).kind(),
            ErrorKind::ResourceExhausted
        );
        assert_eq!(
            map_sdk_code(vot_sdk::ErrorCode::StateConflict).kind(),
            ErrorKind::StateConflict
        );
        assert_eq!(
            map_sdk_code(vot_sdk::ErrorCode::Malformed).kind(),
            ErrorKind::Internal
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_commit_profile_maps_without_collapsing() {
        assert_eq!(
            map_profile(CommitProfile::Fast),
            vot_commit_model::Profile::Fast
        );
        assert_eq!(
            map_profile(CommitProfile::Balanced),
            vot_commit_model::Profile::Balanced
        );
        assert_eq!(
            map_profile(CommitProfile::Strict),
            vot_commit_model::Profile::Strict
        );
    }

    #[cfg(unix)]
    #[test]
    fn journal_error_mapping_preserves_capacity_and_io() {
        assert_eq!(
            map_journal(vot_journal::Error::Io(
                io::ErrorKind::PermissionDenied.into()
            ))
            .kind(),
            ErrorKind::Io
        );
        assert_eq!(
            map_journal(vot_journal::Error::Full).kind(),
            ErrorKind::ResourceExhausted
        );
        assert_eq!(
            map_journal(vot_journal::Error::TooLarge).kind(),
            ErrorKind::ResourceExhausted
        );
        assert_eq!(
            map_journal(vot_journal::Error::Poisoned).kind(),
            ErrorKind::Internal
        );
    }

    #[cfg(unix)]
    #[test]
    fn drop_preserves_a_substituted_staging_name() {
        let directory = directory("substituted");
        let prepared = object(b"bytes");
        let file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let staging = file.staging.clone();
        let held = staging.with_extension("held");
        fs::rename(&staging, &held).unwrap();
        fs::write(&staging, b"replacement").unwrap();
        drop(file);
        assert_eq!(fs::read(&staging).unwrap(), b"replacement");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cancel_reports_substitution_instead_of_hiding_cleanup_failure() {
        let directory = directory("cancel-substituted");
        let prepared = object(b"bytes");
        let file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let staging = file.staging.clone();
        let held = staging.with_extension("held");
        fs::rename(&staging, &held).unwrap();
        fs::write(&staging, b"replacement").unwrap();
        assert_eq!(file.cancel().unwrap_err().kind(), ErrorKind::Io);
        assert_eq!(fs::read(&staging).unwrap(), b"replacement");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sealed_link_before_journal_record_resumes_without_destination_precheck() {
        let directory = directory("sealed-link-recovery");
        let destination = directory.join("object");
        let bytes = b"verified bytes";
        let prepared = object(bytes);
        let proof = prepared.prove(0, 1).unwrap();
        let verified = vot_sdk::verify::verify_range(
            prepared.object_id(),
            proof.covered_offset(),
            bytes,
            proof.proof(),
        )
        .unwrap();
        let mut file =
            NativeFile::create(prepared.object_id(), &destination, CommitProfile::Fast).unwrap();
        file.accept(&verified).unwrap();
        file.backend
            .as_mut()
            .unwrap()
            .commit
            .finish_transit_verified()
            .unwrap();
        file.sealed = true;
        fs::hard_link(&file.staging, &destination).unwrap();

        file.publish().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn two_writers_race_after_both_destination_prechecks() {
        use std::sync::{Arc, Barrier};

        let directory = directory("post-precheck-race");
        let destination = directory.join("object");
        let bytes = b"racing verified bytes";
        let prepared = object(bytes);
        let proof = prepared.prove(0, 1).unwrap();
        let verified = vot_sdk::verify::verify_range(
            prepared.object_id(),
            proof.covered_offset(),
            bytes,
            proof.proof(),
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut first =
            NativeFile::create(prepared.object_id(), &destination, CommitProfile::Fast).unwrap();
        let mut second =
            NativeFile::create(prepared.object_id(), &destination, CommitProfile::Fast).unwrap();
        first.accept(&verified).unwrap();
        second.accept(&verified).unwrap();
        first.publish_barrier = Some(Arc::clone(&barrier));
        second.publish_barrier = Some(barrier);
        let first = std::thread::spawn(move || {
            let result = first.publish();
            (first, result)
        });
        let second = std::thread::spawn(move || {
            let result = second.publish();
            (second, result)
        });
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        for (file, result) in outcomes {
            if let Err(error) = result {
                assert_eq!(error.kind(), ErrorKind::AlreadyExists);
                assert!(file.sealed, "post-admission conflict was not sealed");
                assert!(!file.recovery_required());
                file.cancel().unwrap();
            }
        }
        assert_eq!(fs::read(destination).unwrap(), bytes);
        fs::remove_dir_all(directory).unwrap();
    }
}
