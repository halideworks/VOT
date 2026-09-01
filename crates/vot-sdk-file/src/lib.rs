//! Native placement of SDK-authenticated ranges with atomic publication.
//!
//! Each [`NativeFile::accept`] call is one bounded cancellation point: it
//! borrows one verified slice, writes it once, and returns current progress.
//! Dropping or cancelling a receiver removes unpublished staging files.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::fmt;
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(unix))]
use vot_sdk::coverage::CoverageCheck;
#[cfg(unix)]
use vot_sdk::coverage::CoverageReserve;
use vot_sdk::coverage::ObjectCoverage;
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
    /// The range collides with an accept still in flight on another thread.
    /// Retryable: after the holder commits, the same range is a replay.
    RangeInFlight,
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
    /// Bytes covered contiguously from offset zero. Ranges arrive out of
    /// order, so this is the only safe offset to resume an upload from;
    /// `covered_bytes` may count extents beyond a hole.
    pub prefix_bytes: u64,
    pub total_bytes: u64,
    pub fragments: usize,
}

/// Result and resulting progress for one authenticated range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acceptance {
    pub status: RangeStatus,
    pub progress: Progress,
}

/// Provider-level observation captured by a successful publish, for callers
/// that issue receipts about the publication. Unix only today: the Windows
/// path does not surface an incarnation or sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishObservation {
    pub incarnation: [u8; 16],
    pub sequence: u64,
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

/// Mutable receive state, everything the one lock covers: coverage, the
/// commit state machine, and the lifecycle flags (ADR-0046). Bytes are
/// written outside it.
struct Shared {
    coverage: ObjectCoverage,
    backend: Option<Backend>,
    sealed: bool,
    preserve_recovery: bool,
    published: bool,
    observation: Option<PublishObservation>,
}

/// One native destination receiving authenticated object ranges.
///
/// [`Self::accept`] takes `&self`: disjoint verified ranges write
/// concurrently, with bookkeeping behind one internal lock. Lifecycle
/// operations ([`Self::publish`], [`Self::cancel`]) take `&mut self` or
/// `self`, so the borrow checker already serializes them against every
/// in-flight accept.
pub struct NativeFile {
    object: ObjectId,
    destination: PathBuf,
    #[cfg_attr(not(windows), allow(dead_code))]
    staging: PathBuf,
    /// Writable staging handle for accepts, held outside the state lock so
    /// disjoint positional writes proceed concurrently.
    #[cfg(unix)]
    write_handle: File,
    #[cfg(unix)]
    profile: CommitProfile,
    shared: std::sync::Mutex<Shared>,
    #[cfg(test)]
    publish_barrier: Option<std::sync::Arc<std::sync::Barrier>>,
    /// Forces the next unlocked positional write to fail, standing in for
    /// the fault injector that sat below the write before ADR-0046 moved
    /// the write out of the commit.
    #[cfg(all(unix, test))]
    write_fault: std::sync::atomic::AtomicBool,
    /// Parks an accept between its successful write and its relock, so a
    /// test can poison the commit inside exactly that window. Both waits
    /// are bounded: a mutant that keeps either side from its rendezvous
    /// must fail the test, never hang it.
    #[cfg(all(unix, test))]
    write_park: Option<std::sync::Arc<TestPark>>,
}

/// Holder-side ends of the park rendezvous: announce fires after a
/// successful write, release lets the relock proceed.
#[cfg(all(unix, test))]
struct TestPark {
    announce: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
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

        #[cfg(unix)]
        let write_handle = match backend.commit.try_clone_staging() {
            Ok(handle) => handle,
            Err(error) => {
                let _ = backend.commit.cancel();
                return Err(map_posix(error));
            }
        };
        Ok(Self {
            object: object.clone(),
            destination,
            staging,
            #[cfg(unix)]
            write_handle,
            #[cfg(unix)]
            profile,
            shared: std::sync::Mutex::new(Shared {
                coverage: ObjectCoverage::new(object),
                backend: Some(backend),
                sealed: false,
                preserve_recovery: false,
                published: false,
                observation: None,
            }),
            #[cfg(test)]
            publish_barrier: None,
            #[cfg(all(unix, test))]
            write_fault: std::sync::atomic::AtomicBool::new(false),
            #[cfg(all(unix, test))]
            write_park: None,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared.lock().expect("native file state lock poisoned")
    }

    fn state_mut(&mut self) -> &mut Shared {
        self.shared
            .get_mut()
            .expect("native file state lock poisoned")
    }

    fn progress_of(&self, shared: &Shared) -> Progress {
        Progress {
            covered_bytes: shared.coverage.covered_bytes(),
            prefix_bytes: shared.coverage.contiguous_prefix(),
            total_bytes: self.object.length,
            fragments: shared.coverage.fragment_count(),
        }
    }

    #[must_use]
    pub fn progress(&self) -> Progress {
        let shared = self.lock();
        self.progress_of(&shared)
    }

    /// Reports whether cleanup must preserve the files needed for recovery.
    #[must_use]
    pub fn recovery_required(&self) -> bool {
        self.lock().preserve_recovery
    }

    /// The provider observation from the last successful [`Self::publish`],
    /// or `None` before publication and on platforms without one.
    #[must_use]
    pub fn publish_observation(&self) -> Option<PublishObservation> {
        self.lock().observation
    }

    /// Refusals every accept observes under the lock before touching
    /// coverage. Lifecycle flags cannot change while any accept runs, since
    /// publish and cancel need exclusive access; the poison state can, from
    /// a concurrent accept whose write failed.
    #[cfg(unix)]
    fn ensure_accepting(shared: &Shared) -> Result<(), Error> {
        if shared.published || shared.sealed {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        let backend = shared
            .backend
            .as_ref()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        match backend.commit.state() {
            vot_commit_model::State::Poisoned => Err(map_posix(vot_commit_posix::Error::Poisoned)),
            vot_commit_model::State::Admitted => Ok(()),
            _ => Err(map_posix(vot_commit_posix::Error::Model(
                vot_commit_model::Error::InvalidTransition,
            ))),
        }
    }

    #[cfg(unix)]
    fn write_ranged(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        #[cfg(test)]
        if self.write_fault.swap(false, Ordering::Relaxed) {
            return Err(io::Error::other("injected write fault"));
        }
        let written = self.write_handle.write_all_at(data, offset);
        #[cfg(test)]
        if written.is_ok()
            && let Some(park) = &self.write_park
        {
            park.announce.send(()).expect("park listener gone");
            park.release
                .lock()
                .expect("park release lock")
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("park release never arrived; the test side is stuck");
        }
        written
    }

    /// Writes one authenticated range and commits its coverage only after
    /// the positional write succeeds. Callers cancel safely between calls.
    ///
    /// Takes `&self`: disjoint ranges verified elsewhere may be accepted
    /// from as many threads as the caller runs (ADR-0046). The write lands
    /// outside the lock; bookkeeping, replay classification, and the poison
    /// transition stay inside it.
    pub fn accept(&self, verified: &VerifiedSlice<'_>) -> Result<Acceptance, Error> {
        #[cfg(unix)]
        {
            self.accept_parallel(verified)
        }
        #[cfg(not(unix))]
        {
            self.accept_serial(verified)
        }
    }

    #[cfg(unix)]
    fn accept_parallel(&self, verified: &VerifiedSlice<'_>) -> Result<Acceptance, Error> {
        let reservation = {
            let mut shared = self.lock();
            Self::ensure_accepting(&shared)?;
            match shared
                .coverage
                .reserve(verified)
                .map_err(|error| map_sdk_code(error.code()))?
            {
                CoverageReserve::Replay => {
                    return Ok(Acceptance {
                        status: RangeStatus::Replay,
                        progress: self.progress_of(&shared),
                    });
                }
                CoverageReserve::New(reservation) => reservation,
            }
        };
        let written = self.write_ranged(verified.covered_offset(), verified.data());
        let mut shared = self.lock();
        match written {
            Ok(()) => {
                // A concurrent accept may have poisoned the commit while
                // this write was in flight; a range whose bytes landed then
                // is released, never committed.
                if let Err(error) = Self::ensure_accepting(&shared) {
                    shared.coverage.release_reservation(reservation);
                    return Err(error);
                }
                shared.coverage.commit_reservation(reservation);
                Ok(Acceptance {
                    status: RangeStatus::Accepted,
                    progress: self.progress_of(&shared),
                })
            }
            Err(error) => {
                shared.coverage.release_reservation(reservation);
                let backend = shared
                    .backend
                    .as_mut()
                    .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
                Err(map_posix(backend.commit.poison_write_failure(error)))
            }
        }
    }

    /// Windows and unsupported platforms keep the serial shape under the
    /// lock; the write sink there needs exclusive access.
    #[cfg(not(unix))]
    fn accept_serial(&self, verified: &VerifiedSlice<'_>) -> Result<Acceptance, Error> {
        let mut shared = self.lock();
        if shared.published || shared.sealed {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        let shared = &mut *shared;
        let backend = shared
            .backend
            .as_mut()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        let checked = shared
            .coverage
            .check(verified)
            .map_err(|error| map_sdk_code(error.code()))?;
        let status = match checked {
            CoverageCheck::Replay => RangeStatus::Replay,
            CoverageCheck::New(booking) => {
                #[cfg(windows)]
                write_all_at_windows(backend, verified.covered_offset(), verified.data())?;
                #[cfg(not(any(unix, windows)))]
                write_all_at_unsupported(backend, verified.covered_offset(), verified.data())?;
                booking.commit();
                RangeStatus::Accepted
            }
        };
        Ok(Acceptance {
            status,
            progress: Progress {
                covered_bytes: shared.coverage.covered_bytes(),
                prefix_bytes: shared.coverage.contiguous_prefix(),
                total_bytes: self.object.length,
                fragments: shared.coverage.fragment_count(),
            },
        })
    }

    /// Publishes complete verified coverage without overwriting a destination.
    ///
    /// Exclusive access here is what serializes publication against every
    /// in-flight accept: an incomplete coverage, which any outstanding
    /// reservation implies, is refused before sealing.
    pub fn publish(&mut self) -> Result<(), Error> {
        let shared = self.state_mut();
        if shared.published {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        if !shared.coverage.is_complete() {
            return Err(Error::plain(ErrorKind::Incomplete));
        }
        if !shared.sealed {
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

        let shared = self.state_mut();
        shared.published = true;
        Self::cleanup_backend(shared);
        Ok(())
    }

    /// Cancels before publication and reports cleanup failures.
    pub fn cancel(mut self) -> Result<(), Error> {
        let shared = self.state_mut();
        if shared.preserve_recovery || shared.published {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        self.remove_backend()
    }

    #[cfg(unix)]
    fn publish_unix(&mut self) -> Result<(), Error> {
        let object = self.object.clone();
        let profile = self.profile;
        let shared = self.state_mut();
        let backend = shared
            .backend
            .as_mut()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        if !shared.sealed {
            backend
                .commit
                .finish_transit_verified()
                .map_err(map_posix)?;
            shared.sealed = true;
        }
        let result = if backend.commit.state() == vot_commit_model::State::RecoveryRequired {
            backend.commit.retry_publication()
        } else {
            match profile {
                CommitProfile::Fast | CommitProfile::Balanced => backend.commit.publish(),
                CommitProfile::Strict => {
                    let suite = vot_commit_strict::Suite::try_from(object.suite)
                        .map_err(|_| Error::plain(ErrorKind::Internal))?;
                    backend.commit.publish_strict(suite, &object.root, 4096)
                }
            }
        };
        shared.preserve_recovery =
            backend.commit.state() == vot_commit_model::State::RecoveryRequired;
        result
            .map(|receipt| {
                shared.observation = Some(PublishObservation {
                    incarnation: receipt.incarnation,
                    sequence: receipt.sequence,
                });
            })
            .map_err(map_posix)
    }

    #[cfg(windows)]
    fn write_all_at_windows_publish(&mut self) -> Result<(), Error> {
        let staging = self.staging.clone();
        let destination = self.destination.clone();
        let shared = self.state_mut();
        let backend = shared
            .backend
            .as_ref()
            .ok_or_else(|| Error::plain(ErrorKind::StateConflict))?;
        shared.sealed = true;
        let result = vot_commit_platform::publish_native_file(
            backend.sink.file(),
            &staging,
            &destination,
            vot_receipt::CommitProfile::Fast,
        );
        if result.is_err() {
            shared.preserve_recovery =
                vot_platform_fs::same_file_handle(backend.sink.file(), &destination)
                    .unwrap_or(true);
        }
        result.map(|_| ()).map_err(write_all_at_windows_error)
    }

    fn cleanup_backend(shared: &mut Shared) {
        let Some(backend) = shared.backend.take() else {
            return;
        };
        #[cfg(unix)]
        let _ = backend.commit.cleanup_published();
        #[cfg(not(unix))]
        let _ = backend;
    }

    fn remove_backend(&mut self) -> Result<(), Error> {
        let backend = self
            .state_mut()
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
        let shared = self.state_mut();
        if !shared.preserve_recovery && !shared.published {
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
        vot_sdk::ErrorCode::RangeInFlight => ErrorKind::RangeInFlight,
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
        file.state_mut().sealed = true;
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
        file.state_mut().preserve_recovery = true;
        assert!(file.recovery_required());
        let staging = file.staging.clone();
        assert_eq!(file.cancel().unwrap_err().kind(), ErrorKind::StateConflict);
        assert!(staging.exists(), "recovery state was discarded by Drop");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn publish_captures_a_provider_observation() {
        let directory = directory("observation");
        let bytes = b"observed bytes";
        let prepared = object(bytes);
        let proof = prepared.prove(0, 1).unwrap();
        let verified = vot_sdk::verify::verify_range(
            prepared.object_id(),
            proof.covered_offset(),
            bytes,
            proof.proof(),
        )
        .unwrap();
        let mut file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        assert_eq!(file.publish_observation(), None);
        file.accept(&verified).unwrap();
        file.publish().unwrap();
        let observation = file.publish_observation().expect("published observation");
        assert!(observation.sequence >= 1);
        assert_ne!(observation.incarnation, [0; 16]);
        fs::remove_dir_all(directory).unwrap();
    }

    const GROUP: usize = 65_536;

    fn object_with(suite: Suite, bytes: &[u8]) -> vot_sdk::object::InMemoryPreparedObject {
        let mut builder =
            InMemoryObjectBuilder::new(suite, Some(bytes.len() as u64), bytes.len() as u64)
                .unwrap();
        builder.update(bytes).unwrap();
        builder.finish().unwrap()
    }

    /// Test-side ends of the park rendezvous, bounded on both sides.
    #[cfg(unix)]
    fn armed_park(
        file: &mut NativeFile,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (announce_tx, announce_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        file.write_park = Some(std::sync::Arc::new(TestPark {
            announce: announce_tx,
            release: std::sync::Mutex::new(release_rx),
        }));
        (announce_rx, release_tx)
    }

    /// One proof and verified slice per 64 KiB group, precomputed so worker
    /// threads only verify and accept.
    fn group_proofs(
        prepared: &vot_sdk::object::InMemoryPreparedObject,
        data: &[u8],
    ) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        (0..data.len() / GROUP)
            .map(|group| {
                let offset = group * GROUP;
                let proof = prepared.prove(offset as u64, 1).unwrap();
                (
                    proof.covered_offset(),
                    data[offset..offset + GROUP].to_vec(),
                    proof.proof().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn concurrent_disjoint_ranges_accept_once_and_publish_the_source() {
        for (name, suite) in [
            ("parallel-blake3", Suite::Blake3Bao64),
            ("parallel-sha256", Suite::Sha256Bep52),
        ] {
            let directory = directory(name);
            let data: Vec<u8> = (0..8 * GROUP)
                .map(|index| u8::try_from(index % 256).unwrap())
                .collect();
            let prepared = object_with(suite, &data);
            let destination = directory.join("object");
            let mut file =
                NativeFile::create(prepared.object_id(), &destination, CommitProfile::Fast)
                    .unwrap();
            let object_id = prepared.object_id().clone();
            std::thread::scope(|scope| {
                let file = &file;
                let object_id = &object_id;
                for (offset, bytes, proof) in group_proofs(&prepared, &data) {
                    scope.spawn(move || {
                        let verified =
                            vot_sdk::verify::verify_range(object_id, offset, &bytes, &proof)
                                .unwrap();
                        let accepted = file.accept(&verified).unwrap();
                        assert_eq!(accepted.status, RangeStatus::Accepted);
                        // Progress is monotone: it includes at least this
                        // range's bytes the moment accept returns.
                        assert!(accepted.progress.covered_bytes >= GROUP as u64);
                    });
                }
            });
            let progress = file.progress();
            assert_eq!(progress.covered_bytes, data.len() as u64);
            assert_eq!(progress.prefix_bytes, data.len() as u64);
            // A committed range replays instead of double counting.
            let (offset, bytes, proof) = group_proofs(&prepared, &data).remove(0);
            let verified =
                vot_sdk::verify::verify_range(&object_id, offset, &bytes, &proof).unwrap();
            let replay = file.accept(&verified).unwrap();
            assert_eq!(replay.status, RangeStatus::Replay);
            assert_eq!(replay.progress.covered_bytes, data.len() as u64);
            file.publish().unwrap();
            assert_eq!(fs::read(&destination).unwrap(), data);
            drop(file);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn racing_duplicates_of_one_range_accept_exactly_once() {
        let directory = directory("duplicate-race");
        let data = vec![0x3c; 4 * GROUP];
        let prepared = object(&data);
        let file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let object_id = prepared.object_id().clone();
        let proof = prepared.prove(0, 1).unwrap();
        let offset = proof.covered_offset();
        let bytes = &data[..GROUP];
        let proof = proof.proof().to_vec();
        let accepted = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let verified =
                        vot_sdk::verify::verify_range(&object_id, offset, bytes, &proof).unwrap();
                    match file.accept(&verified) {
                        Ok(acceptance) => {
                            if acceptance.status == RangeStatus::Accepted {
                                accepted.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // An in-flight duplicate is refused as retryable;
                        // its retry after the winner commits is a replay.
                        Err(error) => assert_eq!(error.kind(), ErrorKind::RangeInFlight),
                    }
                });
            }
        });
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        assert_eq!(file.progress().covered_bytes, GROUP as u64);
        let verified = vot_sdk::verify::verify_range(&object_id, offset, bytes, &proof).unwrap();
        assert_eq!(file.accept(&verified).unwrap().status, RangeStatus::Replay);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_in_flight_duplicate_is_refused_as_retryable() {
        let directory = directory("in-flight-duplicate");
        let data = vec![0x19; 2 * GROUP];
        let prepared = object(&data);
        let mut file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let (announce, release) = armed_park(&mut file);
        let object_id = prepared.object_id().clone();
        let proofs = group_proofs(&prepared, &data);
        std::thread::scope(|scope| {
            let file = &file;
            let object_id = &object_id;
            let (offset, bytes, proof) = proofs[0].clone();
            let holder = scope.spawn(move || {
                let verified =
                    vot_sdk::verify::verify_range(object_id, offset, &bytes, &proof).unwrap();
                file.accept(&verified)
            });
            // The announcement proves the holder's reservation is in
            // flight, so the duplicate below deterministically collides
            // with a reservation rather than a committed extent.
            announce
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("no write reached the park");
            let (offset, bytes, proof) = &proofs[0];
            let verified = vot_sdk::verify::verify_range(object_id, *offset, bytes, proof).unwrap();
            let refused = file.accept(&verified).unwrap_err();
            assert_eq!(refused.kind(), ErrorKind::RangeInFlight);
            release.send(()).expect("holder gone before release");
            assert_eq!(
                holder.join().unwrap().unwrap().status,
                RangeStatus::Accepted
            );
        });
        // After the holder commits, the same range is a replay.
        let (offset, bytes, proof) = &proofs[0];
        let verified = vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
        assert_eq!(file.accept(&verified).unwrap().status, RangeStatus::Replay);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_poison_landing_mid_write_releases_the_landed_range() {
        let directory = directory("poison-mid-write");
        let data = vec![0x2b; 2 * GROUP];
        let prepared = object(&data);
        let mut file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let (announce, release) = armed_park(&mut file);
        let object_id = prepared.object_id().clone();
        let proofs = group_proofs(&prepared, &data);
        std::thread::scope(|scope| {
            let file = &file;
            let object_id = &object_id;
            let (offset, bytes, proof) = proofs[0].clone();
            let parked = scope.spawn(move || {
                let verified =
                    vot_sdk::verify::verify_range(object_id, offset, &bytes, &proof).unwrap();
                // Writes its bytes, then parks before the relock while the
                // main thread poisons the commit.
                file.accept(&verified)
            });
            // The announcement proves the parked accept already passed
            // its own fault check and wrote its bytes, so the fault below
            // can only fire for this thread's accept, which returns before
            // the park hook.
            announce
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("no write reached the park");
            let (offset, bytes, proof) = &proofs[1];
            let verified = vot_sdk::verify::verify_range(object_id, *offset, bytes, proof).unwrap();
            file.write_fault
                .store(true, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(file.accept(&verified).unwrap_err().kind(), ErrorKind::Io);
            release.send(()).expect("parked accept gone before release");
            let refused = parked.join().unwrap().unwrap_err();
            assert_eq!(refused.kind(), ErrorKind::StateConflict);
        });
        // The parked range's bytes landed but were released, never counted.
        assert_eq!(file.progress().covered_bytes, 0);
        assert_eq!(file.progress().fragments, 0);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_under_concurrency_poisons_and_releases_its_range() {
        let directory = directory("poisoned-write");
        let data = vec![0x77; 2 * GROUP];
        let prepared = object(&data);
        let file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let object_id = prepared.object_id().clone();
        let proofs = group_proofs(&prepared, &data);

        let (offset, bytes, proof) = &proofs[0];
        let verified = vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
        file.write_fault
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = file.accept(&verified).unwrap_err();
        assert_eq!(failed.kind(), ErrorKind::Io);
        // The failed range was released, never counted.
        assert_eq!(file.progress().covered_bytes, 0);
        assert_eq!(file.progress().fragments, 0);
        // Every subsequent accept refuses with the poisoned error, from any
        // number of threads.
        std::thread::scope(|scope| {
            for (offset, bytes, proof) in &proofs {
                scope.spawn(|| {
                    let verified =
                        vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
                    let refused = file.accept(&verified).unwrap_err();
                    assert_eq!(refused.kind(), ErrorKind::StateConflict);
                });
            }
        });
        assert_eq!(file.progress().covered_bytes, 0);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn publication_requires_committed_coverage_and_then_refuses_accepts() {
        let directory = directory("publish-vs-accept");
        let data = vec![0x11; 2 * GROUP];
        let prepared = object(&data);
        let destination = directory.join("object");
        let mut file =
            NativeFile::create(prepared.object_id(), &destination, CommitProfile::Fast).unwrap();
        let object_id = prepared.object_id().clone();
        let proofs = group_proofs(&prepared, &data);
        let (offset, bytes, proof) = &proofs[0];
        let verified = vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
        file.accept(&verified).unwrap();
        // Publication observes only committed coverage; a hole refuses it.
        // An in-flight accept implies exactly such a hole, and the borrow
        // checker already keeps publish exclusive against one.
        assert_eq!(
            file.publish().unwrap_err().kind(),
            ErrorKind::Incomplete,
            "publish must refuse incomplete coverage"
        );
        let (offset, bytes, proof) = &proofs[1];
        let verified = vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
        file.accept(&verified).unwrap();
        file.publish().unwrap();
        // A publish that won refuses later accepts.
        let (offset, bytes, proof) = &proofs[0];
        let verified = vot_sdk::verify::verify_range(&object_id, *offset, bytes, proof).unwrap();
        assert_eq!(
            file.accept(&verified).unwrap_err().kind(),
            ErrorKind::StateConflict
        );
        assert_eq!(fs::read(&destination).unwrap(), data);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn progress_prefix_stops_at_a_hole_left_by_out_of_order_ranges() {
        let directory = directory("prefix");
        let data = vec![0x5a; 131_072];
        let prepared = object(&data);
        let file = NativeFile::create(
            prepared.object_id(),
            directory.join("object"),
            CommitProfile::Fast,
        )
        .unwrap();
        let second_proof = prepared.prove(65_536, 1).unwrap();
        let second = vot_sdk::verify::verify_range(
            prepared.object_id(),
            second_proof.covered_offset(),
            &data[65_536..],
            second_proof.proof(),
        )
        .unwrap();
        let progress = file.accept(&second).unwrap().progress;
        assert_eq!(progress.covered_bytes, 65_536);
        assert_eq!(progress.prefix_bytes, 0);
        let first_proof = prepared.prove(0, 1).unwrap();
        let first = vot_sdk::verify::verify_range(
            prepared.object_id(),
            first_proof.covered_offset(),
            &data[..65_536],
            first_proof.proof(),
        )
        .unwrap();
        let progress = file.accept(&first).unwrap().progress;
        assert_eq!(progress.covered_bytes, 131_072);
        assert_eq!(progress.prefix_bytes, 131_072);
        // Windows cannot remove the staging file while its handle is open.
        drop(file);
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
        {
            let shared = file.state_mut();
            shared
                .backend
                .as_mut()
                .unwrap()
                .commit
                .finish_transit_verified()
                .unwrap();
            shared.sealed = true;
        }
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
        for (mut file, result) in outcomes {
            if let Err(error) = result {
                assert_eq!(error.kind(), ErrorKind::AlreadyExists);
                assert!(
                    file.state_mut().sealed,
                    "post-admission conflict was not sealed"
                );
                assert!(!file.recovery_required());
                file.cancel().unwrap();
            }
        }
        assert_eq!(fs::read(destination).unwrap(), bytes);
        fs::remove_dir_all(directory).unwrap();
    }
}
