//! Shared same-filesystem namespace for a bounded set of active receivers.

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::Path;

use super::{
    Backend, CREATE_ATTEMPTS, CommitProfile, Error, ErrorKind, NativeFile, ObjectCoverage,
    ObjectId, classify_creation_error, map_posix, map_profile, map_sdk_code, next_name,
};
use vot_platform_fs::{Directory, FileLocation, NasContract};

/// Retains two directories regardless of how many files a sequence contains.
/// Parked callers persist names and coverage, not one directory handle per file.
#[derive(Clone, Debug)]
pub struct ReceiveDirectory {
    destination: Directory,
    temporary: Directory,
    nas_contract: NasContract,
}

/// Persist together with the authenticated object and destination name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeState {
    pub staging_name: OsString,
    pub journal_name: OsString,
    pub incarnation: [u8; 16],
    pub profile: CommitProfile,
    pub nas_contract: NasContract,
    pub runs: Vec<(u64, u64)>,
}

impl ReceiveDirectory {
    /// Creates its own private temporary child on the selected filesystem.
    pub fn open(path: impl AsRef<Path>, nas_contract: NasContract) -> Result<Self, Error> {
        let destination =
            Directory::open_with_nas(path.as_ref(), nas_contract).map_err(Error::io)?;
        Self::from_directory(destination)
    }

    /// Reuses a destination reached by walking retained parent directories.
    pub fn from_directory(destination: Directory) -> Result<Self, Error> {
        let nas_contract = destination.nas_contract();
        let temporary = destination
            .private_child(OsStr::new(".vot-stage"))
            .map_err(Error::io)?;
        Ok(Self {
            destination,
            temporary,
            nas_contract,
        })
    }

    /// Resolves a payload or sidecar name through the retained publication directory.
    pub fn destination(&self, name: &OsStr) -> Result<FileLocation, Error> {
        if name.to_string_lossy().eq_ignore_ascii_case(".vot-stage") {
            return Err(Error::plain(ErrorKind::InvalidDestination));
        }
        self.destination.entry(name).map_err(Error::io)
    }

    /// Writes the payload once and publishes by no-replace hard link.
    pub fn create(
        &self,
        object: &ObjectId,
        name: &OsStr,
        profile: CommitProfile,
    ) -> Result<NativeFile, Error> {
        #[cfg(not(target_os = "linux"))]
        super::validate_profile(profile)?;
        let destination = self.destination(name)?;
        require_absent(destination.identity())?;
        for _ in 0..CREATE_ATTEMPTS {
            let (temporary_name, incarnation) = next_name();
            let staging = self
                .temporary
                .entry(OsStr::new(&format!("{temporary_name}.stage")))
                .map_err(Error::io)?;
            let journal = self
                .temporary
                .entry(OsStr::new(&format!("{temporary_name}.journal")))
                .map_err(Error::io)?;
            match vot_commit_posix::PosixCommit::create_at(
                map_profile(profile),
                incarnation,
                staging.clone(),
                destination.clone(),
                journal.clone(),
                self.nas_contract,
                vot_commit_posix::NoFaults,
            ) {
                Ok(mut commit) => {
                    if let Err(error) = commit.set_len(object.length) {
                        let _ = commit.cancel();
                        return Err(map_posix(error));
                    }
                    let mut file = NativeFile::from_backend(
                        object,
                        &destination.path(),
                        profile,
                        Backend { commit },
                        staging.path(),
                        Some(journal.path()),
                        false,
                    )?;
                    file.nas_contract = self.nas_contract;
                    return Ok(file);
                }
                Err(error) => classify_creation_error(error)?,
            }
        }
        Err(Error::plain(ErrorKind::ResourceExhausted))
    }

    /// Reopens admission through the retained directories. Covered runs still
    /// require caller verification after an uncertain interruption.
    pub fn resume(
        &self,
        object: &ObjectId,
        name: &OsStr,
        state: &ResumeState,
    ) -> Result<NativeFile, Error> {
        #[cfg(not(target_os = "linux"))]
        super::validate_profile(state.profile)?;
        if state.nas_contract != self.nas_contract {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        let destination = self.destination(name)?;
        require_absent(destination.identity())?;
        let staging = self
            .temporary
            .entry(&state.staging_name)
            .map_err(Error::io)?;
        let journal = self
            .temporary
            .entry(&state.journal_name)
            .map_err(Error::io)?;
        let coverage = ObjectCoverage::from_runs(object, state.runs.iter().copied())
            .map_err(|error| map_sdk_code(error.code()))?;
        let commit = vot_commit_posix::PosixCommit::reattach_at(
            map_profile(state.profile),
            state.incarnation,
            staging.clone(),
            destination.clone(),
            journal.clone(),
            self.nas_contract,
            vot_commit_posix::NoFaults,
        )
        .map_err(map_posix)?;
        let claimed = coverage
            .runs()
            .last()
            .map_or(0, |(offset, length)| offset + length);
        if commit
            .read_staging()
            .map_err(map_posix)?
            .metadata()
            .map_err(Error::io)?
            .len()
            < claimed
        {
            return Err(Error::plain(ErrorKind::Incomplete));
        }
        let mut file = NativeFile::from_backend(
            object,
            &destination.path(),
            state.profile,
            Backend { commit },
            staging.path(),
            Some(journal.path()),
            true,
        )?;
        file.state_mut().coverage = coverage;
        file.nas_contract = self.nas_contract;
        Ok(file)
    }

    /// Reconciles an existing final name with its saved publication journal.
    /// Rehashing is confined to uncertain restart recovery and makes no Strict
    /// readback claim. Normal receiving does not need this additional read.
    /// Retains the journal until the caller checkpoints and calls `forget_publication`.
    pub fn recover_publication(
        &self,
        object: &ObjectId,
        name: &OsStr,
        state: &ResumeState,
    ) -> Result<super::PublishObservation, Error> {
        let mut commit = self.reopen_publication(name, state)?;
        let suite = vot_verifier::Suite::try_from(object.suite)
            .map_err(|_| Error::plain(ErrorKind::IdentityMismatch))?;
        let mut verifier = vot_verifier::StreamVerifier::new(suite);
        let mut file = commit.recovery_file();
        if file.metadata().map_err(Error::io)?.len() != object.length {
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        let mut buffer = vec![0; 1 << 20];
        let mut remaining = object.length;
        for _ in 0..object.length.div_ceil(buffer.len() as u64) {
            let count = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| Error::plain(ErrorKind::Internal))?;
            file.read_exact(&mut buffer[..count]).map_err(Error::io)?;
            verifier
                .update(&buffer[..count])
                .map_err(|_| Error::plain(ErrorKind::IdentityMismatch))?;
            remaining -= count as u64;
        }
        if file.read(&mut [0]).map_err(Error::io)? != 0 {
            return Err(Error::plain(ErrorKind::IdentityMismatch));
        }
        verifier
            .finish(vot_verifier::ExpectedObject::new(
                suite,
                object.root,
                object.length,
            ))
            .map_err(|_| Error::plain(ErrorKind::IdentityMismatch))?;
        let receipt = commit.finish_recovered_publication().map_err(map_posix)?;
        Ok(super::PublishObservation {
            incarnation: receipt.incarnation,
            sequence: receipt.sequence,
        })
    }

    /// Removes a completed journal after the caller has checkpointed its publication.
    /// The bound final identity and Published journal state must still agree.
    pub fn forget_publication(&self, name: &OsStr, state: &ResumeState) -> Result<(), Error> {
        self.reopen_publication(name, state)?
            .cleanup_published()
            .map_err(map_posix)
    }

    fn reopen_publication(
        &self,
        name: &OsStr,
        state: &ResumeState,
    ) -> Result<vot_commit_posix::PosixCommit<vot_commit_posix::NoFaults>, Error> {
        #[cfg(not(target_os = "linux"))]
        super::validate_profile(state.profile)?;
        if state.nas_contract != self.nas_contract {
            return Err(Error::plain(ErrorKind::StateConflict));
        }
        vot_commit_posix::PosixCommit::reopen_publication_at(
            map_profile(state.profile),
            state.incarnation,
            self.temporary
                .entry(&state.staging_name)
                .map_err(Error::io)?,
            self.destination(name)?,
            self.temporary
                .entry(&state.journal_name)
                .map_err(Error::io)?,
            self.nas_contract,
            vot_commit_posix::NoFaults,
        )
        .map_err(map_posix)
    }
}

fn require_absent(identity: std::io::Result<(u64, u64)>) -> Result<(), Error> {
    match identity {
        Ok(_) => Err(Error::plain(ErrorKind::AlreadyExists)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_requires_absence_without_suppressing_other_errors() {
        assert_eq!(
            require_absent(Ok((1, 2))).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::AlreadyExists,
            std::io::ErrorKind::Other,
        ] {
            assert_eq!(
                require_absent(Err(kind.into())).is_ok(),
                kind == std::io::ErrorKind::NotFound
            );
        }
    }
}
