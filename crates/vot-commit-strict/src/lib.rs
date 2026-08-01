//! Independent aligned direct read-back for the Linux Strict commit profile.

#![allow(clippy::missing_errors_doc)]

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use aligned_vec::{AVec, RuntimeAlign};
use vot_commit_model::{Event, Machine};
use vot_verifier::StreamVerifier;
pub use vot_verifier::Suite;

pub const DIRECT_READ_BUFFER_BYTES: usize = 1024 * 1024;
pub const MAX_DIRECT_ALIGNMENT: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectHash {
    Supported([u8; 32]),
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Verified,
    Unsupported,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectIdentity {
    Match,
    Mismatch,
    Unsupported,
}

#[derive(Debug)]
pub enum Error {
    InvalidAlignment,
    BufferSizeOverflow,
    Io(std::io::Error),
    Verify(vot_verifier::VerifyError),
    HashMismatch,
    Model(vot_commit_model::Error),
}

pub trait ReadBack {
    fn hash(&self, suite: Suite) -> Result<DirectHash, Error>;
}

enum DirectBackend {
    Supported(File),
    Unsupported,
}

enum CapabilityFailure {
    Unsupported,
    Hard(Error),
}

pub struct LinuxDirectReader {
    backend: DirectBackend,
    logical_length: u64,
    alignment: usize,
    buffer_size: usize,
}

impl LinuxDirectReader {
    /// Opens and probes direct-I/O support once with an aligned read at offset zero.
    ///
    /// An `EINVAL` during this capability probe means the backend is unsupported.
    /// Any `EINVAL` after a successful probe is returned as a hard I/O error.
    pub fn open(path: &Path, logical_length: u64, alignment: usize) -> Result<Self, Error> {
        let buffer_size = checked_buffer_size(alignment)?;
        let descriptor =
            match rustix::fs::open(path, direct_open_flags(), rustix::fs::Mode::empty()) {
                Ok(descriptor) => descriptor,
                Err(error) => match classify_open_failure(error) {
                    CapabilityFailure::Unsupported => {
                        return Ok(Self {
                            backend: DirectBackend::Unsupported,
                            logical_length,
                            alignment,
                            buffer_size,
                        });
                    }
                    CapabilityFailure::Hard(error) => return Err(error),
                },
            };
        let file = File::from(descriptor);
        let mut probe = AVec::<u8, RuntimeAlign>::new(alignment);
        probe.resize(alignment, 0);
        match file.read_at(&mut probe, 0) {
            Ok(_) => Ok(Self {
                backend: DirectBackend::Supported(file),
                logical_length,
                alignment,
                buffer_size,
            }),
            Err(error) => match classify_probe_failure(error) {
                CapabilityFailure::Unsupported => Ok(Self {
                    backend: DirectBackend::Unsupported,
                    logical_length,
                    alignment,
                    buffer_size,
                }),
                CapabilityFailure::Hard(error) => Err(error),
            },
        }
    }

    /// Confirms that the direct descriptor and the staged descriptor name the same object.
    pub fn identity(&self, staged: &File) -> Result<DirectIdentity, Error> {
        let DirectBackend::Supported(descriptor) = &self.backend else {
            return Ok(DirectIdentity::Unsupported);
        };
        let direct = descriptor.metadata().map_err(Error::Io)?;
        let staged = staged.metadata().map_err(Error::Io)?;
        if direct.dev() == staged.dev()
            && direct.ino() == staged.ino()
            && direct.len() == staged.len()
            && direct.len() == self.logical_length
        {
            Ok(DirectIdentity::Match)
        } else {
            Ok(DirectIdentity::Mismatch)
        }
    }
}

impl ReadBack for LinuxDirectReader {
    fn hash(&self, suite: Suite) -> Result<DirectHash, Error> {
        let DirectBackend::Supported(descriptor) = &self.backend else {
            return Ok(DirectHash::Unsupported);
        };
        let mut block = AVec::<u8, RuntimeAlign>::new(self.alignment);
        block.resize(self.buffer_size, 0);
        let mut remaining = self.logical_length;
        let mut offset = 0;
        let mut verifier = StreamVerifier::new(suite);
        while remaining > 0 {
            match descriptor.read_at(&mut block, offset) {
                Ok(0) => return Err(short_read()),
                Ok(read) => {
                    let consumed = usize::try_from(remaining.min(read as u64))
                        .map_err(|_| Error::BufferSizeOverflow)?;
                    verifier.update(&block[..consumed]).map_err(Error::Verify)?;
                    remaining -= consumed as u64;
                    offset = offset
                        .checked_add(read as u64)
                        .ok_or(Error::BufferSizeOverflow)?;
                }
                Err(error) => return Err(post_probe_io_error(error)),
            }
        }
        Ok(DirectHash::Supported(
            verifier.finish().map_err(Error::Verify)?,
        ))
    }
}

fn io_error(error: rustix::io::Errno) -> Error {
    Error::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
}

fn direct_open_flags() -> rustix::fs::OFlags {
    let mut flags = rustix::fs::OFlags::RDONLY;
    flags.insert(rustix::fs::OFlags::DIRECT);
    flags.insert(rustix::fs::OFlags::CLOEXEC);
    flags
}

fn checked_buffer_size(alignment: usize) -> Result<usize, Error> {
    if !alignment.is_power_of_two() || !(512..=MAX_DIRECT_ALIGNMENT).contains(&alignment) {
        return Err(Error::InvalidAlignment);
    }
    DIRECT_READ_BUFFER_BYTES
        .div_ceil(alignment)
        .checked_mul(alignment)
        .ok_or(Error::BufferSizeOverflow)
}

fn short_read() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "short direct read",
    ))
}

fn capability_unsupported(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS
    )
}

fn classify_open_failure(error: rustix::io::Errno) -> CapabilityFailure {
    if capability_unsupported(error) {
        CapabilityFailure::Unsupported
    } else {
        CapabilityFailure::Hard(io_error(error))
    }
}

fn classify_probe_failure(error: std::io::Error) -> CapabilityFailure {
    let unsupported = error.raw_os_error().is_some_and(|raw| {
        matches!(
            raw,
            value if value == rustix::io::Errno::INVAL.raw_os_error()
                || value == rustix::io::Errno::OPNOTSUPP.raw_os_error()
                || value == rustix::io::Errno::NOSYS.raw_os_error()
        )
    });
    if unsupported {
        CapabilityFailure::Unsupported
    } else {
        CapabilityFailure::Hard(Error::Io(error))
    }
}

fn post_probe_io_error(error: std::io::Error) -> Error {
    Error::Io(error)
}

pub fn verify<R: ReadBack>(
    reader: &R,
    suite: Suite,
    expected: &[u8; 32],
) -> Result<VerificationOutcome, Error> {
    match reader.hash(suite)? {
        DirectHash::Unsupported => Ok(VerificationOutcome::Unsupported),
        DirectHash::Supported(actual) if actual == *expected => Ok(VerificationOutcome::Verified),
        DirectHash::Supported(_) => Ok(VerificationOutcome::Mismatch),
    }
}

pub fn verify_and_advance<R: ReadBack>(
    machine: &mut Machine,
    reader: &R,
    suite: Suite,
    expected: &[u8; 32],
) -> Result<VerificationOutcome, Error> {
    match verify(reader, suite, expected) {
        Ok(VerificationOutcome::Verified) => {
            machine.apply(Event::AtRestVerified).map_err(Error::Model)?;
            Ok(VerificationOutcome::Verified)
        }
        Ok(VerificationOutcome::Unsupported) => Ok(VerificationOutcome::Unsupported),
        Ok(VerificationOutcome::Mismatch) => {
            machine
                .apply(Event::AtRestVerificationFailed)
                .map_err(Error::Model)?;
            Ok(VerificationOutcome::Mismatch)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct MemoryReader(DirectHash);

    impl ReadBack for MemoryReader {
        fn hash(&self, _suite: Suite) -> Result<DirectHash, Error> {
            Ok(self.0)
        }
    }

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vot-direct-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn unsupported_backend_is_explicit() {
        let reader = MemoryReader(DirectHash::Unsupported);
        assert_eq!(
            verify(&reader, Suite::Blake3Bao64, &[0; 32]).unwrap(),
            VerificationOutcome::Unsupported
        );
    }

    #[test]
    fn verification_outcomes_are_distinct() {
        let expected = [7; 32];
        assert_eq!(
            verify(
                &MemoryReader(DirectHash::Supported(expected)),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Verified
        );
        assert_eq!(
            verify(
                &MemoryReader(DirectHash::Supported([8; 32])),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Mismatch
        );
        assert_eq!(
            verify(
                &MemoryReader(DirectHash::Unsupported),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Unsupported
        );
    }

    #[test]
    fn direct_reader_hashes_aligned_and_tail_lengths_when_supported() {
        let path = path();
        let data: Vec<_> = (0..DIRECT_READ_BUFFER_BYTES + 8_213)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        fs::write(&path, &data).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
        let reader = LinuxDirectReader::open(&path, data.len() as u64, 4096).unwrap();
        let expected = vot_verifier::root(Suite::Blake3Bao64, &data).unwrap();
        match reader.hash(Suite::Blake3Bao64).unwrap() {
            DirectHash::Supported(actual) => assert_eq!(actual, expected),
            DirectHash::Unsupported => assert_eq!(
                verify(&reader, Suite::Blake3Bao64, &expected).unwrap(),
                VerificationOutcome::Unsupported
            ),
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_reader_buffer_is_bounded_independent_of_object_length() {
        assert_eq!(checked_buffer_size(4096).unwrap(), DIRECT_READ_BUFFER_BYTES);
    }

    #[test]
    fn direct_reader_is_bound_to_the_staged_descriptor() {
        let staged_path = path();
        let other_path = path();
        fs::write(&staged_path, b"staged").unwrap();
        fs::write(&other_path, b"staged").unwrap();
        let staged = File::open(&staged_path).unwrap();
        let reader = LinuxDirectReader {
            backend: DirectBackend::Supported(File::open(&staged_path).unwrap()),
            logical_length: 6,
            alignment: 4096,
            buffer_size: DIRECT_READ_BUFFER_BYTES,
        };
        assert_eq!(reader.identity(&staged).unwrap(), DirectIdentity::Match);
        assert_eq!(
            reader.identity(&File::open(&other_path).unwrap()).unwrap(),
            DirectIdentity::Mismatch
        );
        let unsupported = LinuxDirectReader {
            backend: DirectBackend::Unsupported,
            logical_length: 6,
            alignment: 4096,
            buffer_size: DIRECT_READ_BUFFER_BYTES,
        };
        assert_eq!(
            unsupported.identity(&staged).unwrap(),
            DirectIdentity::Unsupported
        );
        fs::remove_file(staged_path).unwrap();
        fs::remove_file(other_path).unwrap();
    }

    #[test]
    fn direct_reader_alignment_bounds_are_exact() {
        assert_eq!(DIRECT_READ_BUFFER_BYTES, 1_048_576);
        assert_eq!(MAX_DIRECT_ALIGNMENT, 4_194_304);
        for alignment in [0, 256, 511, 513, MAX_DIRECT_ALIGNMENT * 2] {
            assert!(matches!(
                checked_buffer_size(alignment),
                Err(Error::InvalidAlignment)
            ));
        }
        assert_eq!(checked_buffer_size(512).unwrap(), DIRECT_READ_BUFFER_BYTES);
        assert_eq!(
            checked_buffer_size(MAX_DIRECT_ALIGNMENT).unwrap(),
            MAX_DIRECT_ALIGNMENT
        );
    }

    #[test]
    fn direct_flags_and_capability_classification_are_exact() {
        let flags = direct_open_flags();
        assert!(flags.contains(rustix::fs::OFlags::DIRECT));
        assert!(flags.contains(rustix::fs::OFlags::CLOEXEC));
        for error in [
            rustix::io::Errno::INVAL,
            rustix::io::Errno::OPNOTSUPP,
            rustix::io::Errno::NOSYS,
        ] {
            assert!(capability_unsupported(error));
            assert!(matches!(
                classify_open_failure(error),
                CapabilityFailure::Unsupported
            ));
            assert!(matches!(
                classify_probe_failure(std::io::Error::from_raw_os_error(error.raw_os_error())),
                CapabilityFailure::Unsupported
            ));
        }
        assert!(matches!(
            post_probe_io_error(std::io::Error::from_raw_os_error(
                rustix::io::Errno::INVAL.raw_os_error()
            )),
            Error::Io(error) if error.raw_os_error()
                == Some(rustix::io::Errno::INVAL.raw_os_error())
        ));
        assert!(!capability_unsupported(rustix::io::Errno::NOENT));
        assert!(matches!(
            classify_open_failure(rustix::io::Errno::NOENT),
            CapabilityFailure::Hard(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(matches!(
            classify_probe_failure(std::io::Error::from_raw_os_error(
                rustix::io::Errno::NOENT.raw_os_error()
            )),
            CapabilityFailure::Hard(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    fn durable_machine() -> Machine {
        let mut machine = Machine::new(vot_commit_model::Profile::Strict);
        machine.apply(Event::Admit).unwrap();
        machine.apply(Event::TransitVerified).unwrap();
        machine.apply(Event::DataFlushSucceeded).unwrap();
        machine.apply(Event::JournalFlushSucceeded).unwrap();
        machine
    }

    #[test]
    fn strict_outcome_advances_or_poisons_the_commit_state() {
        let expected = vot_verifier::root(Suite::Blake3Bao64, b"verified bytes").unwrap();

        let mut verified = durable_machine();
        assert_eq!(
            verify_and_advance(
                &mut verified,
                &MemoryReader(DirectHash::Supported(expected)),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Verified
        );
        assert_eq!(verified.state(), vot_commit_model::State::AtRestVerified);

        let mut corrupted_hash = expected;
        corrupted_hash[0] ^= 1;
        let mut poisoned = durable_machine();
        assert_eq!(
            verify_and_advance(
                &mut poisoned,
                &MemoryReader(DirectHash::Supported(corrupted_hash)),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Mismatch
        );
        assert_eq!(poisoned.state(), vot_commit_model::State::Poisoned);

        let mut unsupported = durable_machine();
        assert_eq!(
            verify_and_advance(
                &mut unsupported,
                &MemoryReader(DirectHash::Unsupported),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap(),
            VerificationOutcome::Unsupported
        );
        assert_eq!(unsupported.state(), vot_commit_model::State::Durable);
    }
}
