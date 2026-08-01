//! Independent aligned direct read-back for the Linux Strict commit profile.

#![allow(clippy::missing_errors_doc)]

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

pub struct LinuxDirectReader<'a> {
    path: &'a Path,
    logical_length: u64,
    alignment: usize,
}

impl<'a> LinuxDirectReader<'a> {
    #[must_use]
    pub const fn new(path: &'a Path, logical_length: u64, alignment: usize) -> Self {
        Self {
            path,
            logical_length,
            alignment,
        }
    }

    fn buffer_size(&self) -> Result<usize, Error> {
        if !self.alignment.is_power_of_two()
            || self.alignment < 512
            || self.alignment > MAX_DIRECT_ALIGNMENT
        {
            return Err(Error::InvalidAlignment);
        }
        DIRECT_READ_BUFFER_BYTES
            .div_ceil(self.alignment)
            .checked_mul(self.alignment)
            .ok_or(Error::BufferSizeOverflow)
    }
}

impl ReadBack for LinuxDirectReader<'_> {
    fn hash(&self, suite: Suite) -> Result<DirectHash, Error> {
        let buffer_size = self.buffer_size()?;
        let descriptor =
            match rustix::fs::open(self.path, direct_open_flags(), rustix::fs::Mode::empty()) {
                Ok(descriptor) => descriptor,
                Err(error) => return classify_direct_error(error),
            };
        let mut block = AVec::<u8, RuntimeAlign>::new(self.alignment);
        block.resize(buffer_size, 0);
        let mut remaining = self.logical_length;
        let mut verifier = StreamVerifier::new(suite);
        while remaining > 0 {
            match rustix::io::read(&descriptor, &mut block[..]) {
                Ok(0) => return Err(short_read()),
                Ok(read) => {
                    let consumed = usize::try_from(remaining.min(read as u64))
                        .map_err(|_| Error::BufferSizeOverflow)?;
                    verifier.update(&block[..consumed]).map_err(Error::Verify)?;
                    remaining -= consumed as u64;
                }
                Err(error) => return classify_direct_error(error),
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

fn classify_direct_error(error: rustix::io::Errno) -> Result<DirectHash, Error> {
    if unsupported(error) {
        Ok(DirectHash::Unsupported)
    } else {
        Err(io_error(error))
    }
}

fn short_read() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "short direct read",
    ))
}

fn unsupported(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS
    )
}

pub fn verify<R: ReadBack>(reader: &R, suite: Suite, expected: &[u8; 32]) -> Result<bool, Error> {
    let DirectHash::Supported(actual) = reader.hash(suite)? else {
        return Ok(false);
    };
    if actual == *expected {
        Ok(true)
    } else {
        Err(Error::HashMismatch)
    }
}

pub fn verify_and_advance<R: ReadBack>(
    machine: &mut Machine,
    reader: &R,
    suite: Suite,
    expected: &[u8; 32],
) -> Result<bool, Error> {
    match verify(reader, suite, expected) {
        Ok(true) => {
            machine.apply(Event::AtRestVerified).map_err(Error::Model)?;
            Ok(true)
        }
        Ok(false) => Ok(false),
        Err(Error::HashMismatch) => {
            machine
                .apply(Event::AtRestVerificationFailed)
                .map_err(Error::Model)?;
            Err(Error::HashMismatch)
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
        assert!(matches!(
            verify(&reader, Suite::Blake3Bao64, &[0; 32]),
            Ok(false)
        ));
    }

    #[test]
    fn direct_reader_hashes_aligned_and_tail_lengths_when_supported() {
        let path = path();
        let data: Vec<_> = (0..DIRECT_READ_BUFFER_BYTES + 8_213)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        fs::write(&path, &data).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
        let reader = LinuxDirectReader::new(&path, data.len() as u64, 4096);
        let expected = vot_verifier::root(Suite::Blake3Bao64, &data).unwrap();
        match reader.hash(Suite::Blake3Bao64).unwrap() {
            DirectHash::Supported(actual) => assert_eq!(actual, expected),
            DirectHash::Unsupported => assert!(matches!(
                verify(&reader, Suite::Blake3Bao64, &expected),
                Ok(false)
            )),
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_reader_buffer_is_bounded_independent_of_object_length() {
        let reader = LinuxDirectReader::new(Path::new("unused"), 500 * 1024 * 1024 * 1024, 4096);
        assert_eq!(reader.buffer_size().unwrap(), DIRECT_READ_BUFFER_BYTES);
    }

    #[test]
    fn direct_reader_alignment_bounds_are_exact() {
        assert_eq!(DIRECT_READ_BUFFER_BYTES, 1_048_576);
        assert_eq!(MAX_DIRECT_ALIGNMENT, 4_194_304);
        for alignment in [0, 256, 511, 513, MAX_DIRECT_ALIGNMENT * 2] {
            assert!(matches!(
                LinuxDirectReader::new(Path::new("unused"), 0, alignment).buffer_size(),
                Err(Error::InvalidAlignment)
            ));
        }
        assert_eq!(
            LinuxDirectReader::new(Path::new("unused"), 0, 512)
                .buffer_size()
                .unwrap(),
            DIRECT_READ_BUFFER_BYTES
        );
        assert_eq!(
            LinuxDirectReader::new(Path::new("unused"), 0, MAX_DIRECT_ALIGNMENT)
                .buffer_size()
                .unwrap(),
            MAX_DIRECT_ALIGNMENT
        );
    }

    #[test]
    fn direct_flags_and_errno_classification_are_exact() {
        let flags = direct_open_flags();
        assert!(flags.contains(rustix::fs::OFlags::DIRECT));
        assert!(flags.contains(rustix::fs::OFlags::CLOEXEC));
        for error in [
            rustix::io::Errno::INVAL,
            rustix::io::Errno::OPNOTSUPP,
            rustix::io::Errno::NOSYS,
        ] {
            assert!(matches!(
                classify_direct_error(error),
                Ok(DirectHash::Unsupported)
            ));
        }
        assert!(matches!(
            classify_direct_error(rustix::io::Errno::NOENT),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
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
        assert!(
            verify_and_advance(
                &mut verified,
                &MemoryReader(DirectHash::Supported(expected)),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap()
        );
        assert_eq!(verified.state(), vot_commit_model::State::AtRestVerified);

        let mut corrupted_hash = expected;
        corrupted_hash[0] ^= 1;
        let mut poisoned = durable_machine();
        assert!(matches!(
            verify_and_advance(
                &mut poisoned,
                &MemoryReader(DirectHash::Supported(corrupted_hash)),
                Suite::Blake3Bao64,
                &expected
            ),
            Err(Error::HashMismatch)
        ));
        assert_eq!(poisoned.state(), vot_commit_model::State::Poisoned);

        let mut unsupported = durable_machine();
        assert!(
            !verify_and_advance(
                &mut unsupported,
                &MemoryReader(DirectHash::Unsupported),
                Suite::Blake3Bao64,
                &expected
            )
            .unwrap()
        );
        assert_eq!(unsupported.state(), vot_commit_model::State::Durable);
    }
}
