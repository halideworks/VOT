//! Independent aligned direct read-back for the Linux Strict commit profile.

#![allow(clippy::missing_errors_doc)]

use std::path::Path;

use aligned_vec::{AVec, RuntimeAlign};
use sha2::{Digest, Sha256};
use vot_commit_model::{Event, Machine};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    Blake3,
    Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectRead {
    Supported(Vec<u8>),
    Unsupported,
}

#[derive(Debug)]
pub enum Error {
    InvalidAlignment,
    LengthOverflow,
    Io(std::io::Error),
    HashMismatch,
    Model(vot_commit_model::Error),
}

pub trait ReadBack {
    fn read_back(&self) -> Result<DirectRead, Error>;
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
}

impl ReadBack for LinuxDirectReader<'_> {
    fn read_back(&self) -> Result<DirectRead, Error> {
        if !self.alignment.is_power_of_two() || self.alignment < 512 {
            return Err(Error::InvalidAlignment);
        }
        let flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECT | rustix::fs::OFlags::CLOEXEC;
        let descriptor = match rustix::fs::open(self.path, flags, rustix::fs::Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(error) if unsupported(error) => return Ok(DirectRead::Unsupported),
            Err(error) => {
                return Err(Error::Io(std::io::Error::from_raw_os_error(
                    error.raw_os_error(),
                )));
            }
        };
        let capacity = usize::try_from(self.logical_length).map_err(|_| Error::LengthOverflow)?;
        let mut output = Vec::with_capacity(capacity);
        let mut block = AVec::<u8, RuntimeAlign>::new(self.alignment);
        block.resize(self.alignment, 0);
        while output.len() < capacity {
            match rustix::io::read(&descriptor, &mut block[..]) {
                Ok(0) => break,
                Ok(read) => {
                    let remaining = capacity - output.len();
                    output.extend_from_slice(&block[..read.min(remaining)]);
                }
                Err(error) if unsupported(error) => return Ok(DirectRead::Unsupported),
                Err(error) => {
                    return Err(Error::Io(std::io::Error::from_raw_os_error(
                        error.raw_os_error(),
                    )));
                }
            }
        }
        if output.len() != capacity {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short direct read",
            )));
        }
        Ok(DirectRead::Supported(output))
    }
}

fn unsupported(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS
    )
}

pub fn verify<R: ReadBack>(reader: &R, suite: Suite, expected: &[u8; 32]) -> Result<bool, Error> {
    let DirectRead::Supported(bytes) = reader.read_back()? else {
        return Ok(false);
    };
    let actual = match suite {
        Suite::Blake3 => *blake3::hash(&bytes).as_bytes(),
        Suite::Sha256 => Sha256::digest(&bytes).into(),
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

    struct MemoryReader(DirectRead);

    impl ReadBack for MemoryReader {
        fn read_back(&self) -> Result<DirectRead, Error> {
            Ok(self.0.clone())
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
    fn strict_catches_backing_corruption_buffered_control_does_not() {
        let original = b"verified bytes".to_vec();
        let expected = *blake3::hash(&original).as_bytes();
        let mut backing = original.clone();
        backing[0] ^= 1;
        let strict = MemoryReader(DirectRead::Supported(backing));
        let buffered_control = MemoryReader(DirectRead::Supported(original));
        assert!(matches!(
            verify(&strict, Suite::Blake3, &expected),
            Err(Error::HashMismatch)
        ));
        assert!(matches!(
            verify(&buffered_control, Suite::Blake3, &expected),
            Ok(true)
        ));
    }

    #[test]
    fn unsupported_backend_is_explicit() {
        let reader = MemoryReader(DirectRead::Unsupported);
        assert!(matches!(
            verify(&reader, Suite::Blake3, &[0; 32]),
            Ok(false)
        ));
    }

    #[test]
    fn linux_direct_reader_handles_aligned_and_tail_lengths_when_supported() {
        let path = path();
        let data: Vec<_> = (0..8_213)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        fs::write(&path, &data).unwrap();
        FileSync::sync(&path);
        let reader = LinuxDirectReader::new(&path, data.len() as u64, 4096);
        match reader.read_back().unwrap() {
            DirectRead::Supported(read) => assert_eq!(read, data),
            DirectRead::Unsupported => {}
        }
        fs::remove_file(path).unwrap();
    }

    struct FileSync;

    impl FileSync {
        fn sync(path: &Path) {
            fs::File::open(path).unwrap().sync_all().unwrap();
        }
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
        let bytes = b"verified bytes".to_vec();
        let expected = *blake3::hash(&bytes).as_bytes();

        let mut verified = durable_machine();
        assert!(
            verify_and_advance(
                &mut verified,
                &MemoryReader(DirectRead::Supported(bytes.clone())),
                Suite::Blake3,
                &expected
            )
            .unwrap()
        );
        assert_eq!(verified.state(), vot_commit_model::State::AtRestVerified);

        let mut corrupted = bytes;
        corrupted[0] ^= 1;
        let mut poisoned = durable_machine();
        assert!(matches!(
            verify_and_advance(
                &mut poisoned,
                &MemoryReader(DirectRead::Supported(corrupted)),
                Suite::Blake3,
                &expected
            ),
            Err(Error::HashMismatch)
        ));
        assert_eq!(poisoned.state(), vot_commit_model::State::Poisoned);

        let mut unsupported = durable_machine();
        assert!(
            !verify_and_advance(
                &mut unsupported,
                &MemoryReader(DirectRead::Unsupported),
                Suite::Blake3,
                &expected
            )
            .unwrap()
        );
        assert_eq!(unsupported.state(), vot_commit_model::State::Durable);
    }
}
