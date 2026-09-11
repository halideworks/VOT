//! Sequential source reads with bounded parallel proof hashing.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::mpsc;

use vot_object::{MAX_OBJECT_LENGTH, PROOF_LEAF_SIZE, proof_leaves_at};

use crate::{Error, Suite};

const PARALLEL_PREPARATION_MIN_BYTES: u64 = 64 * 1024 * 1024;
const STEP: usize = 1024 * 1024;

/// Reads a regular file once and retains its canonical proof leaves.
///
/// Reads start at byte zero and stay sequential. Files of at least 64 MiB
/// use at most eight hashing workers with one 1 MiB buffer each. The file
/// cursor ends at EOF. The caller must keep the source immutable while
/// preparing and serving it. An already known object root must still be
/// compared with the identity reconstructed from these leaves.
///
/// # Errors
/// Rejects objects of one proof leaf or less, unrepresentable lengths,
/// non-regular files, changed lengths, and I/O or worker failures.
pub fn file_proof_leaves(
    input: &mut File,
    suite: Suite,
    expected_length: u64,
) -> Result<Vec<[u8; 32]>, Error> {
    if !(PROOF_LEAF_SIZE + 1..=MAX_OBJECT_LENGTH).contains(&expected_length) {
        return Err(Error::InvalidArguments);
    }
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(Error::InvalidArguments);
    }
    if metadata.len() != expected_length {
        return Err(Error::SourceMutation);
    }
    input.seek(SeekFrom::Start(0))?;
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let leaves = read_leaves(
        input,
        suite,
        expected_length,
        worker_count(expected_length, available),
    )?;
    Ok(leaves)
}

pub(crate) fn parallel_preparation(length: u64) -> bool {
    length >= PARALLEL_PREPARATION_MIN_BYTES
}

fn worker_count(length: u64, available: usize) -> Option<usize> {
    if !parallel_preparation(length) || available < 2 {
        None
    } else {
        Some(available.min(8))
    }
}

fn read_chunk(input: &mut impl Read, buffer: &mut Vec<u8>, remaining: u64) -> Result<(), Error> {
    buffer.resize(usize::try_from(remaining.min(STEP as u64)).unwrap(), 0);
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::SourceMutation
        } else {
            Error::Io(error)
        }
    })
}

fn read_leaves(
    input: &mut impl Read,
    suite: Suite,
    length: u64,
    workers: Option<usize>,
) -> Result<Vec<[u8; 32]>, Error> {
    let chunks = length.div_ceil(STEP as u64);
    let mut leaves = Vec::new();
    if let Some(workers) = workers {
        let workers = workers.min(usize::try_from(chunks).unwrap_or(usize::MAX));
        std::thread::scope(|scope| -> Result<(), Error> {
            let mut lanes = Vec::new();
            for _ in 0..workers {
                let (send, jobs) = mpsc::sync_channel::<(u64, Vec<u8>)>(1);
                let (done, receive) = mpsc::sync_channel(1);
                std::thread::Builder::new().spawn_scoped(scope, move || {
                    for (offset, buffer) in jobs {
                        let result = proof_leaves_at(suite, offset, &buffer, length);
                        if done.send((buffer, result)).is_err() {
                            break;
                        }
                    }
                })?;
                lanes.push((send, receive));
            }
            // Consume completions in submission order; workers never seek the source.
            for turn in 0..chunks + workers as u64 {
                let lane = &lanes[usize::try_from(turn % workers as u64).unwrap()];
                let mut buffer = if turn < workers as u64 {
                    Vec::new()
                } else {
                    let (buffer, result) = lane
                        .1
                        .recv()
                        .map_err(|_| io::Error::other("preparation worker stopped"))?;
                    leaves.extend(result.map_err(|_| Error::InvalidBundle)?);
                    buffer
                };
                if turn < chunks {
                    let offset = turn * STEP as u64;
                    read_chunk(input, &mut buffer, length - offset)?;
                    lane.0
                        .send((offset, buffer))
                        .map_err(|_| io::Error::other("preparation worker stopped"))?;
                }
            }
            Ok(())
        })?;
    } else {
        let mut buffer = Vec::new();
        for chunk in 0..chunks {
            let offset = chunk * STEP as u64;
            read_chunk(input, &mut buffer, length - offset)?;
            leaves.extend(
                proof_leaves_at(suite, offset, &buffer, length)
                    .map_err(|_| Error::InvalidBundle)?,
            );
        }
    }
    if input.read(&mut [0])? != 0 {
        return Err(Error::SourceMutation);
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;
    use vot_object::{ObjectBuilder, PreparedObject};

    fn checked_read(
        input: impl Read + Send + 'static,
        suite: Suite,
        length: u64,
        workers: Option<usize>,
    ) -> Result<Vec<[u8; 32]>, Error> {
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut input = input;
            let _ = send.send(read_leaves(&mut input, suite, length, workers));
        });
        receive
            .recv_timeout(Duration::from_secs(10))
            .expect("preparation must finish and join workers after success or error")
    }

    #[test]
    fn preparation_preserves_both_suites_and_proofs_across_worker_turns() {
        let bytes: Vec<u8> = (0..3 * STEP + 17)
            .map(|index| u8::try_from((index ^ (index / STEP)) % 251).unwrap())
            .collect();
        let length = bytes.len() as u64;
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut builder = ObjectBuilder::new(suite, Some(length)).unwrap();
            builder.update(&bytes).unwrap();
            let serial = builder.finish().unwrap();
            for workers in [None, Some(2), Some(8)] {
                let leaves =
                    checked_read(Cursor::new(bytes.clone()), suite, length, workers).unwrap();
                assert_eq!(Some(leaves.clone()), serial.proof_leaves());
                let prepared = PreparedObject::from_proof_leaves(suite, length, leaves).unwrap();
                assert_eq!(prepared.object_id(), serial.object_id());
                for offset in [0, STEP as u64 - 1, STEP as u64 + 16, length - 1] {
                    assert_eq!(prepared.prove(offset, 1), serial.prove(offset, 1));
                }
            }
        }
    }

    struct FaultyRead {
        remaining: usize,
    }

    impl Read for FaultyRead {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected read failure",
                ));
            }
            let take = bytes.len().min(self.remaining).min(113);
            bytes[..take].fill(7);
            self.remaining -= take;
            Ok(take)
        }
    }

    #[test]
    fn preparation_rejects_short_long_and_failed_reads_without_stranding_workers() {
        let length = (2 * STEP + 31) as u64;
        for workers in [None, Some(2)] {
            for observed in [length - 1, length + 1] {
                assert!(matches!(
                    checked_read(
                        Cursor::new(vec![7; usize::try_from(observed).unwrap()]),
                        Suite::Blake3Bao64,
                        length,
                        workers
                    ),
                    Err(Error::SourceMutation)
                ));
            }
            for remaining in [STEP + 113, usize::try_from(length).unwrap()] {
                let result = checked_read(
                    FaultyRead { remaining },
                    Suite::Blake3Bao64,
                    length,
                    workers,
                );
                assert!(
                    matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
                );
            }
        }
    }

    #[test]
    fn file_preparation_checks_length_and_starts_at_zero() {
        let path = crate::tests::temporary("file-preparation");
        let bytes = vec![9; usize::try_from(PROOF_LEAF_SIZE).unwrap() + 17];
        std::fs::write(&path, &bytes).unwrap();
        let mut input = File::open(&path).unwrap();
        for length in [0, PROOF_LEAF_SIZE, MAX_OBJECT_LENGTH + 1] {
            assert!(matches!(
                file_proof_leaves(&mut input, Suite::Blake3Bao64, length),
                Err(Error::InvalidArguments)
            ));
        }
        for length in [bytes.len() as u64 - 1, bytes.len() as u64 + 1] {
            assert!(matches!(
                file_proof_leaves(&mut input, Suite::Blake3Bao64, length),
                Err(Error::SourceMutation)
            ));
            assert_eq!(input.stream_position().unwrap(), 0, "reject before reading");
        }
        input.seek(SeekFrom::Start(19)).unwrap();
        let leaves = file_proof_leaves(&mut input, Suite::Blake3Bao64, bytes.len() as u64).unwrap();
        assert_eq!(
            leaves,
            proof_leaves_at(Suite::Blake3Bao64, 0, &bytes, bytes.len() as u64).unwrap()
        );
        assert_eq!(input.stream_position().unwrap(), bytes.len() as u64);
    }

    #[cfg(unix)]
    #[test]
    fn file_preparation_rejects_a_directory() {
        let path = crate::tests::temporary("file-preparation-directory");
        std::fs::create_dir(&path).unwrap();
        let mut input = File::open(&path).unwrap();
        assert!(matches!(
            file_proof_leaves(&mut input, Suite::Blake3Bao64, PROOF_LEAF_SIZE + 1),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn small_sources_stay_inline_and_large_sources_cap_workers() {
        assert_eq!(worker_count(67_108_863, 64), None);
        assert_eq!(worker_count(67_108_864, 64), Some(8));
        for (length, available, expected) in [
            (PARALLEL_PREPARATION_MIN_BYTES - 1, 64, None),
            (PARALLEL_PREPARATION_MIN_BYTES, 0, None),
            (PARALLEL_PREPARATION_MIN_BYTES, 1, None),
            (PARALLEL_PREPARATION_MIN_BYTES, 2, Some(2)),
            (PARALLEL_PREPARATION_MIN_BYTES, 8, Some(8)),
            (PARALLEL_PREPARATION_MIN_BYTES, 64, Some(8)),
        ] {
            assert_eq!(worker_count(length, available), expected);
        }
    }
}
