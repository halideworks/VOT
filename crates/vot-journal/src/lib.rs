//! Checksummed append-only journal for VOT commit transitions.

#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAGIC: [u8; 4] = *b"VOTJ";
const VERSION: u8 = 0;
const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 1 + 4;
const MAX_PAYLOAD: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub incarnation: [u8; 16],
    pub sequence: u64,
    pub state: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Poisoned,
    PayloadTooLarge,
    InvalidHeader,
    Checksum,
    SequenceGap,
    SequenceConflict,
    StaleIncarnation,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replay {
    pub records: Vec<Record>,
    pub torn_tail: bool,
}

pub struct Journal {
    file: File,
    incarnation: [u8; 16],
    next_sequence: u64,
    poisoned: bool,
}

impl Journal {
    pub fn create(path: &Path, incarnation: [u8; 16]) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            file,
            incarnation,
            next_sequence: 0,
            poisoned: false,
        })
    }

    pub fn open_current(path: &Path, incarnation: [u8; 16]) -> Result<(Self, Replay), Error> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let replay = replay_reader(&mut file, incarnation)?;
        file.seek(SeekFrom::End(0))?;
        let next_sequence = replay
            .records
            .last()
            .map_or(0, |record| record.sequence + 1);
        Ok((
            Self {
                file,
                incarnation,
                next_sequence,
                poisoned: false,
            },
            replay,
        ))
    }

    pub fn append_durable(&mut self, state: u8, payload: &[u8]) -> Result<u64, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let sequence = self.next_sequence;
        let record = Record {
            incarnation: self.incarnation,
            sequence,
            state,
            payload: payload.to_vec(),
        };
        let encoded = encode(&record)?;
        if let Err(error) = self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_data())
        {
            self.poisoned = true;
            return Err(Error::Io(error));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(Error::SequenceGap)?;
        Ok(sequence)
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn encode(record: &Record) -> Result<Vec<u8>, Error> {
    if record.payload.len() > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + record.payload.len() + 4);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&record.incarnation);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.push(record.state);
    bytes.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&record.payload);
    bytes.extend_from_slice(&crc32c(&bytes).to_le_bytes());
    Ok(bytes)
}

pub fn replay(path: &Path, current_incarnation: [u8; 16]) -> Result<Replay, Error> {
    let mut file = File::open(path)?;
    replay_reader(&mut file, current_incarnation)
}

fn replay_reader(reader: &mut impl Read, current_incarnation: [u8; 16]) -> Result<Replay, Error> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let mut offset = 0;
    let mut records: Vec<Record> = Vec::new();
    let mut torn_tail = false;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            torn_tail = true;
            break;
        }
        let header = &bytes[offset..offset + HEADER_LEN];
        if header[..4] != MAGIC || header[4] != VERSION {
            return Err(Error::InvalidHeader);
        }
        let mut incarnation = [0; 16];
        incarnation.copy_from_slice(&header[5..21]);
        if incarnation != current_incarnation {
            return Err(Error::StaleIncarnation);
        }
        let sequence = u64::from_le_bytes(header[21..29].try_into().unwrap());
        let state = header[29];
        let length = u32::from_le_bytes(header[30..34].try_into().unwrap()) as usize;
        if length > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let record_end = offset
            .checked_add(HEADER_LEN + length + 4)
            .ok_or(Error::PayloadTooLarge)?;
        if record_end > bytes.len() {
            torn_tail = true;
            break;
        }
        let checksum_at = record_end - 4;
        let expected = u32::from_le_bytes(bytes[checksum_at..record_end].try_into().unwrap());
        if crc32c(&bytes[offset..checksum_at]) != expected {
            return Err(Error::Checksum);
        }
        let record = Record {
            incarnation,
            sequence,
            state,
            payload: bytes[offset + HEADER_LEN..checksum_at].to_vec(),
        };
        if let Some(previous) = records.last() {
            if sequence == previous.sequence {
                if record != *previous {
                    return Err(Error::SequenceConflict);
                }
            } else if sequence != previous.sequence + 1 {
                return Err(Error::SequenceGap);
            } else {
                records.push(record);
            }
        } else if sequence == 0 {
            records.push(record);
        } else {
            return Err(Error::SequenceGap);
        }
        offset = record_end;
    }
    Ok(Replay { records, torn_tail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vot-journal-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn durable_records_replay_in_order() {
        let path = temp_path("ordered");
        let incarnation = [7; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        assert_eq!(journal.append_durable(1, b"admitted").unwrap(), 0);
        assert_eq!(journal.append_durable(2, b"verified").unwrap(), 1);
        drop(journal);
        let replayed = replay(&path, incarnation).unwrap();
        assert_eq!(replayed.records.len(), 2);
        assert!(!replayed.torn_tail);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn crash_at_every_tail_byte_never_invents_transition() {
        let path = temp_path("source");
        let incarnation = [8; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        journal.append_durable(1, b"one").unwrap();
        journal.append_durable(2, b"two").unwrap();
        drop(journal);
        let complete = std::fs::read(&path).unwrap();
        for length in 0..complete.len() {
            let truncated = temp_path(format!("tail-{length}").as_str());
            std::fs::write(&truncated, &complete[..length]).unwrap();
            let recovered = replay(&truncated, incarnation).unwrap();
            assert!(recovered.records.len() <= 2);
            assert!(
                recovered
                    .records
                    .iter()
                    .enumerate()
                    .all(|(index, record)| record.sequence == index as u64)
            );
            std::fs::remove_file(truncated).unwrap();
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn corruption_and_stale_incarnation_fail() {
        let path = temp_path("corrupt");
        let incarnation = [9; 16];
        let mut journal = Journal::create(&path, incarnation).unwrap();
        journal.append_durable(1, b"record").unwrap();
        drop(journal);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(replay(&path, incarnation), Err(Error::Checksum)));
        assert!(matches!(
            replay(&path, [3; 16]),
            Err(Error::StaleIncarnation)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
