//! The record wire format: constants, the fixed header, and encoding.

use super::{Error, crc32c};

pub(super) const MAGIC: [u8; 4] = *b"VOTJ";
pub(super) const VERSION: u8 = 0;
pub(super) const HEADER_LEN: usize = 4 + 1 + 16 + 8 + 1 + 4;
pub(super) const MAX_PAYLOAD: usize = 1_048_576;
pub(super) const CHECKPOINT_FLAG: u8 = 0x80;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub incarnation: [u8; 16],
    pub sequence: u64,
    pub state: u8,
    pub payload: Vec<u8>,
    pub checkpoint: bool,
}

/// The fixed record header, so the wire offsets exist in one place. Decode
/// checks only what the header alone can prove (magic and version); the
/// incarnation and length policy stay with the caller, which is what keeps
/// the existing error precedence: a stale journal with a bad length is
/// stale first.
pub(super) struct Header {
    pub(super) incarnation: [u8; 16],
    pub(super) sequence: u64,
    pub(super) state: u8,
    pub(super) checkpoint: bool,
    pub(super) payload_length: usize,
}

impl Header {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        debug_assert_eq!(bytes.len(), HEADER_LEN);
        if bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(Error::InvalidHeader);
        }
        let mut incarnation = [0; 16];
        incarnation.copy_from_slice(&bytes[5..21]);
        let encoded_state = bytes[29];
        Ok(Self {
            incarnation,
            sequence: u64::from_le_bytes(bytes[21..29].try_into().unwrap()),
            state: encoded_state & !CHECKPOINT_FLAG,
            checkpoint: encoded_state & CHECKPOINT_FLAG != 0,
            payload_length: u32::from_le_bytes(bytes[30..34].try_into().unwrap()) as usize,
        })
    }

    pub(super) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION;
        bytes[5..21].copy_from_slice(&self.incarnation);
        bytes[21..29].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[29] = if self.checkpoint {
            self.state + CHECKPOINT_FLAG
        } else {
            self.state
        };
        bytes[30..34].copy_from_slice(&(self.payload_length as u32).to_le_bytes());
        bytes
    }
}

pub(super) fn encode(record: &Record) -> Result<Vec<u8>, Error> {
    if record.payload.len() > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }
    if record.state & CHECKPOINT_FLAG != 0 {
        return Err(Error::InvalidState);
    }
    let header = Header {
        incarnation: record.incarnation,
        sequence: record.sequence,
        state: record.state,
        checkpoint: record.checkpoint,
        payload_length: record.payload.len(),
    };
    let mut bytes = Vec::with_capacity(HEADER_LEN + record.payload.len() + 4);
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&record.payload);
    bytes.extend_from_slice(&crc32c(&bytes).to_le_bytes());
    Ok(bytes)
}
