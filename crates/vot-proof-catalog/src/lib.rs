//! VOT version-zero static proof catalog encoding and bounded decoding.

#![forbid(unsafe_code)]

mod decode;
mod encode;

pub use decode::{CatalogHeader, SelectedEntry, decode_header, validate_complete};
pub use encode::{CatalogEncoder, CatalogRecord, FinishedCatalog, encode};
pub use vot_object::ObjectId;

pub const HEADER_LENGTH: usize = 128;
pub const INDEX_ENTRY_LENGTH: usize = 16;
pub const GROUP_LENGTH: u64 = 65_536;
pub const RANGE_LENGTH: u64 = 4_194_304;
pub const MAX_PROOF_LENGTH: u64 = 8_192;
pub const MAX_OBJECT_LENGTH: u64 = vot_object::MAX_OBJECT_LENGTH;

pub(crate) const MAGIC: &[u8; 8] = b"VOTPCAT\0";
pub(crate) const VERSION: u16 = 0;
pub(crate) const HEADER_LENGTH_FIELD: u16 = 128;
pub(crate) const PROFILE: u16 = 1;
#[cfg(test)]
pub(crate) const MAX_RECORDS: u64 = 1_u64 << 41;
pub(crate) const MAX_INDEX_LENGTH: u64 = 1_u64 << 45;
pub(crate) const MAX_PROOF_BLOB_LENGTH: u64 = 1_u64 << 54;
pub(crate) const MAX_CATALOG_LENGTH: u64 =
    HEADER_LENGTH as u64 + MAX_INDEX_LENGTH + MAX_PROOF_BLOB_LENGTH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CatalogUnavailable,
    IdentityMismatch,
    MalformedCatalog,
    UnsupportedCatalog,
    ProofInvalid,
    RecordOutOfRange,
    ProofGeneration,
    AllocationFailed,
}

pub(crate) fn geometry(object_length: u64) -> Result<(u64, u64), Error> {
    if object_length > MAX_OBJECT_LENGTH {
        return Err(Error::MalformedCatalog);
    }
    let record_count =
        object_length / RANGE_LENGTH + u64::from(!object_length.is_multiple_of(RANGE_LENGTH));
    let index_length = record_count
        .checked_mul(INDEX_ENTRY_LENGTH as u64)
        .ok_or(Error::MalformedCatalog)?;
    Ok((record_count, index_length))
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub(crate) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
