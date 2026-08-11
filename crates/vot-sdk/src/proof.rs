//! Streaming and explicitly bounded proof catalog handling.

use crate::error;
use crate::object::{InMemoryPreparedObject, ObjectId};
use crate::verify::{self, VerifiedSlice};
use crate::{Error, ErrorCode};

pub const HEADER_LENGTH: usize = vot_proof_catalog::HEADER_LENGTH;
pub const INDEX_ENTRY_LENGTH: usize = vot_proof_catalog::INDEX_ENTRY_LENGTH;
pub const RANGE_LENGTH: u64 = vot_proof_catalog::RANGE_LENGTH;

/// Pull-based encoder yielding one bounded catalog record at a time.
pub struct CatalogEncoder<'prepared> {
    inner: vot_proof_catalog::CatalogEncoder<'prepared>,
}

impl<'prepared> CatalogEncoder<'prepared> {
    pub fn new(prepared: &'prepared InMemoryPreparedObject) -> Result<Self, Error> {
        vot_proof_catalog::CatalogEncoder::new(prepared.inner())
            .map(|inner| Self { inner })
            .map_err(error::proof)
    }

    pub fn next_record(&mut self) -> Result<Option<CatalogRecord>, Error> {
        self.inner
            .next_record()
            .map(|record| record.map(|inner| CatalogRecord { inner }))
            .map_err(error::proof)
    }

    pub fn finish(self) -> Result<FinishedCatalog, Error> {
        self.inner
            .finish()
            .map(|inner| FinishedCatalog { inner })
            .map_err(error::proof)
    }
}

/// One fixed-width catalog index entry and its proof.
#[derive(Debug, Eq, PartialEq)]
pub struct CatalogRecord {
    inner: vot_proof_catalog::CatalogRecord,
}

impl CatalogRecord {
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.inner.ordinal()
    }

    #[must_use]
    pub const fn index_offset(&self) -> u64 {
        self.inner.index_offset()
    }

    #[must_use]
    pub const fn index_entry(&self) -> &[u8; INDEX_ENTRY_LENGTH] {
        self.inner.index_entry()
    }

    #[must_use]
    pub const fn proof_offset(&self) -> u64 {
        self.inner.proof_offset()
    }

    #[must_use]
    pub fn proof(&self) -> &[u8] {
        self.inner.proof()
    }
}

/// Header emitted only after every catalog record succeeds.
#[derive(Debug, Eq, PartialEq)]
pub struct FinishedCatalog {
    inner: vot_proof_catalog::FinishedCatalog,
}

impl FinishedCatalog {
    #[must_use]
    pub const fn header(&self) -> &[u8; HEADER_LENGTH] {
        self.inner.header()
    }

    #[must_use]
    pub const fn catalog_length(&self) -> u64 {
        self.inner.catalog_length()
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.inner.record_count()
    }
}

/// Collects a catalog in memory after checking every write against the limit.
pub fn encode_in_memory(
    prepared: &InMemoryPreparedObject,
    max_catalog_bytes: u64,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    write_at(&mut output, 0, &[0; HEADER_LENGTH], max_catalog_bytes)?;
    let mut encoder = CatalogEncoder::new(prepared)?;
    while let Some(record) = encoder.next_record()? {
        write_at(
            &mut output,
            record.index_offset(),
            record.index_entry(),
            max_catalog_bytes,
        )?;
        write_at(
            &mut output,
            record.proof_offset(),
            record.proof(),
            max_catalog_bytes,
        )?;
    }
    let finished = encoder.finish()?;
    if u64::try_from(output.len()).ok() != Some(finished.catalog_length()) {
        return Err(Error::new(ErrorCode::Internal));
    }
    write_at(&mut output, 0, finished.header(), max_catalog_bytes)?;
    Ok(output)
}

fn write_at(output: &mut Vec<u8>, offset: u64, bytes: &[u8], maximum: u64) -> Result<(), Error> {
    let byte_length =
        u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
    let end = offset
        .checked_add(byte_length)
        .ok_or_else(|| Error::new(ErrorCode::LimitExceeded))?;
    if end > maximum {
        return Err(Error::new(ErrorCode::LimitExceeded));
    }
    let start = usize::try_from(offset).map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
    let end = usize::try_from(end).map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
    let additional = required_capacity(output.len(), end);
    output
        .try_reserve_exact(additional)
        .map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
    let new_length = output.len().max(end);
    output.resize(new_length, 0);
    output[start..end].copy_from_slice(bytes);
    Ok(())
}

const fn required_capacity(current_length: usize, required_length: usize) -> usize {
    required_length.saturating_sub(current_length)
}

/// Validated catalog header bound to an expected object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeader {
    inner: vot_proof_catalog::CatalogHeader,
}

impl CatalogHeader {
    #[must_use]
    pub fn object_id(&self) -> &ObjectId {
        self.inner.object_id()
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.inner.record_count()
    }

    #[must_use]
    pub const fn catalog_length(&self) -> u64 {
        self.inner.catalog_length()
    }

    pub fn index_entry_offset(&self, ordinal: u64) -> Result<u64, Error> {
        self.inner.index_entry_offset(ordinal).map_err(error::proof)
    }

    pub fn decode_entry(&self, ordinal: u64, bytes: &[u8]) -> Result<CatalogEntry<'_>, Error> {
        self.inner
            .decode_entry(ordinal, bytes)
            .map(|inner| CatalogEntry { inner })
            .map_err(error::proof)
    }
}

/// One validated catalog entry with absolute data and proof bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry<'header> {
    inner: vot_proof_catalog::SelectedEntry<'header>,
}

impl CatalogEntry<'_> {
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.inner.ordinal()
    }

    #[must_use]
    pub const fn data_offset(&self) -> u64 {
        self.inner.data_offset()
    }

    #[must_use]
    pub const fn data_length(&self) -> u64 {
        self.inner.data_length()
    }

    #[must_use]
    pub const fn proof_offset(&self) -> u64 {
        self.inner.proof_offset()
    }

    #[must_use]
    pub const fn proof_length(&self) -> u64 {
        self.inner.proof_length()
    }

    pub fn verify<'data>(
        &self,
        data: &'data [u8],
        proof: &[u8],
    ) -> Result<VerifiedSlice<'data>, Error> {
        self.inner
            .verify(data, proof)
            .map(verify::from_inner)
            .map_err(error::proof)
    }
}

pub fn decode_header(bytes: &[u8], expected: &ObjectId) -> Result<CatalogHeader, Error> {
    vot_proof_catalog::decode_header(bytes, expected)
        .map(|inner| CatalogHeader { inner })
        .map_err(error::proof)
}

pub fn validate_catalog(bytes: &[u8], expected: &ObjectId) -> Result<CatalogHeader, Error> {
    vot_proof_catalog::validate_complete(bytes, expected)
        .map(|inner| CatalogHeader { inner })
        .map_err(error::proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_writes_check_bounds_before_growth() {
        let mut output = vec![9, 9];
        write_at(&mut output, 2, &[7, 8], 4).unwrap();
        assert_eq!(output, [9, 9, 7, 8]);
        write_at(&mut output, 1, &[6], 4).unwrap();
        assert_eq!(output, [9, 6, 7, 8]);
        assert_eq!(
            write_at(&mut output, 4, &[5], 4).unwrap_err().code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(required_capacity(2, 5), 3);
        assert_eq!(required_capacity(5, 2), 0);
    }
}
