use vot_object::{PreparedObject, RangeCover};

use crate::{
    Error, HEADER_LENGTH, HEADER_LENGTH_FIELD, INDEX_ENTRY_LENGTH, MAGIC, MAX_CATALOG_LENGTH,
    MAX_PROOF_BLOB_LENGTH, MAX_PROOF_LENGTH, PROFILE, RANGE_LENGTH, VERSION, geometry, write_u16,
    write_u32, write_u64,
};

pub(crate) const fn cover_is_exact(
    actual_offset: u64,
    actual_length: u64,
    expected_offset: u64,
    expected_length: u64,
) -> bool {
    actual_offset == expected_offset && actual_length == expected_length
}

pub(crate) const fn proof_length_is_valid(length: u64) -> bool {
    length <= MAX_PROOF_LENGTH && length.is_multiple_of(32)
}

pub(crate) fn next_proof_blob_length(current: u64, added: u64) -> Result<u64, Error> {
    let next = current.checked_add(added).ok_or(Error::ProofGeneration)?;
    if next > MAX_PROOF_BLOB_LENGTH {
        return Err(Error::ProofGeneration);
    }
    Ok(next)
}

pub(crate) fn record_offsets(
    ordinal: u64,
    proof_blob_offset: u64,
    proof_blob_length: u64,
) -> Result<(u64, u64), Error> {
    let index_offset = ordinal
        .checked_mul(INDEX_ENTRY_LENGTH as u64)
        .and_then(|offset| (HEADER_LENGTH as u64).checked_add(offset))
        .ok_or(Error::ProofGeneration)?;
    let proof_offset = proof_blob_offset
        .checked_add(proof_blob_length)
        .ok_or(Error::ProofGeneration)?;
    Ok((index_offset, proof_offset))
}

pub(crate) fn finished_catalog_length(
    proof_blob_offset: u64,
    proof_blob_length: u64,
    physical_length: u64,
) -> Result<u64, Error> {
    let catalog_length = proof_blob_offset
        .checked_add(proof_blob_length)
        .ok_or(Error::ProofGeneration)?;
    if catalog_length > MAX_CATALOG_LENGTH || physical_length != catalog_length {
        return Err(Error::ProofGeneration);
    }
    Ok(catalog_length)
}

pub(crate) fn record_from_cover(
    cover: RangeCover,
    ordinal: u64,
    expected_offset: u64,
    expected_length: u64,
    proof_blob_offset: u64,
    proof_blob_length: u64,
) -> Result<(CatalogRecord, u64), Error> {
    let (covered_offset, covered_length, proof) = cover.into_parts();
    if !cover_is_exact(
        covered_offset,
        covered_length,
        expected_offset,
        expected_length,
    ) {
        return Err(Error::ProofGeneration);
    }
    let proof_length = u64::try_from(proof.len()).map_err(|_| Error::ProofGeneration)?;
    if !proof_length_is_valid(proof_length) {
        return Err(Error::ProofGeneration);
    }
    let next_proof_blob_length = next_proof_blob_length(proof_blob_length, proof_length)?;
    let (index_offset, proof_offset) =
        record_offsets(ordinal, proof_blob_offset, proof_blob_length)?;
    let mut index_entry = [0_u8; INDEX_ENTRY_LENGTH];
    write_u64(&mut index_entry, 0, proof_blob_length);
    write_u32(
        &mut index_entry,
        8,
        u32::try_from(proof_length).map_err(|_| Error::ProofGeneration)?,
    );
    Ok((
        CatalogRecord {
            ordinal,
            index_offset,
            index_entry,
            proof_offset,
            proof,
        },
        next_proof_blob_length,
    ))
}

/// One canonical catalog index entry and its proof bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct CatalogRecord {
    ordinal: u64,
    index_offset: u64,
    index_entry: [u8; INDEX_ENTRY_LENGTH],
    proof_offset: u64,
    proof: Vec<u8>,
}

impl CatalogRecord {
    /// Returns the zero-based catalog record ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the absolute catalog offset for [`Self::index_entry`].
    #[must_use]
    pub const fn index_offset(&self) -> u64 {
        self.index_offset
    }

    /// Returns the canonical fixed-width index entry.
    #[must_use]
    pub const fn index_entry(&self) -> &[u8; INDEX_ENTRY_LENGTH] {
        &self.index_entry
    }

    /// Returns the absolute catalog offset for [`Self::proof`].
    #[must_use]
    pub const fn proof_offset(&self) -> u64 {
        self.proof_offset
    }

    /// Returns the canonical proof bytes.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

/// The fixed header and dimensions of a successfully completed catalog.
#[derive(Debug, Eq, PartialEq)]
pub struct FinishedCatalog {
    header: [u8; HEADER_LENGTH],
    catalog_length: u64,
    record_count: u64,
}

impl FinishedCatalog {
    /// Returns the canonical fixed-width header.
    #[must_use]
    pub const fn header(&self) -> &[u8; HEADER_LENGTH] {
        &self.header
    }

    /// Returns the exact completed catalog length.
    #[must_use]
    pub const fn catalog_length(&self) -> u64 {
        self.catalog_length
    }

    /// Returns the exact number of catalog records.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }
}

/// Pull-based encoder for bounded positional catalog writes.
///
/// Each successful [`Self::next_record`] owns at most one proof. Callers write
/// the returned entry and proof at their absolute offsets. The fixed header is
/// withheld until [`Self::finish`] succeeds. Output from an abandoned or failed
/// encoder is incomplete and must not be published.
pub struct CatalogEncoder<'prepared> {
    prepared: &'prepared PreparedObject,
    record_count: u64,
    index_length: u64,
    proof_blob_offset: u64,
    next_ordinal: u64,
    proof_blob_length: u64,
    failure: Option<Error>,
}

impl<'prepared> CatalogEncoder<'prepared> {
    /// Starts a catalog encoder for `prepared`.
    ///
    /// # Errors
    /// Reports invalid geometry or arithmetic overflow as proof-generation
    /// failure.
    pub fn new(prepared: &'prepared PreparedObject) -> Result<Self, Error> {
        let object = prepared.object_id();
        let (record_count, index_length) =
            geometry(object.length).map_err(|_| Error::ProofGeneration)?;
        let proof_blob_offset = (HEADER_LENGTH as u64)
            .checked_add(index_length)
            .ok_or(Error::ProofGeneration)?;
        Ok(Self {
            prepared,
            record_count,
            index_length,
            proof_blob_offset,
            next_ordinal: 0,
            proof_blob_length: 0,
            failure: None,
        })
    }

    /// Produces the next bounded canonical index/proof record.
    ///
    /// Returns `None` after all records have been produced. The first error
    /// poisons the encoder, and all later calls return the same error.
    ///
    /// # Errors
    /// Reports proof-generation, proof-shape, or arithmetic failures.
    pub fn next_record(&mut self) -> Result<Option<CatalogRecord>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.next_ordinal == self.record_count {
            return Ok(None);
        }
        let result = self.make_next_record();
        match result {
            Ok((record, next_proof_blob_length)) => {
                self.next_ordinal += 1;
                self.proof_blob_length = next_proof_blob_length;
                Ok(Some(record))
            }
            Err(error) => {
                self.failure = Some(error);
                Err(error)
            }
        }
    }

    /// Completes the encoder and returns the final fixed header.
    ///
    /// # Errors
    /// Returns the stored failure, or proof-generation failure if any record
    /// has not been produced.
    pub fn finish(self) -> Result<FinishedCatalog, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.next_ordinal != self.record_count {
            return Err(Error::ProofGeneration);
        }
        let catalog_length = finished_catalog_length(
            self.proof_blob_offset,
            self.proof_blob_length,
            self.proof_blob_offset
                .checked_add(self.proof_blob_length)
                .ok_or(Error::ProofGeneration)?,
        )?;
        let object = self.prepared.object_id();
        let mut header = [0_u8; HEADER_LENGTH];
        header[..8].copy_from_slice(MAGIC);
        write_u16(&mut header, 8, VERSION);
        write_u16(&mut header, 10, HEADER_LENGTH_FIELD);
        write_u16(&mut header, 16, object.suite);
        write_u16(&mut header, 18, PROFILE);
        header[24..56].copy_from_slice(&object.root);
        write_u64(&mut header, 56, object.length);
        write_u64(&mut header, 64, self.record_count);
        write_u64(&mut header, 72, HEADER_LENGTH as u64);
        write_u64(&mut header, 80, self.index_length);
        write_u64(&mut header, 88, self.proof_blob_offset);
        write_u64(&mut header, 96, self.proof_blob_length);
        write_u64(&mut header, 104, catalog_length);
        Ok(FinishedCatalog {
            header,
            catalog_length,
            record_count: self.record_count,
        })
    }

    fn make_next_record(&self) -> Result<(CatalogRecord, u64), Error> {
        let ordinal = self.next_ordinal;
        let object = self.prepared.object_id();
        let data_offset = ordinal
            .checked_mul(RANGE_LENGTH)
            .ok_or(Error::ProofGeneration)?;
        let data_length = RANGE_LENGTH.min(
            object
                .length
                .checked_sub(data_offset)
                .ok_or(Error::ProofGeneration)?,
        );
        let cover = self
            .prepared
            .prove(data_offset, data_length)
            .map_err(|_| Error::ProofGeneration)?;
        record_from_cover(
            cover,
            ordinal,
            data_offset,
            data_length,
            self.proof_blob_offset,
            self.proof_blob_length,
        )
    }
}

struct MemoryCatalogSink {
    bytes: Vec<u8>,
}

impl MemoryCatalogSink {
    fn new(prefix_length: u64) -> Result<Self, Error> {
        let prefix_length = usize::try_from(prefix_length).map_err(|_| Error::AllocationFailed)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(prefix_length)
            .map_err(|_| Error::AllocationFailed)?;
        bytes.resize(prefix_length, 0);
        Ok(Self { bytes })
    }

    fn write_at(&mut self, offset: u64, value: &[u8]) -> Result<(), Error> {
        let start = usize::try_from(offset).map_err(|_| Error::AllocationFailed)?;
        let end = start
            .checked_add(value.len())
            .ok_or(Error::AllocationFailed)?;
        let new_length = self.bytes.len().max(end);
        let additional = new_length.saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve(additional)
            .map_err(|_| Error::AllocationFailed)?;
        self.bytes.resize(new_length, 0);
        self.bytes[start..end].copy_from_slice(value);
        Ok(())
    }

    fn finish(self, expected_length: u64) -> Result<Vec<u8>, Error> {
        let physical_length =
            u64::try_from(self.bytes.len()).map_err(|_| Error::ProofGeneration)?;
        if physical_length != expected_length {
            return Err(Error::ProofGeneration);
        }
        Ok(self.bytes)
    }
}

/// Encodes the canonical in-memory version-zero catalog for a prepared object.
///
/// # Errors
/// Reports proof-generation, arithmetic, or output-reservation failures.
pub fn encode(prepared: &PreparedObject) -> Result<Vec<u8>, Error> {
    let mut encoder = CatalogEncoder::new(prepared)?;
    let mut sink = MemoryCatalogSink::new(encoder.proof_blob_offset)?;
    for _ in 0..encoder.record_count {
        let record = encoder.next_record()?.ok_or(Error::ProofGeneration)?;
        sink.write_at(record.index_offset(), record.index_entry())?;
        sink.write_at(record.proof_offset(), record.proof())?;
    }
    if encoder.next_record()?.is_some() {
        return Err(Error::ProofGeneration);
    }
    let finished = encoder.finish()?;
    sink.write_at(0, finished.header())?;
    sink.finish(finished.catalog_length())
}
