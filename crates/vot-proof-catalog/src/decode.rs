use vot_object::Suite;

use crate::{
    Error, HEADER_LENGTH, HEADER_LENGTH_FIELD, INDEX_ENTRY_LENGTH, MAGIC, MAX_CATALOG_LENGTH,
    MAX_OBJECT_LENGTH, MAX_PROOF_BLOB_LENGTH, MAX_PROOF_LENGTH, ObjectId, PROFILE, RANGE_LENGTH,
    VERSION, geometry, read_u16, read_u32, read_u64,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeader {
    object: ObjectId,
    suite: Suite,
    record_count: u64,
    index_offset: u64,
    index_length: u64,
    proof_blob_offset: u64,
    proof_blob_length: u64,
    catalog_length: u64,
}

impl CatalogHeader {
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    #[must_use]
    pub const fn catalog_length(&self) -> u64 {
        self.catalog_length
    }

    /// # Errors
    /// Returns [`Error::RecordOutOfRange`] when `ordinal` names no record.
    pub fn index_entry_offset(&self, ordinal: u64) -> Result<u64, Error> {
        if ordinal >= self.record_count {
            return Err(Error::RecordOutOfRange);
        }
        let offset = self
            .index_offset
            .checked_add(
                ordinal
                    .checked_mul(INDEX_ENTRY_LENGTH as u64)
                    .ok_or(Error::MalformedCatalog)?,
            )
            .ok_or(Error::MalformedCatalog)?;
        let end = offset
            .checked_add(INDEX_ENTRY_LENGTH as u64)
            .ok_or(Error::MalformedCatalog)?;
        if end > self.proof_blob_offset {
            return Err(Error::MalformedCatalog);
        }
        Ok(offset)
    }

    /// Decodes one independently fetched entry without requiring its neighbors.
    ///
    /// # Errors
    /// Reports a missing entry, invalid ordinal, or malformed proof bounds.
    pub fn decode_entry<'header>(
        &'header self,
        ordinal: u64,
        bytes: &[u8],
    ) -> Result<SelectedEntry<'header>, Error> {
        let _ = self.index_entry_offset(ordinal)?;
        if bytes.len() < INDEX_ENTRY_LENGTH {
            return Err(Error::CatalogUnavailable);
        }
        if bytes.len() != INDEX_ENTRY_LENGTH {
            return Err(Error::MalformedCatalog);
        }
        let relative = read_u64(bytes, 0);
        let proof_length = u64::from(read_u32(bytes, 8));
        if read_u32(bytes, 12) != 0 || proof_length > MAX_PROOF_LENGTH || proof_length % 32 != 0 {
            return Err(Error::MalformedCatalog);
        }
        let relative_end = relative
            .checked_add(proof_length)
            .ok_or(Error::MalformedCatalog)?;
        if relative_end > self.proof_blob_length {
            return Err(Error::MalformedCatalog);
        }
        let proof_offset = self
            .proof_blob_offset
            .checked_add(relative)
            .ok_or(Error::MalformedCatalog)?;
        let proof_end = proof_offset
            .checked_add(proof_length)
            .ok_or(Error::MalformedCatalog)?;
        if proof_end > self.catalog_length {
            return Err(Error::MalformedCatalog);
        }
        let data_offset = ordinal
            .checked_mul(RANGE_LENGTH)
            .ok_or(Error::MalformedCatalog)?;
        let data_length = RANGE_LENGTH.min(
            self.object
                .length
                .checked_sub(data_offset)
                .ok_or(Error::MalformedCatalog)?,
        );
        Ok(SelectedEntry {
            header: self,
            ordinal,
            data_offset,
            data_length,
            proof_relative_offset: relative,
            proof_offset,
            proof_length,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedEntry<'header> {
    header: &'header CatalogHeader,
    ordinal: u64,
    data_offset: u64,
    data_length: u64,
    proof_relative_offset: u64,
    proof_offset: u64,
    proof_length: u64,
}

impl SelectedEntry<'_> {
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    #[must_use]
    pub const fn data_offset(&self) -> u64 {
        self.data_offset
    }
    #[must_use]
    pub const fn data_length(&self) -> u64 {
        self.data_length
    }
    #[must_use]
    pub const fn proof_offset(&self) -> u64 {
        self.proof_offset
    }
    #[must_use]
    pub const fn proof_length(&self) -> u64 {
        self.proof_length
    }

    /// # Errors
    /// Reports absent proof bytes or data/proof that fails suite verification.
    pub fn verify<'data>(
        &self,
        data: &'data [u8],
        proof: &[u8],
    ) -> Result<vot_verified_range::VerifiedSlice<'data>, Error> {
        let proof_length = u64::try_from(proof.len()).map_err(|_| Error::MalformedCatalog)?;
        if proof_length < self.proof_length {
            return Err(Error::CatalogUnavailable);
        }
        if proof_length != self.proof_length {
            return Err(Error::MalformedCatalog);
        }
        if u64::try_from(data.len()).ok() != Some(self.data_length) {
            return Err(Error::ProofInvalid);
        }
        let object = vot_codec::frames::ObjectId {
            suite: self.header.suite.identifier(),
            root: self.header.object.root,
            length: self.header.object.length,
        };
        vot_verified_range::verify_range(object, self.data_offset, data, proof)
            .map_err(|_| Error::ProofInvalid)
    }
}

/// Decodes the bounded header prefix and authenticates it before addressing.
///
/// # Errors
/// Distinguishes unavailable, unsupported, identity, and malformed outcomes.
pub fn decode_header(bytes: &[u8], expected: &ObjectId) -> Result<CatalogHeader, Error> {
    if bytes.len() < HEADER_LENGTH {
        return Err(Error::CatalogUnavailable);
    }
    let bytes = &bytes[..HEADER_LENGTH];
    if &bytes[..8] != MAGIC
        || read_u16(bytes, 10) != HEADER_LENGTH_FIELD
        || read_u32(bytes, 12) != 0
    {
        return Err(Error::MalformedCatalog);
    }
    let version = read_u16(bytes, 8);
    let suite = read_u16(bytes, 16);
    let profile = read_u16(bytes, 18);
    let Ok(decoded_suite) = Suite::try_from(suite) else {
        return Err(Error::UnsupportedCatalog);
    };
    if version != VERSION || profile != PROFILE {
        return Err(Error::UnsupportedCatalog);
    }
    let object_length = read_u64(bytes, 56);
    if read_u32(bytes, 20) != 0
        || bytes[112..128].iter().any(|byte| *byte != 0)
        || object_length > MAX_OBJECT_LENGTH
    {
        return Err(Error::MalformedCatalog);
    }
    let mut root = [0; 32];
    root.copy_from_slice(&bytes[24..56]);
    if suite != expected.suite || root != expected.root || object_length != expected.length {
        return Err(Error::IdentityMismatch);
    }
    let (record_count, index_length) = geometry(object_length)?;
    let proof_blob_offset = (HEADER_LENGTH as u64)
        .checked_add(index_length)
        .ok_or(Error::MalformedCatalog)?;
    let proof_blob_length = read_u64(bytes, 96);
    let catalog_length = proof_blob_offset
        .checked_add(proof_blob_length)
        .ok_or(Error::MalformedCatalog)?;
    if read_u64(bytes, 64) != record_count
        || read_u64(bytes, 72) != HEADER_LENGTH as u64
        || read_u64(bytes, 80) != index_length
        || read_u64(bytes, 88) != proof_blob_offset
        || proof_blob_length > MAX_PROOF_BLOB_LENGTH
        || read_u64(bytes, 104) != catalog_length
        || catalog_length > MAX_CATALOG_LENGTH
    {
        return Err(Error::MalformedCatalog);
    }
    Ok(CatalogHeader {
        object: expected.clone(),
        suite: decoded_suite,
        record_count,
        index_offset: HEADER_LENGTH as u64,
        index_length,
        proof_blob_offset,
        proof_blob_length,
        catalog_length,
    })
}

/// Allocation-free complete-catalog canonical scanner.
///
/// # Errors
/// Reports header errors, physical-length errors, and noncanonical entries.
pub fn validate_complete(bytes: &[u8], expected: &ObjectId) -> Result<CatalogHeader, Error> {
    let header = decode_header(bytes, expected)?;
    let physical_length = u64::try_from(bytes.len()).map_err(|_| Error::MalformedCatalog)?;
    if physical_length < header.catalog_length {
        return Err(Error::CatalogUnavailable);
    }
    if physical_length != header.catalog_length {
        return Err(Error::MalformedCatalog);
    }
    let mut expected_relative = 0;
    for ordinal in 0..header.record_count {
        let start = header.index_entry_offset(ordinal)?;
        let end = start
            .checked_add(INDEX_ENTRY_LENGTH as u64)
            .ok_or(Error::MalformedCatalog)?;
        let start = usize::try_from(start).map_err(|_| Error::MalformedCatalog)?;
        let end = usize::try_from(end).map_err(|_| Error::MalformedCatalog)?;
        let entry = header.decode_entry(ordinal, &bytes[start..end])?;
        if entry.proof_relative_offset != expected_relative {
            return Err(Error::MalformedCatalog);
        }
        expected_relative = entry
            .proof_relative_offset
            .checked_add(entry.proof_length)
            .ok_or(Error::MalformedCatalog)?;
    }
    if expected_relative != header.proof_blob_length {
        return Err(Error::MalformedCatalog);
    }
    debug_assert_eq!(
        header.index_length,
        header.record_count * INDEX_ENTRY_LENGTH as u64
    );
    Ok(header)
}
