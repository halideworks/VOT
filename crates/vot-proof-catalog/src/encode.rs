use vot_object::PreparedObject;

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
    length <= MAX_PROOF_LENGTH && length % 32 == 0
}

pub(crate) fn next_proof_blob_length(current: u64, added: u64) -> Result<u64, Error> {
    let next = current.checked_add(added).ok_or(Error::ProofGeneration)?;
    if next > MAX_PROOF_BLOB_LENGTH {
        return Err(Error::ProofGeneration);
    }
    Ok(next)
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

/// Encodes the canonical in-memory version-zero catalog for a prepared object.
///
/// # Errors
/// Reports proof-generation, arithmetic, or output-reservation failures.
pub fn encode(prepared: &PreparedObject) -> Result<Vec<u8>, Error> {
    let object = prepared.object_id();
    let (record_count, index_length) =
        geometry(object.length).map_err(|_| Error::ProofGeneration)?;
    let proof_blob_offset = (HEADER_LENGTH as u64)
        .checked_add(index_length)
        .ok_or(Error::ProofGeneration)?;
    let prefix_length = usize::try_from(proof_blob_offset).map_err(|_| Error::AllocationFailed)?;
    let mut catalog = Vec::new();
    catalog
        .try_reserve_exact(prefix_length)
        .map_err(|_| Error::AllocationFailed)?;
    catalog.resize(prefix_length, 0);

    let mut proof_blob_length = 0_u64;
    for ordinal in 0..record_count {
        let data_offset = ordinal
            .checked_mul(RANGE_LENGTH)
            .ok_or(Error::ProofGeneration)?;
        let data_length = RANGE_LENGTH.min(
            object
                .length
                .checked_sub(data_offset)
                .ok_or(Error::ProofGeneration)?,
        );
        let cover = prepared
            .prove(data_offset, data_length)
            .map_err(|_| Error::ProofGeneration)?;
        if !cover_is_exact(
            cover.covered_offset(),
            cover.covered_length(),
            data_offset,
            data_length,
        ) {
            return Err(Error::ProofGeneration);
        }
        let proof = cover.proof();
        let proof_length = u64::try_from(proof.len()).map_err(|_| Error::ProofGeneration)?;
        if !proof_length_is_valid(proof_length) {
            return Err(Error::ProofGeneration);
        }
        let next_proof_length = next_proof_blob_length(proof_blob_length, proof_length)?;
        catalog
            .try_reserve(proof.len())
            .map_err(|_| Error::AllocationFailed)?;
        let entry_offset = (HEADER_LENGTH as u64)
            .checked_add(
                ordinal
                    .checked_mul(INDEX_ENTRY_LENGTH as u64)
                    .ok_or(Error::ProofGeneration)?,
            )
            .ok_or(Error::ProofGeneration)?;
        let entry_offset = usize::try_from(entry_offset).map_err(|_| Error::AllocationFailed)?;
        write_u64(&mut catalog, entry_offset, proof_blob_length);
        write_u32(
            &mut catalog,
            entry_offset + 8,
            u32::try_from(proof_length).map_err(|_| Error::ProofGeneration)?,
        );
        catalog.extend_from_slice(proof);
        proof_blob_length = next_proof_length;
    }
    let physical_length = u64::try_from(catalog.len()).map_err(|_| Error::ProofGeneration)?;
    let catalog_length =
        finished_catalog_length(proof_blob_offset, proof_blob_length, physical_length)?;
    catalog[..8].copy_from_slice(MAGIC);
    write_u16(&mut catalog, 8, VERSION);
    write_u16(&mut catalog, 10, HEADER_LENGTH_FIELD);
    write_u16(&mut catalog, 16, object.suite);
    write_u16(&mut catalog, 18, PROFILE);
    catalog[24..56].copy_from_slice(&object.root);
    write_u64(&mut catalog, 56, object.length);
    write_u64(&mut catalog, 64, record_count);
    write_u64(&mut catalog, 72, HEADER_LENGTH as u64);
    write_u64(&mut catalog, 80, index_length);
    write_u64(&mut catalog, 88, proof_blob_offset);
    write_u64(&mut catalog, 96, proof_blob_length);
    write_u64(&mut catalog, 104, catalog_length);
    Ok(catalog)
}
