//! Bundle identity, record ordering, and range-proof checks.

use super::{BTreeMap, Error, MAX_PROOF_RANGE_BYTES, RANGE_UNIT_BYTES, SubjectId, Suite};

/// Checks a bundle's identity against its subject and orders its records.
pub(super) fn validate_typed_bundle<'records>(
    subject: SubjectId,
    bundle: &vot_codec::frames::ProofBundle,
    records: &'records [vot_codec::frames::DataRecord],
) -> Result<BTreeMap<u64, &'records vot_codec::frames::DataRecord>, Error> {
    bundle.validate().map_err(|_| Error::ProofInvalid)?;
    if bundle.object.suite != subject.suite
        || bundle.object.root != subject.root
        || bundle.object.length != subject.length
        || bundle.data_record_count != records.len() as u64
    {
        return Err(Error::LengthMismatch);
    }
    let mut ordered = BTreeMap::new();
    for record in records {
        record.validate().map_err(|_| Error::ProofInvalid)?;
        if record.bundle_id != bundle.bundle_id {
            return Err(Error::ProofInvalid);
        }
        if record.compression != 0 {
            return Err(Error::UnsupportedCompression);
        }
        if ordered.insert(record.record_index, record).is_some() {
            return Err(Error::LengthMismatch);
        }
    }
    Ok(ordered)
}

/// Reassembles ordered records into the bundle's covered bytes.
pub(super) fn assemble_ordered(
    bundle: &vot_codec::frames::ProofBundle,
    ordered: &BTreeMap<u64, &vot_codec::frames::DataRecord>,
) -> Result<Vec<u8>, Error> {
    let covered_bytes = bundle.covered_length;
    let capacity = usize::try_from(covered_bytes).map_err(|_| Error::LengthExceeded)?;
    let mut data = Vec::with_capacity(capacity);
    for index in 0..bundle.data_record_count {
        let record = ordered.get(&index).ok_or(Error::LengthMismatch)?;
        let expected_offset = bundle
            .covered_offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?)
            .ok_or(Error::LengthExceeded)?;
        if record.plaintext_offset != expected_offset {
            return Err(Error::LengthMismatch);
        }
        data.extend_from_slice(&record.encoded);
    }
    if data.len() as u64 != covered_bytes {
        return Err(Error::LengthMismatch);
    }
    Ok(data)
}

/// Holds a range's bounds and its proof. Pure: no receiver state access.
///
/// # Errors
/// Rejects a range outside the subject, off the 64 KiB unit grid other than
/// at the object's end, oversized or empty, or whose proof does not hold.
pub(super) fn check_range_proof(
    subject: SubjectId,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    let bytes = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
    if bytes == 0 || bytes > MAX_PROOF_RANGE_BYTES {
        return Err(Error::RecordTooLarge);
    }
    let covered_end = covered_offset
        .checked_add(bytes)
        .ok_or(Error::LengthExceeded)?;
    if covered_offset % RANGE_UNIT_BYTES != 0 || covered_end > subject.length {
        return Err(Error::LengthExceeded);
    }
    if covered_end < subject.length && bytes % RANGE_UNIT_BYTES != 0 {
        return Err(Error::LengthExceeded);
    }
    match suite(subject.suite)? {
        Suite::Blake3Bao64 => {
            vot_proof_blake3::verify(&subject.root, subject.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
        Suite::Sha256Bep52 => {
            vot_proof_sha256::verify(&subject.root, subject.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
    }
    Ok(())
}

pub(super) fn suite(id: u16) -> Result<Suite, Error> {
    Suite::try_from(id).map_err(|_| Error::UnknownObject)
}
