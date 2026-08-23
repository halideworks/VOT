//! Scheduler adapters for pure bundle and range verification.

use super::{Error, MAX_PROOF_RANGE_BYTES, SubjectId, Suite};
use vot_codec::frames::{DataRecordRef, ObjectId, ProofBundle};

pub(super) fn validate_typed_bundle<'records>(
    subject: SubjectId,
    bundle: &'records ProofBundle,
    records: &[DataRecordRef<'records>],
) -> Result<vot_verified_range::ValidatedBundle<'records>, Error> {
    vot_verified_range::validate_typed_bundle_ref(object_id(subject)?, bundle, records)
        .map_err(map_error)
}

pub(super) fn assemble_ordered(
    bundle: vot_verified_range::ValidatedBundle<'_>,
) -> Result<Vec<u8>, Error> {
    bundle.assemble().map_err(map_error)
}

pub(super) fn check_range_proof<'data>(
    subject: SubjectId,
    covered_offset: u64,
    data: &'data [u8],
    proof: &[u8],
) -> Result<vot_verified_range::VerifiedSlice<'data>, Error> {
    if u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)? > MAX_PROOF_RANGE_BYTES {
        return Err(Error::RecordTooLarge);
    }
    vot_verified_range::verify_range(object_id(subject)?, covered_offset, data, proof)
        .map_err(map_error)
}

pub(super) fn verify_typed_bundle(
    subject: SubjectId,
    bundle: &ProofBundle,
    records: &[DataRecordRef<'_>],
) -> Result<vot_verified_range::VerifiedRange, Error> {
    vot_verified_range::verify_typed_bundle_ref(object_id(subject)?, bundle, records)
        .map_err(map_error)
}

pub(super) fn suite(id: u16) -> Result<Suite, Error> {
    Suite::try_from(id).map_err(|_| Error::UnknownObject)
}

pub(super) fn subject_id(object: ObjectId) -> SubjectId {
    SubjectId::try_from(object).expect("a verified object names a registered suite")
}

fn object_id(subject: SubjectId) -> Result<ObjectId, Error> {
    ObjectId::try_from(subject).map_err(|_| Error::UnknownObject)
}

const fn map_error(error: vot_verified_range::Error) -> Error {
    match error {
        vot_verified_range::Error::UnknownSuite => Error::UnknownObject,
        vot_verified_range::Error::RecordTooLarge => Error::RecordTooLarge,
        vot_verified_range::Error::LengthExceeded => Error::LengthExceeded,
        vot_verified_range::Error::LengthMismatch => Error::LengthMismatch,
        vot_verified_range::Error::ProofInvalid => Error::ProofInvalid,
        vot_verified_range::Error::UnsupportedCompression => Error::UnsupportedCompression,
    }
}
