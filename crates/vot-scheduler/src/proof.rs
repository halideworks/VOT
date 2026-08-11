//! Scheduler adapters for pure bundle and range verification.

use super::{Error, SubjectId, Suite};
use vot_codec::frames::{DataRecord, ObjectId, ProofBundle};

pub(super) fn validate_typed_bundle<'records>(
    subject: SubjectId,
    bundle: &'records ProofBundle,
    records: &'records [DataRecord],
) -> Result<vot_verified_range::ValidatedBundle<'records>, Error> {
    vot_verified_range::validate_typed_bundle(object_id(subject), bundle, records)
        .map_err(map_error)
}

pub(super) fn assemble_ordered(
    bundle: vot_verified_range::ValidatedBundle<'_>,
) -> Result<Vec<u8>, Error> {
    bundle.assemble().map_err(map_error)
}

pub(super) fn check_range_proof(
    subject: SubjectId,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    vot_verified_range::verify_range(object_id(subject), covered_offset, data, proof)
        .map_err(map_error)
}

pub(super) fn verify_typed_bundle(
    subject: SubjectId,
    bundle: &ProofBundle,
    records: &[DataRecord],
) -> Result<vot_verified_range::VerifiedRange, Error> {
    vot_verified_range::verify_typed_bundle(object_id(subject), bundle, records).map_err(map_error)
}

pub(super) fn suite(id: u16) -> Result<Suite, Error> {
    Suite::try_from(id).map_err(|_| Error::UnknownObject)
}

pub(super) const fn subject_id(object: ObjectId) -> SubjectId {
    SubjectId {
        suite: object.suite,
        root: object.root,
        length: object.length,
    }
}

const fn object_id(subject: SubjectId) -> ObjectId {
    ObjectId {
        suite: subject.suite,
        root: subject.root,
        length: subject.length,
    }
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
