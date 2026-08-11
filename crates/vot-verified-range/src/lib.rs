//! Pure validation and verification of proof-bearing object ranges.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use vot_codec::frames::{DataRecord, ObjectId, ProofBundle};
use vot_verifier::Suite;

/// Range granularity covered by both frozen proof suites.
pub const RANGE_UNIT_BYTES: u64 = 65_536;
/// Maximum bytes carried by one proof-bearing range.
pub const MAX_PROOF_RANGE_BYTES: u64 = 4_259_840;

/// A pure bundle or range verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownSuite,
    RecordTooLarge,
    LengthExceeded,
    LengthMismatch,
    ProofInvalid,
    UnsupportedCompression,
}

/// Bundle metadata and records whose individual encodings and relationship
/// have been checked, but whose bytes have not yet been assembled or proved.
#[derive(Debug)]
pub struct ValidatedBundle<'records> {
    bundle: &'records ProofBundle,
    ordered: BTreeMap<u64, &'records DataRecord>,
}

impl ValidatedBundle<'_> {
    /// Bytes the bundle declares it will assemble.
    #[must_use]
    pub const fn covered_length(&self) -> u64 {
        self.bundle.covered_length
    }

    /// Reassembles records in index order and checks their plaintext offsets.
    ///
    /// # Errors
    /// Returns [`Error::LengthMismatch`] for a missing record, a discontinuous
    /// plaintext offset, or an assembled length different from the bundle.
    /// Returns [`Error::LengthExceeded`] on arithmetic or platform conversion
    /// overflow.
    pub fn assemble(self) -> Result<Vec<u8>, Error> {
        assemble_ordered(self.bundle, &self.ordered)
    }
}

/// An owned range whose bytes have been authenticated against its object root.
///
/// Its fields are private and only [`verify_typed_bundle`] constructs it.
#[derive(Debug)]
pub struct VerifiedRange {
    object: ObjectId,
    covered_offset: u64,
    data: Vec<u8>,
}

impl VerifiedRange {
    /// Object identity that authenticated the range.
    #[must_use]
    pub const fn object(&self) -> ObjectId {
        self.object
    }

    /// Object-relative byte offset of the range.
    #[must_use]
    pub const fn covered_offset(&self) -> u64 {
        self.covered_offset
    }

    /// Authenticated bytes carried by the range.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Checks a bundle's identity and records without assembling their bytes.
///
/// This split lets a caller reserve the declared covered length before the
/// allocation performed by [`ValidatedBundle::assemble`].
///
/// # Errors
/// Rejects malformed bundle or record fields, identity and count conflicts,
/// mismatched bundle identifiers, compression, and duplicate record indices.
pub fn validate_typed_bundle<'records>(
    object: ObjectId,
    bundle: &'records ProofBundle,
    records: &'records [DataRecord],
) -> Result<ValidatedBundle<'records>, Error> {
    bundle.validate().map_err(|_| Error::ProofInvalid)?;
    if bundle.object.suite != object.suite
        || bundle.object.root != object.root
        || bundle.object.length != object.length
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
    Ok(ValidatedBundle { bundle, ordered })
}

/// Validates, reassembles, and authenticates a typed proof bundle.
///
/// # Errors
/// Returns the same validation, assembly, bounds, suite, and proof failures as
/// [`validate_typed_bundle`], [`ValidatedBundle::assemble`], and
/// [`verify_range`].
pub fn verify_typed_bundle(
    object: ObjectId,
    bundle: &ProofBundle,
    records: &[DataRecord],
) -> Result<VerifiedRange, Error> {
    let data = validate_typed_bundle(object, bundle, records)?.assemble()?;
    verify_range(object, bundle.covered_offset, &data, &bundle.proof)?;
    Ok(VerifiedRange {
        object,
        covered_offset: bundle.covered_offset,
        data,
    })
}

/// Authenticates borrowed range bytes without copying or retaining them.
///
/// # Errors
/// Rejects an empty or oversized range, arithmetic overflow, a range outside
/// the object, non-final partial units, unknown suites, and invalid proofs.
pub fn verify_range(
    object: ObjectId,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    let bytes = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
    check_range_geometry(object.length, covered_offset, bytes)?;
    match Suite::try_from(object.suite).map_err(|_| Error::UnknownSuite)? {
        Suite::Blake3Bao64 => {
            vot_proof_blake3::verify(&object.root, object.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
        Suite::Sha256Bep52 => {
            vot_proof_sha256::verify(&object.root, object.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
    }
    Ok(())
}

fn assemble_ordered(
    bundle: &ProofBundle,
    ordered: &BTreeMap<u64, &DataRecord>,
) -> Result<Vec<u8>, Error> {
    let capacity = usize::try_from(bundle.covered_length).map_err(|_| Error::LengthExceeded)?;
    let mut data = Vec::with_capacity(capacity);
    for index in 0..bundle.data_record_count {
        let record = ordered.get(&index).ok_or(Error::LengthMismatch)?;
        let assembled = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
        let expected_offset = checked_offset(bundle.covered_offset, assembled)?;
        if record.plaintext_offset != expected_offset {
            return Err(Error::LengthMismatch);
        }
        data.extend_from_slice(&record.encoded);
    }
    if data.len() as u64 != bundle.covered_length {
        return Err(Error::LengthMismatch);
    }
    Ok(data)
}

fn checked_offset(covered_offset: u64, assembled: u64) -> Result<u64, Error> {
    covered_offset
        .checked_add(assembled)
        .ok_or(Error::LengthExceeded)
}

fn check_range_geometry(object_length: u64, covered_offset: u64, bytes: u64) -> Result<u64, Error> {
    if bytes == 0 || bytes > MAX_PROOF_RANGE_BYTES {
        return Err(Error::RecordTooLarge);
    }
    let covered_end = checked_offset(covered_offset, bytes)?;
    if covered_offset % RANGE_UNIT_BYTES != 0 || covered_end > object_length {
        return Err(Error::LengthExceeded);
    }
    if covered_end < object_length && bytes % RANGE_UNIT_BYTES != 0 {
        return Err(Error::LengthExceeded);
    }
    Ok(covered_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        bytes: Vec<u8>,
        object: ObjectId,
        bundle: ProofBundle,
        records: Vec<DataRecord>,
    }

    fn make_fixture(suite: Suite) -> Fixture {
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let (root, proof) = match suite {
            Suite::Blake3Bao64 => {
                let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
                (vot_proof_blake3::root(&bytes), proof.proof)
            }
            Suite::Sha256Bep52 => {
                let proof = vot_proof_sha256::prove(&bytes, 0, bytes.len() as u64).unwrap();
                (vot_proof_sha256::root(&bytes), proof.proof)
            }
        };
        let object = ObjectId {
            suite: suite.identifier(),
            root,
            length: bytes.len() as u64,
        };
        let bundle = ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object,
            requested_offset: 0,
            requested_length: object.length,
            covered_offset: 0,
            covered_length: object.length,
            data_record_count: 2,
            total_plaintext_length: object.length,
            proof,
        };
        let records = vec![
            DataRecord {
                bundle_id: bundle.bundle_id,
                record_index: 1,
                plaintext_offset: RANGE_UNIT_BYTES,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[usize::try_from(RANGE_UNIT_BYTES).unwrap()..].to_vec(),
            },
            DataRecord {
                bundle_id: bundle.bundle_id,
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[..usize::try_from(RANGE_UNIT_BYTES).unwrap()].to_vec(),
            },
        ];
        Fixture {
            bytes,
            object,
            bundle,
            records,
        }
    }

    #[test]
    fn typed_bundle_builds_an_opaque_verified_range() {
        let fixture = make_fixture(Suite::Blake3Bao64);
        let validated =
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap();
        assert_eq!(validated.covered_length(), fixture.object.length);
        assert_eq!(validated.assemble().unwrap(), fixture.bytes);

        let range = verify_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap();
        assert_eq!(range.object(), fixture.object);
        assert_eq!(range.covered_offset(), 0);
        assert_eq!(range.data(), fixture.bytes);
        assert_eq!(range.data().len() as u64, fixture.object.length);
    }

    #[test]
    fn verified_range_reports_a_nonzero_covered_offset() {
        let fixture = make_fixture(Suite::Blake3Bao64);
        let range = VerifiedRange {
            object: fixture.object,
            covered_offset: RANGE_UNIT_BYTES,
            data: vec![0x5a; 3],
        };
        assert_eq!(range.covered_offset(), RANGE_UNIT_BYTES);
    }

    #[test]
    fn both_frozen_suites_verify_borrowed_ranges() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let fixture = make_fixture(suite);
            assert_eq!(
                verify_range(
                    fixture.object,
                    fixture.bundle.covered_offset,
                    &fixture.bytes,
                    &fixture.bundle.proof,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn every_bundle_identity_field_and_record_count_must_match() {
        for change in 0..4 {
            let fixture = make_fixture(Suite::Blake3Bao64);
            let mut object = fixture.object;
            let mut records = fixture.records.clone();
            match change {
                0 => object.suite = 2,
                1 => object.root[0] ^= 1,
                2 => object.length += 1,
                3 => {
                    records.pop();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate_typed_bundle(object, &fixture.bundle, &records).unwrap_err(),
                Error::LengthMismatch
            );
        }
    }

    #[test]
    fn malformed_bundle_and_record_fields_are_proof_invalid() {
        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.bundle.requested_length = 0;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap_err(),
            Error::ProofInvalid
        );

        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].plaintext_length = 0;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap_err(),
            Error::ProofInvalid
        );
    }

    #[test]
    fn bundle_id_compression_and_duplicate_indices_keep_their_errors() {
        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].bundle_id[0] ^= 1;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap_err(),
            Error::ProofInvalid
        );

        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].compression = 1;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap_err(),
            Error::UnsupportedCompression
        );

        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].record_index = fixture.records[1].record_index;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records).unwrap_err(),
            Error::LengthMismatch
        );
    }

    #[test]
    fn assembly_rejects_missing_discontinuous_and_short_records() {
        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].record_index = 2;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records)
                .unwrap()
                .assemble()
                .unwrap_err(),
            Error::LengthMismatch
        );

        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].plaintext_offset += 1;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records)
                .unwrap()
                .assemble()
                .unwrap_err(),
            Error::LengthMismatch
        );

        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.records[0].encoded.pop();
        fixture.records[0].plaintext_length -= 1;
        assert_eq!(
            validate_typed_bundle(fixture.object, &fixture.bundle, &fixture.records)
                .unwrap()
                .assemble()
                .unwrap_err(),
            Error::LengthMismatch
        );
    }

    #[test]
    fn range_geometry_preserves_each_error_class() {
        assert_eq!(check_range_geometry(1, 0, 0), Err(Error::RecordTooLarge));
        assert_eq!(
            check_range_geometry(u64::MAX, 0, MAX_PROOF_RANGE_BYTES + 1),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            check_range_geometry(MAX_PROOF_RANGE_BYTES, 0, MAX_PROOF_RANGE_BYTES),
            Ok(MAX_PROOF_RANGE_BYTES)
        );
        assert_eq!(
            check_range_geometry(u64::MAX, u64::MAX, 1),
            Err(Error::LengthExceeded)
        );
        assert_eq!(
            check_range_geometry(RANGE_UNIT_BYTES * 2, 1, RANGE_UNIT_BYTES),
            Err(Error::LengthExceeded)
        );
        assert_eq!(
            check_range_geometry(RANGE_UNIT_BYTES, 0, RANGE_UNIT_BYTES + 1),
            Err(Error::LengthExceeded)
        );
        assert_eq!(
            check_range_geometry(RANGE_UNIT_BYTES * 2, 0, 1),
            Err(Error::LengthExceeded)
        );
        assert_eq!(
            check_range_geometry(RANGE_UNIT_BYTES * 2, 0, RANGE_UNIT_BYTES),
            Ok(RANGE_UNIT_BYTES)
        );
        assert_eq!(check_range_geometry(1, 0, 1), Ok(1));
    }

    #[test]
    fn unknown_suite_and_bad_proofs_keep_their_errors() {
        let mut fixture = make_fixture(Suite::Blake3Bao64);
        fixture.object.suite = 9;
        assert_eq!(
            verify_range(fixture.object, 0, &fixture.bytes, &fixture.bundle.proof),
            Err(Error::UnknownSuite)
        );

        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let fixture = make_fixture(suite);
            assert_eq!(
                verify_range(fixture.object, 0, &fixture.bytes, &[0]),
                Err(Error::ProofInvalid)
            );
        }
    }

    #[test]
    fn assembled_offset_overflow_is_length_exceeded() {
        assert_eq!(checked_offset(u64::MAX, 1), Err(Error::LengthExceeded));
    }
}
