use super::{Error, RANGE_UNIT_BYTES, Suite, VerifiedRange, VerifiedSlice, check_range_geometry};
use vot_codec::frames::ObjectId;
use vot_verifier::GROUP_SIZE;

/// Owned immutable range bytes with cached verification-group commitments.
///
/// Constructed only by retaining a verified range or slice. Returned witnesses
/// borrow these bytes; neither the bytes nor their commitments can be replaced.
/// This retains RAM, not a file or a durable receiver checkpoint.
///
/// ```compile_fail
/// fn overwrite(range: &mut vot_verified_range::RetainedRange) {
///     range.as_slice().data()[0] = 0;
/// }
/// ```
///
/// ```compile_fail
/// fn detach(range: vot_verified_range::RetainedRange) -> vot_verified_range::VerifiedSlice<'static> {
///     range.as_slice()
/// }
/// ```
#[derive(Debug)]
pub struct RetainedRange {
    range: VerifiedRange,
    commitments: Vec<[u8; 32]>,
    small_root: Option<[u8; 32]>,
}

impl RetainedRange {
    pub(super) fn new(range: VerifiedRange) -> Self {
        let suite =
            Suite::try_from(range.object.suite).expect("a verified range has a known suite");
        let commitments = match suite {
            Suite::Blake3Bao64 => vot_proof_blake3::group_cvs_at(
                range.covered_offset,
                &range.data,
                range.object.length,
            )
            .expect("a verified range has valid group geometry"),
            Suite::Sha256Bep52 => vot_proof_sha256::piece_hashes_at(
                range.covered_offset,
                &range.data,
                range.object.length,
            )
            .expect("a verified range has valid piece geometry"),
        };
        let small_root = (range.covered_offset == 0).then(|| {
            let first = &range.data[..range.data.len().min(GROUP_SIZE)];
            match suite {
                Suite::Blake3Bao64 => vot_proof_blake3::root(first),
                Suite::Sha256Bep52 => vot_proof_sha256::root(first),
            }
        });
        Self {
            range,
            commitments,
            small_root,
        }
    }

    /// Borrows all retained bytes under their original authenticated identity.
    #[must_use]
    pub fn as_slice(&self) -> VerifiedSlice<'_> {
        self.range.as_slice()
    }

    /// Authenticates retained groups against another identity in the same suite.
    ///
    /// The cover must be wholly retained, start at a group boundary, and end at
    /// a group boundary or the retained range's original end. Only the target's
    /// last group may be short. Proofs authenticate cached commitments without
    /// reading or hashing payload bytes again. The result borrows the exact
    /// retained bytes and can enter ordinary identity-bound coverage.
    ///
    /// # Errors
    /// Rejects invalid target identities, a different suite, invalid geometry,
    /// unretained bytes, shortened cached groups, and invalid or trailing proof
    /// material. Failure leaves the retained range unchanged.
    pub fn verify_for(
        &self,
        object: ObjectId,
        covered_offset: u64,
        covered_length: u64,
        proof: &[u8],
    ) -> Result<VerifiedSlice<'_>, Error> {
        object.validate().map_err(|_| Error::ProofInvalid)?;
        if object.suite != self.range.object.suite {
            return Err(Error::ProofInvalid);
        }
        let covered_end = check_range_geometry(object.length, covered_offset, covered_length)?;
        let relative = covered_offset
            .checked_sub(self.range.covered_offset)
            .ok_or(Error::LengthExceeded)?;
        let relative = usize::try_from(relative).map_err(|_| Error::LengthExceeded)?;
        let relative_end = usize::try_from(covered_end - self.range.covered_offset)
            .map_err(|_| Error::LengthExceeded)?;
        let data = self
            .range
            .data
            .get(relative..relative_end)
            .ok_or(Error::LengthExceeded)?;
        if relative_end != self.range.data.len() && !relative_end.is_multiple_of(GROUP_SIZE) {
            return Err(Error::LengthExceeded);
        }
        if object.length <= RANGE_UNIT_BYTES {
            if !proof.is_empty() || self.small_root != Some(object.root) {
                return Err(Error::ProofInvalid);
            }
        } else {
            let first = relative / GROUP_SIZE;
            let end = relative_end.div_ceil(GROUP_SIZE);
            let hashes = &self.commitments[first..end];
            match object.suite {
                1 => vot_proof_blake3::verify_group_cvs(
                    &object.root,
                    object.length,
                    covered_offset,
                    covered_length,
                    hashes,
                    proof,
                )
                .map_err(|_| Error::ProofInvalid)?,
                _ => vot_proof_sha256::verify_piece_hashes(
                    &object.root,
                    object.length,
                    covered_offset,
                    covered_length,
                    hashes,
                    proof,
                )
                .map_err(|_| Error::ProofInvalid)?,
            }
        }
        Ok(VerifiedSlice {
            object,
            covered_offset,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_range;

    fn fixture(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    fn identity(suite: Suite, bytes: &[u8]) -> ObjectId {
        ObjectId {
            suite: suite.identifier(),
            root: vot_verifier::root(suite, bytes).unwrap(),
            length: bytes.len() as u64,
        }
    }

    fn proof(suite: Suite, bytes: &[u8], offset: u64, length: u64) -> Vec<u8> {
        match suite {
            Suite::Blake3Bao64 => {
                vot_proof_blake3::prove(bytes, offset, length)
                    .unwrap()
                    .proof
            }
            Suite::Sha256Bep52 => {
                vot_proof_sha256::prove(bytes, offset, length)
                    .unwrap()
                    .proof
            }
        }
    }

    #[test]
    fn retained_subranges_match_byte_verification_across_tree_and_tail_boundaries() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [
                1,
                16_384,
                16_385,
                GROUP_SIZE,
                GROUP_SIZE + 1,
                5 * GROUP_SIZE + 17,
            ] {
                let bytes = fixture(length);
                let object = identity(suite, &bytes);
                let retained =
                    verify_range(object, 0, &bytes, &proof(suite, &bytes, 0, length as u64))
                        .unwrap()
                        .retain();
                for start in (0..length).step_by(GROUP_SIZE) {
                    for end in ((start + GROUP_SIZE)..(length + GROUP_SIZE)).step_by(GROUP_SIZE) {
                        let end = end.min(length);
                        let offset = start as u64;
                        let count = (end - start) as u64;
                        let material = proof(suite, &bytes, offset, count);
                        let checked = retained
                            .verify_for(object, offset, count, &material)
                            .unwrap();
                        verify_range(object, offset, &bytes[start..end], &material).unwrap();
                        assert_eq!(checked.object(), object);
                        assert_eq!(checked.covered_offset(), offset);
                        assert_eq!(checked.data(), &bytes[start..end]);
                        assert!(std::ptr::eq(
                            checked.data(),
                            &raw const retained.as_slice().data()[start..end]
                        ));
                        let mut trailing = material.clone();
                        trailing.push(0);
                        assert_eq!(
                            retained
                                .verify_for(object, offset, count, &trailing)
                                .unwrap_err(),
                            Error::ProofInvalid
                        );
                        if !material.is_empty() {
                            assert!(
                                retained
                                    .verify_for(
                                        object,
                                        offset,
                                        count,
                                        &material[..material.len() - 1]
                                    )
                                    .is_err()
                            );
                            let mut changed = material;
                            changed[0] ^= 1;
                            assert!(
                                retained
                                    .verify_for(object, offset, count, &changed)
                                    .is_err()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn changed_groups_do_not_prevent_reuse_of_unchanged_subranges() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut bytes = fixture(3 * GROUP_SIZE + 17);
            let before = identity(suite, &bytes);
            let old_proof = proof(suite, &bytes, 0, bytes.len() as u64);
            let retained = verify_range(before, 0, &bytes, &old_proof)
                .unwrap()
                .retain();
            bytes[GROUP_SIZE] ^= 1;
            let after = identity(suite, &bytes);
            let fresh = proof(suite, &bytes, 0, bytes.len() as u64);
            assert!(retained.verify_for(after, 0, after.length, &fresh).is_err());
            assert!(
                retained
                    .verify_for(after, 0, after.length, &old_proof)
                    .is_err()
            );
            for (offset, length) in [
                (0, RANGE_UNIT_BYTES),
                (2 * RANGE_UNIT_BYTES, RANGE_UNIT_BYTES + 17),
            ] {
                let checked = retained
                    .verify_for(after, offset, length, &proof(suite, &bytes, offset, length))
                    .unwrap();
                assert_eq!(checked.object(), after);
                assert_eq!(checked.covered_offset(), offset);
            }
            assert_eq!(retained.as_slice().object(), before);
            assert_ne!(retained.as_slice().data()[GROUP_SIZE], bytes[GROUP_SIZE]);
            retained
                .verify_for(before, 0, before.length, &old_proof)
                .unwrap();
        }
    }

    #[test]
    fn small_roots_and_group_commitments_are_kept_distinct_on_growth_and_truncation() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [1, 16_384, 16_385, GROUP_SIZE] {
                let bytes = fixture(length);
                let small = identity(suite, &bytes);
                let retained = verify_range(small, 0, &bytes, &[]).unwrap().retain();
                retained.verify_for(small, 0, small.length, &[]).unwrap();
                let mut larger = bytes.clone();
                larger.resize(2 * GROUP_SIZE + 1, 5);
                let object = identity(suite, &larger);
                let material = proof(suite, &larger, 0, RANGE_UNIT_BYTES);
                assert_eq!(
                    retained
                        .verify_for(object, 0, RANGE_UNIT_BYTES, &material)
                        .is_ok(),
                    length == GROUP_SIZE
                );
                let full =
                    verify_range(object, 0, &larger, &proof(suite, &larger, 0, object.length))
                        .unwrap()
                        .retain();
                let first = identity(suite, &larger[..GROUP_SIZE]);
                full.verify_for(first, 0, first.length, &[]).unwrap();
                let mut wrong = first;
                wrong.root[0] ^= 1;
                assert!(full.verify_for(wrong, 0, wrong.length, &[]).is_err());
                for short in [1, 16_384, GROUP_SIZE - 1] {
                    let actual = identity(suite, &larger[..short]);
                    assert!(full.verify_for(actual, 0, actual.length, &[]).is_err());
                    let forged = ObjectId {
                        length: short as u64,
                        ..first
                    };
                    assert!(full.verify_for(forged, 0, forged.length, &[]).is_err());
                }
                if length > 1 {
                    let forged = ObjectId {
                        length: small.length - 1,
                        ..small
                    };
                    assert!(retained.verify_for(forged, 0, forged.length, &[]).is_err());
                }
            }
        }
    }

    #[test]
    fn nonzero_retention_binds_suite_offset_length_and_original_tail() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let bytes = fixture(3 * GROUP_SIZE + 17);
            let object = identity(suite, &bytes);
            let offset = RANGE_UNIT_BYTES;
            let count = object.length - offset;
            let material = proof(suite, &bytes, offset, count);
            let retained = verify_range(object, offset, &bytes[GROUP_SIZE..], &material)
                .unwrap()
                .retain();
            assert_eq!(retained.small_root, None);
            retained
                .verify_for(object, offset, count, &material)
                .unwrap();
            for (offset, count) in [
                (0, RANGE_UNIT_BYTES),
                (RANGE_UNIT_BYTES + 1, RANGE_UNIT_BYTES),
                (RANGE_UNIT_BYTES, 0),
                (RANGE_UNIT_BYTES, count + 1),
                (RANGE_UNIT_BYTES, count - 1),
                (3 * RANGE_UNIT_BYTES, 16),
                (4 * RANGE_UNIT_BYTES, RANGE_UNIT_BYTES),
            ] {
                assert!(
                    retained
                        .verify_for(object, offset, count, &material)
                        .is_err()
                );
            }
            for length in [object.length - 1, object.length + 1] {
                let forged = ObjectId { length, ..object };
                assert!(
                    retained
                        .verify_for(forged, offset, count, &material)
                        .is_err()
                );
                assert!(
                    retained
                        .verify_for(forged, offset, length - offset, &material)
                        .is_err()
                );
            }
            for suite_id in [0, 1, 2, u16::MAX] {
                if suite_id == object.suite {
                    continue;
                }
                let other = ObjectId {
                    suite: suite_id,
                    ..object
                };
                assert_eq!(
                    retained
                        .verify_for(other, offset, count, &material)
                        .unwrap_err(),
                    Error::ProofInvalid
                );
            }
            let huge = ObjectId {
                length: u64::MAX,
                ..object
            };
            assert_eq!(
                retained
                    .verify_for(huge, offset, count, &material)
                    .unwrap_err(),
                Error::ProofInvalid
            );
            let zero = ObjectId {
                length: 0,
                ..object
            };
            assert!(retained.verify_for(zero, 0, 0, &[]).is_err());
        }
    }
}
