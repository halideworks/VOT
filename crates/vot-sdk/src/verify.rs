//! Borrowed witnesses for authenticated range bytes.

use crate::Error;
use crate::error;
use crate::object::ObjectId;

/// Borrowed bytes authenticated against one exact object identity.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedSlice<'data> {
    inner: vot_verified_range::VerifiedSlice<'data>,
}

impl<'data> From<vot_verified_range::VerifiedSlice<'data>> for VerifiedSlice<'data> {
    fn from(inner: vot_verified_range::VerifiedSlice<'data>) -> Self {
        Self { inner }
    }
}

impl VerifiedSlice<'_> {
    /// Copies authenticated bytes and computes cached commitments for later
    /// checkpoint verification.
    #[must_use]
    pub fn retain(self) -> RetainedRange {
        RetainedRange {
            inner: self.inner.retain(),
        }
    }

    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        let object = self.inner.object();
        ObjectId {
            suite: object.suite,
            root: object.root,
            length: object.length,
        }
    }

    #[must_use]
    pub const fn covered_offset(&self) -> u64 {
        self.inner.covered_offset()
    }

    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.inner.data()
    }
}

/// Immutable retained bytes whose groups can authenticate to later checkpoints.
/// Witnesses borrow these bytes. This type does not establish disk durability.
#[derive(Debug)]
pub struct RetainedRange {
    inner: vot_verified_range::RetainedRange,
}

impl From<vot_verified_range::RetainedRange> for RetainedRange {
    fn from(inner: vot_verified_range::RetainedRange) -> Self {
        Self { inner }
    }
}

impl RetainedRange {
    #[must_use]
    pub fn as_slice(&self) -> VerifiedSlice<'_> {
        self.inner.as_slice().into()
    }

    /// Verifies an aligned retained subrange against `object` in the same suite.
    /// A cached group cannot be shortened; a changed tail needs fresh bytes.
    pub fn verify_for(
        &self,
        object: &ObjectId,
        covered_offset: u64,
        covered_length: u64,
        proof: &[u8],
    ) -> Result<VerifiedSlice<'_>, Error> {
        let object = vot_codec::frames::ObjectId {
            suite: object.suite,
            root: object.root,
            length: object.length,
        };
        self.inner
            .verify_for(object, covered_offset, covered_length, proof)
            .map(VerifiedSlice::from)
            .map_err(error::verify)
    }
}

pub fn verify_range<'data>(
    object: &ObjectId,
    covered_offset: u64,
    data: &'data [u8],
    proof: &[u8],
) -> Result<VerifiedSlice<'data>, Error> {
    let object = vot_codec::frames::ObjectId {
        suite: object.suite,
        root: object.root,
        length: object.length,
    };
    vot_verified_range::verify_range(object, covered_offset, data, proof)
        .map(|inner| VerifiedSlice { inner })
        .map_err(error::verify)
}

pub(crate) const fn from_inner(inner: vot_verified_range::VerifiedSlice<'_>) -> VerifiedSlice<'_> {
    VerifiedSlice { inner }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{InMemoryObjectBuilder, Suite};

    #[test]
    fn a_new_checkpoint_reuses_verified_groups_and_receives_only_the_changed_group() {
        use crate::ErrorCode;
        use crate::coverage::{CoverageUpdate, ObjectCoverage};
        use vot_object::ObjectCheckpoint;

        const GROUP: usize = 65_536;
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut bytes = vec![7; 3 * GROUP + 17];
            let length = bytes.len() as u64;
            let checkpoint = ObjectCheckpoint::new(suite)
                .unwrap()
                .updated(0, &bytes, length)
                .unwrap();
            let prepared = checkpoint.prepared();
            let original_proof = prepared.prove(0, length).unwrap();
            let retained = verify_range(checkpoint.object_id(), 0, &bytes, original_proof.proof())
                .unwrap()
                .retain();
            let original_bytes = retained.as_slice().data().to_vec();

            bytes[GROUP] = 9;
            let next = checkpoint
                .updated(GROUP as u64, &bytes[GROUP..2 * GROUP], length)
                .unwrap();
            let target = next.prepared();
            let mut coverage = ObjectCoverage::new(next.object_id());
            assert_eq!(
                coverage.accept(&retained.as_slice()).unwrap_err().code(),
                ErrorCode::IdentityMismatch
            );
            let mut transferred = 0;
            let mut reused = 0;
            let mut assembled = Vec::new();
            for offset in (0..bytes.len()).step_by(GROUP) {
                let proof = target.prove(offset as u64, 1).unwrap();
                let length = proof.covered_length();
                let verified = if offset == GROUP {
                    assert!(
                        retained
                            .verify_for(next.object_id(), offset as u64, length, proof.proof())
                            .is_err()
                    );
                    transferred += length;
                    verify_range(
                        next.object_id(),
                        offset as u64,
                        &bytes[offset..offset + GROUP],
                        proof.proof(),
                    )
                    .unwrap()
                } else {
                    reused += length;
                    retained
                        .verify_for(next.object_id(), offset as u64, length, proof.proof())
                        .unwrap()
                };
                assembled.extend_from_slice(verified.data());
                assert_eq!(
                    coverage.accept(&verified).unwrap(),
                    CoverageUpdate::Accepted
                );
                assert_eq!(coverage.accept(&verified).unwrap(), CoverageUpdate::Replay);
            }
            assert!(coverage.is_complete());
            assert_eq!(coverage.covered_bytes(), length);
            assert_eq!(transferred, GROUP as u64);
            assert_eq!(reused, length - GROUP as u64);
            assert_eq!(assembled, bytes);
            assert_eq!(retained.as_slice().data(), original_bytes);
            let mut builder = InMemoryObjectBuilder::new(suite, Some(length), length).unwrap();
            builder.update(&assembled).unwrap();
            assert_eq!(builder.finish().unwrap().object_id(), next.object_id());
        }
    }

    #[test]
    fn retained_transport_conversion_preserves_bytes_and_borrowed_subrange() {
        let bytes = vec![42; 131_072];
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut builder = InMemoryObjectBuilder::new(suite, Some(131_072), 131_072).unwrap();
            builder.update(&bytes).unwrap();
            let object = builder.finish().unwrap();
            let proof = object.prove(65_536, 65_536).unwrap();
            let id = object.object_id();
            let raw = vot_verified_range::verify_range(
                vot_codec::frames::ObjectId {
                    suite: id.suite,
                    root: id.root,
                    length: id.length,
                },
                65_536,
                &bytes[65_536..],
                proof.proof(),
            )
            .unwrap()
            .retain();
            let pointer = raw.as_slice().data().as_ptr();
            let retained = RetainedRange::from(raw);
            assert_eq!(retained.as_slice().data().as_ptr(), pointer);
            let checked = retained
                .verify_for(id, 65_536, 65_536, proof.proof())
                .unwrap();
            assert_eq!(checked.object_id(), *id);
            assert_eq!(checked.covered_offset(), 65_536);
            assert_eq!(checked.data().as_ptr(), pointer);
        }
    }

    #[test]
    fn transport_witness_conversion_preserves_identity_offset_and_borrow() {
        let bytes = vec![42; 131_072];
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut builder = InMemoryObjectBuilder::new(suite, Some(131_072), 131_072).unwrap();
            builder.update(&bytes).unwrap();
            let object = builder.finish().unwrap();
            let proof = object.prove(65_536, 65_536).unwrap();
            let id = object.object_id();
            let inner = vot_verified_range::verify_range(
                vot_codec::frames::ObjectId {
                    suite: id.suite,
                    root: id.root,
                    length: id.length,
                },
                65_536,
                &bytes[65_536..],
                proof.proof(),
            )
            .unwrap();
            let converted = VerifiedSlice::from(inner);
            assert_eq!(converted.object_id(), *id);
            assert_eq!(converted.covered_offset(), 65_536);
            assert!(std::ptr::eq(converted.data(), inner.data()));
        }
    }
}
