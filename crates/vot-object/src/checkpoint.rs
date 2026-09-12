use std::sync::Arc;

use super::{
    Error, GROUP_SIZE, MAX_OBJECT_LENGTH, ObjectBuilder, ObjectId, PROOF_LEAF_SIZE, PreparedObject,
    RangeCover, RetainedProof, Suite, map_blake3_error, map_sha256_error, proof_leaves_at,
};

#[derive(Clone)]
enum Proof {
    Small(Arc<PreparedObject>),
    Blake3(vot_proof_blake3::ProofCheckpoint),
    Sha256(vot_proof_sha256::ProofCheckpoint),
}

/// Incrementally prepared, immutable object identity and range-proof metadata.
///
/// Updates share unchanged subtrees with prior checkpoints. The caller must
/// own or otherwise control the source bytes and report every change. This
/// type neither retains the payload nor detects external writes, establishes
/// producer completion, or authorizes reuse of receiver coverage.
#[derive(Clone)]
pub struct ObjectCheckpoint {
    suite: Suite,
    object: ObjectId,
    proof: Proof,
}

fn validate_update(previous: u64, length: u64, offset: u64, bytes: u64) -> Result<(), Error> {
    if length > MAX_OBJECT_LENGTH {
        return Err(Error::ExpectedLengthOutOfRange);
    }
    let end = offset.checked_add(bytes).ok_or(Error::LengthOverflow)?;
    if !offset.is_multiple_of(PROOF_LEAF_SIZE)
        || end > length
        || (!bytes.is_multiple_of(PROOF_LEAF_SIZE) && end != length)
    {
        return Err(Error::InvalidRange);
    }
    if length > previous && (offset > previous / PROOF_LEAF_SIZE * PROOF_LEAF_SIZE || end != length)
    {
        return Err(Error::InvalidRange);
    }
    if length < previous && !length.is_multiple_of(PROOF_LEAF_SIZE) && end != length {
        return Err(Error::InvalidRange);
    }
    if length > PROOF_LEAF_SIZE && previous <= PROOF_LEAF_SIZE && offset != 0 {
        return Err(Error::InvalidRange);
    }
    if length <= PROOF_LEAF_SIZE && !(length == previous && bytes == 0) && bytes != length {
        return Err(Error::InvalidRange);
    }
    Ok(())
}

impl ObjectCheckpoint {
    /// Starts with the canonical empty object for the selected suite.
    ///
    /// # Errors
    /// Propagates object preparation errors.
    pub fn new(suite: Suite) -> Result<Self, Error> {
        Self::small(suite, &[])
    }

    fn small(suite: Suite, bytes: &[u8]) -> Result<Self, Error> {
        let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64))?;
        builder.update(bytes)?;
        let prepared = builder.finish()?;
        Ok(Self {
            suite,
            object: prepared.object_id().clone(),
            proof: Proof::Small(Arc::new(prepared)),
        })
    }

    /// Returns a new checkpoint after replacing complete proof groups.
    ///
    /// `offset` is group-aligned. Only the final group may be short. Growth
    /// must supply every new byte and the old partial tail group; partial
    /// truncation must supply the shortened final group. Crossing from at
    /// most one group to a larger object also requires the first group.
    /// Results of at most one group require all their bytes, except no-ops.
    /// An aligned truncation of a larger object may use an empty slice.
    ///
    /// Hashing and newly allocated metadata are bounded by supplied groups
    /// plus tree depth. Old checkpoints remain valid. Dropping checkpoints
    /// can reclaim all nodes no other checkpoint retains.
    ///
    /// # Errors
    /// Rejects unrepresentable lengths, incomplete groups, holes on growth,
    /// missing shortened tails, and ranges outside the new object. Errors
    /// leave this checkpoint unchanged.
    pub fn updated(&self, offset: u64, bytes: &[u8], length: u64) -> Result<Self, Error> {
        let byte_count = u64::try_from(bytes.len()).map_err(|_| Error::LengthOverflow)?;
        validate_update(self.object.length, length, offset, byte_count)?;
        if bytes.is_empty() && length == self.object.length {
            return Ok(self.clone());
        }
        if length <= PROOF_LEAF_SIZE {
            return Self::small(self.suite, bytes);
        }
        let leaves = if bytes.is_empty() {
            Vec::new()
        } else {
            proof_leaves_at(self.suite, offset, bytes, length)?
        };
        let first = usize::try_from(offset / PROOF_LEAF_SIZE).map_err(|_| Error::InvalidRange)?;
        let proof = match &self.proof {
            Proof::Small(_) => match self.suite {
                Suite::Blake3Bao64 => Proof::Blake3(
                    vot_proof_blake3::ProofCheckpoint::new(length, &leaves)
                        .map_err(map_blake3_error)?,
                ),
                Suite::Sha256Bep52 => Proof::Sha256(
                    vot_proof_sha256::ProofCheckpoint::new(length, &leaves)
                        .map_err(map_sha256_error)?,
                ),
            },
            Proof::Blake3(previous) => Proof::Blake3(
                previous
                    .updated(length, first, &leaves)
                    .map_err(map_blake3_error)?,
            ),
            Proof::Sha256(previous) => Proof::Sha256(
                previous
                    .updated(length, first, &leaves)
                    .map_err(map_sha256_error)?,
            ),
        };
        let root = match &proof {
            Proof::Blake3(proof) => proof.root(),
            Proof::Sha256(proof) => proof.root(),
            Proof::Small(_) => unreachable!("multi-group updates use a retained tree"),
        };
        Ok(Self {
            suite: self.suite,
            object: ObjectId {
                suite: self.suite.identifier(),
                root,
                length,
            },
            proof,
        })
    }

    /// Canonical identity of the bytes described by this checkpoint.
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object
    }

    /// Exposes this immutable snapshot through the ordinary preparation API.
    /// Shares proof metadata without flattening or copying the tree.
    #[must_use]
    pub fn prepared(&self) -> PreparedObject {
        PreparedObject {
            object: self.object.clone(),
            proof: Box::new(self.clone()),
        }
    }
}

impl RetainedProof for ObjectCheckpoint {
    fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        match &self.proof {
            Proof::Small(object) => object.prove(offset, length),
            Proof::Blake3(proof) => proof
                .prove(offset, length)
                .map(|cover| RangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(map_blake3_error),
            Proof::Sha256(proof) => proof
                .prove(offset, length)
                .map(|cover| RangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(map_sha256_error),
        }
    }

    fn holds(&self, first: usize, bytes: &[u8]) -> bool {
        match &self.proof {
            Proof::Small(object) => object.holds(0, bytes),
            Proof::Blake3(proof) => bytes
                .chunks(GROUP_SIZE)
                .enumerate()
                .all(|(index, group)| proof.holds(first + index, group)),
            Proof::Sha256(proof) => bytes
                .chunks(GROUP_SIZE)
                .enumerate()
                .all(|(index, group)| proof.holds(first + index, group)),
        }
    }

    fn tree_root(&self) -> Result<Option<[u8; 32]>, Error> {
        Ok(Some(self.object.root))
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize {
        usize::try_from(self.object.length.div_ceil(PROOF_LEAF_SIZE)).unwrap()
    }

    #[cfg(test)]
    fn proof_tree_retained(&self) -> bool {
        !matches!(self.proof, Proof::Small(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(checkpoint: &ObjectCheckpoint, bytes: &[u8]) {
        let mut builder = ObjectBuilder::new(checkpoint.suite, Some(bytes.len() as u64)).unwrap();
        builder.update(bytes).unwrap();
        let fresh = builder.finish().unwrap();
        let prepared = checkpoint.prepared();
        assert_eq!(prepared.object_id(), fresh.object_id());
        assert_eq!(
            checkpoint.tree_root().unwrap(),
            Some(fresh.object_id().root)
        );
        for offset in (0..bytes.len()).step_by(GROUP_SIZE / 2) {
            for count in [1, GROUP_SIZE + 3, bytes.len()] {
                let count = count.min(bytes.len() - offset);
                let proof = prepared.prove(offset as u64, count as u64).unwrap();
                assert_eq!(proof, fresh.prove(offset as u64, count as u64).unwrap());
                let first = usize::try_from(proof.covered_offset()).unwrap();
                let end = first + usize::try_from(proof.covered_length()).unwrap();
                assert!(prepared.holds(first as u64, &bytes[first..end]));
                match checkpoint.suite {
                    Suite::Blake3Bao64 => vot_proof_blake3::verify(
                        &checkpoint.object.root,
                        bytes.len() as u64,
                        first as u64,
                        &bytes[first..end],
                        proof.proof(),
                    )
                    .unwrap(),
                    Suite::Sha256Bep52 => vot_proof_sha256::verify(
                        &checkpoint.object.root,
                        bytes.len() as u64,
                        first as u64,
                        &bytes[first..end],
                        proof.proof(),
                    )
                    .unwrap(),
                }
            }
        }
        assert!(prepared.prove(bytes.len() as u64, 1).is_err());
        assert!(prepared.prove(0, 0).is_err());
    }

    #[test]
    fn checkpoints_preserve_canonical_roots_proofs_and_prior_snapshots() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut checkpoint = ObjectCheckpoint::new(suite).unwrap();
            let mut bytes = Vec::new();
            for length in [
                0,
                1,
                16_383,
                16_384,
                16_385,
                GROUP_SIZE,
                GROUP_SIZE + 1,
                3 * GROUP_SIZE + 17,
                8 * GROUP_SIZE,
                9 * GROUP_SIZE + 3,
                5 * GROUP_SIZE + 1,
                4 * GROUP_SIZE,
                2 * GROUP_SIZE + 1,
                GROUP_SIZE,
                17,
                0,
                2 * GROUP_SIZE + 17,
            ] {
                let previous = checkpoint.clone();
                let previous_bytes = bytes.clone();
                let offset = if bytes.len() <= GROUP_SIZE || length <= GROUP_SIZE {
                    0
                } else {
                    length.min(bytes.len()) / GROUP_SIZE * GROUP_SIZE
                };
                bytes.resize(length, 7);
                checkpoint = checkpoint
                    .updated(offset as u64, &bytes[offset..], length as u64)
                    .unwrap();
                check(&checkpoint, &bytes);
                check(&previous, &previous_bytes);
                let unchanged = checkpoint.updated(0, &[], length as u64).unwrap();
                assert_eq!(unchanged.object_id(), checkpoint.object_id());
                if length > GROUP_SIZE {
                    for index in (0..length.div_ceil(GROUP_SIZE)).rev() {
                        let start = index * GROUP_SIZE;
                        let end = (start + GROUP_SIZE).min(length);
                        bytes[start] ^= 0x5b;
                        checkpoint = checkpoint
                            .updated(start as u64, &bytes[start..end], length as u64)
                            .unwrap();
                    }
                    check(&checkpoint, &bytes);
                    check(&previous, &previous_bytes);
                    let mut wrong = bytes.clone();
                    wrong[0] ^= 1;
                    assert!(!checkpoint.prepared().holds(0, &wrong[..GROUP_SIZE]));
                }
            }
        }
    }

    #[test]
    fn update_boundaries_reject_missing_bytes_before_changing_the_checkpoint() {
        let group = PROOF_LEAF_SIZE;
        assert_eq!(
            validate_update(0, MAX_OBJECT_LENGTH, 0, MAX_OBJECT_LENGTH),
            Ok(())
        );
        assert_eq!(
            validate_update(0, MAX_OBJECT_LENGTH + 1, 0, 0),
            Err(Error::ExpectedLengthOutOfRange)
        );
        assert_eq!(validate_update(group, group, group, 0), Ok(()));
        for (previous, length, offset, bytes) in [
            (0, MAX_OBJECT_LENGTH + 1, 0, 0),
            (2 * group, 2 * group, u64::MAX, 1),
            (2 * group, 2 * group, 1, group),
            (2 * group, 2 * group, 0, 1),
            (2 * group, 2 * group, 2 * group, 1),
            (2 * group, 4 * group, 3 * group, group),
            (2 * group, 4 * group, 2 * group, group),
            (group + 1, 3 * group, 2 * group, group),
            (3 * group, group + 1, 0, group),
            (group, 2 * group, group, group),
            (3 * group, group, group, 0),
            (3 * group, group, 0, 0),
            (3 * group, 17, 0, 0),
        ] {
            assert!(
                validate_update(previous, length, offset, bytes).is_err(),
                "{previous} {length} {offset} {bytes}"
            );
        }
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let bytes = vec![9; 2 * GROUP_SIZE + 1];
            let checkpoint = ObjectCheckpoint::new(suite)
                .unwrap()
                .updated(0, &bytes, bytes.len() as u64)
                .unwrap();
            assert!(checkpoint.updated(0, &[], PROOF_LEAF_SIZE + 1).is_err());
            assert!(
                checkpoint
                    .updated(
                        3 * PROOF_LEAF_SIZE,
                        &vec![0; GROUP_SIZE],
                        4 * PROOF_LEAF_SIZE
                    )
                    .is_err()
            );
            check(&checkpoint, &bytes);
        }
    }
}
