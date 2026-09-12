use super::{
    Error, GROUP_SIZE, Mode, Node, RangeCover, RangeGeometry, group_count, group_cvs_at,
    merge_subtrees_non_root, merge_subtrees_root,
};
use vot_proof_store::{ProofSubtree, ProofTree};

/// Shared immutable proof material for an object larger than one group.
/// Cached values describe content; they do not establish source ownership.
#[derive(Clone)]
pub struct ProofCheckpoint {
    tree: ProofTree,
    length: u64,
}

impl ProofCheckpoint {
    /// Builds a checkpoint from positioned, non-root group chaining values.
    pub fn new(length: u64, leaves: &[[u8; 32]]) -> Result<Self, Error> {
        let count = usize::try_from(group_count(length)).map_err(|_| Error::OutOfBounds)?;
        if count < 2 || count != leaves.len() {
            return Err(Error::OutOfBounds);
        }
        Ok(Self {
            tree: ProofTree::new(leaves, |left, right| {
                merge_subtrees_non_root(left, right, Mode::Hash)
            }),
            length,
        })
    }

    /// Replaces positioned group values and changes the represented length.
    /// The caller must refresh any partial group whose length changes.
    pub fn updated(&self, length: u64, first: usize, leaves: &[[u8; 32]]) -> Result<Self, Error> {
        let count = usize::try_from(group_count(length)).map_err(|_| Error::OutOfBounds)?;
        if count < 2 {
            return Err(Error::OutOfBounds);
        }
        Ok(Self {
            tree: self
                .tree
                .updated(first, leaves, count)
                .ok_or(Error::OutOfBounds)?,
            length,
        })
    }

    /// Canonical root, applying root mode only at the final merge.
    ///
    /// # Panics
    /// Panics only if private tree invariants are violated.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let (left, right) = self.tree.root().unwrap().children().unwrap();
        *merge_subtrees_root(&left.hash(), &right.hash(), Mode::Hash).as_bytes()
    }

    /// Canonical range proof without rebuilding unchanged subtrees.
    ///
    /// # Panics
    /// Panics only if private tree invariants are violated.
    pub fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        let RangeGeometry {
            covered_offset,
            covered_end,
            first,
            end,
        } = RangeGeometry::of(self.length, offset, length)?;
        let mut proof = Vec::new();
        encode(self.tree.root().unwrap(), 0, first, end, &mut proof);
        Ok(RangeCover {
            covered_offset,
            covered_length: covered_end - covered_offset,
            proof,
        })
    }

    /// Whether the supplied positioned group matches its retained value.
    #[must_use]
    pub fn holds(&self, index: usize, bytes: &[u8]) -> bool {
        let Some(expected) = self.tree.subtree(index, 1) else {
            return false;
        };
        group_cvs_at(index as u64 * GROUP_SIZE, bytes, self.length)
            .is_ok_and(|leaves| leaves.as_slice() == [expected])
    }
}

fn encode(tree: ProofSubtree<'_>, start: u64, first: u64, end: u64, output: &mut Vec<u8>) {
    let node = Node {
        start,
        count: tree.leaf_count() as u64,
    };
    if !node.intersects(first, end) {
        return;
    }
    if let Some((left, right)) = tree.children() {
        output.extend_from_slice(&left.hash());
        output.extend_from_slice(&right.hash());
        encode(left, start, first, end, output);
        encode(right, start + left.leaf_count() as u64, first, end, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_match_fresh_proofs_and_reject_invalid_shapes() {
        let group = GROUP_SIZE as usize;
        let mut bytes = vec![17; 3 * group + 1];
        let leaves = group_cvs_at(0, &bytes, bytes.len() as u64).unwrap();
        assert!(ProofCheckpoint::new(0, &[]).is_err());
        assert!(ProofCheckpoint::new(bytes.len() as u64, &leaves[..1]).is_err());
        let mut checkpoint = ProofCheckpoint::new(bytes.len() as u64, &leaves).unwrap();
        assert!(checkpoint.updated(1, 0, &[]).is_err());
        assert!(
            checkpoint
                .updated(
                    bytes.len() as u64 + 2 * GROUP_SIZE,
                    leaves.len() + 1,
                    &[[0; 32]]
                )
                .is_err()
        );
        assert!(!checkpoint.holds(usize::MAX, &[0]));
        assert!(!checkpoint.holds(0, &[]));
        assert!(!checkpoint.holds(0, &[0]));
        assert!(!checkpoint.holds(0, &vec![0; group]));
        for length in [
            5 * group + 3,
            8 * group,
            8 * group + 1,
            9 * group + 17,
            2 * group,
            2 * group + 1,
        ] {
            let old = checkpoint.clone();
            let old_bytes = bytes.clone();
            let offset = bytes.len().min(length) / group * group;
            bytes.resize(length, 93);
            let changed = if offset == length {
                Vec::new()
            } else {
                group_cvs_at(offset as u64, &bytes[offset..], length as u64).unwrap()
            };
            checkpoint = checkpoint
                .updated(length as u64, offset / group, &changed)
                .unwrap();
            bytes[group] ^= 0x49;
            let changed =
                group_cvs_at(group as u64, &bytes[group..2 * group], length as u64).unwrap();
            checkpoint = checkpoint.updated(length as u64, 1, &changed).unwrap();
            for (snapshot, data) in [(&old, &old_bytes), (&checkpoint, &bytes)] {
                assert_eq!(snapshot.root(), super::super::root(data));
                assert!(snapshot.prove(0, 0).is_err());
                assert!(snapshot.prove(data.len() as u64, 1).is_err());
                for (index, piece) in data.chunks(group).enumerate() {
                    assert!(snapshot.holds(index, piece));
                    for length in [1, (data.len() - index * group) as u64] {
                        let actual = snapshot.prove((index * group) as u64, length).unwrap();
                        let fresh =
                            super::super::prove(data, (index * group) as u64, length).unwrap();
                        assert_eq!(actual.covered_offset, fresh.covered_offset);
                        assert_eq!(actual.covered_length, fresh.data.len() as u64);
                        assert_eq!(actual.proof, fresh.proof);
                    }
                }
            }
        }
    }
}
