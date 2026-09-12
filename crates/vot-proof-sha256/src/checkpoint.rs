use super::{
    Error, PIECE_SIZE, RangeCover, RangeGeometry, encode_proof_by, parent, piece_hashes_at,
    zero_piece,
};
use std::sync::OnceLock;
use vot_proof_store::{ProofSubtree, ProofTree};

/// Shared immutable proof material for an object larger than one piece.
/// Cached values describe content; they do not establish source ownership.
#[derive(Clone)]
pub struct ProofCheckpoint {
    tree: ProofTree,
    length: u64,
}

fn zero(width: usize) -> [u8; 32] {
    static ZEROS: OnceLock<[[u8; 32]; usize::BITS as usize]> = OnceLock::new();
    ZEROS.get_or_init(|| {
        let mut nodes = [[0; 32]; usize::BITS as usize];
        nodes[0] = zero_piece();
        for level in 1..nodes.len() {
            nodes[level] = parent(&nodes[level - 1], &nodes[level - 1]);
        }
        nodes
    })[width.trailing_zeros() as usize]
}

impl ProofCheckpoint {
    /// Builds a checkpoint from 64 KiB piece hashes, including padded tail pieces.
    pub fn new(length: u64, leaves: &[[u8; 32]]) -> Result<Self, Error> {
        let count = usize::try_from(length.div_ceil(PIECE_SIZE)).map_err(|_| Error::OutOfBounds)?;
        if count < 2 || count != leaves.len() {
            return Err(Error::OutOfBounds);
        }
        Ok(Self {
            tree: ProofTree::new(leaves, parent),
            length,
        })
    }

    /// Replaces piece hashes and changes the represented length.
    /// The caller must refresh any partial piece whose length changes.
    pub fn updated(&self, length: u64, first: usize, leaves: &[[u8; 32]]) -> Result<Self, Error> {
        let count = usize::try_from(length.div_ceil(PIECE_SIZE)).map_err(|_| Error::OutOfBounds)?;
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

    /// Canonical BEP 52 root with zero-hash padding at the ragged right edge.
    ///
    /// # Panics
    /// Panics only if private tree invariants are violated.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        padded(
            self.tree.root().unwrap(),
            self.tree.len().next_power_of_two(),
        )
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
        Ok(RangeCover {
            covered_offset,
            covered_length: covered_end - covered_offset,
            proof: encode_proof_by(self.tree.len(), first, end, |start, width| {
                let start = start as usize;
                let width = width as usize;
                let tree = self
                    .tree
                    .root()
                    .unwrap()
                    .subtree(start, width.min(self.tree.len() - start))
                    .unwrap();
                padded(tree, width)
            }),
        })
    }

    /// Whether the supplied piece matches its retained value.
    #[must_use]
    pub fn holds(&self, index: usize, bytes: &[u8]) -> bool {
        let Some(expected) = self.tree.subtree(index, 1) else {
            return false;
        };
        piece_hashes_at(index as u64 * PIECE_SIZE, bytes, self.length)
            .is_ok_and(|leaves| leaves.as_slice() == [expected])
    }
}

fn padded(tree: ProofSubtree<'_>, width: usize) -> [u8; 32] {
    let covered = tree.leaf_count().next_power_of_two();
    let mut hash = if tree.leaf_count().is_power_of_two() {
        tree.hash()
    } else {
        let (left, right) = tree.children().unwrap();
        parent(&left.hash(), &padded(right, covered / 2))
    };
    for level in covered.trailing_zeros()..width.trailing_zeros() {
        hash = parent(&hash, &zero(1 << level));
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_match_fresh_proofs_and_reject_invalid_shapes() {
        let group = PIECE_SIZE as usize;
        let mut bytes = vec![17; 3 * group + 1];
        let leaves = piece_hashes_at(0, &bytes, bytes.len() as u64).unwrap();
        assert!(ProofCheckpoint::new(0, &[]).is_err());
        assert!(ProofCheckpoint::new(bytes.len() as u64, &leaves[..1]).is_err());
        let mut checkpoint = ProofCheckpoint::new(bytes.len() as u64, &leaves).unwrap();
        assert!(checkpoint.updated(1, 0, &[]).is_err());
        assert!(
            checkpoint
                .updated(
                    bytes.len() as u64 + 2 * PIECE_SIZE,
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
                piece_hashes_at(offset as u64, &bytes[offset..], length as u64).unwrap()
            };
            checkpoint = checkpoint
                .updated(length as u64, offset / group, &changed)
                .unwrap();
            bytes[group] ^= 0x49;
            let changed =
                piece_hashes_at(group as u64, &bytes[group..2 * group], length as u64).unwrap();
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
