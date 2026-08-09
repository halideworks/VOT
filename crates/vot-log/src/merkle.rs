//! RFC 6962 leaf and node hashing and the log itself.

use super::{Digest, Error, Hash, LEAF_PREFIX, MAX_ENTRIES, NODE_PREFIX, Sha256, path, subproof};

#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

#[must_use]
pub(super) fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Largest power of two strictly less than `n`, for `n > 1`.
pub(super) fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Append-only merkle tree. Proofs are recomputed from leaves (no caching).
#[derive(Clone, Debug, Default)]
pub struct MerkleLog {
    leaves: Vec<Hash>,
}

impl MerkleLog {
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Appends one entry and returns its index.
    ///
    /// # Errors
    /// Rejects an append past the size limit.
    pub fn append(&mut self, entry: &[u8]) -> Result<usize, Error> {
        if self.leaves.len() >= MAX_ENTRIES {
            return Err(Error::Full);
        }
        self.leaves.push(leaf_hash(entry));
        Ok(self.leaves.len() - 1)
    }

    /// Head of the tree over the first `size` entries.
    ///
    /// # Errors
    /// Rejects a size beyond the log.
    pub fn root_at(&self, size: usize) -> Result<Hash, Error> {
        if size > self.leaves.len() {
            return Err(Error::OutOfRange);
        }
        Ok(root_of(&self.leaves[..size]))
    }

    /// Head of the whole log.
    ///
    /// # Errors
    /// Never fails; the signature matches `root_at`.
    pub fn root(&self) -> Result<Hash, Error> {
        self.root_at(self.leaves.len())
    }

    /// Proof that entry `index` is in the tree of `size` entries.
    ///
    /// # Errors
    /// Rejects an index at or beyond `size`, or a size beyond the log.
    pub fn inclusion_proof(&self, index: usize, size: usize) -> Result<Vec<Hash>, Error> {
        if size > self.leaves.len() || index >= size {
            return Err(Error::OutOfRange);
        }
        Ok(path(index, &self.leaves[..size]))
    }

    /// Proof that the tree of `old_size` entries is a prefix of `new_size`.
    ///
    /// # Errors
    /// Rejects a zero or shrinking range, or a size beyond the log.
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Result<Vec<Hash>, Error> {
        if old_size == 0 || old_size > new_size || new_size > self.leaves.len() {
            return Err(Error::OutOfRange);
        }
        Ok(subproof(old_size, &self.leaves[..new_size], true))
    }
}

pub(super) fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}
