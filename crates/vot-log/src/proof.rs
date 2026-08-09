//! Inclusion and consistency proof generation and verification.

use super::{Error, Hash, MAX_ENTRIES, node_hash, root_of, split};

pub(super) fn path(index: usize, leaves: &[Hash]) -> Vec<Hash> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = split(leaves.len());
    if index < k {
        let mut proof = path(index, &leaves[..k]);
        proof.push(root_of(&leaves[k..]));
        proof
    } else {
        let mut proof = path(index - k, &leaves[k..]);
        proof.push(root_of(&leaves[..k]));
        proof
    }
}

pub(super) fn subproof(old_size: usize, leaves: &[Hash], is_prefix: bool) -> Vec<Hash> {
    if old_size == leaves.len() {
        return if is_prefix {
            Vec::new()
        } else {
            vec![root_of(leaves)]
        };
    }
    let k = split(leaves.len());
    if old_size <= k {
        let mut proof = subproof(old_size, &leaves[..k], is_prefix);
        proof.push(root_of(&leaves[k..]));
        proof
    } else {
        let mut proof = subproof(old_size - k, &leaves[k..], false);
        proof.push(root_of(&leaves[..k]));
        proof
    }
}

/// Splits an inclusion proof into the part inside the leaf's subtree and the
/// part along the tree's right border.
///
/// Deriving both lengths lets the verifier reject a proof of the wrong length
/// outright, rather than consuming what it is given.
pub(super) fn decompose(index: usize, size: usize) -> (u32, u32) {
    let inner = usize::BITS - (index ^ (size - 1)).leading_zeros();
    let border = (index >> inner).count_ones();
    (inner, border)
}

/// Recomputes a head from a leaf hash and its inclusion proof.
///
/// # Errors
/// Rejects an out-of-range index, a proof of the wrong length, or one that does
/// not reconstruct `root`.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), Error> {
    if size == 0 || size > MAX_ENTRIES || index >= size {
        return Err(Error::OutOfRange);
    }
    let (inner, border) = decompose(index, size);
    if proof.len() != (inner + border) as usize {
        return Err(Error::ProofInvalid);
    }
    let inner = inner as usize;
    let mut computed = *leaf;
    for (level, sibling) in proof[..inner].iter().enumerate() {
        computed = if (index >> level) & 1 == 0 {
            node_hash(&computed, sibling)
        } else {
            node_hash(sibling, &computed)
        };
    }
    for sibling in &proof[inner..] {
        computed = node_hash(sibling, &computed);
    }
    if computed == *root {
        Ok(())
    } else {
        Err(Error::ProofInvalid)
    }
}

/// Checks that the tree of `old_size` entries is a prefix of the tree of
/// `new_size` entries.
///
/// This is the property that makes a log append-only to a reader: it shows
/// nothing before `old_size` was changed or removed.
///
/// # Errors
/// Rejects a malformed range, a proof of the wrong length, or one that does not
/// reconcile both heads.
pub fn verify_consistency(
    old_size: usize,
    old_root: &Hash,
    new_size: usize,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), Error> {
    if old_size == 0 || old_size > new_size || new_size > MAX_ENTRIES {
        return Err(Error::OutOfRange);
    }
    if old_size == new_size {
        // Nothing appended: the heads must agree and the proof must be empty.
        // Accepting nodes here would let a prover pad a proof.
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(Error::ProofInvalid)
        };
    }

    // Walk up from the old tree's right edge to the root.
    let mut node = old_size - 1;
    let mut last = new_size - 1;
    for _ in 0..usize::BITS {
        if node & 1 == 0 {
            break;
        }
        node >>= 1;
        last >>= 1;
    }

    let mut rest = proof;
    let (mut from_old, mut from_new) = if node > 0 {
        let (first, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
        rest = tail;
        (*first, *first)
    } else {
        // node == 0 means the old tree is a complete subtree, so its own head
        // is the starting node and the prover omits it.
        (*old_root, *old_root)
    };

    for _ in 0..usize::BITS {
        if node == 0 {
            break;
        }
        if node & 1 == 1 {
            let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
            rest = tail;
            from_old = node_hash(sibling, &from_old);
            from_new = node_hash(sibling, &from_new);
        } else if node < last {
            let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
            rest = tail;
            from_new = node_hash(&from_new, sibling);
        }
        node >>= 1;
        last >>= 1;
    }

    for _ in 0..usize::BITS {
        if last == 0 {
            break;
        }
        let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
        rest = tail;
        from_new = node_hash(&from_new, sibling);
        last >>= 1;
    }

    if from_old == *old_root && from_new == *new_root && rest.is_empty() {
        Ok(())
    } else {
        Err(Error::ProofInvalid)
    }
}
