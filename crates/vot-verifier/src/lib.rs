//! Shared bounded streaming verification for both frozen VOT suites.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const GROUP_SIZE: usize = 65_536;
const SHA256_LEAF_SIZE: usize = 16_384;

pub type Root = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    Blake3Bao64,
    Sha256Bep52,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    GroupOutOfOrder,
    InvalidGroupLength,
    GroupAfterFinal,
    LengthOverflow,
}

pub trait GroupVerifier: Sized {
    /// # Errors
    /// Rejects out-of-order, empty, oversized, or post-final groups.
    fn feed(&mut self, group_index: u64, bytes: &[u8]) -> Result<(), VerifyError>;
    /// # Errors
    /// Reports arithmetic or incomplete accumulator state.
    fn finish(self) -> Result<Root, VerifyError>;
}

pub struct Verifier {
    inner: VerifierInner,
}

enum VerifierInner {
    Blake3 {
        hasher: Box<blake3::Hasher>,
        next_group: u64,
        saw_final: bool,
    },
    Sha256 {
        tree: MerkleAccumulator,
        next_group: u64,
        saw_final: bool,
        single_root: Option<Root>,
    },
}

impl Verifier {
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        match suite {
            Suite::Blake3Bao64 => Self {
                inner: VerifierInner::Blake3 {
                    hasher: Box::new(blake3::Hasher::new()),
                    next_group: 0,
                    saw_final: false,
                },
            },
            Suite::Sha256Bep52 => Self {
                inner: VerifierInner::Sha256 {
                    tree: MerkleAccumulator::default(),
                    next_group: 0,
                    saw_final: false,
                    single_root: None,
                },
            },
        }
    }
}

impl GroupVerifier for Verifier {
    fn feed(&mut self, group_index: u64, bytes: &[u8]) -> Result<(), VerifyError> {
        match &mut self.inner {
            VerifierInner::Blake3 {
                hasher,
                next_group,
                saw_final,
            } => {
                validate_group(*next_group, *saw_final, group_index, bytes)?;
                hasher.update(bytes);
                *saw_final = bytes.len() < GROUP_SIZE;
                *next_group = next_group
                    .checked_add(1)
                    .ok_or(VerifyError::LengthOverflow)?;
            }
            VerifierInner::Sha256 {
                tree,
                next_group,
                saw_final,
                single_root,
            } => {
                validate_group(*next_group, *saw_final, group_index, bytes)?;
                tree.add_leaf(piece_hash(bytes))?;
                if *next_group == 0 {
                    *single_root = Some(single_group_root(bytes));
                }
                *saw_final = bytes.len() < GROUP_SIZE;
                *next_group = next_group
                    .checked_add(1)
                    .ok_or(VerifyError::LengthOverflow)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Root, VerifyError> {
        match self.inner {
            VerifierInner::Blake3 { hasher, .. } => Ok(*hasher.finalize().as_bytes()),
            VerifierInner::Sha256 {
                next_group: 1,
                single_root,
                ..
            } => single_root.ok_or(VerifyError::LengthOverflow),
            VerifierInner::Sha256 { tree, .. } => tree.finish(),
        }
    }
}

fn validate_group(
    next_group: u64,
    saw_final: bool,
    group_index: u64,
    bytes: &[u8],
) -> Result<(), VerifyError> {
    if group_index != next_group {
        return Err(VerifyError::GroupOutOfOrder);
    }
    if saw_final {
        return Err(VerifyError::GroupAfterFinal);
    }
    if bytes.is_empty() || bytes.len() > GROUP_SIZE {
        return Err(VerifyError::InvalidGroupLength);
    }
    Ok(())
}

pub struct StreamVerifier {
    verifier: Verifier,
    pending: Vec<u8>,
    next_group: u64,
}

impl StreamVerifier {
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        Self {
            verifier: Verifier::new(suite),
            pending: Vec::with_capacity(GROUP_SIZE),
            next_group: 0,
        }
    }

    /// # Errors
    /// Propagates group-order or length overflow errors from the verifier.
    pub fn update(&mut self, mut bytes: &[u8]) -> Result<(), VerifyError> {
        while !bytes.is_empty() {
            let available = GROUP_SIZE - self.pending.len();
            let consumed = available.min(bytes.len());
            self.pending.extend_from_slice(&bytes[..consumed]);
            bytes = &bytes[consumed..];
            if self.pending.len() == GROUP_SIZE {
                self.verifier.feed(self.next_group, &self.pending)?;
                self.next_group = self
                    .next_group
                    .checked_add(1)
                    .ok_or(VerifyError::LengthOverflow)?;
                self.pending.clear();
            }
        }
        Ok(())
    }

    /// # Errors
    /// Propagates final-group or tree accumulator errors.
    pub fn finish(mut self) -> Result<Root, VerifyError> {
        if !self.pending.is_empty() {
            self.verifier.feed(self.next_group, &self.pending)?;
        }
        self.verifier.finish()
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.pending.len()
    }
}

/// # Errors
/// Propagates streaming verifier group and accumulator errors.
pub fn root(suite: Suite, bytes: &[u8]) -> Result<Root, VerifyError> {
    let mut verifier = StreamVerifier::new(suite);
    verifier.update(bytes)?;
    verifier.finish()
}

#[derive(Default)]
struct MerkleAccumulator {
    count: u64,
    levels: Vec<Option<Root>>,
}

impl MerkleAccumulator {
    fn add_leaf(&mut self, leaf: Root) -> Result<(), VerifyError> {
        self.add_subtree(leaf, 0)
    }

    fn add_subtree(&mut self, mut node: Root, mut level: usize) -> Result<(), VerifyError> {
        let width = 1_u64
            .checked_shl(u32::try_from(level).map_err(|_| VerifyError::LengthOverflow)?)
            .ok_or(VerifyError::LengthOverflow)?;
        if self.count % width != 0 {
            return Err(VerifyError::LengthOverflow);
        }
        while self.count
            & 1_u64
                .checked_shl(u32::try_from(level).map_err(|_| VerifyError::LengthOverflow)?)
                .ok_or(VerifyError::LengthOverflow)?
            != 0
        {
            let left = self
                .levels
                .get_mut(level)
                .and_then(Option::take)
                .ok_or(VerifyError::LengthOverflow)?;
            node = parent(&left, &node);
            level += 1;
        }
        if self.levels.len() <= level {
            self.levels.resize(level + 1, None);
        }
        self.levels[level] = Some(node);
        self.count = self
            .count
            .checked_add(width)
            .ok_or(VerifyError::LengthOverflow)?;
        Ok(())
    }

    fn finish(mut self) -> Result<Root, VerifyError> {
        if self.count == 0 {
            return Ok(Sha256::digest([]).into());
        }
        let target = self
            .count
            .checked_next_power_of_two()
            .ok_or(VerifyError::LengthOverflow)?;
        while self.count < target {
            let remaining = target - self.count;
            let aligned = 1_u64 << self.count.trailing_zeros();
            let width = aligned.min(1_u64 << (63 - remaining.leading_zeros()));
            let level = width.trailing_zeros() as usize;
            self.add_subtree(zero_subtree(level), level)?;
        }
        let level = target.trailing_zeros() as usize;
        self.levels
            .get_mut(level)
            .and_then(Option::take)
            .ok_or(VerifyError::LengthOverflow)
    }
}

fn hash(bytes: &[u8]) -> Root {
    Sha256::digest(bytes).into()
}

fn parent(left: &Root, right: &Root) -> Root {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    hash(&bytes)
}

fn piece_hash(bytes: &[u8]) -> Root {
    let mut leaves: Vec<_> = bytes.chunks(SHA256_LEAF_SIZE).map(hash).collect();
    leaves.resize(4, [0; 32]);
    reduce(&leaves)
}

fn single_group_root(bytes: &[u8]) -> Root {
    let mut leaves: Vec<_> = bytes.chunks(SHA256_LEAF_SIZE).map(hash).collect();
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    reduce(&leaves)
}

fn reduce(nodes: &[Root]) -> Root {
    let mut current = nodes.to_vec();
    while current.len() > 1 {
        current = current
            .chunks_exact(2)
            .map(|pair| parent(&pair[0], &pair[1]))
            .collect();
    }
    current[0]
}

fn zero_subtree(mut level: usize) -> Root {
    let mut value = piece_hash(&[]);
    while level > 0 {
        value = parent(&value, &value);
        level -= 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    #[test]
    fn chunking_does_not_change_either_root() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let data = fixture(5 * GROUP_SIZE + 37);
            let expected = root(suite, &data).unwrap();
            for chunk in [1, 511, 4096, GROUP_SIZE, 1024 * 1024] {
                let mut verifier = StreamVerifier::new(suite);
                for bytes in data.chunks(chunk) {
                    verifier.update(bytes).unwrap();
                    assert!(verifier.buffered_bytes() <= GROUP_SIZE);
                }
                assert_eq!(verifier.finish().unwrap(), expected);
            }
        }
    }

    #[test]
    fn group_order_and_final_length_are_enforced() {
        let mut verifier = Verifier::new(Suite::Blake3Bao64);
        assert_eq!(
            verifier.feed(1, &vec![0; GROUP_SIZE]),
            Err(VerifyError::GroupOutOfOrder)
        );
        verifier.feed(0, &[1]).unwrap();
        assert_eq!(verifier.feed(1, &[2]), Err(VerifyError::GroupAfterFinal));
    }
}
