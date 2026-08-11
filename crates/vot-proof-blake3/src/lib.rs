#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

//! VOT `blake3-bao64` roots, canonical outboards, and range proofs.

use blake3::hazmat::{HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root};
use vot_proof_store::{ProofNodeStorage, StoreError};

pub const GROUP_SIZE: u64 = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeProof {
    pub covered_offset: u64,
    pub data: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyRange,
    OutOfBounds,
    LengthOverflow,
    MalformedProof,
    HashMismatch,
    Storage(StoreError),
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, Copy)]
struct Node {
    start: u64,
    count: u64,
}

impl Node {
    fn split(self) -> (Self, Self) {
        let left_count = 1_u64 << (63 - (self.count - 1).leading_zeros());
        (
            Self {
                start: self.start,
                count: left_count,
            },
            Self {
                start: self.start + left_count,
                count: self.count - left_count,
            },
        )
    }

    fn intersects(self, first: u64, end: u64) -> bool {
        self.start < end && first < self.start + self.count
    }
}

#[must_use]
/// # Panics
/// Panics only if the shared verifier rejects a contiguous bounded slice,
/// which cannot violate its group-order or length rules.
pub fn root(data: &[u8]) -> [u8; 32] {
    vot_verifier::root(vot_verifier::Suite::Blake3Bao64, data)
        .expect("a bounded slice is a valid verifier stream")
}

#[must_use]
pub fn canonical_outboard(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let groups = group_count(data.len() as u64);
    encode_all(
        Node {
            start: 0,
            count: groups,
        },
        data,
        &mut encoded,
    );
    encoded
}

/// Proof bytes and the range they cover. Used when proving without the object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeCover {
    pub covered_offset: u64,
    pub covered_length: u64,
    pub proof: Vec<u8>,
}

/// Chaining values of every 64 KiB group, in order. Enough to prove any
/// range without the object (~512 KiB per gigabyte).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GroupCvs {
    cvs: Vec<[u8; 32]>,
    length: u64,
    /// Set once a group shorter than [`GROUP_SIZE`] has been taken, because
    /// only the last group may be short.
    ended: bool,
}

impl GroupCvs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the next group, keeping only its chaining value.
    ///
    /// # Errors
    /// Rejects an empty group, a group larger than [`GROUP_SIZE`], and anything
    /// after a short one, because only the last group may be short and a hole
    /// would put every later group at the wrong offset.
    pub fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        if group.is_empty() || group.len() as u64 > GROUP_SIZE {
            return Err(Error::OutOfBounds);
        }
        if self.ended {
            return Err(Error::OutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(self.length);
        hasher.update(group);
        self.cvs.push(hasher.finalize_non_root());
        self.length += group.len() as u64;
        self.ended = (group.len() as u64) < GROUP_SIZE;
        Ok(())
    }

    /// The object length these cover.
    #[must_use]
    pub const fn object_len(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub fn groups(&self) -> usize {
        self.cvs.len()
    }

    /// Whether `group` matches what this layer took at `index`. Catches
    /// object rewrites that keep the length.
    #[must_use]
    pub fn holds(&self, index: usize, group: &[u8]) -> bool {
        let Some(cv) = self.cvs.get(index) else {
            return false;
        };
        let Ok(offset) = u64::try_from(index) else {
            return false;
        };
        let Some(input_offset) = offset.checked_mul(GROUP_SIZE) else {
            return false;
        };
        if group.is_empty() || group.len() as u64 > GROUP_SIZE {
            return false;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(input_offset);
        hasher.update(group);
        hasher.finalize_non_root() == *cv
    }
}

const MAX_STORED_LEVELS: usize = 49;

#[derive(Clone, Copy)]
struct StoredLevel {
    base: u64,
    count: u64,
}

impl StoredLevel {
    const EMPTY: Self = Self { base: 0, count: 0 };
}

/// Chaining values retained in caller-supplied sequential storage.
pub struct StoredGroupCvs {
    storage: Box<dyn ProofNodeStorage>,
    length: u64,
    groups: usize,
    ended: bool,
    failure: Option<StoreError>,
}

impl StoredGroupCvs {
    /// Starts an empty retained layer over an empty node store.
    ///
    /// # Errors
    ///
    /// Rejects unavailable storage and storage that already contains nodes.
    pub fn new(storage: Box<dyn ProofNodeStorage>) -> Result<Self, Error> {
        if !storage.is_empty()? {
            return Err(Error::Storage(StoreError::Corrupt));
        }
        Ok(Self {
            storage,
            length: 0,
            groups: 0,
            ended: false,
            failure: None,
        })
    }

    /// Takes the next group and appends its absolute-offset chaining value.
    ///
    /// # Errors
    ///
    /// Rejects invalid group ordering and length. A storage error poisons the
    /// layer because an append may have partially changed its backing store.
    pub fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(Error::Storage(error));
        }
        if group.is_empty() || group.len() as u64 > GROUP_SIZE || self.ended {
            return Err(Error::OutOfBounds);
        }
        let group_length = u64::try_from(group.len()).map_err(|_| Error::LengthOverflow)?;
        let next_length = self
            .length
            .checked_add(group_length)
            .ok_or(Error::LengthOverflow)?;
        let next_groups = self
            .groups
            .checked_add(1)
            .ok_or(Error::Storage(StoreError::Capacity))?;
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(self.length);
        hasher.update(group);
        if let Err(error) = self.storage.append(hasher.finalize_non_root()) {
            self.failure = Some(error);
            return Err(Error::Storage(error));
        }
        self.length = next_length;
        self.groups = next_groups;
        self.ended = group_length < GROUP_SIZE;
        Ok(())
    }

    /// Appends complete aligned parent levels and seals the retained layer.
    ///
    /// # Errors
    ///
    /// Rejects prior storage failure, inconsistent storage length, unavailable
    /// nodes, and checked ordinal overflow.
    pub fn finish(mut self) -> Result<SealedGroupCvs, Error> {
        if let Some(error) = self.failure {
            return Err(Error::Storage(error));
        }
        let group_count =
            u64::try_from(self.groups).map_err(|_| Error::Storage(StoreError::Capacity))?;
        if self.storage.len()? != group_count {
            return Err(Error::Storage(StoreError::Corrupt));
        }

        let mut levels = [StoredLevel::EMPTY; MAX_STORED_LEVELS];
        let mut level_count = usize::from(group_count != 0);
        if group_count != 0 {
            levels[0] = StoredLevel {
                base: 0,
                count: group_count,
            };
        }
        let mut previous = levels[0];
        let mut expected_records = group_count;
        while previous.count >= 2 {
            if level_count >= MAX_STORED_LEVELS {
                return Err(Error::Storage(StoreError::Capacity));
            }
            if self.storage.len()? != expected_records {
                return Err(Error::Storage(StoreError::Corrupt));
            }
            let count = previous.count / 2;
            let level = StoredLevel {
                base: expected_records,
                count,
            };
            for index in 0..count {
                let child = index
                    .checked_mul(2)
                    .ok_or(Error::Storage(StoreError::Capacity))?;
                let left_ordinal = previous
                    .base
                    .checked_add(child)
                    .ok_or(Error::Storage(StoreError::Capacity))?;
                let right_ordinal = left_ordinal
                    .checked_add(1)
                    .ok_or(Error::Storage(StoreError::Capacity))?;
                let left = self.storage.read(left_ordinal)?;
                let right = self.storage.read(right_ordinal)?;
                self.storage
                    .append(merge_subtrees_non_root(&left, &right, Mode::Hash))?;
            }
            expected_records = expected_records
                .checked_add(count)
                .ok_or(Error::Storage(StoreError::Capacity))?;
            if self.storage.len()? != expected_records {
                return Err(Error::Storage(StoreError::Corrupt));
            }
            levels[level_count] = level;
            level_count += 1;
            previous = level;
        }

        Ok(SealedGroupCvs {
            storage: self.storage,
            length: self.length,
            groups: self.groups,
            levels,
            level_count,
        })
    }
}

/// A stored chaining-value layer ready for readback checks and range proofs.
pub struct SealedGroupCvs {
    storage: Box<dyn ProofNodeStorage>,
    length: u64,
    groups: usize,
    levels: [StoredLevel; MAX_STORED_LEVELS],
    level_count: usize,
}

impl SealedGroupCvs {
    /// The object length these nodes cover.
    #[must_use]
    pub const fn object_len(&self) -> u64 {
        self.length
    }

    /// The number of retained verification groups.
    #[must_use]
    pub const fn groups(&self) -> usize {
        self.groups
    }

    /// Whether `group` matches the retained node at `index`.
    #[must_use]
    pub fn holds(&self, index: usize, group: &[u8]) -> bool {
        if group.is_empty() || group.len() as u64 > GROUP_SIZE {
            return false;
        }
        let Ok(index) = u64::try_from(index) else {
            return false;
        };
        let Some(level) = self.levels.first() else {
            return false;
        };
        if index >= level.count {
            return false;
        }
        let Some(ordinal) = level.base.checked_add(index) else {
            return false;
        };
        let Ok(expected) = self.storage.read(ordinal) else {
            return false;
        };
        let Some(input_offset) = index.checked_mul(GROUP_SIZE) else {
            return false;
        };
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(input_offset);
        hasher.update(group);
        hasher.finalize_non_root() == expected
    }

    /// Creates the canonical proof for a requested range.
    ///
    /// # Errors
    ///
    /// Rejects invalid range geometry and unavailable or corrupt stored nodes.
    pub fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        let RangeGeometry {
            covered_offset,
            covered_end,
            first,
            end,
        } = RangeGeometry::of(self.length, offset, length)?;
        let mut proof = Vec::new();
        encode_selected_stored(
            self,
            Node {
                start: 0,
                count: group_count(self.length),
            },
            first,
            end,
            &mut proof,
        )?;
        Ok(RangeCover {
            covered_offset,
            covered_length: covered_end - covered_offset,
            proof,
        })
    }

    fn node_cv(&self, node: Node) -> Result<[u8; 32], Error> {
        if node.count.is_power_of_two() && node.start % node.count == 0 {
            let level_index = node.count.trailing_zeros() as usize;
            if level_index >= self.level_count {
                return Err(Error::Storage(StoreError::Corrupt));
            }
            let level = self.levels[level_index];
            let index = node.start / node.count;
            if index >= level.count {
                return Err(Error::Storage(StoreError::Corrupt));
            }
            let ordinal = level
                .base
                .checked_add(index)
                .ok_or(Error::Storage(StoreError::Capacity))?;
            return self.storage.read(ordinal).map_err(Error::Storage);
        }
        let (left, right) = node.split();
        Ok(merge_subtrees_non_root(
            &self.node_cv(left)?,
            &self.node_cv(right)?,
            Mode::Hash,
        ))
    }
}

/// Request-to-cover geometry for one range proof: the aligned start, an end
/// clipped to the object, and the first and past-the-end unit indices. One
/// derivation for the cold and precomputed paths, so they cannot disagree on
/// what a request covers.
struct RangeGeometry {
    covered_offset: u64,
    covered_end: u64,
    first: u64,
    end: u64,
}

impl RangeGeometry {
    fn of(object_len: u64, offset: u64, length: u64) -> Result<Self, Error> {
        if length == 0 {
            return Err(Error::EmptyRange);
        }
        let request_end = offset.checked_add(length).ok_or(Error::LengthOverflow)?;
        if request_end > object_len {
            return Err(Error::OutOfBounds);
        }
        let covered_offset = offset / GROUP_SIZE * GROUP_SIZE;
        let covered_end = request_end
            .div_ceil(GROUP_SIZE)
            .checked_mul(GROUP_SIZE)
            .ok_or(Error::LengthOverflow)?
            .min(object_len);
        Ok(Self {
            covered_offset,
            covered_end,
            first: covered_offset / GROUP_SIZE,
            end: covered_end.div_ceil(GROUP_SIZE),
        })
    }
}

/// Proves a range from chaining values. Byte-identical to [`prove`] for the
/// same range.
///
/// # Errors
/// Rejects an empty range and one that runs past the object.
pub fn prove_with(cvs: &GroupCvs, offset: u64, length: u64) -> Result<RangeCover, Error> {
    let object_len = cvs.length;
    let RangeGeometry {
        covered_offset,
        covered_end,
        first,
        end,
    } = RangeGeometry::of(object_len, offset, length)?;
    let mut proof = Vec::new();
    encode_selected_from(
        Node {
            start: 0,
            count: group_count(object_len),
        },
        first,
        end,
        &cvs.cvs,
        &mut proof,
    );
    Ok(RangeCover {
        covered_offset,
        covered_length: covered_end - covered_offset,
        proof,
    })
}

pub fn prove(data: &[u8], offset: u64, length: u64) -> Result<RangeProof, Error> {
    let object_len = data.len() as u64;
    let RangeGeometry {
        covered_offset,
        covered_end,
        first,
        end,
    } = RangeGeometry::of(object_len, offset, length)?;
    let mut proof = Vec::new();
    let groups = group_count(object_len);
    encode_selected(
        Node {
            start: 0,
            count: groups,
        },
        first,
        end,
        data,
        &mut proof,
    );
    let start = usize::try_from(covered_offset).map_err(|_| Error::OutOfBounds)?;
    let stop = usize::try_from(covered_end).map_err(|_| Error::OutOfBounds)?;
    Ok(RangeProof {
        covered_offset,
        data: data[start..stop].to_vec(),
        proof,
    })
}

pub fn verify(
    expected_root: &[u8; 32],
    object_len: u64,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    if covered_offset % GROUP_SIZE != 0 || data.is_empty() {
        return Err(Error::OutOfBounds);
    }
    let data_len = u64::try_from(data.len()).map_err(|_| Error::OutOfBounds)?;
    let covered_end = covered_offset
        .checked_add(data_len)
        .ok_or(Error::LengthOverflow)?;
    if covered_end > object_len || (covered_end < object_len && covered_end % GROUP_SIZE != 0) {
        return Err(Error::OutOfBounds);
    }
    let first = covered_offset / GROUP_SIZE;
    let end = covered_end.div_ceil(GROUP_SIZE);
    let groups = group_count(object_len);
    if end > groups {
        return Err(Error::OutOfBounds);
    }
    if groups == 1 {
        if !proof.is_empty() {
            return Err(Error::MalformedProof);
        }
        return if root(data) == *expected_root {
            Ok(())
        } else {
            Err(Error::HashMismatch)
        };
    }

    let root_node = Node {
        start: 0,
        count: groups,
    };
    let (left_node, right_node) = root_node.split();
    let mut cursor = 0;
    let (left, right) = read_parent(proof, &mut cursor)?;
    verify_child(
        left_node,
        first,
        end,
        covered_offset,
        data,
        proof,
        &mut cursor,
        &left,
    )?;
    verify_child(
        right_node,
        first,
        end,
        covered_offset,
        data,
        proof,
        &mut cursor,
        &right,
    )?;
    if cursor != proof.len() {
        return Err(Error::MalformedProof);
    }
    let actual = merge_subtrees_root(&left, &right, Mode::Hash);
    if actual.as_bytes() == expected_root {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

fn group_count(length: u64) -> u64 {
    length.max(1).div_ceil(GROUP_SIZE)
}

fn group_cv(data: &[u8], index: u64) -> [u8; 32] {
    let start_u64 = index * GROUP_SIZE;
    let start = start_u64 as usize;
    let end = (start + GROUP_SIZE as usize).min(data.len());
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(start_u64);
    hasher.update(&data[start..end]);
    hasher.finalize_non_root()
}

fn node_cv(node: Node, data: &[u8]) -> [u8; 32] {
    if node.count == 1 {
        return group_cv(data, node.start);
    }
    let (left, right) = node.split();
    merge_subtrees_non_root(&node_cv(left, data), &node_cv(right, data), Mode::Hash)
}

fn encode_all(node: Node, data: &[u8], output: &mut Vec<u8>) {
    if node.count == 1 {
        return;
    }
    let (left, right) = node.split();
    output.extend_from_slice(&node_cv(left, data));
    output.extend_from_slice(&node_cv(right, data));
    encode_all(left, data, output);
    encode_all(right, data, output);
}

/// A node's chaining value, merged up from the group layer.
///
/// The same value [`node_cv`] computes from the object, without reading it.
fn node_cv_from(node: Node, cvs: &[[u8; 32]]) -> [u8; 32] {
    if node.count == 1 {
        return cvs[node.start as usize];
    }
    let (left, right) = node.split();
    merge_subtrees_non_root(
        &node_cv_from(left, cvs),
        &node_cv_from(right, cvs),
        Mode::Hash,
    )
}

fn encode_selected_from(node: Node, first: u64, end: u64, cvs: &[[u8; 32]], output: &mut Vec<u8>) {
    if node.count == 1 || !node.intersects(first, end) {
        return;
    }
    let (left, right) = node.split();
    output.extend_from_slice(&node_cv_from(left, cvs));
    output.extend_from_slice(&node_cv_from(right, cvs));
    encode_selected_from(left, first, end, cvs, output);
    encode_selected_from(right, first, end, cvs, output);
}

fn encode_selected_stored(
    cvs: &SealedGroupCvs,
    node: Node,
    first: u64,
    end: u64,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if node.count == 1 || !node.intersects(first, end) {
        return Ok(());
    }
    let (left, right) = node.split();
    output.extend_from_slice(&cvs.node_cv(left)?);
    output.extend_from_slice(&cvs.node_cv(right)?);
    encode_selected_stored(cvs, left, first, end, output)?;
    encode_selected_stored(cvs, right, first, end, output)
}

fn encode_selected(node: Node, first: u64, end: u64, data: &[u8], output: &mut Vec<u8>) {
    if node.count == 1 || !node.intersects(first, end) {
        return;
    }
    let (left, right) = node.split();
    output.extend_from_slice(&node_cv(left, data));
    output.extend_from_slice(&node_cv(right, data));
    encode_selected(left, first, end, data, output);
    encode_selected(right, first, end, data, output);
}

fn read_parent(proof: &[u8], cursor: &mut usize) -> Result<([u8; 32], [u8; 32]), Error> {
    let end = cursor.checked_add(64).ok_or(Error::MalformedProof)?;
    let bytes = proof.get(*cursor..end).ok_or(Error::MalformedProof)?;
    let mut left = [0; 32];
    let mut right = [0; 32];
    left.copy_from_slice(&bytes[..32]);
    right.copy_from_slice(&bytes[32..]);
    *cursor = end;
    Ok((left, right))
}

#[allow(clippy::too_many_arguments)]
fn verify_child(
    node: Node,
    first: u64,
    end: u64,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
    cursor: &mut usize,
    expected: &[u8; 32],
) -> Result<(), Error> {
    if !node.intersects(first, end) {
        return Ok(());
    }
    let actual = if node.count == 1 {
        let absolute = node.start * GROUP_SIZE;
        let relative = absolute
            .checked_sub(covered_offset)
            .ok_or(Error::OutOfBounds)?;
        let start = usize::try_from(relative).map_err(|_| Error::OutOfBounds)?;
        let stop = (start + GROUP_SIZE as usize).min(data.len());
        if start >= stop {
            return Err(Error::OutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(absolute);
        hasher.update(&data[start..stop]);
        hasher.finalize_non_root()
    } else {
        let (left_node, right_node) = node.split();
        let (left, right) = read_parent(proof, cursor)?;
        verify_child(
            left_node,
            first,
            end,
            covered_offset,
            data,
            proof,
            cursor,
            &left,
        )?;
        verify_child(
            right_node,
            first,
            end,
            covered_offset,
            data,
            proof,
            cursor,
            &right,
        )?;
        merge_subtrees_non_root(&left, &right, Mode::Hash)
    };
    if actual == *expected {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{RefUnwindSafe, UnwindSafe};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use vot_proof_store::{MemoryNodeStorage, ProofNode};

    #[derive(Default)]
    struct FaultStore {
        nodes: Vec<ProofNode>,
        append_failure_at: Option<u64>,
        read_failure: Arc<AtomicBool>,
        length_failure: bool,
    }

    impl ProofNodeStorage for FaultStore {
        fn len(&self) -> Result<u64, StoreError> {
            if self.length_failure {
                return Err(StoreError::Unavailable);
            }
            u64::try_from(self.nodes.len()).map_err(|_| StoreError::Capacity)
        }

        fn append(&mut self, node: ProofNode) -> Result<(), StoreError> {
            if self.append_failure_at == Some(self.len()?) {
                return Err(StoreError::Unavailable);
            }
            self.nodes.push(node);
            Ok(())
        }

        fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError> {
            if self.read_failure.load(Ordering::Relaxed) {
                return Err(StoreError::Unavailable);
            }
            let index = usize::try_from(ordinal).map_err(|_| StoreError::Capacity)?;
            self.nodes.get(index).copied().ok_or(StoreError::Corrupt)
        }
    }

    fn fixture(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect()
    }

    #[test]
    fn roots_match_official_api_across_geometry() {
        for length in [0, 1, 1024, 65_535, 65_536, 65_537, 196_731, 393_233] {
            let data = fixture(length);
            assert_eq!(root(&data), *blake3::hash(&data).as_bytes());
        }
    }

    #[test]
    fn arbitrary_request_expands_and_verifies() {
        let data = fixture(5 * GROUP_SIZE as usize + 71);
        let expected = root(&data);
        for (offset, length, covered_offset, covered_length) in [
            (1, 1, 0, GROUP_SIZE),
            (70_000, 90_000, GROUP_SIZE, 2 * GROUP_SIZE),
            (196_700, 130_000, 3 * GROUP_SIZE, 2 * GROUP_SIZE),
            (327_680, 71, 5 * GROUP_SIZE, 71),
        ] {
            let bundle = prove(&data, offset, length).unwrap();
            assert_eq!(bundle.covered_offset, covered_offset);
            assert_eq!(bundle.data.len() as u64, covered_length);
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &bundle.data,
                &bundle.proof,
            )
            .unwrap();
        }
    }

    /// Streams `data` through the builder one group at a time, the way a sender
    /// that never holds the object does.
    fn cvs_of(data: &[u8]) -> GroupCvs {
        let mut cvs = GroupCvs::new();
        for group in data.chunks(GROUP_SIZE as usize) {
            cvs.push(group).unwrap();
        }
        cvs
    }

    fn stored_cvs_of(data: &[u8]) -> SealedGroupCvs {
        let mut cvs = StoredGroupCvs::new(Box::new(MemoryNodeStorage::new())).unwrap();
        for group in data.chunks(GROUP_SIZE as usize) {
            cvs.push(group).unwrap();
        }
        cvs.finish().unwrap()
    }

    fn assert_stored_auto_traits<T: Send + Sync + UnwindSafe + RefUnwindSafe>() {}

    #[test]
    fn stored_layers_require_empty_available_storage() {
        let empty = StoredGroupCvs::new(Box::new(MemoryNodeStorage::new())).unwrap();
        let sealed = empty.finish().unwrap();
        assert_eq!(sealed.object_len(), 0);
        assert_eq!(sealed.groups(), 0);

        let mut occupied = MemoryNodeStorage::new();
        occupied.append([1; 32]).unwrap();
        assert!(matches!(
            StoredGroupCvs::new(Box::new(occupied)),
            Err(Error::Storage(StoreError::Corrupt))
        ));
        assert!(matches!(
            StoredGroupCvs::new(Box::new(FaultStore {
                length_failure: true,
                ..FaultStore::default()
            })),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn stored_builder_enforces_every_group_order_boundary() {
        let mut stored = StoredGroupCvs::new(Box::new(MemoryNodeStorage::new())).unwrap();
        assert_eq!(stored.push(&[]), Err(Error::OutOfBounds));
        assert_eq!(
            stored.push(&fixture(GROUP_SIZE as usize + 1)),
            Err(Error::OutOfBounds)
        );
        stored.push(&fixture(GROUP_SIZE as usize)).unwrap();
        stored.push(&fixture(GROUP_SIZE as usize)).unwrap();
        stored.push(&fixture(7)).unwrap();
        assert_eq!(stored.push(&[1]), Err(Error::OutOfBounds));
        let sealed = stored.finish().unwrap();
        assert_eq!(sealed.object_len(), 2 * GROUP_SIZE + 7);
        assert_eq!(sealed.groups(), 3);
    }

    #[test]
    fn stored_layers_match_memory_across_irregular_tree_widths() {
        for groups in [1_usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let length = groups * GROUP_SIZE as usize - 7;
            let data = fixture(length);
            let memory = cvs_of(&data);
            let stored = stored_cvs_of(&data);
            assert_eq!(stored.object_len(), memory.object_len());
            assert_eq!(stored.groups(), memory.groups());

            for (index, group) in data.chunks(GROUP_SIZE as usize).enumerate() {
                assert_eq!(stored.holds(index, group), memory.holds(index, group));
            }
            for (offset, request) in [
                (0, 1),
                (GROUP_SIZE.saturating_sub(1), 1),
                (length as u64 - 1, 1),
                (0, length as u64),
            ] {
                assert_eq!(
                    stored.prove(offset, request),
                    prove_with(&memory, offset, request)
                );
            }
        }
    }

    #[test]
    fn stored_holds_rejects_changed_and_unavailable_nodes() {
        let data = fixture(3 * GROUP_SIZE as usize + 7);
        let read_failure = Arc::new(AtomicBool::new(false));
        let mut building = StoredGroupCvs::new(Box::new(FaultStore {
            read_failure: Arc::clone(&read_failure),
            ..FaultStore::default()
        }))
        .unwrap();
        for group in data.chunks(GROUP_SIZE as usize) {
            building.push(group).unwrap();
        }
        let stored = building.finish().unwrap();
        assert!(stored.holds(0, &data[..GROUP_SIZE as usize]));
        assert!(!stored.holds(0, &[]));
        assert!(!stored.holds(0, &fixture(GROUP_SIZE as usize + 1)));
        let mut changed = data[..GROUP_SIZE as usize].to_vec();
        changed[0] ^= 1;
        assert!(!stored.holds(0, &changed));

        read_failure.store(true, Ordering::Relaxed);
        assert!(!stored.holds(0, &data[..GROUP_SIZE as usize]));
        assert!(matches!(
            stored.prove(0, 1),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn append_storage_failure_poison_is_permanent() {
        let mut stored = StoredGroupCvs::new(Box::new(FaultStore {
            append_failure_at: Some(0),
            ..FaultStore::default()
        }))
        .unwrap();
        assert_eq!(
            stored.push(b"first"),
            Err(Error::Storage(StoreError::Unavailable))
        );
        assert_eq!(
            stored.push(b"second"),
            Err(Error::Storage(StoreError::Unavailable))
        );
        assert!(matches!(
            stored.finish(),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn finish_surfaces_parent_read_and_append_failures() {
        let group = vec![7; GROUP_SIZE as usize];

        let read_failure = Arc::new(AtomicBool::new(false));
        let mut unreadable = StoredGroupCvs::new(Box::new(FaultStore {
            read_failure: Arc::clone(&read_failure),
            ..FaultStore::default()
        }))
        .unwrap();
        unreadable.push(&group).unwrap();
        unreadable.push(&group).unwrap();
        read_failure.store(true, Ordering::Relaxed);
        assert!(matches!(
            unreadable.finish(),
            Err(Error::Storage(StoreError::Unavailable))
        ));

        let mut unwritable = StoredGroupCvs::new(Box::new(FaultStore {
            append_failure_at: Some(2),
            ..FaultStore::default()
        }))
        .unwrap();
        unwritable.push(&group).unwrap();
        unwritable.push(&group).unwrap();
        assert!(matches!(
            unwritable.finish(),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn stored_layers_keep_required_auto_traits() {
        assert_stored_auto_traits::<StoredGroupCvs>();
        assert_stored_auto_traits::<SealedGroupCvs>();
    }

    #[test]
    fn chaining_values_hold_groups_to_their_content_and_their_place() {
        let data = fixture(3 * GROUP_SIZE as usize + 71);
        let cvs = cvs_of(&data);
        let groups: Vec<&[u8]> = data.chunks(GROUP_SIZE as usize).collect();
        for (index, group) in groups.iter().enumerate() {
            assert!(cvs.holds(index, group), "group {index} is its own bytes");
        }

        let mut altered = groups[1].to_vec();
        altered[0] ^= 1;
        assert!(!cvs.holds(1, &altered));
        let mut altered = groups[1].to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(!cvs.holds(1, &altered));

        let repeated = vec![7u8; 3 * GROUP_SIZE as usize];
        let same = cvs_of(&repeated);
        assert_ne!(same.cvs[0], same.cvs[1]);
        assert_ne!(same.cvs[1], same.cvs[2]);
        assert!(!cvs.holds(0, groups[1]));
        assert!(!cvs.holds(2, groups[1]));

        assert!(!cvs.holds(groups.len(), groups[0]));
        assert!(!cvs.holds(usize::MAX, groups[0]));
        assert!(!cvs.holds(0, &[]));
        assert!(!cvs.holds(0, &fixture(GROUP_SIZE as usize + 1)));
    }

    #[test]
    fn proving_from_chaining_values_matches_proving_from_the_object() {
        for length in [
            1,
            GROUP_SIZE as usize,
            GROUP_SIZE as usize + 1,
            3 * GROUP_SIZE as usize,
            5 * GROUP_SIZE as usize + 71,
            9 * GROUP_SIZE as usize,
        ] {
            let data = fixture(length);
            let cvs = cvs_of(&data);
            assert_eq!(cvs.object_len(), data.len() as u64);
            assert_eq!(cvs.groups(), group_count(data.len() as u64) as usize);
            for (offset, request) in [(0, 1), (0, length as u64), (length as u64 - 1, 1)] {
                let whole = prove(&data, offset, request).unwrap();
                let cover = prove_with(&cvs, offset, request).unwrap();
                assert_eq!(cover.proof, whole.proof, "length {length} offset {offset}");
                assert_eq!(cover.covered_offset, whole.covered_offset);
                assert_eq!(cover.covered_length, whole.data.len() as u64);

                let start = cover.covered_offset as usize;
                let stop = start + cover.covered_length as usize;
                verify(
                    &root(&data),
                    data.len() as u64,
                    cover.covered_offset,
                    &data[start..stop],
                    &cover.proof,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn the_builder_takes_full_groups_until_a_short_last_one() {
        let mut cvs = GroupCvs::new();
        assert_eq!(cvs.push(&[]), Err(Error::OutOfBounds));
        assert_eq!(
            cvs.push(&fixture(GROUP_SIZE as usize + 1)),
            Err(Error::OutOfBounds)
        );
        assert_eq!(cvs.object_len(), 0);

        cvs.push(&fixture(GROUP_SIZE as usize)).unwrap();
        cvs.push(&fixture(7)).unwrap();
        assert_eq!(cvs.object_len(), GROUP_SIZE + 7);
        assert_eq!(cvs.push(&fixture(1)), Err(Error::OutOfBounds));
    }

    #[test]
    fn a_range_past_the_object_is_refused_from_chaining_values_too() {
        let data = fixture(2 * GROUP_SIZE as usize);
        let cvs = cvs_of(&data);
        assert_eq!(prove_with(&cvs, 0, 0), Err(Error::EmptyRange));
        assert_eq!(prove_with(&cvs, u64::MAX, 2), Err(Error::LengthOverflow));
        assert_eq!(
            prove_with(&cvs, data.len() as u64, 1),
            Err(Error::OutOfBounds)
        );
        assert!(prove_with(&cvs, 0, data.len() as u64).is_ok());
    }

    #[test]
    fn corruption_and_malformed_proofs_fail() {
        let data = fixture(3 * GROUP_SIZE as usize + 9);
        let expected = root(&data);
        let bundle = prove(&data, GROUP_SIZE + 7, 2).unwrap();
        let mut corrupt_data = bundle.data.clone();
        corrupt_data[3] ^= 1;
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &corrupt_data,
                &bundle.proof
            ),
            Err(Error::HashMismatch)
        );
        let mut corrupt_proof = bundle.proof.clone();
        corrupt_proof[0] ^= 1;
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &bundle.data,
                &corrupt_proof
            ),
            Err(Error::HashMismatch)
        );
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &bundle.data,
                &bundle.proof[..bundle.proof.len() - 1]
            ),
            Err(Error::MalformedProof)
        );
    }

    #[test]
    fn outboard_has_exact_preorder_size() {
        let data = fixture(5 * GROUP_SIZE as usize + 1);
        let outboard = canonical_outboard(&data);
        assert_eq!(&outboard[..8], &(data.len() as u64).to_le_bytes());
        assert_eq!(outboard.len(), 8 + 64 * 5);
    }

    #[test]
    fn proof_request_bounds_are_exact() {
        let data = fixture(GROUP_SIZE as usize + 1);
        assert_eq!(prove(&data, 0, 0), Err(Error::EmptyRange));
        assert_eq!(prove(&data, u64::MAX, 2), Err(Error::LengthOverflow));
        assert_eq!(prove(&data, data.len() as u64, 1), Err(Error::OutOfBounds));
    }

    #[test]
    fn verifier_rejects_each_invalid_range_dimension() {
        let object_len = 2 * GROUP_SIZE;
        let expected = root(&fixture(object_len as usize));
        assert_eq!(verify(&expected, 0, 0, &[1], &[]), Err(Error::OutOfBounds));
        assert_eq!(
            verify(&expected, object_len, 1, &[1], &[]),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(&expected, object_len, 0, &[], &[]),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(
                &expected,
                object_len,
                0,
                &fixture(object_len as usize + 1),
                &[]
            ),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(&expected, object_len, 0, &[1], &[]),
            Err(Error::OutOfBounds)
        );
    }

    #[test]
    fn single_group_requires_exact_root_and_empty_proof() {
        let data = fixture(1234);
        let expected = root(&data);
        assert_eq!(verify(&expected, data.len() as u64, 0, &data, &[]), Ok(()));

        let mut wrong_root = expected;
        wrong_root[0] ^= 1;
        assert_eq!(
            verify(&wrong_root, data.len() as u64, 0, &data, &[]),
            Err(Error::HashMismatch)
        );
        assert_eq!(
            verify(&expected, data.len() as u64, 0, &data, &[0]),
            Err(Error::MalformedProof)
        );
    }
}
