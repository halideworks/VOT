#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

//! VOT `blake3-bao64` roots, canonical outboards, and range proofs.

use blake3::hazmat::{HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root};

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

pub fn prove(data: &[u8], offset: u64, length: u64) -> Result<RangeProof, Error> {
    let object_len = data.len() as u64;
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
        .ok_or(Error::LengthOverflow)?;
    let covered_end = covered_end.min(object_len);
    let first = covered_offset / GROUP_SIZE;
    let end = covered_end.div_ceil(GROUP_SIZE);
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
    use super::*;

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
