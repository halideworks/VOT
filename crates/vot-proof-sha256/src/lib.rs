#![allow(clippy::missing_errors_doc, clippy::cast_possible_truncation)]

//! Exact BEP 52 SHA-256 tree geometry with 64 KiB VOT range proofs.

use sha2::{Digest, Sha256};

pub const LEAF_SIZE: usize = 16_384;
pub const PIECE_SIZE: u64 = 65_536;

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

#[must_use]
pub fn root(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return hash(data);
    }
    let leaves = leaf_hashes(data);
    reduce(leaves)
}

#[must_use]
pub fn piece_layer(data: &[u8]) -> Vec<[u8; 32]> {
    if data.is_empty() {
        return Vec::new();
    }
    if data.len() <= PIECE_SIZE as usize {
        vec![root(data)]
    } else {
        data.chunks(PIECE_SIZE as usize).map(piece_hash).collect()
    }
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
    let covered_offset = offset / PIECE_SIZE * PIECE_SIZE;
    let covered_end = request_end
        .checked_add(PIECE_SIZE - 1)
        .ok_or(Error::LengthOverflow)?
        / PIECE_SIZE
        * PIECE_SIZE;
    let covered_end = covered_end.min(object_len);
    let first = covered_offset / PIECE_SIZE;
    let end = covered_end.div_ceil(PIECE_SIZE);
    let pieces = piece_layer(data);
    let proof = encode_proof(&pieces, first, end);
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
    if object_len == 0 || covered_offset % PIECE_SIZE != 0 || data.is_empty() {
        return Err(Error::OutOfBounds);
    }
    let data_len = u64::try_from(data.len()).map_err(|_| Error::OutOfBounds)?;
    let covered_end = covered_offset
        .checked_add(data_len)
        .ok_or(Error::LengthOverflow)?;
    if covered_end > object_len || (covered_end < object_len && covered_end % PIECE_SIZE != 0) {
        return Err(Error::OutOfBounds);
    }
    let piece_count = object_len.div_ceil(PIECE_SIZE);
    let first = covered_offset / PIECE_SIZE;
    let end = covered_end.div_ceil(PIECE_SIZE);
    if end > piece_count {
        return Err(Error::OutOfBounds);
    }
    let covered_hashes: Vec<_> = if object_len <= PIECE_SIZE {
        vec![root(data)]
    } else {
        data.chunks(PIECE_SIZE as usize).map(piece_hash).collect()
    };
    let actual = decode_root(piece_count, first, end, &covered_hashes, proof)?;
    if actual == *expected_root {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

fn hash(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    hash(&input)
}

fn leaf_hashes(data: &[u8]) -> Vec<[u8; 32]> {
    let mut leaves: Vec<_> = data.chunks(LEAF_SIZE).map(hash).collect();
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    leaves
}

fn reduce(mut nodes: Vec<[u8; 32]>) -> [u8; 32] {
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| parent(&pair[0], &pair[1]))
            .collect();
    }
    nodes[0]
}

fn piece_hash(data: &[u8]) -> [u8; 32] {
    let mut leaves: Vec<_> = data.chunks(LEAF_SIZE).map(hash).collect();
    leaves.resize(4, [0; 32]);
    reduce(leaves)
}

fn zero_piece() -> [u8; 32] {
    let zero_parent = parent(&[0; 32], &[0; 32]);
    parent(&zero_parent, &zero_parent)
}

fn padded_piece_tree(pieces: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let width = pieces.len().max(1).next_power_of_two();
    let mut base = pieces.to_vec();
    base.resize(width, zero_piece());
    let mut layers = vec![base];
    while layers.last().unwrap().len() > 1 {
        let next = layers
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| parent(&pair[0], &pair[1]))
            .collect();
        layers.push(next);
    }
    layers
}

fn proof_window(first: u64, end: u64, tree_width: u64) -> (u64, u64) {
    let mut width = (end - first).next_power_of_two();
    if tree_width > 1 {
        width = width.max(2);
    }
    loop {
        let start = first / width * width;
        if end <= start + width {
            return (start, width);
        }
        width *= 2;
    }
}

fn encode_proof(pieces: &[[u8; 32]], first: u64, end: u64) -> Vec<u8> {
    if pieces.len() <= 1 {
        return Vec::new();
    }
    let layers = padded_piece_tree(pieces);
    let tree_width = layers[0].len() as u64;
    let (window_start, window_width) = proof_window(first, end, tree_width);
    let mut output = Vec::new();
    for index in window_start..window_start + window_width {
        if (index < first || index >= end) && index < pieces.len() as u64 {
            output.extend_from_slice(&layers[0][index as usize]);
        }
    }
    let mut start = window_start;
    let mut width = window_width;
    let mut level = width.trailing_zeros() as usize;
    while width < tree_width {
        let node_index = start / width;
        let sibling = node_index ^ 1;
        let sibling_start = sibling * width;
        if sibling_start < pieces.len() as u64 {
            output.extend_from_slice(&layers[level][sibling as usize]);
        }
        start = start.min(sibling_start);
        width *= 2;
        level += 1;
    }
    output
}

fn read_hash(proof: &[u8], cursor: &mut usize) -> Result<[u8; 32], Error> {
    let end = cursor.checked_add(32).ok_or(Error::MalformedProof)?;
    let bytes = proof.get(*cursor..end).ok_or(Error::MalformedProof)?;
    let mut value = [0; 32];
    value.copy_from_slice(bytes);
    *cursor = end;
    Ok(value)
}

fn zero_subtree(mut width: u64) -> [u8; 32] {
    let mut value = zero_piece();
    while width > 1 {
        value = parent(&value, &value);
        width /= 2;
    }
    value
}

fn decode_root(
    piece_count: u64,
    first: u64,
    end: u64,
    covered: &[[u8; 32]],
    proof: &[u8],
) -> Result<[u8; 32], Error> {
    if piece_count == 1 {
        if first != 0 || end != 1 || covered.len() != 1 || !proof.is_empty() {
            return Err(Error::MalformedProof);
        }
        return Ok(covered[0]);
    }
    if covered.len() as u64 != end - first {
        return Err(Error::MalformedProof);
    }
    let tree_width = piece_count.next_power_of_two();
    let (window_start, window_width) = proof_window(first, end, tree_width);
    let mut cursor = 0;
    let mut nodes = Vec::with_capacity(window_width as usize);
    for index in window_start..window_start + window_width {
        let value = if index >= first && index < end {
            covered[(index - first) as usize]
        } else if index < piece_count {
            read_hash(proof, &mut cursor)?
        } else {
            zero_piece()
        };
        nodes.push(value);
    }
    let mut value = reduce(nodes);
    let mut start = window_start;
    let mut width = window_width;
    while width < tree_width {
        let sibling_start = ((start / width) ^ 1) * width;
        let sibling = if sibling_start < piece_count {
            read_hash(proof, &mut cursor)?
        } else {
            zero_subtree(width)
        };
        value = if sibling_start < start {
            parent(&sibling, &value)
        } else {
            parent(&value, &sibling)
        };
        start = start.min(sibling_start);
        width *= 2;
    }
    if cursor != proof.len() {
        return Err(Error::MalformedProof);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| (i.wrapping_mul(17) % 251) as u8)
            .collect()
    }

    #[test]
    fn exact_bep52_leaf_geometry() {
        for length in [1, 16_383, 16_384, 16_385, 65_536, 65_537, 9 * LEAF_SIZE + 3] {
            let data = fixture(length);
            let leaves = leaf_hashes(&data);
            assert_eq!(root(&data), reduce(leaves));
        }
        assert_eq!(root(&[]), hash(&[]));
    }

    #[test]
    fn arbitrary_ranges_verify() {
        let data = fixture(7 * PIECE_SIZE as usize + 37);
        let expected = root(&data);
        for (offset, length) in [(1, 1), (70_000, 100_000), (196_700, 200_000), (458_752, 37)] {
            let bundle = prove(&data, offset, length).unwrap();
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
    fn corruption_truncation_and_extra_nodes_fail() {
        let data = fixture(5 * PIECE_SIZE as usize + 19);
        let expected = root(&data);
        let bundle = prove(&data, PIECE_SIZE + 4, 8).unwrap();
        let mut corrupt = bundle.data.clone();
        corrupt[0] ^= 1;
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &corrupt,
                &bundle.proof
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
        let mut extra = bundle.proof.clone();
        extra.extend_from_slice(&[0; 32]);
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                bundle.covered_offset,
                &bundle.data,
                &extra
            ),
            Err(Error::MalformedProof)
        );
    }

    #[test]
    fn piece_layer_rebuilds_root_with_derived_padding() {
        let data = fixture(9 * LEAF_SIZE + 7);
        let pieces = piece_layer(&data);
        assert_eq!(
            root(&data),
            *padded_piece_tree(&pieces).last().unwrap().first().unwrap()
        );
    }
}
