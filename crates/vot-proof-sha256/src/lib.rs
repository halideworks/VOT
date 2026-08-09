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
/// # Panics
/// Panics only if the shared verifier rejects a contiguous bounded slice,
/// which cannot violate its group-order or length rules.
pub fn root(data: &[u8]) -> [u8; 32] {
    vot_verifier::root(vot_verifier::Suite::Sha256Bep52, data)
        .expect("a bounded slice is a valid verifier stream")
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

/// Which bytes a proof covers, and the proof itself.
///
/// [`prove`] returns the covered bytes with it because it was given the object.
/// This is what a caller gets when it supplied only the piece hashes, and it
/// already has, or can regenerate, the bytes the cover names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeCover {
    pub covered_offset: u64,
    pub covered_length: u64,
    pub proof: Vec<u8>,
}

/// Hash of every 64 KiB piece, in order. Enough to prove any range without
/// the object (~512 KiB per gigabyte). No single-piece case: the proof is
/// empty and the root comes from the bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PieceHashes {
    hashes: Vec<[u8; 32]>,
    length: u64,
    ended: bool,
}

impl PieceHashes {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the next piece, keeping only its hash.
    ///
    /// # Errors
    /// Rejects an empty piece, a piece larger than [`PIECE_SIZE`], and anything
    /// after a short one, because only the last piece may be short.
    pub fn push(&mut self, piece: &[u8]) -> Result<(), Error> {
        if piece.is_empty() || piece.len() as u64 > PIECE_SIZE {
            return Err(Error::OutOfBounds);
        }
        if self.ended {
            return Err(Error::OutOfBounds);
        }
        self.hashes.push(piece_hash(piece));
        self.length += piece.len() as u64;
        self.ended = (piece.len() as u64) < PIECE_SIZE;
        Ok(())
    }

    /// The object length these cover.
    #[must_use]
    pub const fn object_len(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub fn pieces(&self) -> usize {
        self.hashes.len()
    }

    /// Whether `piece` is still the bytes this layer took at `index`.
    ///
    #[must_use]
    pub fn holds(&self, index: usize, piece: &[u8]) -> bool {
        let Some(hash) = self.hashes.get(index) else {
            return false;
        };
        if piece.is_empty() || piece.len() as u64 > PIECE_SIZE {
            return false;
        }
        piece_hash(piece) == *hash
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
        let covered_offset = offset / PIECE_SIZE * PIECE_SIZE;
        let covered_end = request_end
            .div_ceil(PIECE_SIZE)
            .checked_mul(PIECE_SIZE)
            .ok_or(Error::LengthOverflow)?
            .min(object_len);
        Ok(Self {
            covered_offset,
            covered_end,
            first: covered_offset / PIECE_SIZE,
            end: covered_end.div_ceil(PIECE_SIZE),
        })
    }
}

/// Proves a range from piece hashes. Byte-identical to [`prove`] for the
/// same range.
///
/// # Errors
/// Rejects an empty range and one that runs past the object.
pub fn prove_with(pieces: &PieceHashes, offset: u64, length: u64) -> Result<RangeCover, Error> {
    let object_len = pieces.length;
    let RangeGeometry {
        covered_offset,
        covered_end,
        first,
        end,
    } = RangeGeometry::of(object_len, offset, length)?;
    Ok(RangeCover {
        covered_offset,
        covered_length: covered_end - covered_offset,
        proof: encode_proof(&pieces.hashes, first, end),
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
    if covered_offset % PIECE_SIZE != 0 || data.is_empty() {
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

#[cfg(test)]
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
    while width != tree_width {
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
        let node_index = start / width;
        let sibling_on_left = node_index & 1 == 1;
        let sibling_start = if sibling_on_left {
            start - width
        } else {
            start + width
        };
        let sibling = if sibling_start < piece_count {
            read_hash(proof, &mut cursor)?
        } else {
            zero_subtree(width)
        };
        value = if sibling_on_left {
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

    /// Streams `data` through the builder one piece at a time, the way a
    /// sender that never holds the object does.
    fn pieces_of(data: &[u8]) -> PieceHashes {
        let mut pieces = PieceHashes::new();
        for piece in data.chunks(PIECE_SIZE as usize) {
            pieces.push(piece).unwrap();
        }
        pieces
    }

    #[test]
    fn piece_hashes_hold_pieces_to_their_content() {
        let data = fixture(3 * PIECE_SIZE as usize + 71);
        let pieces = pieces_of(&data);
        let chunks: Vec<&[u8]> = data.chunks(PIECE_SIZE as usize).collect();
        for (index, piece) in chunks.iter().enumerate() {
            assert!(pieces.holds(index, piece), "piece {index} is its own bytes");
        }

        let mut altered = chunks[1].to_vec();
        altered[0] ^= 1;
        assert!(!pieces.holds(1, &altered));
        let mut altered = chunks[1].to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(!pieces.holds(1, &altered));

        assert!(!pieces.holds(0, chunks[1]));
        let repeated = vec![7u8; 2 * PIECE_SIZE as usize];
        let layer = pieces_of(&repeated);
        assert!(layer.holds(0, &repeated[..PIECE_SIZE as usize]));
        assert!(layer.holds(1, &repeated[..PIECE_SIZE as usize]));

        assert!(!pieces.holds(chunks.len(), chunks[0]));
        assert!(!pieces.holds(usize::MAX, chunks[0]));
        assert!(!pieces.holds(0, &[]));
        assert!(!pieces.holds(0, &fixture(PIECE_SIZE as usize + 1)));
    }

    #[test]
    fn proving_from_piece_hashes_matches_proving_from_the_object() {
        for length in [
            1,
            PIECE_SIZE as usize,
            PIECE_SIZE as usize + 1,
            3 * PIECE_SIZE as usize,
            5 * PIECE_SIZE as usize + 71,
        ] {
            let data = fixture(length);
            let pieces = pieces_of(&data);
            assert_eq!(pieces.object_len(), data.len() as u64);
            for (offset, request) in [(0, 1), (0, length as u64), (length as u64 - 1, 1)] {
                let whole = prove(&data, offset, request).unwrap();
                let cover = prove_with(&pieces, offset, request).unwrap();
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
    fn the_builder_takes_full_pieces_until_a_short_last_one() {
        let mut pieces = PieceHashes::new();
        assert_eq!(pieces.push(&[]), Err(Error::OutOfBounds));
        assert_eq!(
            pieces.push(&fixture(PIECE_SIZE as usize + 1)),
            Err(Error::OutOfBounds)
        );
        assert_eq!(pieces.object_len(), 0);
        assert_eq!(pieces.pieces(), 0);

        pieces.push(&fixture(PIECE_SIZE as usize)).unwrap();
        pieces.push(&fixture(7)).unwrap();
        assert_eq!(pieces.object_len(), PIECE_SIZE + 7);
        assert_eq!(pieces.pieces(), 2);
        assert_eq!(pieces.push(&fixture(1)), Err(Error::OutOfBounds));
    }

    #[test]
    fn a_range_past_the_object_is_refused_from_piece_hashes_too() {
        let data = fixture(2 * PIECE_SIZE as usize);
        let pieces = pieces_of(&data);
        assert_eq!(prove_with(&pieces, 0, 0), Err(Error::EmptyRange));
        assert_eq!(prove_with(&pieces, u64::MAX, 2), Err(Error::LengthOverflow));
        assert_eq!(
            prove_with(&pieces, data.len() as u64, 1),
            Err(Error::OutOfBounds)
        );
        assert!(prove_with(&pieces, 0, data.len() as u64).is_ok());
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
        for (offset, length, covered_offset, covered_length) in [
            (1, 1, 0, PIECE_SIZE),
            (70_000, 100_000, PIECE_SIZE, 2 * PIECE_SIZE),
            (196_700, 200_000, 3 * PIECE_SIZE, 4 * PIECE_SIZE),
            (458_752, 37, 7 * PIECE_SIZE, 37),
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

    #[test]
    fn proof_request_and_verifier_bounds_are_exact() {
        let data = fixture(2 * PIECE_SIZE as usize);
        let expected = root(&data);
        assert_eq!(prove(&data, 0, 0), Err(Error::EmptyRange));
        assert_eq!(prove(&data, u64::MAX, 2), Err(Error::LengthOverflow));
        assert_eq!(prove(&data, data.len() as u64, 1), Err(Error::OutOfBounds));

        assert_eq!(verify(&expected, 0, 0, &[1], &[]), Err(Error::OutOfBounds));
        assert_eq!(
            verify(&expected, data.len() as u64, 1, &[1], &[]),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(&expected, data.len() as u64, 0, &[], &[]),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(
                &expected,
                data.len() as u64,
                0,
                &fixture(data.len() + 1),
                &[]
            ),
            Err(Error::OutOfBounds)
        );
        assert_eq!(
            verify(&expected, data.len() as u64, 0, &[1], &[]),
            Err(Error::OutOfBounds)
        );
    }

    #[test]
    fn single_piece_requires_exact_root_and_empty_proof() {
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

    #[test]
    fn proof_windows_are_exact_and_aligned() {
        for (first, end, tree_width, expected) in [
            (0, 1, 1, (0, 1)),
            (0, 1, 4, (0, 2)),
            (2, 4, 8, (2, 2)),
            (3, 5, 8, (0, 8)),
            (3, 7, 8, (0, 8)),
            (4, 6, 8, (4, 2)),
        ] {
            assert_eq!(proof_window(first, end, tree_width), expected);
        }
    }

    #[test]
    fn encoded_proofs_contain_only_required_siblings() {
        let pieces = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let mut expected = Vec::new();
        expected.extend_from_slice(&pieces[0]);
        expected.extend_from_slice(&parent(&pieces[2], &pieces[3]));
        assert_eq!(encode_proof(&pieces, 1, 2), expected);

        let padded = [[1; 32], [2; 32], [3; 32]];
        assert_eq!(
            encode_proof(&padded, 2, 3),
            parent(&padded[0], &padded[1]).to_vec()
        );

        let right_edge = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]];
        assert_eq!(
            encode_proof(&right_edge, 4, 6),
            parent(
                &parent(&right_edge[0], &right_edge[1]),
                &parent(&right_edge[2], &right_edge[3])
            )
            .to_vec()
        );
    }

    #[test]
    fn zero_subtrees_match_repeated_bep52_padding() {
        let width_one = zero_piece();
        let width_two = parent(&width_one, &width_one);
        let width_four = parent(&width_two, &width_two);
        assert_eq!(zero_subtree(1), width_one);
        assert_eq!(zero_subtree(2), width_two);
        assert_eq!(zero_subtree(4), width_four);
    }

    #[test]
    fn single_piece_decoder_rejects_each_malformed_dimension() {
        let covered = [[7; 32]];
        assert_eq!(decode_root(1, 0, 1, &covered, &[]), Ok(covered[0]));
        assert_eq!(
            decode_root(1, 1, 1, &covered, &[]),
            Err(Error::MalformedProof)
        );
        assert_eq!(
            decode_root(1, 0, 2, &covered, &[]),
            Err(Error::MalformedProof)
        );
        assert_eq!(decode_root(1, 0, 1, &[], &[]), Err(Error::MalformedProof));
        assert_eq!(
            decode_root(1, 0, 1, &covered, &[0]),
            Err(Error::MalformedProof)
        );
    }

    #[test]
    fn proof_decoder_rebuilds_every_subrange_across_padding() {
        for piece_count in 2_usize..=9 {
            let pieces: Vec<[u8; 32]> = (0..piece_count)
                .map(|index| [u8::try_from(index + 1).unwrap(); 32])
                .collect();
            let expected = padded_piece_tree(&pieces)
                .last()
                .unwrap()
                .first()
                .copied()
                .unwrap();
            for first in 0..piece_count {
                for end in first + 1..=piece_count {
                    let proof = encode_proof(&pieces, first as u64, end as u64);
                    assert_eq!(
                        decode_root(
                            piece_count as u64,
                            first as u64,
                            end as u64,
                            &pieces[first..end],
                            &proof
                        ),
                        Ok(expected),
                        "piece_count={piece_count} range={first}..{end}"
                    );
                }
            }
        }
    }
}
