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

/// A suite identifier this revision cannot name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownSuite(pub u16);

impl Suite {
    /// The registered wire identifier, the authority every layer converts
    /// through.
    #[must_use]
    pub const fn identifier(self) -> u16 {
        match self {
            Self::Blake3Bao64 => 1,
            Self::Sha256Bep52 => 2,
        }
    }
}

impl TryFrom<u16> for Suite {
    type Error = UnknownSuite;

    fn try_from(identifier: u16) -> Result<Self, Self::Error> {
        match identifier {
            1 => Ok(Self::Blake3Bao64),
            2 => Ok(Self::Sha256Bep52),
            other => Err(UnknownSuite(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    GroupOutOfOrder,
    InvalidGroupLength,
    GroupAfterFinal,
    LengthOverflow,
    SuiteMismatch,
    LengthMismatch,
    RootMismatch,
}

/// Claimed suite, root, and length. [`StreamVerifier::finish`] is what checks
/// a stream against this claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedObject {
    suite: Suite,
    root: Root,
    length: u64,
}

impl ExpectedObject {
    #[must_use]
    pub const fn new(suite: Suite, root: Root, length: u64) -> Self {
        Self {
            suite,
            root,
            length,
        }
    }
}

/// Suite, root, and length that matched a finished stream.
///
/// ```compile_fail,E0451
/// use vot_verifier::{Suite, VerifiedObject};
/// let _ = VerifiedObject {
///     suite: Suite::Blake3Bao64,
///     root: [0; 32],
///     length: 0,
/// };
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedObject {
    suite: Suite,
    root: Root,
    length: u64,
}

impl VerifiedObject {
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    #[must_use]
    pub const fn root(&self) -> Root {
        self.root
    }

    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
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
    sequence: GroupSequence,
    inner: VerifierInner,
}

/// Group ordering and finality, owned once for both suites. `check` and
/// `commit` are separate so the feed order stays explicit: validate, update
/// the suite backend, then commit, and a backend error leaves the sequence
/// where it was.
#[derive(Default)]
struct GroupSequence {
    next: u64,
    saw_final: bool,
}

impl GroupSequence {
    fn check(&self, group_index: u64, bytes: &[u8]) -> Result<(), VerifyError> {
        if group_index != self.next {
            return Err(VerifyError::GroupOutOfOrder);
        }
        if self.saw_final {
            return Err(VerifyError::GroupAfterFinal);
        }
        if bytes.is_empty() || bytes.len() > GROUP_SIZE {
            return Err(VerifyError::InvalidGroupLength);
        }
        Ok(())
    }

    /// Records the accepted group. Finality is recorded before the index
    /// advance, so an index overflow leaves `saw_final` already set, as it
    /// always has.
    fn commit(&mut self, bytes: &[u8]) -> Result<(), VerifyError> {
        self.saw_final = bytes.len() < GROUP_SIZE;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(VerifyError::LengthOverflow)?;
        Ok(())
    }
}

enum VerifierInner {
    Blake3 {
        hasher: Box<blake3::Hasher>,
    },
    Sha256 {
        tree: MerkleAccumulator,
        single_root: Option<Root>,
    },
}

impl Verifier {
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        let inner = match suite {
            Suite::Blake3Bao64 => VerifierInner::Blake3 {
                hasher: Box::new(blake3::Hasher::new()),
            },
            Suite::Sha256Bep52 => VerifierInner::Sha256 {
                tree: MerkleAccumulator::default(),
                single_root: None,
            },
        };
        Self {
            sequence: GroupSequence::default(),
            inner,
        }
    }

    /// Feeds the next expected group, reading the authoritative index instead
    /// of mirroring it.
    fn feed_next(&mut self, bytes: &[u8]) -> Result<(), VerifyError> {
        self.feed(self.sequence.next, bytes)
    }
}

impl GroupVerifier for Verifier {
    fn feed(&mut self, group_index: u64, bytes: &[u8]) -> Result<(), VerifyError> {
        self.sequence.check(group_index, bytes)?;
        match &mut self.inner {
            VerifierInner::Blake3 { hasher } => {
                hasher.update(bytes);
            }
            VerifierInner::Sha256 { tree, single_root } => {
                tree.add_leaf(piece_hash(bytes))?;
                if self.sequence.next == 0 {
                    *single_root = Some(single_group_root(bytes));
                }
            }
        }
        self.sequence.commit(bytes)
    }

    fn finish(self) -> Result<Root, VerifyError> {
        match self.inner {
            VerifierInner::Blake3 { hasher } => Ok(*hasher.finalize().as_bytes()),
            VerifierInner::Sha256 { single_root, .. } if self.sequence.next == 1 => {
                single_root.ok_or(VerifyError::LengthOverflow)
            }
            VerifierInner::Sha256 { tree, .. } => tree.finish(),
        }
    }
}

pub struct StreamVerifier {
    suite: Suite,
    verifier: Verifier,
    pending: Vec<u8>,
    length: u64,
}

impl StreamVerifier {
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        Self {
            suite,
            verifier: Verifier::new(suite),
            pending: Vec::with_capacity(GROUP_SIZE),
            length: 0,
        }
    }

    /// # Errors
    /// Propagates group-order or length overflow errors from the verifier.
    pub fn update(&mut self, mut bytes: &[u8]) -> Result<(), VerifyError> {
        let incoming = bytes.len();
        if !self.pending.is_empty() {
            let consumed = (GROUP_SIZE - self.pending.len()).min(bytes.len());
            self.pending.extend_from_slice(&bytes[..consumed]);
            bytes = &bytes[consumed..];
            if self.pending.len() == GROUP_SIZE {
                self.feed_pending()?;
            }
        }
        if self.pending.is_empty() {
            let mut groups = bytes.chunks_exact(GROUP_SIZE);
            for group in groups.by_ref() {
                self.feed_group(group)?;
            }
            bytes = groups.remainder();
        }
        self.pending.extend_from_slice(bytes);
        let added = u64::try_from(incoming).map_err(|_| VerifyError::LengthOverflow)?;
        self.length = self
            .length
            .checked_add(added)
            .ok_or(VerifyError::LengthOverflow)?;
        Ok(())
    }

    fn feed_group(&mut self, group: &[u8]) -> Result<(), VerifyError> {
        self.verifier.feed_next(group)
    }

    /// Feeds the buffered group, leaving the buffer empty but allocated.
    fn feed_pending(&mut self) -> Result<(), VerifyError> {
        let pending = std::mem::take(&mut self.pending);
        let result = self.feed_group(&pending);
        self.pending = pending;
        if result.is_ok() {
            self.pending.clear();
        }
        result
    }

    /// Computed root of the bytes accepted so far. Hash construction uses this
    /// when there is no expected identity to check.
    ///
    /// # Errors
    /// Propagates final-group or tree accumulator errors.
    pub fn digest(mut self) -> Result<Root, VerifyError> {
        if !self.pending.is_empty() {
            self.verifier.feed_next(&self.pending)?;
        }
        self.verifier.finish()
    }

    /// # Errors
    /// Rejects a suite, length, or root that does not match the accepted
    /// bytes, and propagates final-group or tree accumulator errors.
    pub fn finish(self, expected: ExpectedObject) -> Result<VerifiedObject, VerifyError> {
        if self.suite != expected.suite {
            return Err(VerifyError::SuiteMismatch);
        }
        if self.length != expected.length {
            return Err(VerifyError::LengthMismatch);
        }
        let root = self.digest()?;
        if root != expected.root {
            return Err(VerifyError::RootMismatch);
        }
        Ok(VerifiedObject {
            suite: expected.suite,
            root,
            length: expected.length,
        })
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
    verifier.digest()
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
        if !self.count.is_multiple_of(width) {
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
            let level = self.count.trailing_zeros() as usize;
            debug_assert!(1_u64 << level <= target - self.count);
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

fn zero_subtree(level: usize) -> Root {
    (0..level).fold(piece_hash(&[]), |value, _| parent(&value, &value))
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
                assert_eq!(verifier.digest().unwrap(), expected);
            }
        }
    }

    #[test]
    fn aligned_updates_are_hashed_without_buffering() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let data = fixture(3 * GROUP_SIZE);
            let mut verifier = StreamVerifier::new(suite);
            verifier.update(&data).unwrap();
            assert_eq!(verifier.buffered_bytes(), 0);
            assert_eq!(verifier.digest().unwrap(), root(suite, &data).unwrap());

            let mut split = StreamVerifier::new(suite);
            split.update(&data[..7]).unwrap();
            assert_eq!(split.buffered_bytes(), 7);
            split.update(&data[7..]).unwrap();
            assert_eq!(split.buffered_bytes(), 0);
            assert_eq!(split.digest().unwrap(), root(suite, &data).unwrap());
        }
    }

    #[test]
    fn suite_identifiers_are_the_registered_ones() {
        assert_eq!(Suite::Blake3Bao64.identifier(), 1);
        assert_eq!(Suite::Sha256Bep52.identifier(), 2);
        assert_eq!(Suite::try_from(1), Ok(Suite::Blake3Bao64));
        assert_eq!(Suite::try_from(2), Ok(Suite::Sha256Bep52));
        assert_eq!(Suite::try_from(0), Err(UnknownSuite(0)));
        assert_eq!(Suite::try_from(3), Err(UnknownSuite(3)));
    }

    #[test]
    fn group_order_and_final_length_are_enforced() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut verifier = Verifier::new(suite);
            assert_eq!(
                verifier.feed(1, &vec![0; GROUP_SIZE]),
                Err(VerifyError::GroupOutOfOrder)
            );
            assert_eq!(verifier.feed(0, &[]), Err(VerifyError::InvalidGroupLength));
            assert_eq!(
                verifier.feed(0, &vec![0; GROUP_SIZE + 1]),
                Err(VerifyError::InvalidGroupLength)
            );
            verifier.feed(0, &[1]).unwrap();
            assert_eq!(verifier.feed(1, &[2]), Err(VerifyError::GroupAfterFinal));
        }
    }

    fn patterned(length: usize, step: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from((index * step) % 251).unwrap())
            .collect()
    }

    fn hex(root: Root) -> String {
        use std::fmt::Write as _;
        root.iter()
            .fold(String::with_capacity(64), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            })
    }

    /// Known-answer roots for both suites (committed test vectors).
    #[test]
    fn suite_roots_match_the_committed_vectors() {
        const BLAKE3_STEP: usize = 31;
        const BLAKE3_CASES: [(usize, &str); 4] = [
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                65_536,
                "41f346d59742824f0994ddec8e9ef409b79edc89383484265b3c0328c07b1ba2",
            ),
            (
                327_699,
                "d86f6d9efdf00fbc8d659a073b78c28e43a512a4f028ad2bf01cedfc17f6d7da",
            ),
        ];
        const SHA256_STEP: usize = 17;
        const SHA256_CASES: [(usize, &str); 4] = [
            (
                0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            (
                65_536,
                "5d649ce791079f3b6a46c154d02bf35492dd4eaa7b33d5a6acc5dfbf1e8d7ae0",
            ),
            (
                327_699,
                "3bc7fc08b51b9bb438542846bde6e5714d2509fb1fe7761e0c3d47a9e353032e",
            ),
        ];

        for (length, expected) in BLAKE3_CASES {
            let data = patterned(length, BLAKE3_STEP);
            assert_eq!(
                hex(root(Suite::Blake3Bao64, &data).unwrap()),
                expected,
                "blake3-bao64 length {length}"
            );
        }
        for (length, expected) in SHA256_CASES {
            let data = patterned(length, SHA256_STEP);
            assert_eq!(
                hex(root(Suite::Sha256Bep52, &data).unwrap()),
                expected,
                "sha256-bep52-64k length {length}"
            );
            let mut streamed = StreamVerifier::new(Suite::Sha256Bep52);
            for chunk in data.chunks(4096) {
                streamed.update(chunk).unwrap();
            }
            assert_eq!(hex(streamed.digest().unwrap()), expected);
        }
    }

    #[test]
    fn finish_returns_a_witness_only_for_the_expected_identity() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let data = fixture(GROUP_SIZE + 17);
            let digest = root(suite, &data).unwrap();
            let expected = ExpectedObject::new(suite, digest, data.len() as u64);

            let mut verifier = StreamVerifier::new(suite);
            verifier.update(&data).unwrap();
            let witness = verifier.finish(expected).unwrap();
            assert_eq!(witness.suite(), suite);
            assert_eq!(witness.root(), digest);
            assert_eq!(witness.length(), data.len() as u64);

            let other = match suite {
                Suite::Blake3Bao64 => Suite::Sha256Bep52,
                Suite::Sha256Bep52 => Suite::Blake3Bao64,
            };
            let mut verifier = StreamVerifier::new(suite);
            verifier.update(&data).unwrap();
            assert_eq!(
                verifier.finish(ExpectedObject::new(other, digest, data.len() as u64)),
                Err(VerifyError::SuiteMismatch)
            );

            let mut verifier = StreamVerifier::new(suite);
            verifier.update(&data).unwrap();
            assert_eq!(
                verifier.finish(ExpectedObject::new(suite, digest, data.len() as u64 - 1)),
                Err(VerifyError::LengthMismatch)
            );

            let mut wrong = digest;
            wrong[0] ^= 1;
            let mut verifier = StreamVerifier::new(suite);
            verifier.update(&data).unwrap();
            assert_eq!(
                verifier.finish(ExpectedObject::new(suite, wrong, data.len() as u64)),
                Err(VerifyError::RootMismatch)
            );
        }
    }

    #[test]
    fn an_empty_stream_finishes_against_the_empty_object() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let digest = root(suite, &[]).unwrap();
            let witness = StreamVerifier::new(suite)
                .finish(ExpectedObject::new(suite, digest, 0))
                .unwrap();
            assert_eq!(witness.suite(), suite);
            assert_eq!(witness.root(), digest);
            assert_eq!(witness.length(), 0);
        }
    }
}
