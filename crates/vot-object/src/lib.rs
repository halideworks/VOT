//! Suite-neutral streaming object identity and retained range-proof preparation.

#![forbid(unsafe_code)]

use std::mem;
use std::panic::{RefUnwindSafe, UnwindSafe};

pub use vot_manifest::ObjectId;
pub use vot_proof_store::{ProofNodeStorage, StoreError};
pub use vot_verifier::Suite;
use vot_verifier::{GROUP_SIZE, StreamVerifier, VerifyError};

/// Largest object length representable by the VOT object model.
pub const MAX_OBJECT_LENGTH: u64 = i64::MAX as u64;

/// Object preparation or retained-proof failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The declared length cannot be represented by the VOT object model.
    ExpectedLengthOutOfRange,
    /// The observed byte count overflowed.
    LengthOverflow,
    /// An update would exceed the declared or representable object length.
    LengthExceeded,
    /// The stream ended before reaching its declared length.
    LengthMismatch,
    /// A requested range is empty, overflows, or lies outside the object.
    InvalidRange,
    /// A retained proof backend rejected internally consistent builder state.
    Proof,
    /// Host-provided retained proof storage failed.
    Storage(StoreError),
    /// The canonical streaming verifier rejected an update or finalization.
    Verifier(VerifyError),
}

impl From<VerifyError> for Error {
    fn from(error: VerifyError) -> Self {
        Self::Verifier(error)
    }
}

/// A group-aligned range and the proof authenticating it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeCover {
    covered_offset: u64,
    covered_length: u64,
    proof: Vec<u8>,
}

impl RangeCover {
    /// First object byte covered by the proof.
    #[must_use]
    pub const fn covered_offset(&self) -> u64 {
        self.covered_offset
    }

    /// Number of object bytes covered by the proof.
    #[must_use]
    pub const fn covered_length(&self) -> u64 {
        self.covered_length
    }

    /// Canonical suite-specific proof bytes.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Consumes the cover into its offset, length, and proof bytes.
    #[must_use]
    pub fn into_parts(self) -> (u64, u64, Vec<u8>) {
        (self.covered_offset, self.covered_length, self.proof)
    }
}

trait RetainedProofBuilder: Send + Sync + UnwindSafe + RefUnwindSafe {
    fn push(&mut self, group: &[u8]) -> Result<(), Error>;
    fn finish(self: Box<Self>) -> Result<Box<dyn RetainedProof>, Error>;
}

trait RetainedProof: Send + Sync + UnwindSafe + RefUnwindSafe {
    fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error>;
    fn holds(&self, first: usize, bytes: &[u8]) -> bool;

    /// The leaf hashes this store proves from, for a caller that means to
    /// keep them. `None` for a store that does not hold them in memory.
    fn leaves(&self) -> Option<Vec<[u8; 32]>> {
        None
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize;

    /// Whether proofs read a tree this store keeps rather than building one
    /// per proof. False for a store that has no such tree to keep.
    #[cfg(test)]
    fn proof_tree_retained(&self) -> bool {
        false
    }
}

enum MemoryProofStore {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

impl MemoryProofStore {
    fn new(suite: Suite) -> Self {
        match suite {
            Suite::Blake3Bao64 => Self::Blake3(vot_proof_blake3::GroupCvs::new()),
            Suite::Sha256Bep52 => Self::Sha256(vot_proof_sha256::PieceHashes::new()),
        }
    }
}

impl RetainedProofBuilder for MemoryProofStore {
    fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        match self {
            Self::Blake3(cvs) => cvs.push(group).map_err(|_| Error::Proof),
            Self::Sha256(pieces) => pieces.push(group).map_err(|_| Error::Proof),
        }
    }

    fn finish(mut self: Box<Self>) -> Result<Box<dyn RetainedProof>, Error> {
        // The object is complete here, so the tree every later proof reads is
        // built once rather than per proof. Without it a serve pays a hash
        // per piece of the object for every range it answers, which is the
        // whole object hashed again per answer: a 12 GB transfer spent 40 of
        // its 95 seconds of processor time there.
        match self.as_mut() {
            Self::Sha256(pieces) => pieces.seal(),
            Self::Blake3(cvs) => cvs.seal(),
        }
        Ok(self)
    }
}

impl RetainedProof for MemoryProofStore {
    fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        match self {
            Self::Blake3(cvs) => vot_proof_blake3::prove_with(cvs, offset, length)
                .map(|cover| RangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(map_blake3_error),
            Self::Sha256(pieces) => vot_proof_sha256::prove_with(pieces, offset, length)
                .map(|cover| RangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(map_sha256_error),
        }
    }

    fn holds(&self, first: usize, bytes: &[u8]) -> bool {
        bytes.chunks(GROUP_SIZE).enumerate().all(|(offset, group)| {
            match first.checked_add(offset) {
                Some(index) => match self {
                    Self::Blake3(cvs) => cvs.holds(index, group),
                    Self::Sha256(pieces) => pieces.holds(index, group),
                },
                None => false,
            }
        })
    }

    fn leaves(&self) -> Option<Vec<[u8; 32]>> {
        Some(match self {
            Self::Sha256(pieces) => pieces.piece_hashes().to_vec(),
            Self::Blake3(cvs) => cvs.group_cvs().to_vec(),
        })
    }

    #[cfg(test)]
    fn proof_tree_retained(&self) -> bool {
        match self {
            Self::Sha256(pieces) => pieces.sealed(),
            Self::Blake3(cvs) => cvs.sealed(),
        }
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize {
        match self {
            Self::Blake3(cvs) => cvs.groups(),
            Self::Sha256(pieces) => pieces.pieces(),
        }
    }
}

enum StoredProofBuilder {
    Blake3(vot_proof_blake3::StoredGroupCvs),
    Sha256(vot_proof_sha256::StoredPieceHashes),
}

impl StoredProofBuilder {
    fn new(suite: Suite, storage: Box<dyn ProofNodeStorage>) -> Result<Self, Error> {
        match suite {
            Suite::Blake3Bao64 => vot_proof_blake3::StoredGroupCvs::new(storage)
                .map(Self::Blake3)
                .map_err(map_blake3_error),
            Suite::Sha256Bep52 => vot_proof_sha256::StoredPieceHashes::new(storage)
                .map(Self::Sha256)
                .map_err(map_sha256_error),
        }
    }
}

impl RetainedProofBuilder for StoredProofBuilder {
    fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        match self {
            Self::Blake3(cvs) => cvs.push(group).map_err(map_blake3_error),
            Self::Sha256(pieces) => pieces.push(group).map_err(map_sha256_error),
        }
    }

    fn finish(self: Box<Self>) -> Result<Box<dyn RetainedProof>, Error> {
        match *self {
            Self::Blake3(cvs) => cvs
                .finish()
                .map(|sealed| Box::new(sealed) as Box<dyn RetainedProof>)
                .map_err(map_blake3_error),
            Self::Sha256(pieces) => pieces
                .finish()
                .map(|sealed| Box::new(sealed) as Box<dyn RetainedProof>)
                .map_err(map_sha256_error),
        }
    }
}

impl RetainedProof for vot_proof_blake3::SealedGroupCvs {
    fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        vot_proof_blake3::SealedGroupCvs::prove(self, offset, length)
            .map(|cover| RangeCover {
                covered_offset: cover.covered_offset,
                covered_length: cover.covered_length,
                proof: cover.proof,
            })
            .map_err(map_blake3_error)
    }

    fn holds(&self, first: usize, bytes: &[u8]) -> bool {
        bytes.chunks(GROUP_SIZE).enumerate().all(|(offset, group)| {
            match first.checked_add(offset) {
                Some(index) => vot_proof_blake3::SealedGroupCvs::holds(self, index, group),
                None => false,
            }
        })
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize {
        self.groups()
    }
}

impl RetainedProof for vot_proof_sha256::SealedPieceHashes {
    fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        vot_proof_sha256::SealedPieceHashes::prove(self, offset, length)
            .map(|cover| RangeCover {
                covered_offset: cover.covered_offset,
                covered_length: cover.covered_length,
                proof: cover.proof,
            })
            .map_err(map_sha256_error)
    }

    fn holds(&self, first: usize, bytes: &[u8]) -> bool {
        bytes.chunks(GROUP_SIZE).enumerate().all(|(offset, group)| {
            match first.checked_add(offset) {
                Some(index) => vot_proof_sha256::SealedPieceHashes::holds(self, index, group),
                None => false,
            }
        })
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize {
        usize::try_from(self.pieces()).unwrap()
    }
}

fn map_blake3_error(error: vot_proof_blake3::Error) -> Error {
    match error {
        vot_proof_blake3::Error::EmptyRange | vot_proof_blake3::Error::OutOfBounds => {
            Error::InvalidRange
        }
        vot_proof_blake3::Error::LengthOverflow => Error::LengthOverflow,
        vot_proof_blake3::Error::MalformedProof | vot_proof_blake3::Error::HashMismatch => {
            Error::Proof
        }
        vot_proof_blake3::Error::Storage(error) => Error::Storage(error),
    }
}

fn map_sha256_error(error: vot_proof_sha256::Error) -> Error {
    match error {
        vot_proof_sha256::Error::EmptyRange | vot_proof_sha256::Error::OutOfBounds => {
            Error::InvalidRange
        }
        vot_proof_sha256::Error::LengthOverflow => Error::LengthOverflow,
        vot_proof_sha256::Error::MalformedProof | vot_proof_sha256::Error::HashMismatch => {
            Error::Proof
        }
        vot_proof_sha256::Error::Storage(error) => Error::Storage(error),
    }
}

/// Streams one immutable object into canonical identity and retained proof material.
pub struct ObjectBuilder {
    suite: Suite,
    expected_length: Option<u64>,
    length: u64,
    verifier: StreamVerifier,
    proof: Box<dyn RetainedProofBuilder>,
    pending: Vec<u8>,
    failure: Option<Error>,
    #[cfg(test)]
    fail_after_verifier: bool,
}

impl ObjectBuilder {
    /// Starts an object builder without allocating from the declared length.
    ///
    /// # Errors
    ///
    /// Rejects an expected length outside the VOT object model.
    pub fn new(suite: Suite, expected_length: Option<u64>) -> Result<Self, Error> {
        Self::with_builder(
            suite,
            expected_length,
            Box::new(MemoryProofStore::new(suite)),
        )
    }

    /// Starts an object builder backed by caller-provided proof-node storage.
    ///
    /// The store must be empty. Its availability is temporary preparation
    /// state and does not establish durability or any assurance transition.
    ///
    /// # Errors
    ///
    /// Rejects an invalid expected length or unavailable, corrupt, or nonempty storage.
    pub fn with_proof_storage(
        suite: Suite,
        expected_length: Option<u64>,
        storage: Box<dyn ProofNodeStorage>,
    ) -> Result<Self, Error> {
        if expected_length.is_some_and(|length| length > MAX_OBJECT_LENGTH) {
            return Err(Error::ExpectedLengthOutOfRange);
        }
        let proof = Box::new(StoredProofBuilder::new(suite, storage)?);
        Self::with_builder(suite, expected_length, proof)
    }

    fn with_builder(
        suite: Suite,
        expected_length: Option<u64>,
        proof: Box<dyn RetainedProofBuilder>,
    ) -> Result<Self, Error> {
        if expected_length.is_some_and(|length| length > MAX_OBJECT_LENGTH) {
            return Err(Error::ExpectedLengthOutOfRange);
        }
        Ok(Self {
            suite,
            expected_length,
            length: 0,
            verifier: StreamVerifier::new(suite),
            proof,
            pending: Vec::with_capacity(GROUP_SIZE),
            failure: None,
            #[cfg(test)]
            fail_after_verifier: false,
        })
    }

    #[cfg(test)]
    const fn observed_length(&self) -> u64 {
        self.length
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.pending.len()
    }

    /// Adds the next contiguous bytes.
    ///
    /// Expected-length and arithmetic failures occur before state changes and
    /// are retryable. A verifier or proof failure permanently poisons the builder.
    ///
    /// # Errors
    ///
    /// Rejects length overflow, bytes beyond the declared length, and backend failures.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let incoming = u64::try_from(bytes.len()).map_err(|_| Error::LengthOverflow)?;
        let next_length = self
            .length
            .checked_add(incoming)
            .ok_or(Error::LengthOverflow)?;
        if next_length > MAX_OBJECT_LENGTH
            || self
                .expected_length
                .is_some_and(|expected| next_length > expected)
        {
            return Err(Error::LengthExceeded);
        }
        match self.update_inner(bytes) {
            Ok(()) => {
                self.length = next_length;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error);
                Err(error)
            }
        }
    }

    fn update_inner(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
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
        Ok(())
    }

    fn feed_pending(&mut self) -> Result<(), Error> {
        let pending = mem::take(&mut self.pending);
        let result = self.feed_group(&pending);
        self.pending = pending;
        if result.is_ok() {
            self.pending.clear();
        }
        result
    }

    fn feed_group(&mut self, group: &[u8]) -> Result<(), Error> {
        self.verifier.update(group)?;
        #[cfg(test)]
        if self.fail_after_verifier {
            self.fail_after_verifier = false;
            return Err(Error::Proof);
        }
        self.proof.push(group)
    }

    /// Finishes the object and binds its proof material to the resulting identity.
    ///
    /// # Errors
    ///
    /// Rejects prior backend failure, an expected-length mismatch, or finalization failure.
    pub fn finish(mut self) -> Result<PreparedObject, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self
            .expected_length
            .is_some_and(|expected| expected != self.length)
        {
            return Err(Error::LengthMismatch);
        }
        if !self.pending.is_empty() {
            self.feed_pending()?;
        }
        let root = self.verifier.digest()?;
        let proof = self.proof.finish()?;
        Ok(PreparedObject {
            object: ObjectId {
                suite: self.suite.identifier(),
                root,
                length: self.length,
            },
            proof,
        })
    }
}

/// An immutable object identity bound to the material needed for range proofs.
pub struct PreparedObject {
    object: ObjectId,
    proof: Box<dyn RetainedProof>,
}

impl PreparedObject {
    /// Canonical identity of the bytes supplied to the builder.
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object
    }

    /// The leaf hashes the proofs are read from, for a caller that means to
    /// keep them beside the object and prepare from them next time.
    #[must_use]
    pub fn proof_leaves(&self) -> Option<Vec<[u8; 32]>> {
        self.proof.leaves()
    }

    /// Prepares an object from leaf hashes a caller kept, without reading
    /// the object itself.
    ///
    /// The leaves are not an authority: what comes back names the object
    /// they describe, and a caller that already knows the root compares the
    /// two before serving anything. A caller that does not know the root has
    /// no business calling this.
    ///
    /// # Errors
    /// Rejects leaves that cannot describe an object of this length, and an
    /// object short enough that its root is not the top of a tree.
    pub fn from_proof_leaves(
        suite: Suite,
        length: u64,
        leaves: Vec<[u8; 32]>,
    ) -> Result<Self, Error> {
        let (proof, root): (Box<dyn RetainedProof>, [u8; 32]) = match suite {
            Suite::Sha256Bep52 => {
                let pieces = vot_proof_sha256::PieceHashes::from_piece_hashes(leaves, length)
                    .map_err(map_sha256_error)?;
                let root = pieces.tree_root().ok_or(Error::Proof)?;
                (Box::new(MemoryProofStore::Sha256(pieces)), root)
            }
            Suite::Blake3Bao64 => {
                let cvs = vot_proof_blake3::GroupCvs::from_group_cvs(leaves, length)
                    .map_err(map_blake3_error)?;
                let root = cvs.tree_root().ok_or(Error::Proof)?;
                (Box::new(MemoryProofStore::Blake3(cvs)), root)
            }
        };
        Ok(Self {
            object: ObjectId {
                suite: suite.identifier(),
                root,
                length,
            },
            proof,
        })
    }

    /// Creates the canonical proof for a requested range.
    ///
    /// # Errors
    ///
    /// Rejects an empty, overflowing, or out-of-bounds range.
    pub fn prove(&self, offset: u64, length: u64) -> Result<RangeCover, Error> {
        self.proof.prove(offset, length)
    }

    /// Whether aligned readback bytes match the retained preparation material.
    #[must_use]
    pub fn holds(&self, covered_offset: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() || covered_offset % GROUP_SIZE as u64 != 0 {
            return false;
        }
        let Ok(length) = u64::try_from(bytes.len()) else {
            return false;
        };
        let Some(end) = covered_offset.checked_add(length) else {
            return false;
        };
        if end > self.object.length {
            return false;
        }
        let Ok(first) = usize::try_from(covered_offset / GROUP_SIZE as u64) else {
            return false;
        };
        self.proof.holds(first, bytes)
    }

    #[cfg(test)]
    fn retained_units(&self) -> usize {
        self.proof.retained_units()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_finished_sha256_store_retains_its_tree() {
        // Without this the store rebuilds the whole piece tree for every
        // range it proves, which is the object hashed again per answer: a
        // 12 GB transfer spent 40 of its 95 seconds of processor there and
        // the cost per byte grew with the object.
        let mut store = Box::new(MemoryProofStore::new(Suite::Sha256Bep52));
        let piece =
            vec![3_u8; usize::try_from(vot_proof_sha256::PIECE_SIZE).expect("a piece fits")];
        store.push(&piece).unwrap();
        store.push(&piece).unwrap();
        store.push(&piece).unwrap();
        let retained = store.finish().unwrap();
        assert!(
            retained.proof_tree_retained(),
            "a finished store proves from a tree it keeps"
        );
    }

    use std::fmt::Write as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use vot_proof_store::{MemoryNodeStorage, ProofNode};

    fn assert_auto_traits<T: Send + Sync + UnwindSafe + RefUnwindSafe>() {}

    #[test]
    fn builders_and_prepared_objects_keep_their_auto_traits() {
        assert_auto_traits::<ObjectBuilder>();
        assert_auto_traits::<PreparedObject>();
    }

    fn fixture(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from(index.wrapping_mul(31) % 251).unwrap())
            .collect()
    }

    fn prepared(suite: Suite, bytes: &[u8], chunk: usize) -> PreparedObject {
        let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).unwrap();
        for part in bytes.chunks(chunk) {
            builder.update(part).unwrap();
            assert!(builder.buffered_bytes() <= GROUP_SIZE);
        }
        builder.finish().unwrap()
    }

    fn prepared_stored(suite: Suite, bytes: &[u8], chunk: usize) -> PreparedObject {
        let mut builder = ObjectBuilder::with_proof_storage(
            suite,
            Some(bytes.len() as u64),
            Box::new(MemoryNodeStorage::new()),
        )
        .unwrap();
        for part in bytes.chunks(chunk) {
            builder.update(part).unwrap();
            assert!(builder.buffered_bytes() <= GROUP_SIZE);
        }
        builder.finish().unwrap()
    }

    #[test]
    fn host_backed_preparation_matches_the_default_backend() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [0, 1, GROUP_SIZE, GROUP_SIZE + 1, 5 * GROUP_SIZE + 71] {
                let bytes = fixture(length);
                let memory = prepared(suite, &bytes, 7_919);
                let stored = prepared_stored(suite, &bytes, 4_093);
                assert_eq!(stored.object_id(), memory.object_id());
                assert_eq!(stored.retained_units(), memory.retained_units());
                if !bytes.is_empty() {
                    for (offset, requested) in
                        [(0, 1), (bytes.len() as u64 - 1, 1), (0, bytes.len() as u64)]
                    {
                        assert_eq!(
                            stored.prove(offset, requested),
                            memory.prove(offset, requested)
                        );
                    }
                    assert!(stored.holds(0, &bytes));
                }
            }
        }
    }

    #[test]
    fn host_backed_forwarding_preserves_nontrivial_results() {
        let bytes = fixture(2 * GROUP_SIZE + 71);
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let stored = prepared_stored(suite, &bytes, 4_093);
            let cover = stored.prove(1, 1).unwrap();
            assert_eq!(cover.covered_offset(), 0);
            assert_eq!(cover.covered_length(), GROUP_SIZE as u64);
            assert!(!cover.proof().is_empty());
            assert!(stored.holds(0, &bytes[..GROUP_SIZE]));
            let mut changed = bytes[..GROUP_SIZE].to_vec();
            changed[0] ^= 1;
            assert!(!stored.holds(0, &changed));
        }
    }

    #[test]
    fn host_storage_preflights_and_failures_are_typed() {
        struct PanicStorage;
        impl ProofNodeStorage for PanicStorage {
            fn len(&self) -> Result<u64, StoreError> {
                panic!("length preflight must run before storage access")
            }
            fn append(&mut self, _node: ProofNode) -> Result<(), StoreError> {
                unreachable!()
            }
            fn read(&self, _ordinal: u64) -> Result<ProofNode, StoreError> {
                unreachable!()
            }
        }
        assert!(matches!(
            ObjectBuilder::with_proof_storage(
                Suite::Blake3Bao64,
                Some(MAX_OBJECT_LENGTH + 1),
                Box::new(PanicStorage)
            ),
            Err(Error::ExpectedLengthOutOfRange)
        ));

        let mut nonempty = MemoryNodeStorage::new();
        nonempty.append([7; 32]).unwrap();
        assert!(matches!(
            ObjectBuilder::with_proof_storage(Suite::Sha256Bep52, None, Box::new(nonempty)),
            Err(Error::Storage(StoreError::Corrupt))
        ));

        let maximum = ObjectBuilder::with_proof_storage(
            Suite::Blake3Bao64,
            Some(MAX_OBJECT_LENGTH),
            Box::new(MemoryNodeStorage::new()),
        );
        assert!(maximum.is_ok());
        let builder = maximum.unwrap();
        assert_eq!(builder.suite, Suite::Blake3Bao64);
        assert_eq!(builder.expected_length, Some(MAX_OBJECT_LENGTH));
        assert_eq!(builder.observed_length(), 0);
        assert_eq!(builder.buffered_bytes(), 0);
    }

    #[test]
    fn host_backed_updates_advance_exactly_once() {
        let mut builder = ObjectBuilder::with_proof_storage(
            Suite::Sha256Bep52,
            Some(3),
            Box::new(MemoryNodeStorage::new()),
        )
        .unwrap();
        builder.update(b"abc").unwrap();
        assert_eq!(builder.observed_length(), 3);
        assert_eq!(builder.buffered_bytes(), 3);
        assert_eq!(builder.finish().unwrap().object_id().length, 3);
    }

    struct FailingStorage {
        inner: MemoryNodeStorage,
        fail_append: bool,
        fail_read: Arc<AtomicBool>,
    }

    impl ProofNodeStorage for FailingStorage {
        fn len(&self) -> Result<u64, StoreError> {
            self.inner.len()
        }

        fn append(&mut self, node: ProofNode) -> Result<(), StoreError> {
            if self.fail_append {
                self.inner.append(node)?;
                return Err(StoreError::Unavailable);
            }
            self.inner.append(node)
        }

        fn read(&self, ordinal: u64) -> Result<ProofNode, StoreError> {
            if self.fail_read.load(Ordering::Relaxed) {
                return Err(StoreError::Unavailable);
            }
            self.inner.read(ordinal)
        }
    }

    #[test]
    fn host_append_failure_poisons_the_object_builder() {
        let storage = FailingStorage {
            inner: MemoryNodeStorage::new(),
            fail_append: true,
            fail_read: Arc::new(AtomicBool::new(false)),
        };
        let mut builder =
            ObjectBuilder::with_proof_storage(Suite::Blake3Bao64, None, Box::new(storage)).unwrap();
        let error = builder.update(&vec![0; GROUP_SIZE]).unwrap_err();
        assert_eq!(error, Error::Storage(StoreError::Unavailable));
        assert_eq!(builder.update(&[]), Err(error));
        assert!(matches!(builder.finish(), Err(failure) if failure == error));
    }

    #[test]
    fn host_append_failure_on_the_final_short_group_fails_closed() {
        let storage = FailingStorage {
            inner: MemoryNodeStorage::new(),
            fail_append: true,
            fail_read: Arc::new(AtomicBool::new(false)),
        };
        let mut builder =
            ObjectBuilder::with_proof_storage(Suite::Sha256Bep52, Some(7), Box::new(storage))
                .unwrap();
        builder.update(b"partial").unwrap();
        assert!(matches!(
            builder.finish(),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn host_read_failure_aborts_finish_without_a_prepared_object() {
        let fail_read = Arc::new(AtomicBool::new(false));
        let storage = FailingStorage {
            inner: MemoryNodeStorage::new(),
            fail_append: false,
            fail_read: Arc::clone(&fail_read),
        };
        let mut builder = ObjectBuilder::with_proof_storage(
            Suite::Sha256Bep52,
            Some((2 * GROUP_SIZE) as u64),
            Box::new(storage),
        )
        .unwrap();
        builder.update(&vec![0; 2 * GROUP_SIZE]).unwrap();
        fail_read.store(true, Ordering::Relaxed);
        assert!(matches!(
            builder.finish(),
            Err(Error::Storage(StoreError::Unavailable))
        ));
    }

    #[test]
    fn roots_are_suite_exact_across_lengths_and_chunking() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [
                0,
                1,
                16_384,
                GROUP_SIZE,
                GROUP_SIZE + 1,
                3 * GROUP_SIZE + 71,
            ] {
                let bytes = fixture(length);
                let expected = vot_verifier::root(suite, &bytes).unwrap();
                for chunk in [1, 511, GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE + 1] {
                    let object = prepared(suite, &bytes, chunk);
                    assert_eq!(object.object_id().suite, suite.identifier());
                    assert_eq!(object.object_id().root, expected);
                    assert_eq!(object.object_id().length, length as u64);
                    assert_eq!(object.retained_units(), length.div_ceil(GROUP_SIZE));
                }
            }
        }
    }

    #[test]
    fn literal_roots_pin_both_suite_transcripts() {
        let one = [0_u8];
        for (suite, bytes, expected) in [
            (
                Suite::Blake3Bao64,
                &[][..],
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                Suite::Blake3Bao64,
                &one[..],
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                Suite::Sha256Bep52,
                &[][..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                Suite::Sha256Bep52,
                &one[..],
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
        ] {
            let actual = prepared(suite, bytes, 1).object_id().root;
            let rendered = actual.iter().fold(
                String::with_capacity(actual.len() * 2),
                |mut rendered, byte| {
                    write!(rendered, "{byte:02x}").unwrap();
                    rendered
                },
            );
            assert_eq!(rendered, expected);
        }
    }

    #[test]
    fn retained_proofs_equal_cold_proofs_and_verify() {
        let bytes = fixture(4 * GROUP_SIZE + 71);
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let object = prepared(suite, &bytes, 7_919);
            for (offset, length) in [
                (0, 1),
                (1, 1),
                (GROUP_SIZE as u64 + 17, 90_000),
                (bytes.len() as u64 - 1, 1),
            ] {
                let cover = object.prove(offset, length).unwrap();
                let start = usize::try_from(cover.covered_offset()).unwrap();
                let cover_length = usize::try_from(cover.covered_length()).unwrap();
                let end = start.checked_add(cover_length).unwrap();
                match suite {
                    Suite::Blake3Bao64 => {
                        let cold = vot_proof_blake3::prove(&bytes, offset, length).unwrap();
                        assert_eq!(cover.covered_offset(), cold.covered_offset);
                        assert_eq!(cover.covered_length(), cold.data.len() as u64);
                        assert_eq!(cover.proof(), cold.proof);
                        vot_proof_blake3::verify(
                            &object.object_id().root,
                            object.object_id().length,
                            cover.covered_offset(),
                            &bytes[start..end],
                            cover.proof(),
                        )
                        .unwrap();
                    }
                    Suite::Sha256Bep52 => {
                        let cold = vot_proof_sha256::prove(&bytes, offset, length).unwrap();
                        assert_eq!(cover.covered_offset(), cold.covered_offset);
                        assert_eq!(cover.covered_length(), cold.data.len() as u64);
                        assert_eq!(cover.proof(), cold.proof);
                        vot_proof_sha256::verify(
                            &object.object_id().root,
                            object.object_id().length,
                            cover.covered_offset(),
                            &bytes[start..end],
                            cover.proof(),
                        )
                        .unwrap();
                    }
                }
                let expected_parts = (
                    cover.covered_offset(),
                    cover.covered_length(),
                    cover.proof().to_vec(),
                );
                assert_eq!(cover.into_parts(), expected_parts);
            }
        }
    }

    #[test]
    fn readback_checks_content_position_and_bounds() {
        let bytes = fixture(3 * GROUP_SIZE + 71);
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let object = prepared(suite, &bytes, 4_093);
            assert!(object.holds(0, &bytes[..GROUP_SIZE]));
            assert!(object.holds(GROUP_SIZE as u64, &bytes[GROUP_SIZE..2 * GROUP_SIZE]));
            assert!(object.holds(0, &bytes));
            let mut altered = bytes[..GROUP_SIZE].to_vec();
            altered[0] ^= 1;
            assert!(!object.holds(0, &altered));
            assert!(!object.holds(1, &bytes[..GROUP_SIZE]));
            assert!(!object.holds(0, &[]));
            assert!(!object.holds(u64::MAX - 1, &[0; 4]));
            assert!(object.holds(3 * GROUP_SIZE as u64, &bytes[3 * GROUP_SIZE..]));
            assert!(!object.holds(
                3 * GROUP_SIZE as u64,
                &bytes[3 * GROUP_SIZE..bytes.len() - 1]
            ));
        }
    }

    #[test]
    fn expected_length_preflights_are_retryable_and_exact() {
        assert!(matches!(
            ObjectBuilder::new(Suite::Blake3Bao64, Some(MAX_OBJECT_LENGTH + 1)),
            Err(Error::ExpectedLengthOutOfRange)
        ));

        let mut exact = ObjectBuilder::new(Suite::Blake3Bao64, Some(3)).unwrap();
        exact.update(b"abc").unwrap();
        assert_eq!(exact.finish().unwrap().object_id().length, 3);

        let mut short = ObjectBuilder::new(Suite::Blake3Bao64, Some(4)).unwrap();
        short.update(b"abc").unwrap();
        assert!(matches!(short.finish(), Err(Error::LengthMismatch)));

        let mut retry = ObjectBuilder::new(Suite::Blake3Bao64, Some(3)).unwrap();
        assert_eq!(retry.update(b"abcd"), Err(Error::LengthExceeded));
        assert_eq!(retry.observed_length(), 0);
        assert_eq!(retry.buffered_bytes(), 0);
        retry.update(b"abc").unwrap();
        retry.finish().unwrap();
    }

    #[test]
    fn arithmetic_and_backend_failures_have_distinct_atomicity() {
        let mut too_long = ObjectBuilder::new(Suite::Blake3Bao64, None).unwrap();
        too_long.length = MAX_OBJECT_LENGTH;
        too_long.update(&[]).unwrap();
        assert_eq!(too_long.update(&[0]), Err(Error::LengthExceeded));
        too_long.length = u64::MAX;
        assert_eq!(too_long.update(&[0]), Err(Error::LengthOverflow));

        let mut poisoned = ObjectBuilder::new(Suite::Blake3Bao64, None).unwrap();
        poisoned.fail_after_verifier = true;
        let error = poisoned.update(&vec![0; GROUP_SIZE]).unwrap_err();
        assert_eq!(error, Error::Proof);
        assert_eq!(poisoned.update(&[]), Err(error));
        assert!(matches!(poisoned.finish(), Err(failure) if failure == error));
    }

    #[test]
    fn empty_updates_and_exact_groups_do_not_add_empty_units() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let mut empty = ObjectBuilder::new(suite, Some(0)).unwrap();
            empty.update(&[]).unwrap();
            assert_eq!(empty.finish().unwrap().retained_units(), 0);

            let bytes = fixture(GROUP_SIZE);
            let mut exact = ObjectBuilder::new(suite, Some(GROUP_SIZE as u64)).unwrap();
            exact.update(&bytes).unwrap();
            assert_eq!(exact.buffered_bytes(), 0);
            assert_eq!(exact.finish().unwrap().retained_units(), 1);
        }
    }

    #[test]
    fn invalid_ranges_are_suite_neutral() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let object = prepared(suite, b"abc", 2);
            assert_eq!(object.prove(0, 0), Err(Error::InvalidRange));
            assert_eq!(object.prove(3, 1), Err(Error::InvalidRange));
            assert_eq!(object.prove(u64::MAX, 2), Err(Error::LengthOverflow));
        }
    }
}
