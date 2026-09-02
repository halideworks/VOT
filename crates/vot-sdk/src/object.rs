//! Bounded in-memory object preparation.

pub use vot_object::{ObjectId, Suite};

use crate::error;
use crate::{Error, ErrorCode};

pub const MAX_OBJECT_LENGTH: u64 = vot_object::MAX_OBJECT_LENGTH;
pub const PROOF_LEAF_SIZE: u64 = vot_object::PROOF_LEAF_SIZE;

/// In-memory preparation with an explicit bound on retained proof material.
pub struct InMemoryObjectBuilder {
    inner: vot_object::ObjectBuilder,
    observed_length: u64,
    max_object_length: u64,
}

impl InMemoryObjectBuilder {
    pub fn new(
        suite: Suite,
        expected_length: Option<u64>,
        max_object_length: u64,
    ) -> Result<Self, Error> {
        if max_object_length > MAX_OBJECT_LENGTH {
            return Err(Error::new(ErrorCode::InvalidInput));
        }
        if expected_length.is_some_and(|length| length > max_object_length) {
            return Err(Error::new(ErrorCode::LimitExceeded));
        }
        Ok(Self {
            inner: vot_object::ObjectBuilder::new(suite, expected_length).map_err(error::object)?,
            observed_length: 0,
            max_object_length,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let incoming =
            u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::LimitExceeded))?;
        let next = self
            .observed_length
            .checked_add(incoming)
            .ok_or_else(|| Error::new(ErrorCode::LimitExceeded))?;
        if next > self.max_object_length {
            return Err(Error::new(ErrorCode::LimitExceeded));
        }
        self.inner.update(bytes).map_err(error::object)?;
        self.observed_length = next;
        Ok(())
    }

    pub fn finish(self) -> Result<InMemoryPreparedObject, Error> {
        self.inner
            .finish()
            .map(|inner| InMemoryPreparedObject { inner })
            .map_err(error::object)
    }
}

/// The proof leaves of one segment hashed where it sits in an object of
/// `object_length` bytes, so an object can be prepared from segments hashed
/// independently. A segment must start on a leaf and be whole leaves unless
/// it ends the object.
pub fn proof_leaves_at(
    suite: Suite,
    offset: u64,
    bytes: &[u8],
    object_length: u64,
) -> Result<Vec<[u8; 32]>, Error> {
    vot_object::proof_leaves_at(suite, offset, bytes, object_length).map_err(error::object)
}

/// Object identity bound to in-memory retained proof material.
pub struct InMemoryPreparedObject {
    inner: vot_object::PreparedObject,
}

impl InMemoryPreparedObject {
    /// Prepares an object from leaves the caller hashed with
    /// [`proof_leaves_at`], under the same length bound the builder applies.
    /// The leaves name the object; nothing checks them against a root the
    /// caller may already hold. An object of one leaf or less has no tree to
    /// assemble and is refused; hash it with the builder.
    pub fn from_proof_leaves(
        suite: Suite,
        length: u64,
        leaves: Vec<[u8; 32]>,
        max_object_length: u64,
    ) -> Result<Self, Error> {
        if max_object_length > MAX_OBJECT_LENGTH {
            return Err(Error::new(ErrorCode::InvalidInput));
        }
        if length > max_object_length {
            return Err(Error::new(ErrorCode::LimitExceeded));
        }
        vot_object::PreparedObject::from_proof_leaves(suite, length, leaves)
            .map(|inner| Self { inner })
            .map_err(error::object)
    }

    #[must_use]
    pub fn object_id(&self) -> &ObjectId {
        self.inner.object_id()
    }

    pub fn prove(&self, offset: u64, length: u64) -> Result<RangeProof, Error> {
        self.inner
            .prove(offset, length)
            .map(|inner| RangeProof { inner })
            .map_err(error::object)
    }

    #[must_use]
    pub fn holds(&self, covered_offset: u64, bytes: &[u8]) -> bool {
        self.inner.holds(covered_offset, bytes)
    }

    pub(crate) const fn inner(&self) -> &vot_object::PreparedObject {
        &self.inner
    }
}

/// Group-aligned range and canonical proof bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeProof {
    inner: vot_object::RangeCover,
}

impl RangeProof {
    #[must_use]
    pub const fn covered_offset(&self) -> u64 {
        self.inner.covered_offset()
    }

    #[must_use]
    pub const fn covered_length(&self) -> u64 {
        self.inner.covered_length()
    }

    #[must_use]
    pub fn proof(&self) -> &[u8] {
        self.inner.proof()
    }

    #[must_use]
    pub fn into_parts(self) -> (u64, u64, Vec<u8>) {
        self.inner.into_parts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembling_from_leaves_keeps_the_builder_bounds() {
        let leaf = usize::try_from(PROOF_LEAF_SIZE).unwrap();
        let data = vec![7u8; leaf * 2 + 9];
        let length = data.len() as u64;
        let leaves = proof_leaves_at(Suite::Blake3Bao64, 0, &data, length).unwrap();
        let assembled = InMemoryPreparedObject::from_proof_leaves(
            Suite::Blake3Bao64,
            length,
            leaves.clone(),
            length,
        )
        .unwrap();
        let mut builder =
            InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(length), length).unwrap();
        builder.update(&data).unwrap();
        assert_eq!(assembled.object_id(), builder.finish().unwrap().object_id());
        let over = InMemoryPreparedObject::from_proof_leaves(
            Suite::Blake3Bao64,
            length,
            leaves.clone(),
            MAX_OBJECT_LENGTH + 1,
        );
        assert_eq!(over.err().map(|e| e.code()), Some(ErrorCode::InvalidInput));
        let too_long = InMemoryPreparedObject::from_proof_leaves(
            Suite::Blake3Bao64,
            length,
            leaves,
            length - 1,
        );
        assert_eq!(
            too_long.err().map(|e| e.code()),
            Some(ErrorCode::LimitExceeded)
        );
    }
}
