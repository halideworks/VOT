//! Bounded in-memory object preparation.

pub use vot_object::{ObjectId, Suite};

use crate::error;
use crate::{Error, ErrorCode};

pub const MAX_OBJECT_LENGTH: u64 = vot_object::MAX_OBJECT_LENGTH;

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

/// Object identity bound to in-memory retained proof material.
pub struct InMemoryPreparedObject {
    inner: vot_object::PreparedObject,
}

impl InMemoryPreparedObject {
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
