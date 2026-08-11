//! Identity-bound bookkeeping for authenticated object ranges.

use crate::error;
use crate::object::ObjectId;
use crate::verify::VerifiedSlice;
use crate::{Error, ErrorCode};

pub const MAX_FRAGMENTS: usize = vot_coverage::MAX_FRAGMENTS;

/// Result of accepting an authenticated range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageUpdate {
    Accepted,
    Replay,
}

/// Coverage that accepts authenticated ranges for exactly one object.
#[derive(Debug)]
pub struct ObjectCoverage {
    object: ObjectId,
    inner: vot_coverage::Coverage,
}

impl ObjectCoverage {
    #[must_use]
    pub fn new(object: &ObjectId) -> Self {
        Self {
            object: object.clone(),
            inner: vot_coverage::Coverage::new(),
        }
    }

    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object
    }

    /// Accepts one already authenticated range for this exact object.
    pub fn accept(&mut self, verified: &VerifiedSlice<'_>) -> Result<CoverageUpdate, Error> {
        if verified.object_id() != self.object {
            return Err(Error::new(ErrorCode::IdentityMismatch));
        }
        let length = u64::try_from(verified.data().len())
            .map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
        match self
            .inner
            .check(verified.covered_offset(), length)
            .map_err(error::coverage)?
        {
            vot_coverage::Check::Replay => Ok(CoverageUpdate::Replay),
            vot_coverage::Check::New(booking) => {
                booking.commit();
                Ok(CoverageUpdate::Accepted)
            }
        }
    }

    #[must_use]
    pub const fn covered_bytes(&self) -> u64 {
        self.inner.covered_bytes()
    }

    #[must_use]
    pub fn fragment_count(&self) -> usize {
        self.inner.fragment_count()
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.inner.is_complete(self.object.length)
    }
}
