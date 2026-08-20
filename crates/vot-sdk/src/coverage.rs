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

/// Result of checking an authenticated range before accepting its bytes.
#[derive(Debug)]
pub enum CoverageCheck<'coverage> {
    Replay,
    New(CoverageBooking<'coverage>),
}

/// A checked authenticated range that has not yet entered verified coverage.
#[derive(Debug)]
pub struct CoverageBooking<'coverage> {
    inner: vot_coverage::Booking<'coverage>,
}

impl CoverageBooking<'_> {
    /// Records the range after its bytes have been accepted by the caller.
    pub fn commit(self) {
        self.inner.commit();
    }
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

    /// Checks one authenticated range without changing coverage.
    ///
    /// A new range returns a booking that the caller commits only after its
    /// fallible destination write succeeds.
    pub fn check(&mut self, verified: &VerifiedSlice<'_>) -> Result<CoverageCheck<'_>, Error> {
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
            vot_coverage::Check::Replay => Ok(CoverageCheck::Replay),
            vot_coverage::Check::New(inner) => Ok(CoverageCheck::New(CoverageBooking { inner })),
        }
    }

    /// Accepts one already authenticated range for this exact object.
    pub fn accept(&mut self, verified: &VerifiedSlice<'_>) -> Result<CoverageUpdate, Error> {
        match self.check(verified)? {
            CoverageCheck::Replay => Ok(CoverageUpdate::Replay),
            CoverageCheck::New(booking) => {
                booking.commit();
                Ok(CoverageUpdate::Accepted)
            }
        }
    }

    #[must_use]
    pub const fn covered_bytes(&self) -> u64 {
        self.inner.covered_bytes()
    }

    /// Bytes covered contiguously from offset zero; the safe resume point.
    #[must_use]
    pub fn contiguous_prefix(&self) -> u64 {
        self.inner.contiguous_prefix()
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
