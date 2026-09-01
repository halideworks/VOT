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

/// Result of reserving an authenticated range for an unlocked write.
#[derive(Debug)]
pub enum CoverageReserve {
    Replay,
    New(CoverageReservation),
}

/// A reserved authenticated range held as a value across the caller's
/// unlocked write.
#[derive(Debug)]
pub struct CoverageReservation {
    inner: vot_coverage::Reservation,
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

    /// Reserves one authenticated range for a write that happens while no
    /// borrow of this coverage is held.
    ///
    /// The reservation must come back through [`Self::commit_reservation`]
    /// or [`Self::release_reservation`]. An in-flight duplicate of a
    /// reserved range is refused as a conflict, not classified as a replay:
    /// its bytes are not covered until the holder commits, so callers retry
    /// and observe the replay then.
    pub fn reserve(&mut self, verified: &VerifiedSlice<'_>) -> Result<CoverageReserve, Error> {
        if verified.object_id() != self.object {
            return Err(Error::new(ErrorCode::IdentityMismatch));
        }
        let length = u64::try_from(verified.data().len())
            .map_err(|_| Error::new(ErrorCode::ResourceExhausted))?;
        match self
            .inner
            .reserve(verified.covered_offset(), length)
            .map_err(error::coverage)?
        {
            vot_coverage::Reserve::Replay => Ok(CoverageReserve::Replay),
            vot_coverage::Reserve::New(inner) => {
                Ok(CoverageReserve::New(CoverageReservation { inner }))
            }
        }
    }

    /// Records a reserved range whose bytes landed.
    pub fn commit_reservation(&mut self, reservation: CoverageReservation) {
        self.inner.commit_reservation(reservation.inner);
    }

    /// Releases a reserved range whose write failed.
    pub fn release_reservation(&mut self, reservation: CoverageReservation) {
        self.inner.release_reservation(reservation.inner);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{InMemoryObjectBuilder, Suite};

    fn prepared(bytes: &[u8]) -> crate::object::InMemoryPreparedObject {
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(bytes).unwrap();
        builder.finish().unwrap()
    }

    #[test]
    fn reservations_bind_to_the_object_and_change_coverage_only_on_commit() {
        let bytes = vec![0x2e; 65_536];
        let object = prepared(&bytes);
        let other = prepared(&vec![0x55; 65_536]);
        let proof = object.prove(0, 1).unwrap();
        let verified = crate::verify::verify_range(
            object.object_id(),
            proof.covered_offset(),
            &bytes,
            proof.proof(),
        )
        .unwrap();
        // A slice authenticated for another object is refused.
        let mut wrong = ObjectCoverage::new(other.object_id());
        assert_eq!(
            wrong.reserve(&verified).unwrap_err().code(),
            ErrorCode::IdentityMismatch
        );

        let mut coverage = ObjectCoverage::new(object.object_id());
        let CoverageReserve::New(held) = coverage.reserve(&verified).unwrap() else {
            panic!("a new reservation");
        };
        assert_eq!(coverage.covered_bytes(), 0);
        // A release returns the range to reservable, still uncovered.
        coverage.release_reservation(held);
        assert_eq!(coverage.covered_bytes(), 0);
        let CoverageReserve::New(held) = coverage.reserve(&verified).unwrap() else {
            panic!("reservable again after release");
        };
        // Only the commit records the range.
        coverage.commit_reservation(held);
        assert_eq!(coverage.covered_bytes(), 65_536);
        assert!(coverage.is_complete());
        assert!(matches!(
            coverage.reserve(&verified).unwrap(),
            CoverageReserve::Replay
        ));
    }
}
