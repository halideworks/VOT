//! Bounded, dependency-free bookkeeping for accepted byte ranges.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Maximum disjoint covered extents retained for one object.
pub const MAX_FRAGMENTS: usize = 4096;

/// A coverage check or commit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyRange,
    LengthExceeded,
    PartialOverlap,
    FragmentsExhausted,
}

/// Result of checking a range against accepted coverage.
#[derive(Debug)]
pub enum Check<'coverage> {
    /// The range is wholly contained in an accepted extent.
    Replay,
    /// The range is new and may be committed after its bytes are accepted.
    New(Booking<'coverage>),
}

/// A checked range that exclusively borrows its originating coverage.
///
/// Dropping this value leaves coverage unchanged. Only [`Self::commit`]
/// records the range, so callers can perform fallible work between checking
/// and committing without creating stale or cross-instance bookings.
#[derive(Debug)]
pub struct Booking<'coverage> {
    coverage: &'coverage mut Coverage,
    covered_offset: u64,
    covered_end: u64,
    next_bytes: u64,
}

impl Booking<'_> {
    /// Records the checked range and merges it with adjacent extents.
    pub fn commit(self) {
        let coverage = self.coverage;
        coverage.bytes = self.next_bytes;
        let mut start = self.covered_offset;
        let mut end = self.covered_end;
        if let Some((&earlier_start, &earlier_end)) =
            coverage.extents.range(..self.covered_offset).next_back()
        {
            if earlier_end == self.covered_offset {
                coverage.extents.remove(&earlier_start);
                start = earlier_start;
            }
        }
        if let Some(later_end) = coverage.extents.remove(&self.covered_end) {
            end = later_end;
        }
        coverage.extents.insert(start, end);
    }
}

/// Disjoint accepted extents and their exact covered-byte count.
///
/// Extents are stored as start to exclusive end and coalesced on commit.
#[derive(Debug, Default)]
pub struct Coverage {
    extents: BTreeMap<u64, u64>,
    bytes: u64,
}

impl Coverage {
    /// Creates empty coverage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            extents: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Checks whether a range is new, a replay, or conflicts with coverage.
    ///
    /// A new range returns a borrow-bound [`Booking`]. Coverage changes only
    /// when that booking is committed.
    ///
    /// # Errors
    /// Rejects empty ranges, arithmetic overflow, partial overlap with an
    /// accepted extent, and a new isolated extent beyond [`MAX_FRAGMENTS`].
    pub fn check(&mut self, covered_offset: u64, bytes: u64) -> Result<Check<'_>, Error> {
        if bytes == 0 {
            return Err(Error::EmptyRange);
        }
        let covered_end = covered_offset
            .checked_add(bytes)
            .ok_or(Error::LengthExceeded)?;
        if self
            .extents
            .range(..=covered_offset)
            .next_back()
            .is_some_and(|(_, end)| *end >= covered_end)
        {
            return Ok(Check::Replay);
        }
        let earlier = self.extents.range(..covered_offset).next_back();
        let overlaps_earlier = earlier.is_some_and(|(_, end)| covered_offset < *end);
        let overlaps_later = self
            .extents
            .range(covered_offset..)
            .next()
            .is_some_and(|(offset, _)| *offset < covered_end);
        if overlaps_earlier || overlaps_later {
            return Err(Error::PartialOverlap);
        }
        let next_bytes = self.bytes.checked_add(bytes).ok_or(Error::LengthExceeded)?;
        let merges_earlier = earlier.is_some_and(|(_, end)| *end == covered_offset);
        let merges_later = self.extents.contains_key(&covered_end);
        if !merges_earlier && !merges_later && self.extents.len() >= MAX_FRAGMENTS {
            return Err(Error::FragmentsExhausted);
        }
        Ok(Check::New(Booking {
            coverage: self,
            covered_offset,
            covered_end,
            next_bytes,
        }))
    }

    /// Bytes covered, counting every byte once.
    #[must_use]
    pub const fn covered_bytes(&self) -> u64 {
        self.bytes
    }

    /// Whether the covered-byte count exactly equals `length`.
    #[must_use]
    pub const fn is_complete(&self, length: u64) -> bool {
        self.bytes == length
    }

    /// Number of disjoint covered extents retained.
    #[must_use]
    pub fn fragment_count(&self) -> usize {
        self.extents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(coverage: &mut Coverage, offset: u64, bytes: u64) {
        let Check::New(booking) = coverage.check(offset, bytes).unwrap() else {
            panic!("a new range");
        };
        booking.commit();
    }

    fn coverage_at_fragment_cap(first_offset: u64) -> Coverage {
        let mut coverage = Coverage::new();
        for index in 0..u64::try_from(MAX_FRAGMENTS).unwrap() {
            commit(&mut coverage, first_offset + index * 2, 1);
        }
        coverage
    }

    #[test]
    fn new_ranges_coalesce_and_replays_change_nothing() {
        let mut coverage = Coverage::new();
        commit(&mut coverage, 0, 10);
        commit(&mut coverage, 20, 10);
        assert_eq!(coverage.fragment_count(), 2);
        assert_eq!(coverage.covered_bytes(), 20);

        commit(&mut coverage, 10, 10);
        assert_eq!(coverage.fragment_count(), 1);
        assert_eq!(coverage.covered_bytes(), 30);
        assert!(coverage.is_complete(30));
        assert!(!coverage.is_complete(29));
        assert!(matches!(coverage.check(5, 10), Ok(Check::Replay)));
        assert_eq!(coverage.covered_bytes(), 30);
    }

    #[test]
    fn partial_overlap_is_rejected_from_either_direction() {
        let mut coverage = Coverage::new();
        commit(&mut coverage, 10, 10);
        assert!(matches!(coverage.check(5, 10), Err(Error::PartialOverlap)));
        assert!(matches!(coverage.check(15, 10), Err(Error::PartialOverlap)));
        assert_eq!(coverage.fragment_count(), 1);
        assert_eq!(coverage.covered_bytes(), 10);
    }

    #[test]
    fn dropped_booking_does_not_change_coverage() {
        let mut coverage = Coverage::new();
        {
            let Check::New(_booking) = coverage.check(7, 9).unwrap() else {
                panic!("a new range");
            };
        }
        assert_eq!(coverage.fragment_count(), 0);
        assert_eq!(coverage.covered_bytes(), 0);
    }

    #[test]
    fn empty_and_overflowing_ranges_are_rejected() {
        let mut coverage = Coverage::new();
        assert!(matches!(coverage.check(0, 0), Err(Error::EmptyRange)));
        assert!(matches!(
            coverage.check(u64::MAX, 1),
            Err(Error::LengthExceeded)
        ));
        coverage.bytes = u64::MAX;
        assert!(matches!(coverage.check(0, 1), Err(Error::LengthExceeded)));
    }

    #[test]
    fn fragment_cap_rejects_isolation_but_accepts_merges() {
        let mut coverage = coverage_at_fragment_cap(0);
        assert_eq!(coverage.fragment_count(), MAX_FRAGMENTS);
        assert!(matches!(
            coverage.check(u64::try_from(MAX_FRAGMENTS).unwrap() * 2 + 10, 1),
            Err(Error::FragmentsExhausted)
        ));

        commit(&mut coverage, 1, 1);
        assert_eq!(coverage.fragment_count(), MAX_FRAGMENTS - 1);
        assert_eq!(
            coverage.covered_bytes(),
            u64::try_from(MAX_FRAGMENTS).unwrap() + 1
        );
    }

    #[test]
    fn fragment_cap_accepts_an_earlier_only_merge() {
        let mut coverage = coverage_at_fragment_cap(0);
        let offset = u64::try_from(MAX_FRAGMENTS).unwrap() * 2 - 1;

        commit(&mut coverage, offset, 1);

        assert_eq!(coverage.fragment_count(), MAX_FRAGMENTS);
        assert_eq!(
            coverage.covered_bytes(),
            u64::try_from(MAX_FRAGMENTS).unwrap() + 1
        );
    }

    #[test]
    fn fragment_cap_accepts_a_later_only_merge() {
        let mut coverage = coverage_at_fragment_cap(1);

        commit(&mut coverage, 0, 1);

        assert_eq!(coverage.fragment_count(), MAX_FRAGMENTS);
        assert_eq!(
            coverage.covered_bytes(),
            u64::try_from(MAX_FRAGMENTS).unwrap() + 1
        );
    }

    #[test]
    fn exact_adjacency_merges_on_each_side() {
        let mut earlier = Coverage::new();
        commit(&mut earlier, 0, 10);
        commit(&mut earlier, 10, 5);
        assert_eq!(earlier.fragment_count(), 1);

        let mut later = Coverage::new();
        commit(&mut later, 10, 5);
        commit(&mut later, 5, 5);
        assert_eq!(later.fragment_count(), 1);
        assert_eq!(later.covered_bytes(), 10);
    }
}
