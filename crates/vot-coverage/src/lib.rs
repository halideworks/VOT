//! Bounded, dependency-free bookkeeping for accepted byte ranges.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Disjoint covered extents retained for an object of unstated length, and
/// the floor for one whose length is known.
pub const MAX_FRAGMENTS: usize = 4096;

/// Object bytes a retained extent is allowed for, above the floor.
///
/// The extents a transfer holds grow with the object rather than with what
/// is in flight, because rails complete ranges out of order and a hole lives
/// until both its neighbours land. Measured over loopback fetches the peak
/// was about 40 extents a gigabyte, 500 at 12 GB and 1750 at 50 GB, so the
/// flat floor failed a 100 GB fetch at 96% placed. One per 8 MB is four
/// times that density.
///
/// The ceiling this sets is memory: an extent is a pair of offsets in a map,
/// so a terabyte object allows about 131000 of them, a few megabytes.
pub const FRAGMENT_PER_BYTES: u64 = 8 * 1024 * 1024;

/// Extents an object of this length may be covered in.
#[must_use]
pub fn fragment_limit(object_len: u64) -> usize {
    let scaled = usize::try_from(object_len / FRAGMENT_PER_BYTES).unwrap_or(usize::MAX);
    scaled.max(MAX_FRAGMENTS)
}

/// A coverage check or commit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyRange,
    LengthExceeded,
    PartialOverlap,
    /// The range intersects a reservation whose bytes are still in flight.
    /// Retryable: once the holder commits, the same range is a replay; if
    /// the holder releases, it becomes reservable again.
    ReservedOverlap,
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
        coverage.insert_coalesced(self.covered_offset, self.covered_end);
    }
}

/// Result of reserving a range whose bytes are written outside any borrow
/// of this coverage.
#[derive(Debug)]
pub enum Reserve {
    /// The range is wholly contained in an accepted extent.
    Replay,
    /// The range is held against later checks and reservations until it is
    /// committed or released.
    New(Reservation),
}

/// A reserved range, held as a value so it can cross an unlock while its
/// bytes land.
///
/// Unlike [`Booking`] this does not borrow the coverage: dropping it leaves
/// the range reserved for the life of the coverage, so a caller must hand
/// every reservation back through [`Coverage::commit_reservation`] or
/// [`Coverage::release_reservation`].
#[derive(Debug)]
pub struct Reservation {
    covered_offset: u64,
    covered_end: u64,
}

/// Disjoint accepted extents and their exact covered-byte count.
///
/// Extents are stored as start to exclusive end and coalesced on commit.
#[derive(Debug, Default)]
pub struct Coverage {
    extents: BTreeMap<u64, u64>,
    /// Ranges reserved for in-flight writes: refused to later checks and
    /// reservations, not yet counted as covered.
    reserved: BTreeMap<u64, u64>,
    bytes: u64,
    /// Extents this object may be covered in, from its length.
    limit: usize,
}

impl Coverage {
    /// Creates empty coverage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            extents: BTreeMap::new(),
            reserved: BTreeMap::new(),
            bytes: 0,
            limit: MAX_FRAGMENTS,
        }
    }

    /// Coverage for an object of a known length, which is what decides how
    /// many extents it may be covered in.
    #[must_use]
    pub fn for_object(object_len: u64) -> Self {
        Self {
            extents: BTreeMap::new(),
            reserved: BTreeMap::new(),
            bytes: 0,
            limit: fragment_limit(object_len),
        }
    }

    /// Extents this coverage may hold.
    #[must_use]
    pub const fn fragment_limit(&self) -> usize {
        self.limit
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
        if overlaps(&self.extents, covered_offset, covered_end) {
            return Err(Error::PartialOverlap);
        }
        if overlaps(&self.reserved, covered_offset, covered_end) {
            return Err(Error::ReservedOverlap);
        }
        let next_bytes = self.bytes.checked_add(bytes).ok_or(Error::LengthExceeded)?;
        let merges_earlier = earlier.is_some_and(|(_, end)| *end == covered_offset);
        let merges_later = self.extents.contains_key(&covered_end);
        if !merges_earlier && !merges_later && self.extents.len() >= self.limit {
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

    /// Bytes covered contiguously from offset zero.
    ///
    /// Resume decisions need this, not [`Self::covered_bytes`]: ranges commit
    /// out of order, so the covered-byte count can include extents beyond a
    /// hole, and restarting a transfer from that count would skip the hole.
    #[must_use]
    pub fn contiguous_prefix(&self) -> u64 {
        self.extents.get(&0).copied().unwrap_or(0)
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

    /// Covered extents as `(offset, length)` pairs in ascending order, for
    /// a caller that persists coverage across a restart (ADR-0047).
    pub fn runs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.extents
            .iter()
            .map(|(&start, &end)| (start, end - start))
    }

    /// Rebuilds coverage for an object of `object_len` bytes from runs a
    /// caller persisted (ADR-0047). Refuses before any allocation
    /// proportional to the input: runs must be sorted, non-overlapping and
    /// non-adjacent, non-empty, inside the object length, and no more
    /// numerous than [`fragment_limit`] allows. Adjacent runs are refused
    /// rather than merged because [`Self::runs`] never emits them; their
    /// presence means the list is not one this crate wrote.
    ///
    /// The rebuilt coverage is trusted bookkeeping, not re-verified data;
    /// the caller owns that trust boundary.
    ///
    /// # Errors
    /// [`Error::EmptyRange`] for a zero-length run,
    /// [`Error::LengthExceeded`] for a run past `object_len` or an
    /// overflowing bound, [`Error::PartialOverlap`] for unsorted,
    /// overlapping, or adjacent runs, and [`Error::FragmentsExhausted`] for
    /// more runs than the limit.
    pub fn from_runs(
        object_len: u64,
        runs: impl IntoIterator<Item = (u64, u64)>,
    ) -> Result<Self, Error> {
        let limit = fragment_limit(object_len);
        let mut extents = BTreeMap::new();
        let mut bytes = 0u64;
        let mut previous_end: Option<u64> = None;
        for (index, (offset, length)) in runs.into_iter().enumerate() {
            if index >= limit {
                return Err(Error::FragmentsExhausted);
            }
            if length == 0 {
                return Err(Error::EmptyRange);
            }
            let end = offset.checked_add(length).ok_or(Error::LengthExceeded)?;
            if end > object_len {
                return Err(Error::LengthExceeded);
            }
            if previous_end.is_some_and(|previous| offset <= previous) {
                return Err(Error::PartialOverlap);
            }
            previous_end = Some(end);
            bytes += length;
            extents.insert(offset, end);
        }
        Ok(Self {
            extents,
            reserved: BTreeMap::new(),
            bytes,
            limit,
        })
    }

    /// Reserves a range for a write performed outside any borrow of this
    /// coverage, refusing overlap with committed and reserved extents alike
    /// and classifying a committed range as a replay exactly like
    /// [`Self::check`].
    ///
    /// The returned reservation must come back through
    /// [`Self::commit_reservation`] or [`Self::release_reservation`].
    ///
    /// # Errors
    /// Rejects empty ranges, arithmetic overflow, overlap with a committed
    /// or reserved extent, and a new isolated extent beyond the fragment
    /// limit, counting reserved extents against that limit.
    pub fn reserve(&mut self, covered_offset: u64, bytes: u64) -> Result<Reserve, Error> {
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
            return Ok(Reserve::Replay);
        }
        if overlaps(&self.extents, covered_offset, covered_end) {
            return Err(Error::PartialOverlap);
        }
        if overlaps(&self.reserved, covered_offset, covered_end) {
            return Err(Error::ReservedOverlap);
        }
        self.bytes.checked_add(bytes).ok_or(Error::LengthExceeded)?;
        let earlier = self.extents.range(..covered_offset).next_back();
        let merges_earlier = earlier.is_some_and(|(_, end)| *end == covered_offset);
        let merges_later = self.extents.contains_key(&covered_end);
        if !merges_earlier
            && !merges_later
            && self.extents.len() + self.reserved.len() >= self.limit
        {
            return Err(Error::FragmentsExhausted);
        }
        self.reserved.insert(covered_offset, covered_end);
        Ok(Reserve::New(Reservation {
            covered_offset,
            covered_end,
        }))
    }

    /// Records a reserved range whose bytes landed, merging it with adjacent
    /// extents. The reservation must come from this coverage.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consuming the reservation is the API: it cannot commit twice"
    )]
    pub fn commit_reservation(&mut self, reservation: Reservation) {
        let removed = self.reserved.remove(&reservation.covered_offset);
        debug_assert!(removed.is_some(), "reservation from another coverage");
        // Extents and reservations are disjoint sub-ranges of the u64 offset
        // space, so their byte total cannot exceed u64::MAX.
        self.bytes = self
            .bytes
            .saturating_add(reservation.covered_end - reservation.covered_offset);
        self.insert_coalesced(reservation.covered_offset, reservation.covered_end);
    }

    /// Releases a reserved range whose write failed. The reservation must
    /// come from this coverage.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consuming the reservation is the API: it cannot be reused"
    )]
    pub fn release_reservation(&mut self, reservation: Reservation) {
        let removed = self.reserved.remove(&reservation.covered_offset);
        debug_assert!(removed.is_some(), "reservation from another coverage");
    }

    fn insert_coalesced(&mut self, covered_offset: u64, covered_end: u64) {
        let mut start = covered_offset;
        let mut end = covered_end;
        if let Some((&earlier_start, &earlier_end)) =
            self.extents.range(..covered_offset).next_back()
            && earlier_end == covered_offset
        {
            self.extents.remove(&earlier_start);
            start = earlier_start;
        }
        if let Some(later_end) = self.extents.remove(&covered_end) {
            end = later_end;
        }
        self.extents.insert(start, end);
    }
}

/// Whether the range intersects any extent in the map. Callers test full
/// containment in committed extents first, so a hit here is a conflict, not
/// a replay.
fn overlaps(map: &BTreeMap<u64, u64>, covered_offset: u64, covered_end: u64) -> bool {
    map.range(..covered_offset)
        .next_back()
        .is_some_and(|(_, end)| covered_offset < *end)
        || map
            .range(covered_offset..)
            .next()
            .is_some_and(|(offset, _)| *offset < covered_end)
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
    fn the_extent_bound_follows_the_object() {
        // Flat, an object big enough outgrows it: the extents a transfer
        // holds track the object rather than what is in flight, about 40 a
        // gigabyte measured, and a 100 GB fetch died at 96% placed.
        assert_eq!(fragment_limit(0), MAX_FRAGMENTS);
        assert_eq!(fragment_limit(1), MAX_FRAGMENTS);
        // Below the floor the floor holds.
        assert_eq!(fragment_limit(8 * 1024 * 1024 * 4095), MAX_FRAGMENTS);
        // Above it, one per FRAGMENT_PER_BYTES.
        assert_eq!(fragment_limit(FRAGMENT_PER_BYTES * 12_000), 12_000);
        assert_eq!(fragment_limit(100 * 1024 * 1024 * 1024), 12_800);
        // And the coverage it builds carries that bound.
        assert_eq!(
            Coverage::for_object(100 * 1024 * 1024 * 1024).fragment_limit(),
            12_800
        );
        assert_eq!(Coverage::new().fragment_limit(), MAX_FRAGMENTS);
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
    fn contiguous_prefix_stops_at_the_first_hole() {
        let mut coverage = Coverage::new();
        assert_eq!(coverage.contiguous_prefix(), 0);
        commit(&mut coverage, 4, 2);
        assert_eq!(coverage.covered_bytes(), 2);
        assert_eq!(coverage.contiguous_prefix(), 0);
        commit(&mut coverage, 0, 2);
        assert_eq!(coverage.contiguous_prefix(), 2);
        commit(&mut coverage, 2, 2);
        assert_eq!(coverage.contiguous_prefix(), 6);
        assert_eq!(coverage.covered_bytes(), 6);
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
    fn runs_round_trip_and_from_runs_validates_before_building() {
        let mut coverage = Coverage::for_object(64);
        commit(&mut coverage, 0, 10);
        commit(&mut coverage, 20, 10);
        commit(&mut coverage, 40, 10);
        let runs: Vec<_> = coverage.runs().collect();
        assert_eq!(runs, vec![(0, 10), (20, 10), (40, 10)]);
        let rebuilt = Coverage::from_runs(64, runs).unwrap();
        assert_eq!(rebuilt.covered_bytes(), 30);
        assert_eq!(rebuilt.fragment_count(), 3);
        assert_eq!(rebuilt.contiguous_prefix(), 10);
        assert_eq!(rebuilt.fragment_limit(), fragment_limit(64));
        // The rebuilt coverage keeps working: fill a hole, complete, replay.
        commit(&mut coverage, 10, 10);
        let mut rebuilt = Coverage::from_runs(64, coverage.runs()).unwrap();
        assert!(matches!(rebuilt.check(0, 10), Ok(Check::Replay)));
        commit(&mut rebuilt, 30, 10);
        commit(&mut rebuilt, 50, 14);
        assert!(rebuilt.is_complete(64));

        assert!(matches!(
            Coverage::from_runs(64, [(0, 0)]),
            Err(Error::EmptyRange)
        ));
        assert!(matches!(
            Coverage::from_runs(64, [(60, 5)]),
            Err(Error::LengthExceeded)
        ));
        assert!(matches!(
            Coverage::from_runs(64, [(u64::MAX, 1)]),
            Err(Error::LengthExceeded)
        ));
        // A run ending exactly at the object length is inside it.
        let boundary = Coverage::from_runs(64, [(54, 10)]).unwrap();
        assert_eq!(boundary.covered_bytes(), 10);
        assert_eq!(boundary.fragment_count(), 1);
        // Unsorted, overlapping, and adjacent lists are all refused: this
        // crate never writes them.
        assert!(matches!(
            Coverage::from_runs(64, [(20, 10), (0, 10)]),
            Err(Error::PartialOverlap)
        ));
        assert!(matches!(
            Coverage::from_runs(64, [(0, 10), (5, 10)]),
            Err(Error::PartialOverlap)
        ));
        assert!(matches!(
            Coverage::from_runs(64, [(0, 10), (10, 10)]),
            Err(Error::PartialOverlap)
        ));
        // One run past the limit is refused before it is inserted.
        let cap = u64::try_from(MAX_FRAGMENTS).unwrap();
        let too_many = (0..=cap).map(|run| (run * 2, 1));
        assert!(matches!(
            Coverage::from_runs(cap * 2 + 2, too_many),
            Err(Error::FragmentsExhausted)
        ));
    }

    fn reserve_new(coverage: &mut Coverage, offset: u64, bytes: u64) -> Reservation {
        let Reserve::New(reservation) = coverage.reserve(offset, bytes).unwrap() else {
            panic!("a new reservation");
        };
        reservation
    }

    #[test]
    fn reservations_hold_ranges_until_committed_or_released() {
        let mut coverage = Coverage::new();
        let first = reserve_new(&mut coverage, 0, 10);
        // Nothing is covered while the write is in flight.
        assert_eq!(coverage.covered_bytes(), 0);
        assert_eq!(coverage.fragment_count(), 0);
        // The range and every intersection of it are refused to both paths.
        assert!(matches!(
            coverage.reserve(0, 10),
            Err(Error::ReservedOverlap)
        ));
        assert!(matches!(
            coverage.reserve(5, 10),
            Err(Error::ReservedOverlap)
        ));
        assert!(matches!(coverage.check(5, 10), Err(Error::ReservedOverlap)));
        // A disjoint reservation proceeds.
        let second = reserve_new(&mut coverage, 20, 10);
        coverage.commit_reservation(first);
        assert_eq!(coverage.covered_bytes(), 10);
        // A committed range is a replay to later reservations.
        assert!(matches!(coverage.reserve(0, 10), Ok(Reserve::Replay)));
        assert!(matches!(coverage.reserve(2, 3), Ok(Reserve::Replay)));
        // A released range becomes reservable again.
        coverage.release_reservation(second);
        assert_eq!(coverage.covered_bytes(), 10);
        let again = reserve_new(&mut coverage, 20, 10);
        coverage.commit_reservation(again);
        assert_eq!(coverage.covered_bytes(), 20);
        assert_eq!(coverage.fragment_count(), 2);
    }

    #[test]
    fn committed_reservations_coalesce_like_bookings() {
        let mut coverage = Coverage::new();
        let left = reserve_new(&mut coverage, 0, 10);
        let right = reserve_new(&mut coverage, 20, 10);
        let middle = reserve_new(&mut coverage, 10, 10);
        coverage.commit_reservation(left);
        coverage.commit_reservation(right);
        assert_eq!(coverage.fragment_count(), 2);
        coverage.commit_reservation(middle);
        assert_eq!(coverage.fragment_count(), 1);
        assert_eq!(coverage.covered_bytes(), 30);
        assert_eq!(coverage.contiguous_prefix(), 30);
        assert!(coverage.is_complete(30));
    }

    #[test]
    fn reservations_reject_empty_overflowing_and_capped_ranges() {
        let mut coverage = Coverage::new();
        assert!(matches!(coverage.reserve(0, 0), Err(Error::EmptyRange)));
        assert!(matches!(
            coverage.reserve(u64::MAX, 1),
            Err(Error::LengthExceeded)
        ));
        coverage.bytes = u64::MAX;
        assert!(matches!(coverage.reserve(0, 1), Err(Error::LengthExceeded)));

        // Reserved extents count against the fragment cap alongside
        // committed ones.
        let mut capped = coverage_at_fragment_cap(0);
        let base = u64::try_from(MAX_FRAGMENTS).unwrap() * 2 + 10;
        assert!(matches!(
            capped.reserve(base, 1),
            Err(Error::FragmentsExhausted)
        ));
        // A merge-adjacent reservation is allowed at the cap, like a check.
        let merge = reserve_new(&mut capped, 1, 1);
        capped.commit_reservation(merge);
        assert_eq!(capped.fragment_count(), MAX_FRAGMENTS - 1);
        // With headroom, an isolated reservation occupies a slot that a
        // second isolated one at the cap is then refused.
        let held = reserve_new(&mut capped, base, 1);
        assert!(matches!(
            capped.reserve(base + 2, 1),
            Err(Error::FragmentsExhausted)
        ));
        capped.release_reservation(held);
        let allowed = reserve_new(&mut capped, base + 2, 1);
        capped.release_reservation(allowed);
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
