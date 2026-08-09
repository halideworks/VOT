//! Accepted-extent bookkeeping for one object.

use super::{BTreeMap, Error, RangeSink};

/// Bounds the extent map against adversarial arrival patterns.
pub(super) const MAX_RANGE_FRAGMENTS: usize = 4096;

/// Accepted coverage for one object. Extents are merged on insert, so memory
/// tracks fragmentation, not bytes. Completeness is decided from `bytes` alone.
pub(super) struct RangeState {
    pub(super) extents: BTreeMap<u64, u64>,
    pub(super) bytes: u64,
    pub(super) sink: Box<dyn RangeSink>,
}

/// What checking a range against the accepted extents decided.
pub(super) struct Booking {
    covered_end: u64,
    next_bytes: u64,
}

/// Decides whether a range is new, a replay, or a conflict.
/// `Ok(None)` means replay (wholly inside covered extents).
///
/// # Errors
/// Rejects an overlap that straddles covered and uncovered bytes, a byte
/// total that cannot fit the subject, and a fragment budget exceeded.
pub(super) fn check_range(
    active: &RangeState,
    covered_offset: u64,
    bytes: u64,
) -> Result<Option<Booking>, Error> {
    let covered_end = covered_offset
        .checked_add(bytes)
        .ok_or(Error::LengthExceeded)?;
    if active
        .extents
        .range(..=covered_offset)
        .next_back()
        .is_some_and(|(_, end)| *end >= covered_end)
    {
        return Ok(None);
    }
    let earlier = active.extents.range(..covered_offset).next_back();
    let overlaps_earlier = earlier.is_some_and(|(_, end)| covered_offset < *end);
    let overlaps_later = active
        .extents
        .range(covered_offset..)
        .next()
        .is_some_and(|(offset, _)| *offset < covered_end);
    if overlaps_earlier || overlaps_later {
        return Err(Error::LengthMismatch);
    }
    let next_bytes = active
        .bytes
        .checked_add(bytes)
        .ok_or(Error::LengthExceeded)?;
    let merges_earlier = earlier.is_some_and(|(_, end)| *end == covered_offset);
    let merges_later = active.extents.contains_key(&covered_end);
    if !merges_earlier && !merges_later && active.extents.len() >= MAX_RANGE_FRAGMENTS {
        return Err(Error::RangeFragmentsExhausted);
    }
    Ok(Some(Booking {
        covered_end,
        next_bytes,
    }))
}

/// Records what [`check_range`] admitted, merging with either neighbour so
/// the map holds one entry per contiguous covered run.
pub(super) fn book_range(active: &mut RangeState, covered_offset: u64, booking: &Booking) {
    active.bytes = booking.next_bytes;
    let mut start = covered_offset;
    let mut end = booking.covered_end;
    if let Some((&earlier_start, &earlier_end)) = active.extents.range(..covered_offset).next_back()
    {
        if earlier_end == covered_offset {
            active.extents.remove(&earlier_start);
            start = earlier_start;
        }
    }
    if let Some(later_end) = active.extents.remove(&booking.covered_end) {
        end = later_end;
    }
    active.extents.insert(start, end);
}
