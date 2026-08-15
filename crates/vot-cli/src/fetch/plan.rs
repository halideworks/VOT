//! The shared fetch plan and its planned objects.

use super::{
    Arc, BTreeMap, CountingSink, Error, MAX_REQUESTED_RANGE, Mutex, PackageSummary, ResumeStore,
    SubjectId, frames, range_span, total_units_of,
};

/// Store reservations for objects with units to checkpoint; zero-length
/// objects are written directly.
pub(crate) fn reservations_of(objects: &[PlannedObject]) -> Vec<(SubjectId, u64)> {
    objects
        .iter()
        .filter(|planned| planned.object.length > 0)
        .map(|planned| (subject_of(planned), total_units_of(planned.object.length)))
        .collect()
}

/// Outstanding covers the fetch may have on the wire.
///
/// The bound is on the wire, not the queue: a pass costs microseconds and
/// an answer costs a round trip, so bounding the queue lets an object of
/// any size be asked for in full before the first cover lands.
pub(crate) const OUTSTANDING_COVERS: usize = 4;

/// Bytes this fetch may have asked for and not yet placed.
pub(crate) const OUTSTANDING_REQUEST_BYTES: u64 = OUTSTANDING_COVERS as u64 * MAX_REQUESTED_RANGE;

/// One stored object the manifest names, in fetch order.
#[derive(Clone)]
pub(crate) struct PlannedObject {
    pub(crate) object: frames::ObjectId,
    /// Byte extents a previous fetch made durable; the handout skips them.
    pub(crate) resumed: BTreeMap<u64, u64>,
}

impl PlannedObject {
    pub(crate) fn fresh(object: frames::ObjectId) -> Self {
        Self {
            object,
            resumed: BTreeMap::new(),
        }
    }

    /// Whether the checkpointed extents already cover the whole object.
    pub(crate) fn fully_resumed(&self) -> bool {
        self.resumed.values().sum::<u64>() == self.object.length && self.object.length > 0
    }
}

/// The objects still owed once the manifest is validated, behind a lock.
///
/// The plan is the striping point: it hands out range requests, and rails
/// taking from the same handout is work stealing by construction.
pub(crate) type SharedPlan = Arc<Mutex<FetchPlan>>;

/// Marks a plan abandoned, so every rail on it stops at its next pass
/// rather than waiting out a stall budget on spans nobody will answer.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn abandon_plan(plan: &SharedPlan) {
    if let Ok(mut plan) = plan.lock() {
        plan.abandoned = true;
    }
}

/// Disjoint settled extents and the exact bytes they span.
///
/// Coalescing counts each byte once, so a duplicate range from another
/// rail cannot complete an object that still has a hole.
pub(crate) struct CoverageMap {
    /// Extents by start offset, disjoint and coalesced.
    extents: BTreeMap<u64, u64>,
    /// Bytes the extents span, kept exact by [`CoverageMap::insert`].
    bytes: u64,
}

impl CoverageMap {
    pub(crate) fn new() -> Self {
        Self {
            extents: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// A map seeded with already-durable extents, disjoint by construction.
    pub(crate) fn seeded(extents: BTreeMap<u64, u64>) -> Self {
        let bytes = extents.values().sum();
        Self { extents, bytes }
    }

    /// Books an extent, coalescing and counting each byte once.
    pub(crate) fn insert(&mut self, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        let Some(mut end) = offset.checked_add(length) else {
            return;
        };
        let mut start = offset;
        let mut absorbed: u64 = 0;
        // Walk right to left from the extent at or before `end`; extents
        // are disjoint and sorted, so the first gap ends the merge.
        let overlapping: Vec<(u64, u64)> = self
            .extents
            .range(..=end)
            .rev()
            .take_while(|(at, len)| at.saturating_add(**len) >= start)
            .map(|(at, len)| (*at, *len))
            .collect();
        for (at, len) in overlapping {
            self.extents.remove(&at);
            absorbed = absorbed.saturating_add(len);
            start = start.min(at);
            end = end.max(at.saturating_add(len));
        }
        self.extents.insert(start, end - start);
        self.bytes = self
            .bytes
            .saturating_add((end - start).saturating_sub(absorbed));
        debug_assert_eq!(
            self.bytes,
            self.extents.values().sum::<u64>(),
            "coverage bytes drifted from the extents"
        );
    }

    /// Bytes covered, each counted once.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Whether coverage spans an object of `length` whole.
    pub(crate) fn is_complete(&self, length: u64) -> bool {
        self.bytes == length
    }

    /// The extents themselves, for accounts seeded from this map.
    pub(crate) fn extents(&self) -> &BTreeMap<u64, u64> {
        &self.extents
    }
}

/// What a [`SharedPlan`] holds.
pub(crate) struct FetchPlan {
    pub(crate) summary: PackageSummary,
    pub(crate) objects: Vec<PlannedObject>,
    pub(crate) current: usize,
    /// The sink the current object's verified ranges flow into, kept for
    /// the sync that makes its bytes durable before the fetch moves on.
    pub(crate) active: Option<Arc<CountingSink>>,
    /// Bytes placed for objects already left behind, so what this fetch
    /// has settled only ever goes up.
    pub(crate) placed_before: u64,
    /// Where the current object's next range request starts.
    pub(crate) next_offset: u64,
    /// Settled extents of the current object; completion is full coverage,
    /// each byte counted once however many rails a misbehaving server
    /// answers with the same range.
    pub(crate) covered: CoverageMap,
    /// Raised by the rail that saw the current object whole and is syncing
    /// it outside this lock, so no second rail syncs or advances over it.
    pub(crate) syncing: bool,
    /// Raised by a rail that failed, so the others stop instead of waiting
    /// out their stall budgets on spans nobody will answer.
    pub(crate) abandoned: bool,
    /// The current object's resumed extents, which the handout walks
    /// around: what a previous fetch made durable is never asked for.
    pub(crate) skip: BTreeMap<u64, u64>,
    /// Resume store, shared by every rail through the plan.
    pub(crate) store: Option<Arc<Mutex<ResumeStore>>>,
    pub(crate) finished: bool,
}

impl FetchPlan {
    /// The next range a taker would request, uncommitted and unpaced.
    ///
    /// Steps over resumed extents so durable ranges are never re-asked
    /// and no request overlaps one.
    pub(crate) fn next_span(&self) -> Result<Option<(frames::ObjectId, u64, u64)>, Error> {
        if self.active.is_none() {
            return Ok(None);
        }
        let object = self
            .objects
            .get(self.current)
            .ok_or(Error::InvalidBundle)?
            .object;
        let mut offset = self.next_offset;
        // Bounded by the extents themselves: each pass either lands past
        // one more of them or answers, so the walk ends within the skip
        // set's own size.
        for _ in 0..=self.skip.len() {
            if let Some((at, length)) = self
                .skip
                .range(..=offset)
                .next_back()
                .map(|(at, length)| (*at, *length))
            {
                if at.saturating_add(length) > offset {
                    offset = at.saturating_add(length);
                    continue;
                }
            }
            let Some((offset, mut length)) = range_span(offset, object.length) else {
                return Ok(None);
            };
            if let Some(next_skip) = self.skip.range(offset..).next().map(|(at, _)| *at) {
                length = length.min(next_skip.saturating_sub(offset));
            }
            return Ok(Some((object, offset, length)));
        }
        Err(Error::InvalidBundle)
    }

    /// Commits the span [`FetchPlan::next_span`] handed out.
    ///
    /// Called only once the span's frame is queued: committing before the
    /// frame exists would consume it on a failure that leaves a hole.
    pub(crate) fn take(&mut self, offset: u64, length: u64) -> Result<(), Error> {
        // A span behind the cursor would be asked for again forever; failing
        // here turns that spin into a panic the suite sees immediately.
        debug_assert!(
            offset >= self.next_offset,
            "a committed span moved the handout backwards"
        );
        self.next_offset = offset.checked_add(length).ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    /// Books a settled cover into the current object's coverage.
    pub(crate) fn cover(&mut self, offset: u64, length: u64) {
        self.covered.insert(offset, length);
    }
}

pub(crate) fn subject_of(planned: &PlannedObject) -> SubjectId {
    SubjectId::try_from(planned.object).expect("a planned object names a registered suite")
}
