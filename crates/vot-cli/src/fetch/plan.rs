//! The shared fetch plan and its planned objects.

use super::{
    Arc, BTreeMap, CompletionHook, CountingSink, EntryRecord, Error, MAX_REQUESTED_RANGE, Mutex,
    PackageSummary, ReceiveSessionId, ResumeStore, SubjectId, frames, range_span, total_units_of,
};

#[derive(Clone)]
pub(crate) struct ActiveSink {
    pub(crate) sink: Arc<CountingSink>,
    pub(crate) complete: Option<CompletionHook>,
    pub(crate) receive_session: ReceiveSessionId,
}

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
///
/// Eight is a memory budget: the credit it buys, 33.55 MB, has to comfortably
/// exceed the congestion window for a rail to sit at that window rather than
/// at its own turnaround, and the fork pins the window at 29.46 MB. Four
/// covers bound every round trip measured, with every serve pass ending on an
/// empty outbox; eight with the doubled receive-window ceiling moves the
/// binder to the congestion window and takes one rail from 174 to 289 MB/s at
/// 80 ms and 93 to 159 at 160 ms, for 16 to 25 MiB a rail on the serve.
/// Sixteen buys a further 12 to 20% for 2.4 times the added memory, which is
/// the trade this stops short of.
pub(crate) const OUTSTANDING_COVERS: usize = 8;

/// Bundles one cover can be answered in.
///
/// A coded answer is cut into fixed `FEC_PIECE_BYTES` windows of the object
/// and each piece is its own bundle, so a cover spans the pieces its length
/// covers plus one more, because a cover is not aligned to those windows.
const PIECES_PER_COVER: usize = 5;

/// Bundles a fetch holds part-built at once.
///
/// Every cover in flight can be answered in `PIECES_PER_COVER` bundles and
/// each of those is pinned from its `PROOF_BUNDLE` until its last record
/// lands, so the depth is the product of the two rather than either alone.
/// Sized at the cover depth alone, a coded fetch of 16 MB failed four times
/// in five with `PendingBundlesExhausted`, and one of 256 MB every time;
/// the reliable path never noticed because it completes a bundle's records
/// before the next bundle is announced.
///
/// The byte budget beside it is [`PENDING_BUNDLE_BYTES`], which is sized for
/// what the two pipelines actually hold rather than for this count of
/// worst-case bundles.
pub(crate) const PENDING_BUNDLE_DEPTH: usize =
    RELIABLE_BUNDLE_DEPTH + 2 * vot_scheduler::session::MAX_CODING_EPOCHS * PIECES_PER_COVER;

/// Bundles the reliable pipeline alone can hold: every outstanding cover, in
/// every piece it may be answered in.
pub(crate) const RELIABLE_BUNDLE_DEPTH: usize = OUTSTANDING_COVERS * PIECES_PER_COVER;

// Tied to the geometry it stands for, so a change to either the cover bound
// or the piece size breaks the build here rather than showing up as a fetch
// that ends partway through a coded transfer.
const _: () = assert!(
    PIECES_PER_COVER as u64
        == vot_scheduler::MAX_PROOF_RANGE_BYTES.div_ceil(crate::serve::server::FEC_PIECE_BYTES) + 1
);
const _: () = assert!(RELIABLE_BUNDLE_DEPTH == 40);
// An open epoch spans a whole requested cover (ADR-0042) and pins that
// cover's piece bundles for its whole life, so the depth has to hold the
// epochs' pieces on top of the reliable pipeline rather than carve them out
// of it.
//
// Two covers a slot, not one: retiring an epoch frees its slot the moment
// the repair records are queued, so the next request opens a fresh epoch and
// fresh bundles while the retired one is still incomplete at the receiver,
// a transit behind. One slot can hold both for that transit.
const _: () = assert!(PENDING_BUNDLE_DEPTH == 120);

/// Bytes a fetch may hold across part-built bundles.
///
/// The count above says how many bundles may be open; this says how much
/// they may hold, and it is this that bounds the memory a peer can pin.
/// Sized as the two pipelines at once rather than as `PENDING_BUNDLE_DEPTH`
/// worst-case bundles: the reliable pipeline holds at most its own depth of
/// full-sized bundles, and the coded pipeline holds two covers a slot,
/// which are at most `MAX_PROOF_RANGE_BYTES` each. A peer that announces
/// bundles and never completes them holds this much until the session ends.
///
/// Returning credit as records arrive puts up to a window and one span in
/// flight, nine covers rather than eight, and that does not reach this: an
/// entry leaves the pending ledger the moment its last record lands, and
/// `answer_reliably` serializes one cover at a time, so what is part-built
/// here is the one being answered.
pub(crate) const PENDING_BUNDLE_BYTES: usize = OUTSTANDING_COVERS
    * vot_scheduler::session::MAX_PENDING_BUNDLE_BYTES
    + 2 * vot_scheduler::session::MAX_CODING_EPOCHS * COVER_BYTES_USIZE;

/// Orphan records are the same covers before their proof, so they are
/// bounded the same way, against the record bound a bundle without its proof
/// carries.
pub(crate) const ORPHAN_BUNDLE_BYTES: usize = OUTSTANDING_COVERS
    * vot_scheduler::session::MAX_ORPHAN_BUNDLE_BYTES
    + 2 * vot_scheduler::session::MAX_CODING_EPOCHS * COVER_BYTES_USIZE;

// Spelled out, so a slip in either sum is a build failure rather than a
// budget that silently refuses a conforming transfer or admits far more than
// it meant to.
const _: () = assert!(PENDING_BUNDLE_BYTES == 112_197_632);
const _: () = assert!(ORPHAN_BUNDLE_BYTES == 103_809_024);

const COVER_BYTES_USIZE: usize = 4_259_840;
const _: () = assert!(COVER_BYTES_USIZE as u64 == vot_scheduler::MAX_PROOF_RANGE_BYTES);

/// Bundles that may hold records which arrived before their proof.
///
/// Sized so [`ORPHAN_BUNDLE_BYTES`] is what binds, because it is the bytes
/// that bound what a peer can pin and the count is bookkeeping. An entry
/// holds whatever records of its piece have arrived, which on a coded
/// transfer under loss is a few generations rather than a whole piece: at a
/// count of whole pieces, a 4 GB coded fetch across a 216 ms path at 3% loss
/// filled 36 entries of 36 while holding 10.9 MB of a 40 MB budget, and
/// failed seven runs in nine. Divided by one generation, the smallest record
/// such an entry holds, the same fetch completed six times in six.
pub(crate) const ORPHAN_BUNDLE_DEPTH: usize = ORPHAN_BUNDLE_BYTES / FEC_GENERATION_BYTES_USIZE;

const FEC_GENERATION_BYTES_USIZE: usize = 65_536;
const _: () =
    assert!(FEC_GENERATION_BYTES_USIZE as u64 == crate::serve::server::FEC_GENERATION_BYTES);
const _: () = assert!(ORPHAN_BUNDLE_DEPTH == 1_584);

/// Bytes this fetch may have asked for and not yet seen arrive.
pub(crate) const OUTSTANDING_REQUEST_BYTES: u64 = OUTSTANDING_COVERS as u64 * MAX_REQUESTED_RANGE;

/// One stored object the manifest names, in fetch order.
#[derive(Clone)]
pub(crate) struct PlannedObject {
    pub(crate) object: frames::ObjectId,
    pub(crate) entries: Vec<EntryRecord>,
    pub(crate) sink_chosen: bool,
    /// Byte extents a previous fetch made durable; the handout skips them.
    pub(crate) resumed: BTreeMap<u64, u64>,
}

impl PlannedObject {
    pub(crate) fn fresh(object: frames::ObjectId) -> Self {
        Self {
            object,
            entries: Vec::new(),
            sink_chosen: false,
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
    pub(crate) active: Option<ActiveSink>,
    /// Bytes placed for objects already left behind, so what this fetch
    /// has settled only ever goes up.
    pub(crate) placed_before: u64,
    /// Of what `placed_bytes` counts, the part a previous fetch placed: an
    /// object this one found already whole, and the extents a resumed sink
    /// was seeded with. Subtracting it is what separates the bytes that
    /// crossed the wire on this run from the ones that were on disk before
    /// it, which anything divided by this run's clock has to be.
    pub(crate) carried_before: u64,
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
                && at.saturating_add(length) > offset
            {
                offset = at.saturating_add(length);
                continue;
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
