//! Fetching one bundle over a session: opening it, validating the
//! manifest, and pipelining range requests into a bundle directory
//! `receive_bundle` consumes unchanged.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use vot_codec::frames::{
    self, MAX_MANIFEST_REQUEST_PAGES, MAX_REQUESTED_RANGE, ManifestRequest, PackageDescriptor,
    RangeRequest, TypedFrame,
};
use vot_codec::{DecodeLimits, Settings, error_code};
use vot_scheduler::session::{CompletedBundle, SessionReceiver};
use vot_scheduler::{FileSink, ReliableReceiver};
use vot_session::{Authentication, Session};
use vot_transport_api::{Event, MAX_CONTROL_FRAME_PAYLOAD, SubjectId, TransportAdapter};

use vot_resume::{ResumeStore, UnitRanges};

use crate::serve::is_backpressure;
use crate::{Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage};

/// Resume store beside the manifest directory; removed on completion.
const RESUME_STORE: &str = "resume.vot";

/// Store entry binding a store to the package it continues. Suite zero
/// never collides with a stored object; its root is checked before resume.
const fn package_sentinel(root: [u8; 32]) -> SubjectId {
    SubjectId {
        suite: 0,
        root,
        length: 0,
    }
}

/// Checkpoint units of an object, in the receiver's own range currency.
fn total_units_of(length: u64) -> u64 {
    length.div_ceil(vot_scheduler::RANGE_UNIT_BYTES)
}

/// The byte extents `units` stand for, clipped to the object.
fn resumed_extents(units: &UnitRanges, length: u64) -> BTreeMap<u64, u64> {
    let mut extents = BTreeMap::new();
    for (start, count) in units.runs() {
        let at = start.saturating_mul(vot_scheduler::RANGE_UNIT_BYTES);
        let end = start
            .saturating_add(count)
            .saturating_mul(vot_scheduler::RANGE_UNIT_BYTES)
            .min(length);
        if at < end {
            extents.insert(at, end - at);
        }
    }
    extents
}

/// The units wholly inside `covered`, which is what may be checkpointed:
/// a unit only partly placed reads back with a hole, so it is owed again.
fn durable_units(covered: &BTreeMap<u64, u64>, length: u64) -> UnitRanges {
    let unit = vot_scheduler::RANGE_UNIT_BYTES;
    let mut units = UnitRanges::new();
    for (at, len) in covered {
        let first = at.div_ceil(unit);
        let end = at.saturating_add(*len);
        let past = if end >= length {
            total_units_of(length)
        } else {
            end / unit
        }
        // Capped at the object to avoid naming a unit it does not have.
        .min(total_units_of(length));
        units.extend_units(first..past);
    }
    units
}

/// Store reservations for objects with units to checkpoint; zero-length
/// objects are written directly.
fn reservations_of(objects: &[PlannedObject]) -> Vec<(SubjectId, u64)> {
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
const OUTSTANDING_COVERS: usize = 4;

/// Bytes this fetch may have asked for and not yet placed.
const OUTSTANDING_REQUEST_BYTES: u64 = OUTSTANDING_COVERS as u64 * MAX_REQUESTED_RANGE;

/// Credit advertised to the server: the covers this end asked for.
const FETCH_CREDIT_BYTES: u64 = OUTSTANDING_COVERS as u64 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// What the receiver may stage: credit plus the group reservation, so a
/// cover at the limit can still be verified.
const FETCH_STAGING_BYTES: u64 = FETCH_CREDIT_BYTES + vot_verifier::GROUP_SIZE as u64;

// The limit clears the credit by a group; at or under it would refuse a
// conforming answer.
const _: () = assert!(FETCH_CREDIT_BYTES == 17_039_360);
const _: () = assert!(FETCH_STAGING_BYTES == 17_104_896);

/// What one fetch pass left the session as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchStatus {
    /// The fetch is live; call again once the carrier reports an event.
    Active,
    /// The bundle is on disk, synced, and validated.
    Complete,
    /// The carrier ended the session before the bundle was whole.
    Disconnected,
    /// This end closed the session under a registered code.
    Closed(u16),
}

/// Why a frame could not be taken: server protocol fault, wrong package,
/// or local failure.
enum Fault {
    Peer(u16),
    Pin,
    Local(Error),
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

/// Bytes placed between stride flushes.
///
/// The completion sync is serial; flushing each stride spreads that work
/// across the transfer so the final sync covers at most a stride.
const FLUSH_STRIDE_BYTES: u64 = 67_108_864;

/// A sink that counts what it places, and keeps durability in stride.
///
/// The fetch cannot see answers arrive; the placed-byte count is the only
/// signal that paces requests and reports progress.
struct CountingSink {
    file: FileSink,
    placed: AtomicU64,
    /// Next placed-byte crossing due a flush; the exchange keeps two
    /// writers from flushing the same stride.
    flush_due: AtomicU64,
    /// Stride flushes taken.
    flushes: AtomicU64,
    /// Stride flush checkpoint hook, when a store rides the fetch.
    durable: Option<DurableHook>,
}

/// What a stride flush needs to turn durability into a checkpoint.
///
/// Coverage is snapshotted before the sync: checkpointing a range that
/// settles mid-sync would claim durability the disk never promised.
struct DurableHook {
    /// Weak, because the plan holds the sink that holds this.
    plan: std::sync::Weak<Mutex<FetchPlan>>,
    store: Arc<Mutex<ResumeStore>>,
    subject: SubjectId,
}

impl DurableHook {
    /// One stride's durability: snapshot, sync, checkpoint.
    fn flush(&self, file: &FileSink) {
        let covered = self.plan.upgrade().and_then(|plan| {
            let plan = plan.lock().ok()?;
            // Coverage is the current object's; a sink outliving its
            // object flushes without a claim to make.
            (plan.objects.get(plan.current).map(subject_of) == Some(self.subject))
                .then(|| plan.covered.clone())
        });
        if file.file().sync_data().is_err() {
            // Nothing durable to claim; the completion sync will tell
            // the truth loudly.
            return;
        }
        let Some(covered) = covered else {
            return;
        };
        let units = durable_units(&covered, self.subject.length);
        if units.is_empty() {
            return;
        }
        if let Ok(mut store) = self.store.lock() {
            let _ =
                store.checkpoint_units(self.subject, total_units_of(self.subject.length), &units);
        }
    }
}

impl CountingSink {
    fn create(path: &Path, length: u64, durable: Option<DurableHook>) -> std::io::Result<Self> {
        Ok(Self {
            file: FileSink::create(path, length)?,
            placed: AtomicU64::new(0),
            flush_due: AtomicU64::new(FLUSH_STRIDE_BYTES),
            flushes: AtomicU64::new(0),
            durable,
        })
    }

    /// Reopens a partial object, its counters seeded with what the last
    /// fetch already placed so pacing and reporting start true.
    fn resume(
        path: &Path,
        length: u64,
        placed: u64,
        durable: Option<DurableHook>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            file: FileSink::resume(path, length)?,
            placed: AtomicU64::new(placed),
            flush_due: AtomicU64::new(
                placed
                    .saturating_sub(placed % FLUSH_STRIDE_BYTES)
                    .saturating_add(FLUSH_STRIDE_BYTES),
            ),
            flushes: AtomicU64::new(0),
            durable,
        })
    }

    fn placed(&self) -> u64 {
        self.placed.load(Ordering::Relaxed)
    }
}

impl vot_scheduler::RangeSink for CountingSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        self.file.write_at(covered_offset, data)?;
        let placed = self
            .placed
            .fetch_add(data.len() as u64, Ordering::Relaxed)
            .saturating_add(data.len() as u64);
        let due = self.flush_due.load(Ordering::Relaxed);
        if placed >= due
            && self
                .flush_due
                .compare_exchange(
                    due,
                    // The crossing after what is placed, however many
                    // strides this write spanned.
                    placed
                        .saturating_sub(placed % FLUSH_STRIDE_BYTES)
                        .saturating_add(FLUSH_STRIDE_BYTES),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            // Best effort; the completion sync still runs, and a failure
            // here costs only the tail.
            self.flushes.fetch_add(1, Ordering::Relaxed);
            match &self.durable {
                Some(hook) => hook.flush(&self.file),
                None => {
                    let _ = self.file.file().sync_data();
                }
            }
        }
        Ok(())
    }
}

/// Threads that prove and place covers, beside the session thread.
///
/// One thread cannot receive a cover while it proves the one before, so
/// both steps move here and the witness returns through `settle`.
const DEFAULT_PROVING_THREADS: usize = 4;

/// How long a pass waits for a prover it is already owed.
///
/// Only reached when the pass would otherwise book nothing; the work is
/// this end's own and already in hand.
const PROVER_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

/// What a prover is handed: a bundle to prove and where its bytes go.
struct Proving {
    completed: CompletedBundle,
    sink: Arc<CountingSink>,
}

/// What comes back: the bundle, and the witness that it is written.
struct Proved {
    completed: CompletedBundle,
    written: vot_scheduler::WrittenRange,
}

/// The provers and the two channels they sit between.
struct ProvingPool {
    work: mpsc::SyncSender<Proving>,
    proved: mpsc::Receiver<Result<Proved, vot_scheduler::Error>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    /// The receiving half the provers share. Held here too, so a probe of
    /// this handle can tell provers that were joined from provers merely
    /// abandoned: after a drop, no other owner may remain.
    taking: Arc<std::sync::Mutex<mpsc::Receiver<Proving>>>,
    /// Bundles handed out and not yet settled, which is what decides
    /// whether this end has room to take another.
    in_flight: usize,
    /// Witnesses booked over the pool's life.
    witnesses: u64,
    width: usize,
}

impl ProvingPool {
    /// Starts `width` provers. Each holds a clone of the work channel's
    /// receiving half behind a lock, so a bundle goes to whichever is free.
    fn start(width: usize) -> Self {
        // Bounded at twice the width: enough that no prover waits on the
        // session thread for its next bundle, small enough that what is in
        // flight is a few covers rather than an object.
        let (work, taking) = mpsc::sync_channel::<Proving>(width.saturating_mul(2));
        let (finished, proved) = mpsc::channel::<Result<Proved, vot_scheduler::Error>>();
        let taking = Arc::new(std::sync::Mutex::new(taking));
        let mut threads = Vec::with_capacity(width);
        for _ in 0..width {
            let taking = Arc::clone(&taking);
            let finished = finished.clone();
            threads.push(std::thread::spawn(move || {
                loop {
                    let Ok(queue) = taking.lock() else {
                        return;
                    };
                    let Ok(next) = queue.recv() else {
                        return;
                    };
                    drop(queue);
                    if finished.send(prove(next)).is_err() {
                        return;
                    }
                }
            }));
        }
        Self {
            work,
            proved,
            threads,
            taking,
            in_flight: 0,
            witnesses: 0,
            width,
        }
    }

    /// Whether another bundle can be handed over without waiting.
    const fn has_room(&self) -> bool {
        self.in_flight < self.width.saturating_mul(2)
    }

    /// Whether anything is out with a prover.
    const fn busy(&self) -> bool {
        self.in_flight > 0
    }
}

impl Drop for ProvingPool {
    fn drop(&mut self) {
        // The provers end when the work channel closes, which is what
        // dropping this sender does; the joins then cannot outlive them.
        let (closed, _) = mpsc::sync_channel::<Proving>(1);
        drop(std::mem::replace(&mut self.work, closed));
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        // Every prover has been joined, so no other owner of the work
        // queue can remain.
        debug_assert_eq!(std::sync::Arc::strong_count(&self.taking), 1);
    }
}

/// Proves one bundle and places its bytes.
fn prove(work: Proving) -> Result<Proved, vot_scheduler::Error> {
    let range = ReliableReceiver::verify_typed_bundle(
        work.completed.subject(),
        work.completed.bundle(),
        work.completed.records(),
    )?;
    let written = range.write_to(work.sink.as_ref())?;
    Ok(Proved {
        completed: work.completed,
        written,
    })
}

/// One stored object the manifest names, in fetch order.
#[derive(Clone)]
struct PlannedObject {
    object: frames::ObjectId,
    /// Byte extents a previous fetch made durable; the handout skips them.
    resumed: BTreeMap<u64, u64>,
}

impl PlannedObject {
    fn fresh(object: frames::ObjectId) -> Self {
        Self {
            object,
            resumed: BTreeMap::new(),
        }
    }

    /// Whether the checkpointed extents already cover the whole object.
    fn fully_resumed(&self) -> bool {
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

/// What a [`SharedPlan`] holds.
pub(crate) struct FetchPlan {
    summary: PackageSummary,
    objects: Vec<PlannedObject>,
    current: usize,
    /// The sink the current object's verified ranges flow into, kept for
    /// the sync that makes its bytes durable before the fetch moves on.
    active: Option<Arc<CountingSink>>,
    /// Bytes placed for objects already left behind, so what this fetch
    /// has settled only ever goes up.
    placed_before: u64,
    /// Where the current object's next range request starts.
    next_offset: u64,
    /// Settled extents of the current object, coalesced; completion is
    /// full coverage.
    covered: BTreeMap<u64, u64>,
    /// Bytes [`FetchPlan::covered`] spans, each counted once however many
    /// rails a misbehaving server answers with the same range.
    covered_bytes: u64,
    /// Raised by the rail that saw the current object whole and is syncing
    /// it outside this lock, so no second rail syncs or advances over it.
    syncing: bool,
    /// Raised by a rail that failed, so the others stop instead of waiting
    /// out their stall budgets on spans nobody will answer.
    abandoned: bool,
    /// The current object's resumed extents, which the handout walks
    /// around: what a previous fetch made durable is never asked for.
    skip: BTreeMap<u64, u64>,
    /// Resume store, shared by every rail through the plan.
    store: Option<Arc<Mutex<ResumeStore>>>,
    finished: bool,
}

impl FetchPlan {
    /// The next range a taker would request, uncommitted and unpaced.
    ///
    /// Steps over resumed extents so durable ranges are never re-asked
    /// and no request overlaps one.
    fn next_span(&self) -> Result<Option<(frames::ObjectId, u64, u64)>, Error> {
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
    fn take(&mut self, offset: u64, length: u64) -> Result<(), Error> {
        self.next_offset = offset.checked_add(length).ok_or(Error::InvalidBundle)?;
        Ok(())
    }

    /// Books a settled cover into the current object's coverage.
    ///
    /// Coalescing counts each byte once, so a duplicate range from another
    /// rail cannot complete an object that still has a hole.
    fn cover(&mut self, offset: u64, length: u64) {
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
            .covered
            .range(..=end)
            .rev()
            .take_while(|(at, len)| at.saturating_add(**len) >= start)
            .map(|(at, len)| (*at, *len))
            .collect();
        for (at, len) in overlapping {
            self.covered.remove(&at);
            absorbed = absorbed.saturating_add(len);
            start = start.min(at);
            end = end.max(at.saturating_add(len));
        }
        self.covered.insert(start, end - start);
        self.covered_bytes = self
            .covered_bytes
            .saturating_add((end - start).saturating_sub(absorbed));
    }
}

/// The stance a fetch takes on a challenge it has not seen yet.
///
/// Presenting when this fetch holds a capability, which is what makes
/// `pending_presentation` fire and lets it answer. Without one it takes the
/// stance that answers nothing, and `vot_session` ends the session on a
/// challenge that names a format this end cannot supply, which is what the
/// format list in `spec/wire.md` 1.1 is for.
fn client_stance(holder: Option<&crate::authz::Holder>) -> Authentication {
    if holder.is_some() {
        Authentication::Presenting
    } else {
        // The client ignores the nonce; it is the server's freshness.
        Authentication::NotRequired { nonce: [0; 32] }
    }
}

/// One fetch: a client session, the receiver verifying its ranges, and the
/// bundle directory being written.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent fact about one fetch: what it is (a rail, a resume) and what has already happened to it (disconnected, stopped); folding them into states would cross the two"
)]
pub struct BundleFetcher<A: TransportAdapter> {
    receiver: SessionReceiver<A>,
    bundle: PathBuf,
    pin: Option<[u8; 32]>,
    descriptor: Option<PackageDescriptor>,
    seal_bytes: Option<Vec<u8>>,
    page_digests: Vec<[u8; 32]>,
    pages_received: u64,
    /// Manifest request spans still to issue, and the next one due.
    spans: Vec<(u64, u64)>,
    next_span: usize,
    plan: Option<SharedPlan>,
    /// Resume store, held until the manifest hands it to the plan.
    store: Option<Arc<Mutex<ResumeStore>>>,
    /// Whether this fetch continues a partial bundle, which is what makes
    /// the store's checkpoints a seed rather than a record.
    resuming: bool,
    /// Whether this fetcher is a rail on another fetch's plan.
    secondary: bool,
    /// The capability this fetch answers a challenge with, when it has one.
    /// Shared, because every rail opens its own session and answers its own
    /// challenge under the same token.
    holder: Option<Arc<crate::authz::Holder>>,
    /// The object this rail has admitted to its own receiver, by plan
    /// index. Admission is per rail; the plan cannot do it.
    admitted: Option<(usize, SubjectId)>,
    /// Range bytes this rail has committed to spans, only ever going up.
    taken_bytes: u64,
    /// Range bytes this rail has settled witnesses for. The gap between
    /// taken and settled paces requests per rail; pacing on the shared
    /// sink would let one rail overdraw on another's arrivals.
    settled_bytes: u64,
    /// The most this rail keeps outstanding:
    /// [`OUTSTANDING_REQUEST_BYTES`] always, narrowed only by tests so a
    /// small object stripes without a window's worth of data.
    window_bytes: u64,
    pending: VecDeque<Vec<u8>>,
    next_request: u64,
    closed: Option<u16>,
    /// Set once the carrier reported it had gone, so every later pass says
    /// so too rather than only the pass that saw it.
    disconnected: bool,
    /// Set once nothing further will be asked for, whatever ended it.
    stopped: bool,
    /// Everything this end has taken or asked for, only ever going up.
    ///
    /// A driving loop reads it to tell a slow transfer from a stuck one.
    progress: u64,
    /// The provers, started with the first cover so a fetch that carries
    /// none starts no threads.
    pool: Option<ProvingPool>,
    /// How many provers to start, or none for proving on this thread.
    proving_threads: usize,
    /// How long a pass waits for a witness it is owed. Overridden in tests.
    prover_wait: std::time::Duration,
    /// Where placed-byte crossings are reported, if anywhere.
    placed_report: Option<PlacedReport>,
}

/// A caller's window onto placed bytes, paced by the bytes themselves.
struct PlacedReport {
    quantum: u64,
    /// The next crossing worth a report. Starts at one quantum: zero is
    /// where every fetch begins, not news.
    next_at: u64,
    observer: Box<dyn FnMut(u64, Option<u64>) + Send>,
}

/// The crossing after `placed`, if `placed` reached the one due.
///
/// Pure mapping, so a test can hold the boundary exactly.
const fn crossing(placed: u64, next_at: u64, quantum: u64) -> Option<u64> {
    if placed < next_at {
        return None;
    }
    Some(
        placed
            .saturating_sub(placed % quantum)
            .saturating_add(quantum),
    )
}

/// Page spans of at most what one `MANIFEST_REQUEST` may name.
///
/// Bounded by the page count (from the seal), not by a cursor, so a
/// non-advancing span cannot grow this unboundedly.
fn manifest_spans(page_count: u64) -> Vec<(u64, u64)> {
    let mut spans = Vec::new();
    let mut first = 0;
    for _ in 0..page_count.div_ceil(MAX_MANIFEST_REQUEST_PAGES) {
        let count = MAX_MANIFEST_REQUEST_PAGES.min(page_count - first);
        spans.push((first, count));
        first += count;
    }
    spans
}

/// The span to ask for at `offset`, at most what one `RANGE_REQUEST` may
/// carry, or `None` once the object is covered.
///
/// Spans start on group-aligned boundaries, so every cover is exactly its
/// request and nothing is proved or carried twice.
fn range_span(offset: u64, length: u64) -> Option<(u64, u64)> {
    (offset < length).then(|| (offset, MAX_REQUESTED_RANGE.min(length - offset)))
}

/// The code a receiver's refusal closes under.
///
/// Local storage/budget failures are not `PROOF_INVALID`: that code tells
/// a server its proof was bad about a bundle it served correctly.
fn refusal_code(error: &vot_scheduler::Error) -> u16 {
    use vot_scheduler::Error as Refusal;
    match error {
        // This end could not write what it had already verified.
        Refusal::Sink => error_code::STORAGE_WRITE_FAILED,
        // More than this end will hold, whoever's sizing is at fault.
        Refusal::Staging(_)
        | Refusal::PendingBundlesExhausted
        | Refusal::RangeFragmentsExhausted
        | Refusal::AlreadyReceiving => error_code::RESOURCE_LIMIT,
        Refusal::UnknownObject
        | Refusal::RecordTooLarge
        | Refusal::LengthExceeded
        | Refusal::LengthMismatch
        | Refusal::RootMismatch
        | Refusal::Verification(_)
        | Refusal::ProofInvalid
        | Refusal::UnsupportedCompression
        // Handled before this is reached, and named so a variant added
        // later has to be placed rather than falling here.
        | Refusal::Session(_) => error_code::PROOF_INVALID,
    }
}

/// Removes the resume store beside a bundle that is now whole, lock file
/// and all, so the completed bundle looks exactly as one fetched without
/// a store.
fn remove_store_files(bundle: &Path) -> Result<(), Error> {
    // No need to decode a store in order to delete it.
    vot_resume::remove_files(&bundle.join(RESUME_STORE), true).map_err(resume_failure)
}

/// What a store's refusal means to the fetch that asked.
///
/// An identity conflict is the same refusal a wrong pin gets; anything
/// else is the store file itself failing.
fn resume_failure(error: vot_resume::Error) -> Error {
    match error {
        vot_resume::Error::Io(error) => Error::Io(error),
        vot_resume::Error::IdentityMismatch => Error::RootMismatch,
        _ => Error::InvalidBundle,
    }
}

fn subject_of(planned: &PlannedObject) -> SubjectId {
    SubjectId {
        suite: planned.object.suite,
        root: planned.object.root,
        length: planned.object.length,
    }
}

fn encoded(frame: &TypedFrame) -> Result<Vec<u8>, Error> {
    let mut wire = Vec::new();
    frames::encode(frame, &mut wire)?;
    Ok(wire)
}

impl<A: TransportAdapter> BundleFetcher<A> {
    /// Sets how many provers this fetch runs, or none to prove on the
    /// session's own thread.
    ///
    /// # Errors
    /// Surfaces a deferred bound the receiver refuses.
    pub fn set_proving_threads(&mut self, threads: usize) -> Result<(), Error> {
        if (self.secondary || self.resuming) && threads == 0 {
            // Inline proving books no witnesses: a rail paces on them and
            // a resumed fetch completes on coverage they feed.
            return Err(Error::InvalidArguments);
        }
        self.proving_threads = threads;
        self.receiver.defer_proving(threads > 0);
        if threads > 0 {
            // Room for every prover to hold one and one more to be waiting,
            // which is what keeps them all fed without holding an object.
            self.receiver
                .set_deferred_limit(threads.saturating_add(1))?;
        }
        Ok(())
    }

    /// Opens the session and the bundle directory the fetch will fill.
    ///
    /// The optional pin is the package root this fetch will accept. A
    /// destination with a partial bundle and resume store is continued:
    /// the store's identity becomes the pin, the manifest is re-fetched,
    /// and durable ranges are skipped. A destination without a store is
    /// refused.
    pub fn begin(adapter: A, bundle: &Path, pin: Option<[u8; 32]>) -> Result<Self, Error> {
        Self::begin_with(adapter, bundle, pin, None)
    }

    /// [`Self::begin`] holding a capability to present.
    ///
    /// # Errors
    /// As [`Self::begin`].
    pub(crate) fn begin_with(
        adapter: A,
        bundle: &Path,
        pin: Option<[u8; 32]>,
        holder: Option<Arc<crate::authz::Holder>>,
    ) -> Result<Self, Error> {
        let store_path = bundle.join(RESUME_STORE);
        let resuming = bundle.exists();
        if resuming {
            if !store_path.exists() {
                return Err(Error::DestinationExists);
            }
            // The manifest is re-fetched, not resumed: partial pages went
            // with the fetch that died, and re-validating fresh re-derives
            // the identity the store is checked against.
            fs::remove_dir_all(bundle.join(MANIFEST_DIRECTORY))?;
        }
        fs::create_dir_all(bundle.join(MANIFEST_DIRECTORY))?;
        fs::create_dir_all(bundle.join("objects"))?;
        let store = ResumeStore::create(&store_path).map_err(resume_failure)?;
        // The store's identity is the resume pin; a caller's pin that
        // disagrees is refused. A store too young to know binds to the
        // manifest this fetch proves.
        let mut pin = pin;
        if resuming {
            let stored = store
                .subjects()
                .find(|subject| subject.suite == 0)
                .map(|sentinel| sentinel.root);
            match (pin, stored) {
                (Some(pinned), Some(root)) if pinned != root => {
                    return Err(Error::RootMismatch);
                }
                (None, Some(root)) => pin = Some(root),
                _ => {}
            }
        }
        let mut session = Session::client(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            client_stance(holder.as_deref()),
        );
        session.begin()?;
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        let mut receiver = SessionReceiver::new(session, receiver);
        // Every outstanding cover must be holdable in any arrival state;
        // the receiver defaults are too shallow and fail a conforming
        // transfer with `PendingBundlesExhausted`.
        receiver.set_pending_limits(
            OUTSTANDING_COVERS,
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_PENDING_BUNDLE_BYTES,
        )?;
        receiver.set_orphan_limits(
            OUTSTANDING_COVERS,
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_ORPHAN_BUNDLE_BYTES,
        )?;
        let mut fetcher = Self {
            receiver,
            bundle: bundle.to_owned(),
            pin,
            descriptor: None,
            seal_bytes: None,
            page_digests: Vec::new(),
            pages_received: 0,
            spans: Vec::new(),
            next_span: 0,
            plan: None,
            store: Some(Arc::new(Mutex::new(store))),
            resuming,
            secondary: false,
            holder,
            admitted: None,
            taken_bytes: 0,
            settled_bytes: 0,
            window_bytes: OUTSTANDING_REQUEST_BYTES,
            pending: VecDeque::new(),
            next_request: 0,
            closed: None,
            disconnected: false,
            stopped: false,
            progress: 0,
            pool: None,
            proving_threads: 0,
            prover_wait: PROVER_WAIT,
            placed_report: None,
        };
        // Through the one place the deferred wiring lives, so the default
        // width and a caller's cannot come apart.
        fetcher.set_proving_threads(DEFAULT_PROVING_THREADS)?;
        Ok(fetcher)
    }

    /// Opens a rail onto a fetch already planned: a session striping
    /// range requests over the shared plan into the shared sink.
    ///
    /// The rail pins the plan's package root. It reads the announcement
    /// and requests ranges; the manifest is not fetched again.
    ///
    /// # Errors
    /// Surfaces a session or receiver that could not start.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn join(
        adapter: A,
        bundle: &Path,
        plan: SharedPlan,
        holder: Option<Arc<crate::authz::Holder>>,
    ) -> Result<Self, Error> {
        let root = plan.lock().map_err(|_| Error::InvalidBundle)?.summary.root;
        let mut session = Session::client(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            client_stance(holder.as_deref()),
        );
        session.begin()?;
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        let mut receiver = SessionReceiver::new(session, receiver);
        // Same pipeline budgets as the primary: each rail carries the full depth.
        receiver.set_pending_limits(
            OUTSTANDING_COVERS,
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_PENDING_BUNDLE_BYTES,
        )?;
        receiver.set_orphan_limits(
            OUTSTANDING_COVERS,
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_ORPHAN_BUNDLE_BYTES,
        )?;
        let mut fetcher = Self {
            receiver,
            bundle: bundle.to_owned(),
            pin: Some(root),
            descriptor: None,
            seal_bytes: None,
            page_digests: Vec::new(),
            pages_received: 0,
            spans: Vec::new(),
            next_span: 0,
            plan: Some(plan),
            store: None,
            resuming: false,
            secondary: true,
            holder,
            admitted: None,
            taken_bytes: 0,
            settled_bytes: 0,
            window_bytes: OUTSTANDING_REQUEST_BYTES,
            pending: VecDeque::new(),
            next_request: 0,
            closed: None,
            disconnected: false,
            stopped: false,
            progress: 0,
            pool: None,
            proving_threads: 0,
            prover_wait: PROVER_WAIT,
            placed_report: None,
        };
        fetcher.set_proving_threads(DEFAULT_PROVING_THREADS)?;
        Ok(fetcher)
    }

    /// The validated package, once the manifest has been.
    #[must_use]
    pub fn package(&self) -> Option<PackageSummary> {
        self.locked_plan().map(|plan| plan.summary)
    }

    /// The session under the fetch, for the loop that waits on its carrier.
    pub fn session_mut(&mut self) -> &mut Session<A> {
        self.receiver.session_mut()
    }

    /// The plan this fetch stripes over; what a rail joins.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn shared_plan(&self) -> Option<SharedPlan> {
        self.plan.clone()
    }

    /// The capability this fetch presents, for a rail that opens its own
    /// session on the same plan.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn holder(&self) -> Option<Arc<crate::authz::Holder>> {
        self.holder.clone()
    }

    /// The bundle directory this fetch writes.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn bundle(&self) -> &Path {
        &self.bundle
    }

    /// How many provers this fetch runs.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) const fn proving_threads(&self) -> usize {
        self.proving_threads
    }

    /// Everything this end has settled, only ever going up: frames taken,
    /// requests issued, and every byte placed.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.progress.saturating_add(self.placed_bytes())
    }

    /// Bytes verified and placed into the bundle, only ever going up.
    #[must_use]
    pub fn placed_bytes(&self) -> u64 {
        self.locked_plan().map_or(0, |plan| {
            plan.placed_before + plan.active.as_ref().map_or(0, |sink| sink.placed())
        })
    }

    /// The plan under its lock, or nothing before the manifest settles it.
    ///
    /// A poisoned lock reads as no plan; callers have a conservative
    /// answer for that.
    fn locked_plan(&self) -> Option<std::sync::MutexGuard<'_, FetchPlan>> {
        self.plan.as_ref().and_then(|plan| plan.lock().ok())
    }

    /// Reports placed bytes to `observer` at every `quantum` crossing.
    ///
    /// Paced by bytes, not a clock: fast paths report in bursts, slow
    /// ones at their own pace, idle sessions report nothing.
    ///
    /// # Errors
    /// Rejects a zero quantum.
    pub fn report_placed(
        &mut self,
        quantum: u64,
        observer: Box<dyn FnMut(u64, Option<u64>) + Send>,
    ) -> Result<(), Error> {
        if quantum == 0 {
            return Err(Error::InvalidArguments);
        }
        self.placed_report = Some(PlacedReport {
            quantum,
            next_at: quantum,
            observer,
        });
        Ok(())
    }

    /// One report if placed bytes crossed the next quantum, none otherwise.
    fn note_placed(&mut self) {
        let placed = self.placed_bytes();
        let total = self.locked_plan().map(|plan| plan.summary.logical_length);
        let Some(report) = &mut self.placed_report else {
            return;
        };
        let Some(next) = crossing(placed, report.next_at, report.quantum) else {
            return;
        };
        report.next_at = next;
        (report.observer)(placed, total);
    }

    /// Whether a request is queued that the carrier would not take, which
    /// is work another pass can do without an event.
    ///
    /// Ranges not yet asked for are not backlog: the wire is paced by
    /// answers coming back. A stopped fetch owes nothing.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.stopped
            && (!self.pending.is_empty() || self.pool.as_ref().is_some_and(ProvingPool::busy))
    }

    /// Forgets what is owed, because nothing more will be asked or answered.
    fn stop(&mut self) {
        self.pending.clear();
        self.stopped = true;
    }

    /// Answers a challenge that asks for a capability, once.
    ///
    /// A fetch with no capability answers nothing: the challenge fires only
    /// on a session begun `Presenting`, and one begun without a holder is
    /// not. That fetch ends on the challenge instead, which `vot_session`
    /// does for it, so the failure is loud rather than a session that waits
    /// on an answer it cannot give.
    ///
    /// # Errors
    /// Surfaces a proof this end could not make and a carrier that would not
    /// take the request. A refusal from the far end is not an error here; it
    /// arrives as the session closing under its own code.
    fn present_capability(&mut self) -> Result<(), Error> {
        let Some(holder) = self.holder.clone() else {
            return Ok(());
        };
        let request = {
            let Some(challenge) = self.receiver.session().pending_presentation() else {
                return Ok(());
            };
            holder.answer(challenge)?
        };
        self.receiver.session_mut().present(request)?;
        Ok(())
    }

    /// One pass over what the carrier holds: drains queued requests, takes
    /// every event, advances the object plan, and flushes. Never blocks;
    /// the caller waits on the adapter between passes.
    pub fn service(&mut self) -> Result<FetchStatus, Error> {
        if let Some(code) = self.closed {
            return Ok(FetchStatus::Closed(code));
        }
        if self.complete() {
            return Ok(FetchStatus::Complete);
        }
        if self.disconnected {
            // Recorded, so a carrier that has gone is gone for every later
            // pass rather than only the one that saw it go.
            return Ok(FetchStatus::Disconnected);
        }
        if self.locked_plan().is_some_and(|plan| plan.abandoned) {
            // Another rail failed; ending now spares the rest their stall budgets.
            self.stop();
            return Ok(FetchStatus::Disconnected);
        }
        self.present_capability()?;
        self.drain()?;
        loop {
            match self.receiver.poll() {
                Ok(Some(Event::Control(bytes))) => {
                    self.progress = self.progress.saturating_add(1);
                    if let Err(fault) = self.dispatch(&bytes) {
                        return self.fail(fault);
                    }
                }
                Ok(Some(Event::Disconnected(_))) => {
                    self.disconnected = true;
                    break;
                }
                Ok(Some(_)) => self.progress = self.progress.saturating_add(1),
                Ok(None) => break,
                Err(error) => return self.receive_failed(error),
            }
        }
        // Between taking frames and judging the pass: placed bytes advance the plan.
        if let Err(error) = self.pump_provers() {
            return self.receive_failed(error);
        }
        // Advanced before the carrier is judged: a pass that takes the last
        // object's bytes and the disconnect together has a whole bundle,
        // and reporting the carrier over it would throw away a finished
        // fetch.
        self.advance()?;
        // After the advance, so the pass that placed the crossing bytes is
        // the pass that reports them, however the pass then ends.
        self.note_placed();
        if self.complete() {
            self.stop();
            return Ok(FetchStatus::Complete);
        }
        if self.disconnected {
            self.stop();
            return Ok(FetchStatus::Disconnected);
        }
        // Topped up before the drain, so the carrier holds the covers, not
        // a pass's worth of requests each time round.
        self.issue_ranges()?;
        self.drain()?;
        self.receiver.session_mut().flush()?;
        Ok(FetchStatus::Active)
    }

    fn complete(&self) -> bool {
        self.locked_plan().is_some_and(|plan| plan.finished)
    }

    /// Ends a fetch the receiver refused: the session's own faults keep the
    /// code the session closed under, and everything else closes under the
    /// code that names whose fault it was.
    fn receive_failed(&mut self, error: vot_scheduler::Error) -> Result<FetchStatus, Error> {
        if let vot_scheduler::Error::Session(inner) = &error {
            if inner.kind().is_peer_fault() {
                let code = inner.close_code();
                self.close_under(code);
                return Ok(FetchStatus::Closed(code));
            }
            self.stop();
            return Err(Error::Scheduler(error));
        }
        self.close_under(refusal_code(&error));
        Err(Error::Scheduler(error))
    }

    /// Hands completed bundles to the provers, and books what they finish.
    ///
    /// Proof happens off this thread; what returns is a witness the
    /// receiver admits like the inline path does.
    fn pump_provers(&mut self) -> Result<(), vot_scheduler::Error> {
        if self.proving_threads == 0 {
            return Ok(());
        }
        let mut pool = self
            .pool
            .take()
            .unwrap_or_else(|| ProvingPool::start(self.proving_threads));
        // Handed over while there is room, so what is out with a prover is a
        // few covers rather than an object.
        while pool.has_room() {
            // The sink and the subject it is for, under one hold of the
            // lock: taken apart, another rail can advance the plan between
            // the two and the pair no longer describes one object.
            let Some((sink, subject)) = self.locked_plan().and_then(|plan| {
                let sink = plan.active.clone()?;
                let subject = plan.objects.get(plan.current).map(subject_of)?;
                Some((sink, subject))
            }) else {
                break;
            };
            let Some(completed) = self.receiver.take_completed() else {
                break;
            };
            if completed.subject() != subject {
                // A cover for an object the plan moved past: the plan only
                // advances on full coverage, so this is a duplicate for
                // another object's sink.
                continue;
            }
            if pool.work.try_send(Proving { completed, sink }).is_err() {
                break;
            }
            pool.in_flight = pool.in_flight.saturating_add(1);
        }
        // Every ready witness, then one waited for if the pass would
        // otherwise book nothing. A pass that returned without it would spin.
        if pool.in_flight == 0 {
            // Nothing is out, so there is nothing to wait for or book.
            self.pool = Some(pool);
            return Ok(());
        }
        let mut outcome = Ok(());
        // The first witness is waited for (this end's own work, already in
        // hand); the rest are taken as found. Bounded by construction:
        // one bounded wait, then at most what is out with a prover.
        let first = pool.proved.recv_timeout(self.prover_wait).ok();
        let ready: Vec<_> = first
            .into_iter()
            .chain(pool.proved.try_iter())
            .take(pool.in_flight)
            .collect();
        for result in ready {
            pool.in_flight = pool.in_flight.saturating_sub(1);
            match result {
                Ok(proved) => {
                    if let Err(error) = self.receiver.settle(&proved.completed, proved.written) {
                        outcome = Err(error);
                        break;
                    }
                    pool.witnesses = pool.witnesses.saturating_add(1);
                    let bundle = proved.completed.bundle();
                    // Earned back against this rail's window: what was
                    // taken is settled, so the next span may be asked for.
                    self.settled_bytes = self.settled_bytes.saturating_add(bundle.covered_length);
                    // Booked into shared coverage, which completes the object.
                    // The subject check drops stragglers.
                    if let Some(mut plan) = self.locked_plan() {
                        if plan.objects.get(plan.current).map(subject_of)
                            == Some(proved.completed.subject())
                        {
                            plan.cover(bundle.covered_offset, bundle.covered_length);
                        }
                    }
                }
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            }
        }
        self.pool = Some(pool);
        outcome
    }

    /// Closes the carrier under `code` and stops asking for anything.
    fn close_under(&mut self, code: u16) {
        let _ = self.receiver.session_mut().driver().close(code);
        self.closed = Some(code);
        self.stop();
    }

    fn fail(&mut self, fault: Fault) -> Result<FetchStatus, Error> {
        match fault {
            Fault::Peer(code) => {
                self.close_under(code);
                Ok(FetchStatus::Closed(code))
            }
            Fault::Pin => {
                // The server answered for a package this fetch will not
                // accept; that is a refusal, not a protocol fault.
                self.close_under(error_code::OBJECT_IDENTITY_MISMATCH);
                Err(Error::RootMismatch)
            }
            Fault::Local(error) => {
                self.stop();
                Err(error)
            }
        }
    }

    /// Hands queued requests to the session until the carrier refuses one.
    fn drain(&mut self) -> Result<(), Error> {
        while let Some(frame) = self.pending.front() {
            match self.receiver.session_mut().send_control(frame) {
                Ok(()) => {
                    self.pending.pop_front();
                }
                Err(error) if is_backpressure(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Queues one request frame, taking the fields rather than `self` so a
    /// caller holding the plan can still queue.
    fn queue_request(pending: &mut VecDeque<Vec<u8>>, frame: &TypedFrame) -> Result<(), Error> {
        pending.push_back(encoded(frame)?);
        Ok(())
    }

    /// The next request identifier, from a counter for the same reason.
    fn request_identifier(counter: &mut u64) -> Result<[u8; 16], Error> {
        let mut identifier = [0u8; 16];
        identifier[..8].copy_from_slice(&counter.to_be_bytes());
        *counter = counter.checked_add(1).ok_or(Error::InvalidBundle)?;
        Ok(identifier)
    }

    /// Takes one control frame, or ignores one that is not the fetch's.
    fn dispatch(&mut self, bytes: &[u8]) -> Result<(), Fault> {
        let limits = DecodeLimits {
            max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
            max_frames: 1,
        };
        let (frame, consumed) = match frames::decode(bytes, limits) {
            Ok(decoded) => decoded,
            // An unknown optional frame is skipped, per `spec/wire.md`.
            Err(frames::Error::WrongFrameType(_)) => return Ok(()),
            Err(frames::Error::Envelope(error)) => {
                return Err(Fault::Peer(error.protocol_code()));
            }
            Err(_) => return Err(Fault::Peer(error_code::MALFORMED_FRAME)),
        };
        if consumed != bytes.len() {
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        match frame {
            TypedFrame::PackageDescriptor(descriptor) => self.take_descriptor(descriptor),
            TypedFrame::Seal(seal) => self.take_seal(seal),
            TypedFrame::ManifestPage(page) => self.take_page(&page),
            // A well-formed frame this fetch does not consume.
            _ => Ok(()),
        }
    }

    fn take_descriptor(&mut self, descriptor: PackageDescriptor) -> Result<(), Fault> {
        if let Some(existing) = &self.descriptor {
            if *existing == descriptor {
                // An exact re-announcement is idempotent, per the registry.
                return Ok(());
            }
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        if let Some(pin) = self.pin {
            if pin != descriptor.package.root {
                return Err(Fault::Pin);
            }
        }
        if descriptor.package.suite != 1 {
            // The package root is blake3 over the entry sequence; any other
            // suite is not a package this CLI builds or receives.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        self.descriptor = Some(descriptor);
        Ok(())
    }

    fn take_seal(&mut self, seal_bytes: Vec<u8>) -> Result<(), Fault> {
        let Some(descriptor) = &self.descriptor else {
            // The descriptor leads the announcement; a seal without one is
            // out of sequence.
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        };
        if let Some(existing) = &self.seal_bytes {
            if *existing == seal_bytes {
                return Ok(());
            }
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        let seal = vot_manifest::decode_seal(&seal_bytes)
            .map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        let package_matches = seal.manifest_id == descriptor.manifest_id
            && seal.final_page_count == descriptor.page_count
            && seal.package.suite == descriptor.package.suite
            && seal.package.root == descriptor.package.root
            && seal.package.length == descriptor.package.length;
        if !package_matches {
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        if self.secondary {
            // A rail already has the manifest through its plan; nothing
            // further is asked.
            self.seal_bytes = Some(seal_bytes);
            return Ok(());
        }
        self.page_digests = crate::seal_page_digests(&seal)
            .map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        self.spans = manifest_spans(seal.final_page_count);
        self.seal_bytes = Some(seal_bytes);
        self.request_pages()?;
        Ok(())
    }

    /// Issues the next manifest span, one at a time: page arrival order is
    /// what indexes the digest check, so spans stay strictly sequential.
    fn request_pages(&mut self) -> Result<(), Fault> {
        let Some(descriptor) = &self.descriptor else {
            return Ok(());
        };
        let manifest_id = descriptor.manifest_id;
        if let Some((first_page, page_count)) = self.spans.get(self.next_span).copied() {
            if self.pages_received == first_page {
                let request_id =
                    Self::request_identifier(&mut self.next_request).map_err(Fault::Local)?;
                Self::queue_request(
                    &mut self.pending,
                    &TypedFrame::ManifestRequest(ManifestRequest {
                        request_id,
                        manifest_id,
                        first_page,
                        page_count,
                    }),
                )
                .map_err(Fault::Local)?;
                self.next_span += 1;
            }
        }
        Ok(())
    }

    fn take_page(&mut self, page_bytes: &[u8]) -> Result<(), Fault> {
        if self.secondary {
            // A page this rail never asked for; the manifest on disk is
            // the primary's and already validated.
            return Ok(());
        }
        if self.seal_bytes.is_none() {
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        let page = vot_manifest::decode_page(page_bytes)
            .map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        let index = page.index;
        let slot = usize::try_from(index).map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        let Some(committed) = self.page_digests.get(slot) else {
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        };
        if committed != blake3::hash(page_bytes).as_bytes() {
            // Not the page the seal committed to at this index.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        if index < self.pages_received {
            // An exact duplicate of a page already taken is idempotent.
            return Ok(());
        }
        if index > self.pages_received {
            // The control stream is ordered; a gap is the server's doing.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        crate::write_new_synced(
            &crate::manifest_page_path(&self.bundle.join(MANIFEST_DIRECTORY), index),
            page_bytes,
        )
        .map_err(Fault::Local)?;
        self.pages_received = self
            .pages_received
            .checked_add(1)
            .ok_or(Fault::Local(Error::InvalidBundle))?;
        self.request_pages()?;
        if Some(self.pages_received) == self.descriptor.as_ref().map(|d| d.page_count) {
            self.finish_manifest()?;
        }
        Ok(())
    }

    /// Writes the seal, validates the whole manifest the way `receive`
    /// does, and plans the objects it names.
    fn finish_manifest(&mut self) -> Result<(), Fault> {
        let seal_bytes = self
            .seal_bytes
            .as_ref()
            .ok_or(Fault::Local(Error::InvalidBundle))?;
        crate::write_new_synced(
            &self.bundle.join(MANIFEST_DIRECTORY).join(MANIFEST_SEAL),
            seal_bytes,
        )
        .map_err(Fault::Local)?;
        // The independent walk: chain, commitments, and the recomputed
        // package root. A manifest that passes per-page digests but breaks
        // here is the server's doing, not this host's.
        let summary = match crate::scan_manifest(&self.bundle) {
            Ok(summary) => summary,
            Err(Error::Io(error)) => return Err(Fault::Local(Error::Io(error))),
            Err(_) => return Err(Fault::Peer(error_code::MANIFEST_INVALID)),
        };
        let mut reader = ManifestReader::open(&self.bundle).map_err(Fault::Local)?;
        let mut seen = BTreeSet::new();
        let mut objects = Vec::new();
        while let Some(record) = reader.next_record().map_err(Fault::Local)? {
            let (root, length) = match record.storage {
                Storage::Direct => (record.logical_root, record.logical_length),
                Storage::Pack { root, length, .. } => (root, length),
            };
            if seen.insert(root) {
                objects.push(PlannedObject::fresh(frames::ObjectId {
                    suite: crate::suite_id(record.suite),
                    root,
                    length,
                }));
            }
        }
        // The store learns the whole plan in one reservation; a store
        // continuing a different package refuses here. What it already
        // holds seeds the handout.
        if let Some(store) = &self.store {
            let mut locked = store
                .lock()
                .map_err(|_| Fault::Local(Error::InvalidBundle))?;
            let reservations = std::iter::once((package_sentinel(summary.root), 1))
                .chain(reservations_of(&objects));
            locked
                .reserve_many(reservations)
                .map_err(|error| Fault::Local(resume_failure(error)))?;
            if self.resuming {
                for planned in &mut objects {
                    if let Some(units) = locked.checkpointed(subject_of(planned)) {
                        planned.resumed = resumed_extents(units, planned.object.length);
                    }
                }
            }
        }
        self.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects,
            current: 0,
            active: None,
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: self.store.clone(),
            finished: false,
        })));
        Ok(())
    }

    /// Moves the object plan forward: a covered object is synced and left
    /// behind, the next is admitted and requested, the last seals the bundle.
    ///
    /// Every rail runs this. Admission and abandonment are per-rail; the
    /// transition goes to whichever rail sees coverage whole first, and
    /// `syncing` keeps file work outside the lock without duplication.
    fn advance(&mut self) -> Result<(), Error> {
        // The handle apart from self, so the receiver and the bundle stay
        // reachable while the plan is held under its lock.
        let Some(shared) = self.plan.clone() else {
            return Ok(());
        };
        if self.secondary && self.descriptor.is_none() {
            // A rail admits and asks only once the server has answered
            // for the pinned package.
            return Ok(());
        }
        // Counted by the plan itself: every pass either returns or leaves
        // one more object behind, so needing more passes than the plan
        // names objects means the cursor is not moving.
        let objects = shared
            .lock()
            .map_err(|_| Error::InvalidBundle)?
            .objects
            .len();
        for _ in 0..=objects {
            let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
            // Forget partial accounts for objects the plan left behind, so
            // the receiver is bounded by what is current, not everything
            // this rail touched.
            if let Some((index, subject)) = self.admitted {
                if index != plan.current {
                    if !self.receiver.is_verified(subject) {
                        self.receiver.abandon(subject);
                    }
                    self.admitted = None;
                }
            }
            if let Some(sink) = plan.active.clone() {
                let planned = plan.objects.get(plan.current).ok_or(Error::InvalidBundle)?;
                let subject = subject_of(planned);
                let length = planned.object.length;
                if self.admitted != Some((plan.current, subject)) {
                    self.receiver.admit(subject, Box::new(Arc::clone(&sink)))?;
                    self.admitted = Some((plan.current, subject));
                }
                // Complete when shared coverage spans the object, or this
                // rail's receiver verified it.
                let whole = plan.covered_bytes == length || self.receiver.is_verified(subject);
                if !whole || plan.syncing {
                    return Ok(());
                }
                // Durable before the fetch moves on, so a completed fetch
                // never names bytes that were only in the page cache.
                // Synced outside the lock: the other rails keep booking
                // and asking while the file flushes.
                plan.syncing = true;
                let store = plan.store.clone();
                drop(plan);
                let synced = sink.file.file().sync_all();
                if synced.is_ok() {
                    // The whole object is now durable; a resume never asks
                    // for it again.
                    if let Some(store) = &store {
                        if let Ok(mut store) = store.lock() {
                            let mut units = UnitRanges::new();
                            units.extend_units(0..total_units_of(length));
                            let _ = store.checkpoint_units(subject, total_units_of(length), &units);
                        }
                    }
                }
                let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                plan.syncing = false;
                synced?;
                plan.placed_before = plan.placed_before.saturating_add(length);
                plan.active = None;
                plan.covered.clear();
                plan.covered_bytes = 0;
                plan.skip.clear();
                plan.current += 1;
                continue;
            }
            if plan.current == plan.objects.len() {
                if plan.finished || plan.syncing {
                    return Ok(());
                }
                // The seal on the bundle, outside the lock like any sync.
                // The store goes first: a completed bundle looks exactly
                // as one fetched without a store, and the directory sync
                // behind it is what makes the removal durable too.
                plan.syncing = true;
                drop(plan);
                let removed = remove_store_files(&self.bundle);
                let synced =
                    removed.and_then(|()| crate::sync_directories(&self.bundle).map(|_| ()));
                let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                plan.syncing = false;
                synced?;
                plan.store = None;
                plan.finished = true;
                return Ok(());
            }
            let planned = plan.objects.get(plan.current).ok_or(Error::InvalidBundle)?;
            let object = planned.object;
            let whole_from_before = planned.fully_resumed();
            let path = self
                .bundle
                .join("objects")
                .join(crate::object_name(&object.root));
            if object.length == 0 {
                // Nothing to fetch or verify; the empty object simply is.
                // The lock is held, so exactly one rail writes it; a
                // resumed fetch finds its own earlier write and moves on.
                if !path.exists() {
                    crate::write_new_synced(&path, &[])?;
                }
                plan.current += 1;
                continue;
            }
            if whole_from_before && path.exists() {
                // Durable whole from a previous fetch: nothing to admit
                // or ask for, and the store already says so.
                plan.placed_before = plan.placed_before.saturating_add(object.length);
                plan.current += 1;
                continue;
            }
            let subject = SubjectId {
                suite: object.suite,
                root: object.root,
                length: object.length,
            };
            let resumed = if path.exists() {
                planned.resumed.clone()
            } else {
                // The checkpoint outlived its file; clear the store too,
                // or a later resume would trust bytes nobody placed.
                let at = plan.current;
                if !plan.objects[at].resumed.is_empty() {
                    if let Some(store) = &plan.store {
                        if let Ok(mut store) = store.lock() {
                            store.reset(subject).map_err(resume_failure)?;
                        }
                    }
                    plan.objects[at].resumed.clear();
                }
                BTreeMap::new()
            };
            let seeded: u64 = resumed.values().sum();
            let durable = plan.store.as_ref().map(|store| DurableHook {
                plan: Arc::downgrade(&shared),
                store: Arc::clone(store),
                subject,
            });
            let sink = Arc::new(if path.exists() {
                CountingSink::resume(&path, object.length, seeded, durable)?
            } else {
                CountingSink::create(&path, object.length, durable)?
            });
            self.receiver.admit(subject, Box::new(Arc::clone(&sink)))?;
            self.admitted = Some((plan.current, subject));
            plan.active = Some(sink);
            plan.next_offset = 0;
            // The resumed extents seed both accounts: coverage, so the
            // object completes when the gaps do, and the skip set, so the
            // handout never asks for what is already placed.
            plan.covered = resumed.clone();
            plan.covered_bytes = seeded;
            plan.skip = resumed;
            // Released before the requests are issued: the handout takes
            // the same lock, and holding it here would deadlock this
            // rail's own thread.
            drop(plan);
            self.issue_ranges()?;
            return Ok(());
        }
        Err(Error::InvalidBundle)
    }

    /// Asks for as much of the object as this rail may have outstanding.
    ///
    /// Each span is committed only once its frame is queued, so a failure
    /// between the two leaves the span owed. The lock across the pair
    /// prevents two takers from framing the same span.
    ///
    /// Pacing is per rail (taken minus settled): a rail asking on another's
    /// arrivals would overdraw its own receiver. Inline proving uses the
    /// sink's placed count instead of settled witnesses.
    fn issue_ranges(&mut self) -> Result<(), Error> {
        let Some(shared) = self.plan.clone() else {
            return Ok(());
        };
        if self.secondary && self.descriptor.is_none() {
            return Ok(());
        }
        // Counted rather than conditioned on the queue length, so the pass
        // is bounded by the cap itself and no span can spin it.
        for _ in 0..OUTSTANDING_COVERS {
            let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
            let outstanding = if self.proving_threads == 0 {
                plan.next_offset
                    .saturating_sub(plan.active.as_ref().map_or(0, |sink| sink.placed()))
            } else {
                self.taken_bytes.saturating_sub(self.settled_bytes)
            };
            if outstanding >= self.window_bytes {
                return Ok(());
            }
            let Some((object, offset, length)) = plan.next_span()? else {
                return Ok(());
            };
            let request_id = Self::request_identifier(&mut self.next_request)?;
            Self::queue_request(
                &mut self.pending,
                &TypedFrame::RangeRequest(RangeRequest {
                    request_id,
                    object,
                    offset,
                    length,
                }),
            )?;
            plan.take(offset, length)?;
            self.taken_bytes = self.taken_bytes.saturating_add(length);
            self.progress = self.progress.saturating_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, discard, noise, not_required,
        patterned, pump, pump_records_first,
    };
    use crate::tests::temporary;
    use crate::{BundleServer, KeyMaterial, ServeConnection, build_bundle, receive_bundle};
    use vot_transport_api::ConnectionId;

    /// A served session and its state, ready to answer a fetch.
    fn serving(bundle: &Path) -> (BundleServer, Session<Loopback>, ServeConnection) {
        let server = BundleServer::open(bundle).unwrap();
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        (server, session, ServeConnection::new())
    }

    /// Puts the handshake and the server's announcement on the fetcher's
    /// carrier, without the pass that takes them, and answers with the
    /// sequence the pump reached so a caller can go on pumping.
    fn announce(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
    ) -> u64 {
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            serving.driver(),
            &mut sequence,
        );
        server.service(serving, connection).unwrap();
        pump(
            serving.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        sequence
    }

    /// One round of both engines and the pump, the way `run_to_end` runs it.
    fn round(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
        sequence: &mut u64,
    ) -> FetchStatus {
        let status = fetcher.service().unwrap();
        pump(fetcher.session_mut().driver(), serving.driver(), sequence);
        for _ in 0..ROUND_BUDGET {
            server.service(serving, connection).unwrap();
            if !connection.has_backlog() {
                break;
            }
        }
        pump(serving.driver(), fetcher.session_mut().driver(), sequence);
        status
    }

    /// Rounds a fetch may take before it is not progressing.
    ///
    /// Tight on purpose: a round of a stuck fetch re-fetches an object, so
    /// a generous budget means minutes of work before a failure surfaces.
    const ROUND_BUDGET: usize = 32;

    /// Runs both engines and the pump until the fetch reaches a terminal
    /// status, bounded by rounds rather than a clock.
    fn run_to_end(
        server: &BundleServer,
        serving: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
        corrupt_first_record: bool,
    ) -> Result<FetchStatus, Error> {
        let mut sequence = 0;
        let mut corrupted = corrupt_first_record;
        for _ in 0..ROUND_BUDGET {
            let status = fetcher.service()?;
            if status != FetchStatus::Active {
                return Ok(status);
            }
            pump(
                fetcher.session_mut().driver(),
                serving.driver(),
                &mut sequence,
            );
            for _ in 0..ROUND_BUDGET {
                server.service(serving, connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            if corrupted {
                if let Some((_, bytes)) = serving.driver().records.first_mut() {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                    corrupted = false;
                }
            }
            pump(
                serving.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
        }
        panic!("the fetch did not settle within its round budget");
    }

    /// Recursively compares two directory trees by structure and bytes.
    fn assert_same_tree(left: &Path, right: &Path) {
        let names = |root: &Path| {
            let mut entries: Vec<_> = fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            entries.sort();
            entries
        };
        let left_entries = names(left);
        assert_eq!(left_entries, names(right), "differs under {left:?}");
        for name in left_entries {
            let (a, b) = (left.join(&name), right.join(&name));
            if a.is_dir() {
                assert_same_tree(&a, &b);
            } else {
                assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap(), "{a:?}");
            }
        }
    }

    #[test]
    fn a_bundle_round_trips_build_serve_fetch_receive() {
        // A packed pair, a direct object spanning several ranges, and an empty file.
        let source = temporary("trip-source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("a.txt"), patterned(1000)).unwrap();
        fs::write(source.join("nested/b.bin"), patterned(150_000)).unwrap();
        fs::write(source.join("big.bin"), patterned(8_500_000)).unwrap();
        fs::write(source.join("empty.txt"), b"").unwrap();
        let bundle = temporary("trip-bundle");
        let built = build_bundle(&source, &bundle).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("trip-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(fetcher.package(), Some(built));
        assert!(!fetcher.has_backlog());

        assert_same_tree(&bundle, &output);

        let destination = temporary("trip-destination");
        let receipt = temporary("trip-receipt.cbor");
        let report = receive_bundle(
            &output,
            &destination,
            &receipt,
            &KeyMaterial::Shared(vec![7; 32]),
            "2026-08-06T00:00:00Z",
        )
        .unwrap();
        assert_eq!(report.package, built);
        assert_same_tree(&source, &destination);
        discard(&[&source, &bundle, &output, &destination, &receipt]);
    }

    /// Rounds one rail until its plan exists, which is where rails join.
    fn planned(
        server: &BundleServer,
        session: &mut Session<Loopback>,
        connection: &mut ServeConnection,
        fetcher: &mut BundleFetcher<Loopback>,
    ) -> SharedPlan {
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            round(server, session, connection, fetcher, &mut sequence);
            if let Some(plan) = fetcher.plan.clone() {
                return plan;
            }
        }
        panic!("the fetch never planned");
    }

    #[test]
    fn two_rails_stripe_one_object_over_a_shared_plan() {
        // Two sessions striping one object: the primary's window is narrowed
        // to one span so a two-span object must stripe across both rails.
        let length = 2 * usize::try_from(MAX_REQUESTED_RANGE).unwrap();
        let (bundle, built) = built_bundle("striped", &[("big.bin", patterned(length))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session1 = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            crate::harness::not_required(),
        );
        session1.begin().unwrap();
        let mut connection1 = ServeConnection::new();
        let mut session2 = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            crate::harness::not_required(),
        );
        session2.begin().unwrap();
        let mut connection2 = ServeConnection::new();

        let output = temporary("striped-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        primary.window_bytes = MAX_REQUESTED_RANGE;
        let plan = planned(&server, &mut session1, &mut connection1, &mut primary);
        let mut secondary =
            BundleFetcher::join(Loopback::default(), &output, Arc::clone(&plan), None).unwrap();

        let (mut seq1, mut seq2) = (0, 0);
        // Admit the rail before the primary settles, so the handout is deterministic.
        for _ in 0..ROUND_BUDGET {
            round(
                &server,
                &mut session2,
                &mut connection2,
                &mut secondary,
                &mut seq2,
            );
            if secondary.taken_bytes > 0 {
                break;
            }
        }
        let mut settled = false;
        for _ in 0..ROUND_BUDGET {
            let one = round(
                &server,
                &mut session1,
                &mut connection1,
                &mut primary,
                &mut seq1,
            );
            let two = round(
                &server,
                &mut session2,
                &mut connection2,
                &mut secondary,
                &mut seq2,
            );
            if one == FetchStatus::Complete && two == FetchStatus::Complete {
                settled = true;
                break;
            }
        }
        assert!(settled, "the rails never finished the fetch");
        assert_eq!(primary.taken_bytes, MAX_REQUESTED_RANGE);
        assert_eq!(secondary.taken_bytes, MAX_REQUESTED_RANGE);
        assert!(!primary.has_backlog());
        assert!(!secondary.has_backlog());
        assert_eq!(primary.package(), Some(built));
        assert_eq!(secondary.package(), Some(built));
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    fn an_abandoned_plan_ends_every_rail_without_its_stall_budget() {
        // A failed rail marks the plan; the others end at their next pass
        // instead of waiting out a stall budget.
        let (bundle, _) = built_bundle("abandoned", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("abandoned-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut primary);
        let mut secondary =
            BundleFetcher::join(Loopback::default(), &output, Arc::clone(&plan), None).unwrap();

        abandon_plan(&plan);
        assert_eq!(primary.service().unwrap(), FetchStatus::Disconnected);
        assert!(!primary.has_backlog(), "an ended rail owes nothing");
        assert_eq!(secondary.service().unwrap(), FetchStatus::Disconnected);
        assert!(!secondary.has_backlog());
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_rail_paces_itself_and_refuses_inline_proving() {
        // A rail's window is its own account; inline proving would never earn it back.
        let (bundle, _) = built_bundle("railpace", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("railpace-fetched");
        let mut primary = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let plan = planned(&server, &mut session, &mut connection, &mut primary);
        let mut secondary =
            BundleFetcher::join(Loopback::default(), &output, Arc::clone(&plan), None).unwrap();
        assert!(secondary.secondary, "a joined fetcher is a rail");
        assert_eq!(
            secondary.pin,
            Some(server.package().root),
            "the rail pins the plan's package"
        );
        assert!(
            secondary.set_proving_threads(0).is_err(),
            "a rail cannot prove inline"
        );
        assert!(
            secondary.set_proving_threads(2).is_ok(),
            "a narrower pool is the rail's to choose"
        );
        // Budgets are the pipeline depth (a product); a sum would be one bundle wide.
        assert_eq!(
            secondary.receiver.pending_byte_limit(),
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_PENDING_BUNDLE_BYTES
        );
        assert_eq!(
            secondary.receiver.orphan_byte_limit(),
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_ORPHAN_BUNDLE_BYTES
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_rail_forgets_the_object_the_plan_moved_past() {
        // A partial account for a moved-past object is forgotten, or the
        // receiver keeps a reservation per object.
        let output = temporary("railforget");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let first = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [1; 32],
            length: 1000,
        });
        let second = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [2; 32],
            length: 2000,
        });
        let (s0, s1) = (subject_of(&first), subject_of(&second));
        let sink0 = Arc::new(
            CountingSink::create(
                &output.join("objects").join("a.obj"),
                first.object.length,
                None,
            )
            .unwrap(),
        );
        let sink1 = Arc::new(
            CountingSink::create(
                &output.join("objects").join("b.obj"),
                second.object.length,
                None,
            )
            .unwrap(),
        );
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![first, second],
            current: 0,
            active: Some(sink0),
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.admitted,
            Some((0, s0)),
            "the first object is this rail's"
        );

        // Another rail saw the first object whole and moved the plan on.
        {
            let mut plan = fetcher.locked_plan().unwrap();
            plan.current = 1;
            plan.active = Some(sink1);
        }
        fetcher.advance().unwrap();
        assert_eq!(
            fetcher.admitted,
            Some((1, s1)),
            "the current object is admitted"
        );
        assert!(
            !fetcher.receiver.abandon(s0),
            "the partial first object was already forgotten"
        );
        discard(&[&output]);
    }

    #[test]
    fn a_finished_plan_is_left_exactly_as_it_is() {
        // A pass over a finished plan touches nothing; the directory is
        // gone to prove it.
        let output = temporary("finished-left");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: true,
        })));
        fs::remove_dir_all(&output).unwrap();
        fetcher.advance().unwrap();
        assert!(fetcher.complete());
    }

    #[test]
    fn coverage_counts_every_byte_once() {
        // Coalescing counts each byte once, so a duplicate range cannot
        // complete an object with a hole.
        let mut plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: Vec::new(),
            current: 0,
            active: None,
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        };
        plan.cover(0, 10);
        assert_eq!(plan.covered_bytes, 10);
        plan.cover(5, 10);
        assert_eq!(plan.covered_bytes, 15, "the overlap counts once");
        plan.cover(5, 5);
        assert_eq!(plan.covered_bytes, 15, "a duplicate counts never");
        plan.cover(20, 5);
        assert_eq!(plan.covered_bytes, 20, "a gap stays a gap");
        plan.cover(15, 5);
        assert_eq!(plan.covered_bytes, 25, "the gap filled exactly");
        assert_eq!(
            plan.covered.iter().collect::<Vec<_>>(),
            vec![(&0, &25)],
            "adjacent extents coalesce to one"
        );
        plan.cover(0, 25);
        assert_eq!(plan.covered_bytes, 25, "the whole again changes nothing");
        plan.cover(30, 0);
        assert_eq!(plan.covered_bytes, 25, "an empty cover covers nothing");
        plan.cover(u64::MAX, 2);
        assert_eq!(plan.covered_bytes, 25, "an overflowing cover is refused");
    }

    #[test]
    fn a_striped_fetch_over_threads_completes_and_spawns_its_rails() {
        // The connect count pins that the rail was spawned; width one
        // would pass every other assertion.
        use std::sync::Condvar;
        use std::sync::atomic::AtomicUsize;

        type Halves = Arc<(Mutex<VecDeque<crate::harness::Duplex>>, Condvar)>;

        // Small: striping distribution is the interleaved test's subject.
        let (bundle, built) = built_bundle("threaded", &[("big.bin", patterned(300_000))]);
        let output = temporary("threaded-fetched");
        let halves: Halves = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let serving_halves = Arc::clone(&halves);
        let serving_bundle = bundle.clone();
        let serving = std::thread::spawn(move || {
            let server = BundleServer::open(&serving_bundle)?;
            crate::drive::serve_sessions(Some(2), || {
                let (queue, arrived) = &*serving_halves;
                let queue = queue.lock().expect("the accept queue");
                // Bounded, so a fetch that never spawned its rail fails
                // this thread rather than hanging the suite on its join.
                let (mut queue, waited) = arrived
                    .wait_timeout_while(queue, std::time::Duration::from_secs(20), |waiting| {
                        waiting.is_empty()
                    })
                    .expect("the accept queue");
                if waited.timed_out() {
                    return Err(Error::CarrierUnavailable);
                }
                let carrier = queue.pop_front().expect("the wait held until one came");
                crate::drive::ServeSession::begin(&server, carrier, crate::harness::not_required())
            })
        });

        let connects = AtomicUsize::new(0);
        let connect = || {
            connects.fetch_add(1, Ordering::Relaxed);
            let (client, serving) = crate::harness::duplex_pair();
            let (queue, arrived) = &*halves;
            queue.lock().expect("the accept queue").push_back(serving);
            arrived.notify_all();
            Ok(client)
        };
        let fetcher = BundleFetcher::begin(connect().unwrap(), &output, None).unwrap();
        let package = crate::drive::fetch_striped(fetcher, 2, connect).unwrap();
        assert_eq!(package, built);
        assert_eq!(
            connects.load(Ordering::Relaxed),
            2,
            "width two is the primary and exactly one spawned rail"
        );
        assert_same_tree(&bundle, &output);
        serving
            .join()
            .expect("the serving thread")
            .expect("both sessions served");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_stride_crossing_flushes_once_and_arms_the_next() {
        // The crossing writer flushes once; the next mark is a stride
        // above what is placed.
        let output = temporary("stride");
        fs::create_dir_all(&output).unwrap();
        let stride = usize::try_from(FLUSH_STRIDE_BYTES).unwrap();
        let sink =
            CountingSink::create(&output.join("s.obj"), 4 * FLUSH_STRIDE_BYTES, None).unwrap();
        let chunk = vec![7u8; stride - 1];
        vot_scheduler::RangeSink::write_at(&sink, 0, &chunk).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            0,
            "one short of the stride flushes nothing"
        );
        vot_scheduler::RangeSink::write_at(&sink, FLUSH_STRIDE_BYTES - 1, &[7u8]).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            1,
            "the crossing flushes"
        );
        assert_eq!(
            sink.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "and arms the next stride"
        );
        let wide = vec![7u8; 2 * stride];
        vot_scheduler::RangeSink::write_at(&sink, FLUSH_STRIDE_BYTES, &wide).unwrap();
        assert_eq!(
            sink.flushes.load(Ordering::Relaxed),
            2,
            "a write spanning strides flushes once"
        );
        assert_eq!(
            sink.flush_due.load(Ordering::Relaxed),
            4 * FLUSH_STRIDE_BYTES,
            "armed above what is placed, not one stride on"
        );
        discard(&[&output]);
    }

    #[test]
    fn a_killed_fetch_resumes_from_what_it_placed() {
        // Die after the first object is durable, then resume: the second
        // fetch asks only for the rest.
        let (bundle, built) = built_bundle(
            "killed",
            &[("a.bin", patterned(900_000)), ("b.bin", noise(900_000))],
        );
        let output = temporary("killed-fetched");

        // Fetch one: driven until the first object transitions, then
        // dropped where it stands, covers in flight and all.
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            assert!(!fetcher.resuming, "a fresh destination is not a resume");
            let mut sequence = 0;
            let mut first_done = false;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut fetcher,
                    &mut sequence,
                );
                if fetcher
                    .locked_plan()
                    .is_some_and(|plan| plan.placed_before > 0)
                {
                    first_done = true;
                    break;
                }
            }
            assert!(first_done, "the first object never completed");
        }
        assert!(
            output.join(RESUME_STORE).exists(),
            "the partial bundle carries its continuation state"
        );

        // Fetch two: continues instead of refusing, and asks only for
        // the second object.
        let (server, mut session, mut connection) = serving(&bundle);
        let mut resumed = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(resumed.resuming, "a store beside the bundle is a resume");
        assert!(
            resumed.set_proving_threads(0).is_err(),
            "a resumed fetch completes on coverage, which inline proving never feeds"
        );
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut resumed, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(resumed.package(), Some(built));
        let second_length = resumed
            .locked_plan()
            .unwrap()
            .objects
            .iter()
            .map(|planned| planned.object.length)
            .max()
            .unwrap();
        assert_eq!(
            resumed.taken_bytes, second_length,
            "the resumed fetch asked for the unplaced object and nothing more"
        );
        assert!(
            !output.join(RESUME_STORE).exists(),
            "completion removed the store"
        );
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_checkpoint_whose_file_is_gone_is_cleared_in_the_store_too() {
        // A stale checkpoint must be cleared in the store too, or a later
        // resume trusts bytes nobody placed.
        let (bundle, built) = built_bundle(
            "stale",
            &[("a.bin", patterned(900_000)), ("b.bin", noise(900_000))],
        );
        let output = temporary("stale-fetched");
        let first_root;
        {
            let (server, mut session, mut connection) = serving(&bundle);
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            let mut sequence = 0;
            let mut first_done = false;
            for _ in 0..ROUND_BUDGET {
                round(
                    &server,
                    &mut session,
                    &mut connection,
                    &mut fetcher,
                    &mut sequence,
                );
                if fetcher
                    .locked_plan()
                    .is_some_and(|plan| plan.placed_before > 0)
                {
                    first_done = true;
                    break;
                }
            }
            assert!(first_done, "the first object never completed");
            first_root = fetcher.locked_plan().unwrap().objects[0].object.root;
        }
        // The checkpointed file vanishes between the fetches.
        fs::remove_file(output.join("objects").join(crate::object_name(&first_root))).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let mut resumed = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            round(
                &server,
                &mut session,
                &mut connection,
                &mut resumed,
                &mut sequence,
            );
            if resumed
                .locked_plan()
                .is_some_and(|plan| plan.active.is_some())
            {
                break;
            }
        }
        let first_subject = resumed
            .locked_plan()
            .map(|plan| subject_of(&plan.objects[0]))
            .unwrap();
        assert!(
            ResumeStore::open(output.join(RESUME_STORE))
                .unwrap()
                .checkpointed(first_subject)
                .is_none_or(vot_resume::UnitRanges::is_empty),
            "the stale claim was cleared in the store, not only locally"
        );
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut resumed, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        let total: u64 = resumed
            .locked_plan()
            .unwrap()
            .objects
            .iter()
            .map(|planned| planned.object.length)
            .sum();
        assert_eq!(
            resumed.taken_bytes, total,
            "everything was re-requested, the stale claim bought nothing"
        );
        assert_eq!(resumed.package(), Some(built));
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_partial_bundle_without_a_store_is_refused_and_identity_is_held() {
        // Without a store, nothing is safe to continue. With one, its
        // sentinel is the resume pin.
        let occupied = temporary("resume-nostore");
        fs::create_dir_all(occupied.join(MANIFEST_DIRECTORY)).unwrap();
        assert!(matches!(
            BundleFetcher::begin(Loopback::default(), &occupied, None),
            Err(Error::DestinationExists)
        ));

        let bound = temporary("resume-bound");
        fs::create_dir_all(bound.join(MANIFEST_DIRECTORY)).unwrap();
        let mut store = ResumeStore::create(bound.join(RESUME_STORE)).unwrap();
        store
            .reserve_many([(package_sentinel([7; 32]), 1)])
            .unwrap();
        drop(store);
        assert!(
            matches!(
                BundleFetcher::begin(Loopback::default(), &bound, Some([9; 32])),
                Err(Error::RootMismatch)
            ),
            "a pin that disagrees with the store is refused before a byte"
        );
        let agreed = BundleFetcher::begin(Loopback::default(), &bound, None).unwrap();
        assert_eq!(
            agreed.pin,
            Some([7; 32]),
            "the store's identity is the pin a resume is held to"
        );
        drop(agreed);
        let matching = BundleFetcher::begin(Loopback::default(), &bound, Some([7; 32])).unwrap();
        assert_eq!(
            matching.pin,
            Some([7; 32]),
            "a pin that agrees with the store is no refusal"
        );
        discard(&[&occupied, &bound]);
    }

    #[test]
    fn checkpoint_units_and_extents_convert_by_whole_units_only() {
        // Only whole units may be checkpointed; stored units come back
        // clipped to the object.
        let unit = vot_scheduler::RANGE_UNIT_BYTES;
        let length = 3 * unit + 100;
        assert_eq!(total_units_of(length), 4, "the tail unit counts");
        assert_eq!(total_units_of(3 * unit), 3, "an exact fit adds none");

        let mut covered = BTreeMap::new();
        covered.insert(0, unit + 1);
        assert_eq!(
            durable_units(&covered, length).units().collect::<Vec<_>>(),
            vec![0],
            "a byte into the next unit checkpoints only the whole one"
        );
        let mut covered = BTreeMap::new();
        covered.insert(1, unit);
        assert!(
            durable_units(&covered, length).is_empty(),
            "a unit missing its first byte is not durable"
        );
        let mut covered = BTreeMap::new();
        covered.insert(3 * unit, 100);
        assert_eq!(
            durable_units(&covered, length).units().collect::<Vec<_>>(),
            vec![3],
            "the tail unit is whole at the object's end"
        );

        let mut covered = BTreeMap::new();
        covered.insert(0, 2 * unit + 5);
        assert_eq!(
            durable_units(&covered, 4 * unit)
                .units()
                .collect::<Vec<_>>(),
            vec![0, 1],
            "the boundary is a division, not a remainder"
        );

        let mut units = UnitRanges::new();
        units.extend_units([0, 3]);
        let extents = resumed_extents(&units, length);
        assert_eq!(
            extents.iter().collect::<Vec<_>>(),
            vec![(&0, &unit), (&(3 * unit), &100)],
            "stored units come back clipped to the object"
        );
        let mut units = UnitRanges::new();
        units.extend_units([3]);
        assert!(
            resumed_extents(&units, 3 * unit).is_empty(),
            "a unit starting at the object's end stands for no bytes"
        );
    }

    #[test]
    fn store_refusals_map_to_the_fetchs_own_errors() {
        // The identity refusal is the wrong-pin refusal; a broken store
        // file is its own I/O; everything else is a bundle problem.
        assert!(matches!(
            resume_failure(vot_resume::Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            Error::Io(_)
        ));
        assert!(matches!(
            resume_failure(vot_resume::Error::IdentityMismatch),
            Error::RootMismatch
        ));
        assert!(matches!(
            resume_failure(vot_resume::Error::Corrupt),
            Error::InvalidBundle
        ));
    }

    #[test]
    fn only_whole_nonempty_objects_reserve_and_resume_whole() {
        // Reservations exclude zero-length objects; fully_resumed needs a
        // nonempty object fully covered.
        let empty = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [1; 32],
            length: 0,
        });
        let stored = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [2; 32],
            length: 100,
        });
        assert_eq!(
            reservations_of(&[empty.clone(), stored.clone()]),
            vec![(subject_of(&stored), 1)],
            "the empty object reserves nothing, the stored one its units"
        );

        assert!(!empty.fully_resumed(), "an empty object is never resumed");
        assert!(!stored.fully_resumed(), "nothing placed is not whole");
        let mut partial = stored.clone();
        partial.resumed.insert(0, 99);
        assert!(!partial.fully_resumed(), "one byte short is short");
        let mut whole = stored;
        whole.resumed.insert(0, 100);
        assert!(whole.fully_resumed());
    }

    #[test]
    fn a_resumed_sinks_flush_mark_starts_past_what_is_placed() {
        // The seed arms the next stride above resumed bytes, so the first
        // flush is new work.
        let output = temporary("resume-seed");
        fs::create_dir_all(&output).unwrap();
        let path = output.join("s.obj");
        drop(CountingSink::create(&path, 4 * FLUSH_STRIDE_BYTES, None).unwrap());

        let mid = CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, 100, None).unwrap();
        assert_eq!(mid.placed(), 100, "the seed is what was placed");
        assert_eq!(
            mid.flush_due.load(Ordering::Relaxed),
            FLUSH_STRIDE_BYTES,
            "a seed inside the first stride arms the first mark"
        );
        let exact =
            CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, FLUSH_STRIDE_BYTES, None).unwrap();
        assert_eq!(
            exact.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "a seed on the mark arms the one after it"
        );
        let past =
            CountingSink::resume(&path, 4 * FLUSH_STRIDE_BYTES, FLUSH_STRIDE_BYTES + 5, None)
                .unwrap();
        assert_eq!(
            past.flush_due.load(Ordering::Relaxed),
            2 * FLUSH_STRIDE_BYTES,
            "a seed past the mark arms the whole stride above it"
        );
        discard(&[&output]);
    }

    #[test]
    fn a_stride_flush_checkpoints_the_covered_units_of_its_own_object() {
        // Matching coverage becomes checkpointed units after sync; a
        // moved-past object checkpoints nothing.
        let unit = vot_scheduler::RANGE_UNIT_BYTES;
        let output = temporary("hook");
        fs::create_dir_all(&output).unwrap();
        let object = frames::ObjectId {
            suite: 1,
            root: [5; 32],
            length: 4 * unit,
        };
        let planned = PlannedObject::fresh(object);
        let subject = subject_of(&planned);
        let store = Arc::new(Mutex::new(
            ResumeStore::create(output.join(RESUME_STORE)).unwrap(),
        ));
        store
            .lock()
            .unwrap()
            .reserve_many([(subject, total_units_of(object.length))])
            .unwrap();
        let mut covered = BTreeMap::new();
        covered.insert(0, 2 * unit + 5);
        let plan = Arc::new(Mutex::new(FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![planned],
            current: 0,
            active: None,
            placed_before: 0,
            next_offset: 0,
            covered,
            covered_bytes: 2 * unit + 5,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: Some(Arc::clone(&store)),
            finished: false,
        }));
        let sink = CountingSink::create(
            &output.join("h.obj"),
            object.length,
            Some(DurableHook {
                plan: Arc::downgrade(&plan),
                store: Arc::clone(&store),
                subject,
            }),
        )
        .unwrap();

        sink.durable.as_ref().unwrap().flush(&sink.file);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .checkpointed(subject)
                .unwrap()
                .units()
                .collect::<Vec<_>>(),
            vec![0, 1],
            "the whole units inside the snapshot, and no more"
        );

        // The plan moves on; a late flush of the old sink claims nothing.
        let other = PlannedObject::fresh(frames::ObjectId {
            suite: 1,
            root: [6; 32],
            length: unit,
        });
        {
            let mut plan = plan.lock().unwrap();
            plan.objects.push(other);
            plan.current = 1;
            plan.covered.clear();
            plan.covered.insert(0, unit);
        }
        let before = store.lock().unwrap().checkpointed(subject).unwrap().count();
        sink.durable.as_ref().unwrap().flush(&sink.file);
        assert_eq!(
            store.lock().unwrap().checkpointed(subject).unwrap().count(),
            before,
            "another object's coverage is not this sink's to claim"
        );
        discard(&[&output]);
    }

    #[test]
    fn the_handout_walks_around_what_is_already_placed() {
        // The handout never asks inside a resumed extent or overlaps one.
        let object = frames::ObjectId {
            suite: 1,
            root: [3; 32],
            length: 3 * MAX_REQUESTED_RANGE,
        };
        let mut skip = BTreeMap::new();
        // A resumed hole pattern: the middle span is durable.
        skip.insert(MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE);
        let plan = FetchPlan {
            summary: PackageSummary {
                root: [0; 32],
                logical_length: 0,
                entries: 0,
            },
            objects: vec![PlannedObject::fresh(object)],
            current: 0,
            active: Some(Arc::new(
                CountingSink::create(
                    &{
                        let output = temporary("handout-skip");
                        fs::create_dir_all(&output).unwrap();
                        output.join("s.obj")
                    },
                    object.length,
                    None,
                )
                .unwrap(),
            )),
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip,
            store: None,
            finished: false,
        };
        let (_, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (offset, length),
            (0, MAX_REQUESTED_RANGE),
            "clipped at the hole"
        );
        let mut plan = plan;
        plan.take(offset, length).unwrap();
        let (_, offset, length) = plan.next_span().unwrap().unwrap();
        assert_eq!(
            (offset, length),
            (2 * MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE),
            "the walk lands past the durable middle"
        );
        plan.take(offset, length).unwrap();
        assert!(plan.next_span().unwrap().is_none(), "nothing more is owed");
    }

    #[test]
    fn the_crossing_is_the_quantum_after_what_is_placed() {
        assert_eq!(crossing(999_999, 1_000_000, 1_000_000), None);
        assert_eq!(
            crossing(1_000_000, 1_000_000, 1_000_000),
            Some(2_000_000),
            "reaching the crossing is crossing it"
        );
        assert_eq!(crossing(1_200_000, 1_000_000, 1_000_000), Some(2_000_000));
        assert_eq!(
            crossing(2_500_000, 1_000_000, 1_000_000),
            Some(3_000_000),
            "a pass spanning quanta owes one report and the next whole crossing"
        );
        assert_eq!(
            crossing(u64::MAX, 1, 1),
            Some(u64::MAX),
            "the top saturates rather than wraps"
        );
    }

    #[test]
    fn placed_bytes_report_at_their_quantum_and_only_there() {
        // One report per quantum crossing; total is present once the
        // manifest settles.
        const QUANTUM: u64 = 1_000_000;
        type Seen = Arc<std::sync::Mutex<Vec<(u64, Option<u64>)>>>;
        let source = temporary("placed-source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("big.bin"), patterned(8_500_000)).unwrap();
        let bundle = temporary("placed-bundle");
        let built = build_bundle(&source, &bundle).unwrap();

        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("placed-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(
            fetcher.report_placed(0, Box::new(|_, _| {})).is_err(),
            "a zero quantum is a report per pass, refused"
        );
        let seen: Seen = Seen::default();
        let observed = Arc::clone(&seen);
        fetcher
            .report_placed(
                QUANTUM,
                Box::new(move |placed, total| observed.lock().unwrap().push((placed, total))),
            )
            .unwrap();
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);

        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "8.5 MB against a 1 MB quantum reports");
        assert!(
            seen.len() <= 8,
            "more reports than crossings: {}",
            seen.len()
        );
        let mut crossed = 0;
        for (placed, total) in seen.iter() {
            assert!(
                *placed >= crossed + QUANTUM,
                "a report inside an already-reported quantum: {placed} after {crossed}"
            );
            crossed = placed - placed % QUANTUM;
            assert_eq!(
                *total,
                Some(built.logical_length),
                "the total is the manifest's"
            );
        }
        discard(&[&source, &bundle, &output]);
    }

    #[test]
    fn the_pool_reports_room_and_business_from_what_is_out() {
        // Both read `in_flight`; each has an off-by-one that only shows at the bound.
        let mut pool = ProvingPool::start(2);
        assert!(!pool.busy(), "an idle pool owes nothing");
        assert!(pool.has_room(), "an idle pool can take work");
        pool.in_flight = 3;
        assert!(pool.has_room(), "one below the bound still has room");
        assert!(pool.busy(), "anything out with a prover is busy");
        pool.in_flight = 4;
        assert!(!pool.has_room(), "twice the width is the bound");
        assert!(pool.busy());
        pool.in_flight = 0;
    }

    #[test]
    fn dropping_the_pool_ends_its_provers() {
        // The drop joins every prover, so nothing survives it.
        let pool = ProvingPool::start(2);
        let probe = std::sync::Arc::downgrade(&pool.taking);
        drop(pool);
        assert!(
            probe.upgrade().is_none(),
            "a prover outlived the pool that owned it"
        );
    }

    #[test]
    fn a_pass_with_a_witness_owed_books_it_before_returning() {
        // A pass that hands a bundle to a prover settles it in the same pass.
        let (bundle, _) = built_bundle("witness", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("witness-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Rounds until the fetch has planned and asked, because until then
        // every control frame is one `service` has to dispatch itself.
        let mut sequence = 0;
        for _ in 0..ROUND_BUDGET {
            fetcher.service().unwrap();
            pump(
                fetcher.session_mut().driver(),
                session.driver(),
                &mut sequence,
            );
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
            if fetcher.plan.is_some() && fetcher.next_request > 0 {
                break;
            }
        }
        assert!(fetcher.plan.is_some(), "the fetch never planned");

        // Then answers only, polled outside `service`, so a completed
        // bundle is parked for the pump below to be the first to see.
        for _ in 0..ROUND_BUDGET {
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
            while fetcher.receiver.poll().unwrap().is_some() {}
            if fetcher.receiver.completed_bundles() > 0 {
                break;
            }
        }
        assert!(
            fetcher.receiver.completed_bundles() > 0,
            "no cover completed within the round budget"
        );

        // The decisive pass must wait, not spin; set now so the earlier
        // rounds are not slowed.
        fetcher.prover_wait = std::time::Duration::from_secs(5);
        fetcher.pump_provers().unwrap();
        let pool = fetcher.pool.as_ref().expect("the pass started the pool");
        assert!(
            pool.witnesses >= 1,
            "the pass that handed a bundle out did not book its witness"
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    fn the_proving_width_sets_the_deferred_bound_and_nothing_else_does() {
        let (bundle, _) = built_bundle("width", &[("a.txt", patterned(1000))]);
        let output = temporary("width-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // The default width, wired through the same call a caller uses.
        assert_eq!(fetcher.proving_threads, DEFAULT_PROVING_THREADS);
        assert_eq!(
            fetcher.receiver.deferred_limit(),
            DEFAULT_PROVING_THREADS + 1
        );
        // Budgets are the pipeline depth (a product); a sum would be one bundle wide.
        assert_eq!(
            fetcher.receiver.pending_byte_limit(),
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_PENDING_BUNDLE_BYTES
        );
        assert_eq!(
            fetcher.receiver.orphan_byte_limit(),
            OUTSTANDING_COVERS * vot_scheduler::session::MAX_ORPHAN_BUNDLE_BYTES
        );
        // A narrower pool: the bound follows the width.
        fetcher.set_proving_threads(2).unwrap();
        assert_eq!(fetcher.proving_threads, 2);
        assert_eq!(fetcher.receiver.deferred_limit(), 3);
        // Inline: the width is recorded and the bound is left alone, since
        // nothing is deferred to be bounded.
        fetcher.set_proving_threads(0).unwrap();
        assert_eq!(fetcher.proving_threads, 0);
        assert_eq!(fetcher.receiver.deferred_limit(), 3, "no width, no change");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn records_arriving_before_their_proofs_do_not_exhaust_the_receiver() {
        // Records can land before their proofs (the data lane outruns the
        // control stream). Each orphan occupies the receiver's budget; a
        // budget below the pipeline depth fails with
        // `PendingBundlesExhausted`. Noise, not a pattern, so the byte
        // budget is exercised along with the count.
        let (bundle, built) = built_bundle("orphans", &[("big.bin", noise(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("orphans-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        // Inline proving is the slower poll, which is what lets a real
        // carrier queue this deep; the reordering itself is the pump's.
        fetcher.set_proving_threads(0).unwrap();

        let mut sequence = 0;
        let mut status = FetchStatus::Active;
        for _ in 0..ROUND_BUDGET {
            status = fetcher.service().unwrap();
            if status != FetchStatus::Active {
                break;
            }
            pump(
                fetcher.session_mut().driver(),
                session.driver(),
                &mut sequence,
            );
            // Drained fully, so every answered cover is queued at once and
            // the reordering below moves all their records ahead of all
            // their proofs.
            for _ in 0..ROUND_BUDGET {
                server.service(&mut session, &mut connection).unwrap();
                if !connection.has_backlog() {
                    break;
                }
            }
            pump_records_first(
                session.driver(),
                fetcher.session_mut().driver(),
                &mut sequence,
            );
        }
        assert_eq!(status, FetchStatus::Complete);
        assert_eq!(fetcher.package(), Some(built));
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_pinned_fetch_refuses_another_package() {
        let (bundle, _) = built_bundle("pinned", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("pinned-fetched");
        let mut fetcher =
            BundleFetcher::begin(Loopback::default(), &output, Some([9; 32])).unwrap();
        let outcome = run_to_end(&server, &mut session, &mut connection, &mut fetcher, false);
        assert!(matches!(outcome, Err(Error::RootMismatch)));
        assert_eq!(
            fetcher.session_mut().driver().closed,
            Some(error_code::OBJECT_IDENTITY_MISMATCH)
        );
        // And the pinned root it wanted is accepted when it matches.
        let (server, mut session, mut connection) = serving(&bundle);
        let accepted = temporary("pinned-accepted");
        let mut fetcher =
            BundleFetcher::begin(Loopback::default(), &accepted, Some(server.package().root))
                .unwrap();
        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        discard(&[&bundle, &output, &accepted]);
    }

    #[test]
    fn a_tampered_record_ends_the_fetch_as_proof_invalid() {
        // Three covers, so the fetch still has one outstanding when the
        // proof fails.
        let (bundle, _) = built_bundle("tampered", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("tampered-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let outcome = run_to_end(&server, &mut session, &mut connection, &mut fetcher, true);
        assert!(matches!(outcome, Err(Error::Scheduler(_))));
        assert_eq!(
            fetcher.session_mut().driver().closed,
            Some(error_code::PROOF_INVALID)
        );
        assert!(!fetcher.has_backlog(), "a closed fetch owes nothing");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn this_ends_own_failures_do_not_close_as_a_bad_proof() {
        // Local failures must not close as PROOF_INVALID; that blames the
        // server wrongly.
        assert_eq!(
            refusal_code(&vot_scheduler::Error::Sink),
            error_code::STORAGE_WRITE_FAILED
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::PendingBundlesExhausted),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RangeFragmentsExhausted),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::AlreadyReceiving),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::Staging(
                vot_transport_api::Error::StagingExhausted
            )),
            error_code::RESOURCE_LIMIT
        );
        // And a proof the server could not back still is its fault.
        assert_eq!(
            refusal_code(&vot_scheduler::Error::ProofInvalid),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RootMismatch),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::LengthMismatch),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::UnknownObject),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::RecordTooLarge),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::LengthExceeded),
            error_code::PROOF_INVALID
        );
        assert_eq!(
            refusal_code(&vot_scheduler::Error::UnsupportedCompression),
            error_code::PROOF_INVALID
        );
    }

    #[test]
    fn a_zero_length_stored_object_is_written_rather_than_asked_for() {
        // A manifest can name an empty object; the receiver refuses to
        // begin one, so the fetch writes it.
        let (_, summary) = built_bundle("emptyobj", &[("a.txt", patterned(1000))]);
        let output = temporary("emptyobj-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let empty = frames::ObjectId {
            suite: 1,
            root: *blake3::hash(&[]).as_bytes(),
            length: 0,
        };
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(empty)],
            current: 0,
            active: None,
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));
        fetcher.advance().unwrap();

        let path = output.join("objects").join(crate::object_name(&empty.root));
        assert!(fs::read(&path).unwrap().is_empty(), "the empty object is");
        assert!(fetcher.complete(), "and the plan is done with it");
        assert!(
            !fetcher.has_backlog(),
            "nothing was asked for on its account"
        );
        discard(&[&output]);
    }

    #[test]
    fn control_frames_that_are_not_answers_are_refused_or_skipped() {
        let (bundle, _) = built_bundle("frames", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("frames-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();

        // A well-formed frame this end does not consume is not an answer,
        // and not a fault either.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [3; 16],
                    manifest_id: [4; 16],
                    first_page: 0,
                    page_count: 1,
                },
            )));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);

        // Bytes past the frame the envelope declared are malformed.
        let mut trailing = Vec::new();
        frames::encode(
            &TypedFrame::PackageDescriptor(fetcher.descriptor.clone().expect("announced")),
            &mut trailing,
        )
        .unwrap();
        trailing.push(0);
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Control(vot_transport_api::shared_payload(&trailing)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MALFORMED_FRAME)
        );
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_conflicting_announcement_ends_the_fetch() {
        let (bundle, _) = built_bundle("conflict", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("conflict-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Handshake and announcement arrive.
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        let descriptor = fetcher.descriptor.clone().expect("announced");

        // An exact duplicate descriptor is idempotent.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(
                descriptor.clone(),
            )));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);

        // A conflicting one is not.
        let mut conflicting = descriptor;
        conflicting.page_count += 1;
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(conflicting)));
        let status = fetcher.service().unwrap();
        assert_eq!(status, FetchStatus::Closed(error_code::MANIFEST_INVALID));
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_close_forgets_the_requests_the_carrier_never_took() {
        // The queue holds a request the carrier refused; left there it would
        // keep a dead session serviced.
        let (bundle, _) = built_bundle("forget", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("forget-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);

        fetcher.session_mut().driver().refuse_sends = usize::MAX;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(fetcher.has_backlog(), "the manifest request is held");

        let mut conflicting = fetcher.descriptor.clone().expect("announced");
        conflicting.page_count += 1;
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::PackageDescriptor(conflicting)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );
        assert!(!fetcher.has_backlog(), "a closed fetch holds nothing");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_page_the_seal_never_committed_ends_the_fetch() {
        let (bundle, _) = built_bundle("badpage", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("badpage-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        assert!(fetcher.seal_bytes.is_some(), "announcement taken");

        // A well-formed page from a different manifest fails the digest.
        let (other, _) = built_bundle("badpage-other", &[("b.txt", patterned(2000))]);
        let foreign = fs::read(other.join("manifest").join(format!("{:016}.cbor", 0))).unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestPage(foreign)));
        let status = fetcher.service().unwrap();
        assert_eq!(status, FetchStatus::Closed(error_code::MANIFEST_INVALID));
        discard(&[&bundle, &output, &other]);
    }

    #[test]
    fn a_disconnect_mid_fetch_is_reported() {
        let (bundle, _) = built_bundle("dropped", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("dropped-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        // Ready and announced, then the carrier goes away.
        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );
        fetcher.service().unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Disconnected(ConnectionId(3)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Disconnected);
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Disconnected);
        assert!(!fetcher.has_backlog(), "and nothing is still owed");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_disconnect_that_arrives_with_the_last_bytes_still_completes() {
        // Records and disconnect arrive in one pass; the bundle is whole
        // and must complete.
        let (bundle, _) = built_bundle("lastgasp", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("lastgasp-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = announce(&server, &mut session, &mut connection, &mut fetcher);
        let mut answered = false;
        for _ in 0..ROUND_BUDGET {
            let status = round(
                &server,
                &mut session,
                &mut connection,
                &mut fetcher,
                &mut sequence,
            );
            assert_eq!(status, FetchStatus::Active);
            // Everything asked for, and its answer waiting to be taken.
            if !fetcher.has_backlog() && fetcher.locked_plan().is_some_and(|p| p.active.is_some()) {
                answered = true;
                break;
            }
        }
        assert!(answered, "the object was never asked for in full");

        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(Event::Disconnected(ConnectionId(3)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Complete);
        assert_same_tree(&bundle, &output);
        discard(&[&bundle, &output]);
    }

    /// The request the fetcher queued, decoded.
    fn queued_manifest_request(fetcher: &mut BundleFetcher<Loopback>) -> ManifestRequest {
        let frame = fetcher.pending.pop_front().expect("a request was queued");
        match decode_control(&frame) {
            TypedFrame::ManifestRequest(request) => request,
            other => panic!("not a manifest request: {other:?}"),
        }
    }

    #[test]
    fn manifest_spans_are_requested_one_at_a_time_in_arrival_order() {
        // More than 8,192 pages takes multiple requests; the cursor is
        // driven directly.
        let output = temporary("manifest-spans");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.descriptor = Some(PackageDescriptor {
            package: frames::ObjectId {
                suite: 1,
                root: [4; 32],
                length: 9,
            },
            manifest_id: [5; 16],
            page_count: 2 * MAX_MANIFEST_REQUEST_PAGES + 3,
        });
        fetcher.spans = manifest_spans(2 * MAX_MANIFEST_REQUEST_PAGES + 3);
        assert_eq!(fetcher.spans.len(), 3);

        // The first span is asked for, and nothing beyond it.
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let first = queued_manifest_request(&mut fetcher);
        assert_eq!(first.manifest_id, [5; 16]);
        assert_eq!((first.first_page, first.page_count), fetcher.spans[0]);
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(
            fetcher.pending.is_empty(),
            "the next span waits on the pages of this one"
        );

        // The next span waits for prior pages (arrival order indexes the digest check).
        fetcher.pages_received = MAX_MANIFEST_REQUEST_PAGES - 1;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(fetcher.pending.is_empty(), "one page short is still short");
        fetcher.pages_received = MAX_MANIFEST_REQUEST_PAGES;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let second = queued_manifest_request(&mut fetcher);
        assert_eq!((second.first_page, second.page_count), fetcher.spans[1]);
        assert_ne!(second.request_id, first.request_id, "identities are fresh");

        // And the short final span, after which nothing more is owed.
        fetcher.pages_received = 2 * MAX_MANIFEST_REQUEST_PAGES;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        let third = queued_manifest_request(&mut fetcher);
        assert_eq!((third.first_page, third.page_count), fetcher.spans[2]);
        fetcher.pages_received = fetcher.descriptor.as_ref().unwrap().page_count;
        fetcher.request_pages().map_err(|_| ()).unwrap();
        assert!(
            fetcher.pending.is_empty(),
            "the manifest is fully asked for"
        );
        discard(&[&output]);
    }

    #[test]
    fn a_seal_must_answer_the_descriptor_in_every_field() {
        // Each field the seal and descriptor share must agree, or the fetch
        // lands on an unpinned manifest.
        let (bundle, _) = built_bundle("sealfields", &[("a.txt", patterned(1000))]);
        let seal_bytes = fs::read(bundle.join(MANIFEST_DIRECTORY).join(MANIFEST_SEAL)).unwrap();
        let seal = vot_manifest::decode_seal(&seal_bytes).unwrap();
        let truth = PackageDescriptor {
            package: frames::ObjectId {
                suite: seal.package.suite,
                root: seal.package.root,
                length: seal.package.length,
            },
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
        };

        let mut wrong_manifest = truth.clone();
        wrong_manifest.manifest_id[0] ^= 1;
        let mut wrong_pages = truth.clone();
        wrong_pages.page_count += 1;
        let mut wrong_root = truth.clone();
        wrong_root.package.root[0] ^= 1;
        let mut wrong_length = truth.clone();
        wrong_length.package.length += 1;
        for (name, descriptor) in [
            ("manifest", wrong_manifest),
            ("pages", wrong_pages),
            ("root", wrong_root),
            ("length", wrong_length),
        ] {
            let output = temporary(&format!("sealfields-{name}"));
            let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
            fetcher.descriptor = Some(descriptor);
            let outcome = fetcher.take_seal(seal_bytes.clone());
            assert!(
                matches!(outcome, Err(Fault::Peer(code)) if code == error_code::MANIFEST_INVALID),
                "a seal answering a different {name} was taken"
            );
        }

        // And the descriptor it does answer is taken, pages and all.
        let output = temporary("sealfields-answered");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        fetcher.descriptor = Some(truth);
        assert!(fetcher.take_seal(seal_bytes).is_ok());
        assert!(fetcher.has_backlog(), "the manifest is asked for");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn a_repeated_seal_is_idempotent_and_a_conflicting_one_ends_the_fetch() {
        let (bundle, _) = built_bundle("seal", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("seal-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        let seal = fetcher.seal_bytes.clone().expect("announced");
        let asked = fetcher.session_mut().driver().control.len();
        assert!(asked > 0, "the manifest was asked for");

        // The same seal again asks for nothing further.
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::Seal(seal)));
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert_eq!(
            fetcher.session_mut().driver().control.len(),
            asked,
            "a repeated seal asked for the manifest twice"
        );

        // A different one is a different package under the same session.
        let (other, _) = built_bundle("seal-other", &[("b.txt", patterned(2000))]);
        let foreign = fs::read(other.join(MANIFEST_DIRECTORY).join(MANIFEST_SEAL)).unwrap();
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::Seal(foreign)));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );
        discard(&[&bundle, &output, &other]);
    }

    #[test]
    fn manifest_pages_are_taken_in_order_and_only_once() {
        // Two pages, so a page can arrive both twice and early. One entry
        // past the per-page cap is what spills a manifest.
        let files: Vec<(String, Vec<u8>)> = (0..=vot_manifest::MAX_ENTRIES_PER_PAGE)
            .map(|index| {
                (
                    format!("f{index:05}"),
                    vec![u8::try_from(index % 251).unwrap()],
                )
            })
            .collect();
        let named: Vec<(&str, Vec<u8>)> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect();
        let (bundle, _) = built_bundle("pageorder", &named);
        let discarded = bundle.clone();
        let pages: Vec<Vec<u8>> = (0..2)
            .map(|index| {
                fs::read(crate::manifest_page_path(
                    &bundle.join(MANIFEST_DIRECTORY),
                    index,
                ))
                .unwrap()
            })
            .collect();

        // A page before its predecessor is a server-side gap.
        let (server, mut session, mut connection) = serving(&bundle);
        let early = temporary("pageorder-early");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &early, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        assert_eq!(fetcher.pages_received, 0);
        fetcher
            .session_mut()
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestPage(pages[1].clone())));
        assert_eq!(
            fetcher.service().unwrap(),
            FetchStatus::Closed(error_code::MANIFEST_INVALID)
        );

        // The first page twice is the same page twice, and counts once.
        let (server, mut session, mut connection) = serving(&bundle);
        let twice = temporary("pageorder-twice");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &twice, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.service().unwrap();
        for _ in 0..2 {
            fetcher
                .session_mut()
                .driver()
                .events
                .push_back(control_event(&TypedFrame::ManifestPage(pages[0].clone())));
        }
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert_eq!(fetcher.pages_received, 1, "the repeat was counted");
        assert!(fetcher.plan.is_none(), "a page short of the manifest");
        discard(&[&discarded, &early, &twice]);
    }

    #[test]
    fn a_send_failure_that_is_not_backpressure_surfaces() {
        // Backpressure holds a request; anything else is a failure that
        // must surface.
        let (bundle, _) = built_bundle("sendfail", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("sendfail-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.session_mut().driver().fail_sends_with = Some(vot_transport_api::Error::Backend);
        let outcome = fetcher.service();
        assert!(matches!(outcome, Err(Error::Session(_))));
        discard(&[&bundle, &output]);
    }

    #[test]
    fn no_more_is_asked_for_than_may_be_outstanding() {
        // The bound is asked-for minus placed; queue bounding instead would
        // fetch an object in full before any cover lands.
        let (bundle, summary) = built_bundle("inflight", &[("a.txt", patterned(1000))]);
        let output = temporary("inflight-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let object = frames::ObjectId {
            suite: 1,
            root: [3; 32],
            length: 40 * MAX_REQUESTED_RANGE,
        };
        let sink = Arc::new(
            CountingSink::create(&output.join("objects").join("held.obj"), 0, None).unwrap(),
        );
        fetcher.plan = Some(Arc::new(Mutex::new(FetchPlan {
            summary,
            objects: vec![PlannedObject::fresh(object)],
            current: 0,
            active: Some(Arc::clone(&sink)),
            placed_before: 0,
            next_offset: 0,
            covered: BTreeMap::new(),
            covered_bytes: 0,
            syncing: false,
            abandoned: false,
            skip: BTreeMap::new(),
            store: None,
            finished: false,
        })));

        // However many passes, and however readily the carrier takes them.
        for _ in 0..16 {
            fetcher.issue_ranges().unwrap();
            fetcher.pending.clear();
        }
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            OUTSTANDING_REQUEST_BYTES,
            "asked for more than may be outstanding"
        );

        // Pacing is per rail; asking on another's arrivals overdraws both receivers.
        sink.placed.store(MAX_REQUESTED_RANGE, Ordering::Relaxed);
        fetcher.settled_bytes = MAX_REQUESTED_RANGE;
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            OUTSTANDING_REQUEST_BYTES + MAX_REQUESTED_RANGE,
            "a settled cover did not buy the next request"
        );
        // Placing counts as progress, so a driving loop keeps a slow transfer alive.
        assert!(fetcher.progress() >= MAX_REQUESTED_RANGE);

        // A span is committed only once its frame is queued, or a failure
        // leaves a hole nobody re-requests.
        fetcher.settled_bytes = 2 * MAX_REQUESTED_RANGE;
        let owed = fetcher.locked_plan().unwrap().next_offset;
        fetcher.next_request = u64::MAX;
        assert!(
            fetcher.issue_ranges().is_err(),
            "the identifier space ended"
        );
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed,
            "a span whose frame never queued was consumed"
        );

        // The shared sink is not this rail's account; a full window blocks
        // regardless of placement.
        fetcher.next_request = 0;
        fetcher.settled_bytes = MAX_REQUESTED_RANGE;
        sink.placed
            .store(40 * MAX_REQUESTED_RANGE, Ordering::Relaxed);
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed,
            "the shared sink paid for a rail's spans"
        );

        // Inline proving has no witnesses, so the sink's placement is the pace.
        fetcher.set_proving_threads(0).unwrap();
        fetcher.issue_ranges().unwrap();
        assert_eq!(
            fetcher.locked_plan().unwrap().next_offset,
            owed + OUTSTANDING_REQUEST_BYTES,
            "an inline fetch paces on what its own sink placed"
        );

        discard(&[&bundle, &output]);
    }

    #[test]
    fn an_existing_destination_is_refused() {
        let existing = temporary("occupied");
        fs::create_dir_all(&existing).unwrap();
        let outcome = BundleFetcher::begin(Loopback::default(), &existing, None);
        assert!(matches!(outcome, Err(Error::DestinationExists)));
        discard(&[&existing]);
    }

    #[test]
    fn a_backpressured_request_is_held_and_sent() {
        let (bundle, _) = built_bundle("held", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("held-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();

        let mut sequence = 0;
        fetcher.service().unwrap();
        pump(
            fetcher.session_mut().driver(),
            session.driver(),
            &mut sequence,
        );
        server.service(&mut session, &mut connection).unwrap();
        pump(
            session.driver(),
            fetcher.session_mut().driver(),
            &mut sequence,
        );

        // The pass that takes the seal wants to send the manifest request;
        // a refusing carrier holds it rather than losing it.
        fetcher.session_mut().driver().refuse_sends = usize::MAX;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(fetcher.has_backlog(), "the request is held");
        assert!(fetcher.session_mut().driver().control.is_empty());

        fetcher.session_mut().driver().refuse_sends = 0;
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Active);
        assert!(!fetcher.has_backlog(), "and sent when the carrier takes it");
        assert!(!fetcher.session_mut().driver().control.is_empty());
        discard(&[&bundle, &output]);
    }

    #[test]
    fn spans_chunk_by_the_codec_bounds() {
        assert_eq!(manifest_spans(1), vec![(0, 1)]);
        assert_eq!(
            manifest_spans(MAX_MANIFEST_REQUEST_PAGES),
            vec![(0, MAX_MANIFEST_REQUEST_PAGES)]
        );
        assert_eq!(
            manifest_spans(MAX_MANIFEST_REQUEST_PAGES + 1),
            vec![
                (0, MAX_MANIFEST_REQUEST_PAGES),
                (MAX_MANIFEST_REQUEST_PAGES, 1),
            ]
        );
        // Bounded by the length, so a non-advancing span ends the walk
        // instead of filling memory.
        let walk = |length: u64| {
            let mut spans = Vec::new();
            let mut offset = 0;
            for _ in 0..=length.div_ceil(MAX_REQUESTED_RANGE) {
                let Some((at, take)) = range_span(offset, length) else {
                    break;
                };
                spans.push((at, take));
                offset = at + take;
            }
            spans
        };
        assert_eq!(walk(0), vec![]);
        assert_eq!(walk(1), vec![(0, 1)]);
        assert_eq!(walk(MAX_REQUESTED_RANGE), vec![(0, MAX_REQUESTED_RANGE)]);
        assert_eq!(
            walk(MAX_REQUESTED_RANGE + 1),
            vec![(0, MAX_REQUESTED_RANGE), (MAX_REQUESTED_RANGE, 1)]
        );
        assert_eq!(
            walk(3 * MAX_REQUESTED_RANGE - 1),
            vec![
                (0, MAX_REQUESTED_RANGE),
                (MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE),
                (2 * MAX_REQUESTED_RANGE, MAX_REQUESTED_RANGE - 1),
            ]
        );
    }
}
