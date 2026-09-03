//! Session and frame dispatch: the [`BundleFetcher`] passes.

use super::{
    ActiveObject, Arc, Authentication, BTreeMap, BTreeSet, CountingSink, CoverageMap,
    DEFAULT_PROVING_THREADS, DecodeLimits, DurableHook, Error, Event, Fault, FetchPlan,
    FetchStatus, MANIFEST_DIRECTORY, MANIFEST_SEAL, MAX_CONTROL_FRAME_PAYLOAD,
    MAX_MANIFEST_REQUEST_PAGES, MAX_REQUESTED_RANGE, ManifestReader, ManifestRequest, Mutex,
    ORPHAN_BUNDLE_BYTES, ORPHAN_BUNDLE_DEPTH, OUTSTANDING_COVERS, OUTSTANDING_REQUEST_BYTES,
    PENDING_BUNDLE_BYTES, PENDING_BUNDLE_DEPTH, PROVER_WAIT, PackageDescriptor, PackageSummary,
    Path, PathBuf, PlacedReport, PlannedObject, Proving, ProvingPool, RESUME_STORE, RangeRequest,
    ReceiveObject, ReceiveSeams, ReceiveSessionId, ReceiveSink, ReliableReceiver, ResumeStore,
    Session, SessionReceiver, Settings, SharedPlan, Storage, SubjectId, TEST_PROVER_WAIT,
    TransportAdapter, TypedFrame, UnitRanges, VecDeque, crossing, error_code, frames, fs,
    is_backpressure, package_sentinel, remove_store_files, reservations_of, resume_failure,
    resumed_extents, subject_of, total_units_of,
};

pub(super) const fn custom_flush_due(length: u64, fully_resumed: bool, stored: bool) -> bool {
    length == 0 || fully_resumed && stored
}

/// Ends an open the plan no longer wants, discarding the sink it chose.
///
/// Cancellation drains the window under the plan lock, and an object being
/// opened is not in the window yet: the rail that dropped the lock for a
/// sink factory or a completion hook owns the only reference to what it
/// chose, so nothing else would ever discard it. Called with the plan lock
/// released, because a sink's gate is taken before that lock.
fn discard_open(chosen: Option<Box<dyn ReceiveSink>>) -> Result<(), Error> {
    match chosen {
        Some(sink) => sink.discard_partial(),
        None => Ok(()),
    }
}

/// Passes [`BundleFetcher::advance`] may take over `objects` objects.
///
/// Every pass returns, completes one object, or opens one, and the plan
/// opens each object once and completes it once, so two passes an object
/// do all the work there is and one more finds nothing left to do. A pass
/// past this is a plan that is not moving, which is a fault rather than a
/// slow fetch.
pub(super) const fn advance_passes(objects: usize) -> usize {
    2 * objects + 1
}

/// The most objects a fetch keeps in flight.
///
/// The receiver's staging budget is sized for this many admissions on top
/// of the credit, and a receiver is built before a caller chooses a
/// window, so no plan may hold more than this.
pub(crate) const MAX_OBJECT_WINDOW: usize = 16;

/// The window `rails` rails earn: two objects a rail, so a rail always has
/// another object to take spans from while one of them is being synced.
///
/// Only a driving loop chooses a window, and those come with the carrier.
#[cfg(any(test, feature = "wire"))]
pub(crate) fn object_window(rails: usize) -> usize {
    rails.saturating_mul(2).clamp(1, MAX_OBJECT_WINDOW)
}

/// Credit advertised to the server: the covers this end asked for.
pub(crate) const FETCH_CREDIT_BYTES: u64 =
    OUTSTANDING_COVERS as u64 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// What a receiver may stage to carry a window of `window` objects: the
/// credit, plus the group reservation each admitted object holds for as
/// long as it is in flight. Advertised credit is what is left of the
/// staging budget, capped at the target, so on a budget of the credit
/// alone each admitted object's reservation comes out of the credit this
/// end advertises and the rails run on less of it the wider the window.
pub(crate) const fn fetch_staging_bytes(window: usize) -> u64 {
    FETCH_CREDIT_BYTES + window as u64 * vot_verifier::GROUP_SIZE as u64
}

/// What the receiver may stage. Sized for the widest window rather than
/// the one this fetch takes: the receiver is built before the manifest
/// names an object, and a staging limit cannot be changed after.
pub(crate) const FETCH_STAGING_BYTES: u64 = fetch_staging_bytes(MAX_OBJECT_WINDOW);

// The limit clears the credit by one group an in-flight object; at or
// under it the advertised credit is what shrinks. The one-object value is
// what the budget was when the plan held one object.
const _: () = assert!(FETCH_CREDIT_BYTES == 34_078_720);
const _: () = assert!(fetch_staging_bytes(1) == 34_144_256);
const _: () = assert!(FETCH_STAGING_BYTES == 35_127_296);

fn require_push_objects(push: bool, objects: usize) -> Result<(), Fault> {
    if push && objects == 0 {
        return Err(Fault::Peer(error_code::MANIFEST_INVALID));
    }
    Ok(())
}

/// The stance a fetch takes on a challenge it has not seen yet.
///
/// Presenting when this fetch holds a capability, which is what makes
/// `pending_presentation` fire and lets it answer. Without one it takes the
/// stance that answers nothing, and `vot_session` ends the session on a
/// challenge that names a format this end cannot supply, which is what the
/// format list in `spec/wire.md` 1.1 is for.
pub(crate) fn client_stance(holder: Option<&crate::authz::Holder>) -> Authentication {
    if holder.is_some() {
        Authentication::Presenting
    } else {
        // The client ignores the nonce; it is the server's freshness.
        Authentication::NotRequired { nonce: [0; 32] }
    }
}

/// One fetch: a client session, the receiver verifying its ranges, and the
/// bundle directory being written.
pub struct BundleFetcher<A: TransportAdapter> {
    pub(crate) receiver: SessionReceiver<A>,
    pub(crate) bundle: PathBuf,
    pub(crate) pin: Option<[u8; 32]>,
    pub(crate) manifest: ManifestPhase,
    pub(crate) plan: Option<SharedPlan>,
    /// Resume store, held until the manifest hands it to the plan.
    pub(crate) store: Option<Arc<Mutex<ResumeStore>>>,
    /// Whether this fetch continues a partial bundle, which is what makes
    /// the store's checkpoints a seed rather than a record.
    pub(crate) resuming: bool,
    /// Whether this fetcher is a rail on another fetch's plan.
    pub(crate) secondary: bool,
    /// The capability this fetch answers a challenge with, when it has one.
    /// Shared, because every rail opens its own session and answers its own
    /// challenge under the same token.
    pub(crate) holder: Option<Arc<crate::authz::Holder>>,
    /// The extensions every rail of this fetch offers.
    pub(crate) extensions: BTreeSet<u64>,
    pub(crate) rail: RailProgress,
    pub(crate) terminal: Terminal,
    pub(crate) report: ProgressReport,
    pub(crate) proving: ProvingConfig,
    pub(crate) seams: ReceiveSeams,
    pub(crate) receive_session: ReceiveSessionId,
    pub(crate) cancelled: Option<usize>,
    /// Objects the plan this fetch builds keeps in flight. Read when the
    /// manifest is validated, so a caller sets it before then; a rail
    /// joins a plan that already carries its own.
    pub(crate) window: usize,
}

static RECEIVE_SESSION_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The manifest being fetched: identity answered, pages owed and taken.
#[derive(Default)]
pub(crate) struct ManifestPhase {
    pub(crate) descriptor: Option<PackageDescriptor>,
    pub(crate) seal_bytes: Option<Vec<u8>>,
    pub(crate) page_digests: Vec<[u8; 32]>,
    pub(crate) pages_received: u64,
    /// Manifest request spans still to issue, and the next one due.
    pub(crate) spans: Vec<(u64, u64)>,
    pub(crate) next_span: usize,
}

/// What this rail has asked for, settled, and may still have outstanding.
pub(crate) struct RailProgress {
    /// The objects this rail has admitted to its own receiver, by plan
    /// index. Admission is per rail; the plan cannot do it.
    pub(crate) admitted: BTreeMap<usize, SubjectId>,
    /// Range bytes this rail has committed to spans, only ever going up.
    /// The gap between this and what its own receiver has taken off the
    /// carrier paces requests per rail; pacing on the shared sink would let
    /// one rail overdraw on another's arrivals.
    pub(crate) taken_bytes: u64,
    /// The most this rail keeps outstanding:
    /// [`OUTSTANDING_REQUEST_BYTES`] always, narrowed only by tests so a
    /// small object stripes without a window's worth of data.
    pub(crate) window_bytes: u64,
    pub(crate) pending: VecDeque<Vec<u8>>,
    pub(crate) next_request: u64,
}

impl Default for RailProgress {
    fn default() -> Self {
        Self {
            admitted: BTreeMap::new(),
            taken_bytes: 0,
            window_bytes: OUTSTANDING_REQUEST_BYTES,
            pending: VecDeque::new(),
            next_request: 0,
        }
    }
}

/// What has already ended, one independent fact per field.
#[derive(Default)]
pub(crate) struct Terminal {
    pub(crate) closed: Option<u16>,
    /// Set once the carrier reported it had gone, so every later pass says
    /// so too rather than only the pass that saw it.
    pub(crate) disconnected: bool,
    /// Set once nothing further will be asked for, whatever ended it.
    pub(crate) stopped: bool,
}

/// What a driving loop and a caller are told about this fetch.
#[derive(Default)]
pub(crate) struct ProgressReport {
    /// Everything this end has taken or asked for, only ever going up.
    ///
    /// A driving loop reads it to tell a slow transfer from a stuck one.
    pub(crate) progress: u64,
    /// When this fetch first observed bytes it placed itself.
    pub(crate) first_moved: Option<std::time::Instant>,
    /// Where placed-byte crossings are reported, if anywhere.
    pub(crate) placed: Option<PlacedReport>,
}

/// The provers this fetch may start, and how a pass waits on them.
pub(crate) struct ProvingConfig {
    /// The provers, started with the first cover so a fetch that carries
    /// none starts no threads.
    pub(crate) pool: Option<ProvingPool>,
    /// How many provers to start, or none for proving on this thread.
    pub(crate) width: usize,
    /// How long a pass waits for a witness it is owed. Overridden in tests.
    pub(crate) wait: std::time::Duration,
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            pool: None,
            width: 0,
            // A test round waits for the witness it is owed, so starvation
            // cannot turn a counted round budget into a clock.
            wait: if cfg!(test) {
                TEST_PROVER_WAIT
            } else {
                PROVER_WAIT
            },
        }
    }
}

/// Page spans of at most what one `MANIFEST_REQUEST` may name.
///
/// Bounded by the page count (from the seal), not by a cursor, so a
/// non-advancing span cannot grow this unboundedly.
pub(crate) fn manifest_spans(page_count: u64) -> Vec<(u64, u64)> {
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
pub(crate) fn range_span(offset: u64, length: u64) -> Option<(u64, u64)> {
    (offset < length).then(|| (offset, MAX_REQUESTED_RANGE.min(length - offset)))
}

/// The code a receiver's refusal closes under.
///
/// Local storage/budget failures are not `PROOF_INVALID`: that code tells
/// a server its proof was bad about a bundle it served correctly.
pub(crate) fn refusal_code(error: &vot_scheduler::Error) -> u16 {
    use vot_scheduler::Error as Refusal;
    match error {
        // This end could not write what it had already verified.
        Refusal::Sink => error_code::STORAGE_WRITE_FAILED,
        // One epoch identifier opened twice with different content
        // (spec/fec.md section 12).
        Refusal::CodingEpochConflict => error_code::CODING_EPOCH_CONFLICT,
        Refusal::MalformedFecFrame => error_code::MALFORMED_FRAME,
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

pub(crate) fn encoded(frame: &TypedFrame) -> Result<Vec<u8>, Error> {
    let mut wire = Vec::new();
    frames::encode(frame, &mut wire)?;
    Ok(wire)
}

/// Bytes the bundle holds under this plan: what the objects already left
/// behind placed, plus what the ones still in flight have placed so far.
///
/// One function rather than the same sum in each accessor that means it.
fn placed_in(plan: &FetchPlan) -> u64 {
    plan.active
        .values()
        .fold(plan.placed_before, |placed, active| {
            placed + active.sink.placed()
        })
}

impl<A: TransportAdapter> BundleFetcher<A> {
    /// Sets how many provers this fetch runs, or none to prove on the
    /// session's own thread.
    ///
    /// # Errors
    /// Surfaces a deferred bound the receiver refuses.
    pub fn set_proving_threads(&mut self, threads: usize) -> Result<(), Error> {
        if (self.secondary || self.resuming) && threads == 0 {
            // Shared coverage is booked in `pump_provers`, which returns at
            // once at width 0, so an inline rail never advances the plan: a
            // rail's spans and a resumed fetch's completion both need it.
            return Err(Error::InvalidArguments);
        }
        self.proving.width = threads;
        self.receiver.defer_proving(threads > 0);
        if threads > 0 {
            // Room for every prover to hold one and one more to be waiting,
            // which is what keeps them all fed without holding an object.
            self.receiver
                .set_deferred_limit(threads.saturating_add(1))?;
        }
        Ok(())
    }

    /// Sets how many objects the plan this fetch builds keeps in flight.
    ///
    /// Read when the manifest is validated, so it has to be set before the
    /// fetch is driven that far. Narrowed to [`MAX_OBJECT_WINDOW`], which
    /// the receiver's staging budget is sized for: a wider window would
    /// refuse a conforming answer mid-transfer rather than here.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn set_object_window(&mut self, objects: usize) {
        self.window = objects.clamp(1, MAX_OBJECT_WINDOW);
    }

    /// Opens the session and the bundle directory the fetch will fill.
    ///
    /// The optional pin is the package root this fetch will accept. A
    /// destination with a partial bundle and resume store is continued:
    /// the store's identity becomes the pin, the manifest is re-fetched,
    /// and durable ranges are skipped. A destination without a store is
    /// refused.
    pub fn begin(adapter: A, bundle: &Path, pin: Option<[u8; 32]>) -> Result<Self, Error> {
        Self::begin_offering(adapter, bundle, pin, crate::authz::default_extensions())
    }

    /// [`Self::begin`] offering exactly `extensions`; an empty set disables
    /// every optional extension.
    ///
    /// # Errors
    /// As [`Self::begin`].
    pub fn begin_offering(
        adapter: A,
        bundle: &Path,
        pin: Option<[u8; 32]>,
        extensions: BTreeSet<u64>,
    ) -> Result<Self, Error> {
        Self::begin_with(adapter, bundle, pin, None, extensions)
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
        extensions: BTreeSet<u64>,
    ) -> Result<Self, Error> {
        let session = Session::client(
            adapter,
            Settings::default(),
            extensions.clone(),
            client_stance(holder.as_deref()),
        );
        Self::begin_session_with(session, bundle, pin, holder, extensions, true)
    }

    /// Opens a bundle receiver around a caller-constructed session.
    pub fn begin_session(
        session: Session<A>,
        bundle: &Path,
        pin: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        Self::begin_session_with(session, bundle, pin, None, BTreeSet::new(), true)
    }

    /// Opens a bundle receiver around a session whose handshake has started.
    pub fn from_started_session(
        session: Session<A>,
        bundle: &Path,
        pin: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        Self::begin_session_with(session, bundle, pin, None, BTreeSet::new(), false)
    }

    fn begin_session_with(
        mut session: Session<A>,
        bundle: &Path,
        pin: Option<[u8; 32]>,
        holder: Option<Arc<crate::authz::Holder>>,
        extensions: BTreeSet<u64>,
        start: bool,
    ) -> Result<Self, Error> {
        let store_path = bundle.join(RESUME_STORE);
        let existing = fs::symlink_metadata(bundle).ok();
        if existing
            .as_ref()
            .is_some_and(|metadata| !metadata.file_type().is_dir())
        {
            return Err(Error::DestinationExists);
        }
        let exists = existing.is_some();
        let resuming = store_path.exists();
        if exists && !resuming && fs::read_dir(bundle)?.next().is_some() {
            return Err(Error::DestinationExists);
        }
        if resuming {
            // The manifest is re-fetched, not resumed: partial pages went
            // with the fetch that died, and re-validating fresh re-derives
            // the identity the store is checked against.
            fs::remove_dir_all(bundle.join(MANIFEST_DIRECTORY))?;
        } else if !exists {
            crate::create_private_directory(bundle)?;
        }
        let manifests = bundle.join(MANIFEST_DIRECTORY);
        if !manifests.exists() {
            crate::create_private_directory(&manifests)?;
        }
        let objects = bundle.join("objects");
        if !objects.exists() {
            crate::create_private_directory(&objects)?;
        }
        let store = ResumeStore::create(&store_path).map_err(resume_failure)?;
        // The store's identity is the resume pin; a caller's pin that
        // disagrees is refused. A store too young to know binds to the
        // manifest this fetch proves.
        let mut pin = pin;
        if resuming {
            let stored = store
                .subjects()
                .find(|subject| subject.is_marker())
                .map(vot_transport_api::SubjectId::root);
            match (pin, stored) {
                (Some(pinned), Some(root)) if pinned != root => {
                    return Err(Error::RootMismatch);
                }
                (None, Some(root)) => pin = Some(root),
                _ => {}
            }
        }
        if start {
            session.begin()?;
        }
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        let mut receiver = SessionReceiver::new(session, receiver);
        // Every outstanding cover must be holdable in any arrival state;
        // the receiver defaults are too shallow and fail a conforming
        // transfer with `PendingBundlesExhausted`.
        receiver.set_pending_limits(PENDING_BUNDLE_DEPTH, PENDING_BUNDLE_BYTES)?;
        // Its own depth, not the pending one: the coded pipeline orphans
        // records too, and an entry holds the generations of its piece that
        // have arrived rather than the whole piece, so the count that bounds
        // them is derived from the byte budget instead of from pieces.
        receiver.set_orphan_limits(ORPHAN_BUNDLE_DEPTH, ORPHAN_BUNDLE_BYTES)?;
        let mut fetcher = Self {
            receiver,
            bundle: bundle.to_owned(),
            pin,
            manifest: ManifestPhase::default(),
            plan: None,
            store: Some(Arc::new(Mutex::new(store))),
            resuming,
            secondary: false,
            holder,
            extensions,
            rail: RailProgress::default(),
            terminal: Terminal::default(),
            report: ProgressReport::default(),
            proving: ProvingConfig::default(),
            seams: ReceiveSeams::default(),
            receive_session: ReceiveSessionId(
                RECEIVE_SESSION_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ),
            cancelled: None,
            window: 1,
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
        extensions: BTreeSet<u64>,
    ) -> Result<Self, Error> {
        let root = plan.lock().map_err(|_| Error::InvalidBundle)?.summary.root;
        let mut session = Session::client(
            adapter,
            Settings::default(),
            extensions.clone(),
            client_stance(holder.as_deref()),
        );
        session.begin()?;
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        let mut receiver = SessionReceiver::new(session, receiver);
        // Same pipeline budgets as the primary: each rail carries the full depth.
        receiver.set_pending_limits(PENDING_BUNDLE_DEPTH, PENDING_BUNDLE_BYTES)?;
        // Its own depth, not the pending one: the coded pipeline orphans
        // records too, and an entry holds the generations of its piece that
        // have arrived rather than the whole piece, so the count that bounds
        // them is derived from the byte budget instead of from pieces.
        receiver.set_orphan_limits(ORPHAN_BUNDLE_DEPTH, ORPHAN_BUNDLE_BYTES)?;
        let mut fetcher = Self {
            receiver,
            bundle: bundle.to_owned(),
            pin: Some(root),
            manifest: ManifestPhase::default(),
            plan: Some(plan),
            store: None,
            resuming: false,
            secondary: true,
            holder,
            extensions,
            rail: RailProgress::default(),
            terminal: Terminal::default(),
            report: ProgressReport::default(),
            proving: ProvingConfig::default(),
            seams: ReceiveSeams::default(),
            receive_session: ReceiveSessionId(
                RECEIVE_SESSION_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ),
            cancelled: None,
            window: 1,
        };
        fetcher.set_proving_threads(DEFAULT_PROVING_THREADS)?;
        Ok(fetcher)
    }

    /// Joins an already-authenticated push session to an existing receive plan.
    #[cfg(feature = "wire")]
    pub(crate) fn join_started_session(
        session: Session<A>,
        bundle: &Path,
        plan: SharedPlan,
    ) -> Result<Self, Error> {
        let root = plan.lock().map_err(|_| Error::InvalidBundle)?.summary.root;
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        let mut receiver = SessionReceiver::new(session, receiver);
        receiver.set_pending_limits(PENDING_BUNDLE_DEPTH, PENDING_BUNDLE_BYTES)?;
        receiver.set_orphan_limits(ORPHAN_BUNDLE_DEPTH, ORPHAN_BUNDLE_BYTES)?;
        let mut fetcher = Self {
            receiver,
            bundle: bundle.to_owned(),
            pin: Some(root),
            manifest: ManifestPhase::default(),
            plan: Some(plan),
            store: None,
            resuming: false,
            secondary: true,
            holder: None,
            extensions: BTreeSet::new(),
            rail: RailProgress::default(),
            terminal: Terminal::default(),
            report: ProgressReport::default(),
            proving: ProvingConfig::default(),
            seams: ReceiveSeams::default(),
            receive_session: ReceiveSessionId(
                RECEIVE_SESSION_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ),
            cancelled: None,
            window: 1,
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

    /// Installs the hooks used by this receive session.
    pub fn set_receive_seams(&mut self, seams: ReceiveSeams) {
        self.seams = seams;
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

    /// The extensions this fetch offers, for its rails to offer too.
    #[must_use]
    pub fn extensions(&self) -> BTreeSet<u64> {
        self.extensions.clone()
    }

    /// What this fetch's session decoded, abandoned, and refused on the
    /// datagram path.
    #[must_use]
    pub fn fec_counts(&self) -> vot_scheduler::FecCounts {
        self.receiver.fec_counts()
    }

    /// The bundle directory this fetch writes.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn bundle(&self) -> &Path {
        &self.bundle
    }

    /// How many provers this fetch runs.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) const fn proving_threads(&self) -> usize {
        self.proving.width
    }

    /// Everything this end has settled, only ever going up: frames taken,
    /// requests issued, and every byte placed.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.report.progress.saturating_add(self.placed_bytes())
    }

    /// Bytes verified and placed into the bundle, only ever going up.
    #[must_use]
    pub fn placed_bytes(&self) -> u64 {
        self.locked_plan().map_or(0, |plan| placed_in(&plan))
    }

    /// Of [`Self::placed_bytes`], the part this fetch put there itself.
    ///
    /// A fetch into a bundle a previous one left behind resumes it and asks
    /// only for what is missing, so the bytes it placed are the ones that
    /// crossed the wire and the rest were already on disk. Anything divided
    /// by this fetch's own clock has to be this rather than the package's
    /// length, which a resume would make a throughput out of bytes nobody
    /// moved.
    ///
    /// One lock for both halves, so the two cannot be read a rail apart.
    #[must_use]
    pub fn moved_bytes(&self) -> u64 {
        self.locked_plan().map_or(0, |plan| {
            placed_in(&plan).saturating_sub(plan.carried_before)
        })
    }

    /// When this fetch first observed verified bytes from this run.
    #[cfg(any(test, feature = "wire"))]
    pub(crate) fn first_moved(&self) -> Option<std::time::Instant> {
        self.report.first_moved
    }

    /// The plan under its lock, or nothing before the manifest settles it.
    ///
    /// A poisoned lock reads as no plan; callers have a conservative
    /// answer for that.
    pub(crate) fn locked_plan(&self) -> Option<std::sync::MutexGuard<'_, FetchPlan>> {
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
        self.report.placed = Some(PlacedReport {
            quantum,
            next_at: quantum,
            observer,
        });
        Ok(())
    }

    /// One report if placed bytes crossed the next quantum, none otherwise.
    pub(crate) fn note_placed(&mut self) {
        let Some(plan) = self.locked_plan() else {
            return;
        };
        let placed = placed_in(&plan);
        let moved = placed.saturating_sub(plan.carried_before);
        let total = Some(plan.summary.logical_length);
        drop(plan);
        if self.report.first_moved.is_none() && moved != 0 {
            self.report.first_moved = Some(std::time::Instant::now());
        }
        let Some(report) = &mut self.report.placed else {
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
        !self.terminal.stopped
            && (!self.rail.pending.is_empty()
                || self.proving.pool.as_ref().is_some_and(ProvingPool::busy))
    }

    /// Forgets what is owed, because nothing more will be asked or answered.
    pub(crate) fn stop(&mut self) {
        self.rail.pending.clear();
        self.terminal.stopped = true;
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
    pub(crate) fn present_capability(&mut self) -> Result<(), Error> {
        let Some(holder) = self.holder.clone() else {
            return Ok(());
        };
        let request = {
            let Some(challenge) = self.receiver.session().pending_presentation() else {
                return Ok(());
            };
            let channel_binding = self
                .receiver
                .session()
                .channel_binding()
                .ok_or(Error::ChannelBindingUnavailable)?;
            holder.answer(challenge, channel_binding)?
        };
        self.receiver.session_mut().present(request)?;
        Ok(())
    }

    /// One pass over what the carrier holds: drains queued requests, takes
    /// every event, advances the object plan, and flushes. Never blocks;
    /// the caller waits on the adapter between passes.
    pub fn service(&mut self) -> Result<FetchStatus, Error> {
        if let Some(code) = self.terminal.closed {
            return Ok(FetchStatus::Closed(code));
        }
        if self.complete() {
            return Ok(FetchStatus::Complete);
        }
        if let Some(completed) = self.cancelled {
            return Ok(FetchStatus::Cancelled(completed));
        }
        if self.seams.cancellation.is_cancelled() {
            return self.cancel_receive();
        }
        if self.terminal.disconnected {
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
                Ok(Some(Event::Control(bytes))) => match self.dispatch(&bytes) {
                    Ok(true) => {
                        self.report.progress = self.report.progress.saturating_add(1);
                    }
                    Ok(false) => {}
                    Err(fault) => return self.fail(fault),
                },
                Ok(Some(Event::Disconnected(_))) => {
                    self.terminal.disconnected = true;
                    break;
                }
                Ok(Some(_)) => self.report.progress = self.report.progress.saturating_add(1),
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
        if self.terminal.disconnected {
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

    fn cancel_receive(&mut self) -> Result<FetchStatus, Error> {
        // Drained under the lock and discarded outside it: a sink's gate
        // is taken before the plan lock, never after.
        let (cursor, window, store) = if let Some(mut plan) = self.locked_plan() {
            if plan.sealing || plan.active.values().any(|active| active.syncing) {
                // Another rail is flushing, running a completion hook, or
                // sealing. Let that reserved transition settle before
                // deciding which cursor and objects cancellation owns.
                return Ok(FetchStatus::Active);
            }
            // The cursor is taken after the step that moves it: a rail
            // that completed an object marks it done and only advances the
            // cursor on its next pass, and a cancel between the two would
            // report one object fewer than this fetch has durable.
            plan.advance_cursor();
            let cursor = plan.low;
            let window: Vec<ActiveObject> =
                std::mem::take(&mut plan.active).into_values().collect();
            let store = plan.store.clone();
            plan.abandoned = true;
            (cursor, window, store)
        } else {
            (0, Vec::new(), None)
        };
        let frame = encoded(&TypedFrame::GoAway(frames::GoAway {
            cursor: cursor as u64,
        }))?;
        // Every entry, not up to the first failure: a sink that cannot
        // discard is no reason to leave the partials above it on disk.
        let discarded = window
            .iter()
            .map(|active| active.sink.discard_partial())
            .fold(Ok(()), Result::and);
        let reset = match store.as_ref().map(|store| store.lock()) {
            Some(Ok(mut store)) => window
                .iter()
                .map(|active| store.reset(active.subject).map_err(resume_failure))
                .fold(Ok(()), Result::and),
            _ => Ok(()),
        };
        let notified = self
            .receiver
            .session_mut()
            .send_control(&frame)
            .and_then(|()| self.receiver.session_mut().flush());
        self.cancelled = Some(cursor);
        self.stop();
        discarded?;
        reset?;
        notified?;
        Ok(FetchStatus::Cancelled(cursor))
    }

    pub(crate) fn complete(&self) -> bool {
        self.locked_plan().is_some_and(|plan| plan.finished)
    }

    /// Acknowledges a completed transfer with a final-cursor `GOAWAY`.
    ///
    /// A push receiver sends it once every sink and completion hook has
    /// succeeded; a fetch client sends it once the package is proven. The
    /// holder treats the final cursor as completion and ends the session.
    #[cfg(feature = "wire")]
    pub(crate) fn acknowledge_completion(&mut self) -> Result<u64, Error> {
        let cursor = self
            .locked_plan()
            .map(|plan| plan.low as u64)
            .ok_or(Error::InvalidBundle)?;
        let frame = encoded(&TypedFrame::GoAway(frames::GoAway { cursor }))?;
        self.receiver.session_mut().send_control(&frame)?;
        self.receiver.session_mut().flush()?;
        Ok(cursor)
    }

    /// Keeps the acknowledged session alive until the holder closes it.
    #[cfg(feature = "wire")]
    pub(crate) fn await_peer_close(&mut self) -> Result<(), Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(Event::Disconnected(_)) = self.receiver.session_mut().poll()? {
                return Ok(());
            }
            self.receiver.session_mut().flush()?;
            if std::time::Instant::now() >= deadline {
                return Err(Error::Stalled);
            }
            self.receiver
                .session_mut()
                .driver()
                .wait_for_event(std::time::Duration::from_millis(10));
        }
    }

    /// Ends a fetch the receiver refused: the session's own faults keep the
    /// code the session closed under, and everything else closes under the
    /// code that names whose fault it was.
    pub(crate) fn receive_failed(
        &mut self,
        error: vot_scheduler::Error,
    ) -> Result<FetchStatus, Error> {
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
    pub(crate) fn pump_provers(&mut self) -> Result<(), vot_scheduler::Error> {
        if self.proving.width == 0 {
            return Ok(());
        }
        let mut pool = self
            .proving
            .pool
            .take()
            .unwrap_or_else(|| ProvingPool::start(self.proving.width));
        // Handed over while there is room, so what is out with a prover is a
        // few covers rather than an object.
        while pool.has_room() {
            let Some(completed) = self.receiver.take_completed() else {
                break;
            };
            // The sink of the object this bundle is for, found by subject:
            // the window holds several, and the pairing has to be the one
            // the bundle names rather than whichever is lowest.
            let Some(sink) = self.locked_plan().and_then(|plan| {
                let (_, active) = plan.in_window(completed.subject())?;
                Some(Arc::clone(&active.sink))
            }) else {
                // A cover for an object the window no longer holds: an
                // object leaves it only on full coverage, so this is a
                // duplicate for a sink already synced.
                continue;
            };
            if pool.work.try_send(Proving { completed, sink }).is_err() {
                break;
            }
            pool.in_flight = pool.in_flight.saturating_add(1);
        }
        // Every ready witness, then one waited for if the pass would
        // otherwise book nothing. A pass that returned without it would spin.
        if pool.in_flight == 0 {
            // Nothing is out, so there is nothing to wait for or book.
            self.proving.pool = Some(pool);
            return Ok(());
        }
        let mut outcome = Ok(());
        // The first witness is waited for (this end's own work, already in
        // hand); the rest are taken as found. Bounded by construction:
        // one bounded wait, then at most what is out with a prover.
        let first = pool.proved.recv_timeout(self.proving.wait).ok();
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
                    // Booked into shared coverage, which completes the object.
                    // The subject check drops stragglers.
                    if let Some(mut plan) = self.locked_plan() {
                        let booked = plan.in_window(proved.completed.subject()).map(|(at, _)| at);
                        if let Some(at) = booked {
                            plan.cover(at, bundle.covered_offset, bundle.covered_length);
                        }
                    }
                }
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            }
        }
        self.proving.pool = Some(pool);
        outcome
    }

    /// Closes the carrier under `code` and stops asking for anything.
    pub(crate) fn close_under(&mut self, code: u16) {
        let _ = self.receiver.session_mut().driver().close(code);
        self.terminal.closed = Some(code);
        self.stop();
    }

    fn close_with_error(&mut self, code: u16) {
        if let Ok(frame) = encoded(&TypedFrame::Error(frames::ErrorFrame {
            code,
            detail: Vec::new(),
        })) {
            let _ = self.receiver.session_mut().send_control(&frame);
            let _ = self.receiver.session_mut().flush();
        }
        self.close_under(code);
    }

    pub(crate) fn fail(&mut self, fault: Fault) -> Result<FetchStatus, Error> {
        match fault {
            Fault::Peer(code) => {
                self.close_with_error(code);
                Ok(FetchStatus::Closed(code))
            }
            Fault::Reported(code) => {
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
    pub(crate) fn drain(&mut self) -> Result<(), Error> {
        while let Some(frame) = self.rail.pending.front() {
            match self.receiver.session_mut().send_control(frame) {
                Ok(()) => {
                    self.rail.pending.pop_front();
                }
                Err(error) if is_backpressure(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Queues one request frame, taking the fields rather than `self` so a
    /// caller holding the plan can still queue.
    pub(crate) fn queue_request(
        pending: &mut VecDeque<Vec<u8>>,
        frame: &TypedFrame,
    ) -> Result<(), Error> {
        pending.push_back(encoded(frame)?);
        Ok(())
    }

    /// The next request identifier, from a counter for the same reason.
    pub(crate) fn request_identifier(counter: &mut u64) -> Result<[u8; 16], Error> {
        let mut identifier = [0u8; 16];
        identifier[..8].copy_from_slice(&counter.to_be_bytes());
        *counter = counter.checked_add(1).ok_or(Error::InvalidBundle)?;
        Ok(identifier)
    }

    /// Takes one control frame, or ignores one that is not the fetch's.
    pub(crate) fn dispatch(&mut self, bytes: &[u8]) -> Result<bool, Fault> {
        let limits = DecodeLimits {
            max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
            max_frames: 1,
        };
        let (frame, consumed) = match frames::decode(bytes, limits) {
            Ok(decoded) => decoded,
            // An unknown optional frame is skipped, per `spec/wire.md`.
            Err(frames::Error::WrongFrameType(_)) => return Ok(false),
            Err(frames::Error::Envelope(error)) => {
                return Err(Fault::Peer(error.protocol_code()));
            }
            Err(_) => return Err(Fault::Peer(error_code::MALFORMED_FRAME)),
        };
        if consumed != bytes.len() {
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        match frame {
            TypedFrame::Error(error) => Err(Fault::Reported(error.code)),
            TypedFrame::PackageDescriptor(descriptor) => self.take_descriptor(descriptor),
            TypedFrame::Seal(seal) => self.take_seal(seal),
            TypedFrame::ManifestPage(page) => self.take_page(&page),
            // A well-formed frame this fetch does not consume.
            _ => Ok(false),
        }
    }

    pub(crate) fn take_descriptor(&mut self, descriptor: PackageDescriptor) -> Result<bool, Fault> {
        if let Some(existing) = &self.manifest.descriptor {
            if *existing == descriptor {
                // An exact re-announcement is idempotent, per the registry.
                return Ok(false);
            }
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        if let Some(pin) = self.pin
            && pin != descriptor.package.root
        {
            return Err(Fault::Pin);
        }
        if self
            .receiver
            .session()
            .extension_negotiated(vot_codec::extension_id::PUSH)
        {
            let scope = self
                .receiver
                .session()
                .granted()
                .and_then(|grant| vot_capability::decode_scope(&grant.granted_scope).ok())
                .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
            if scope.suite != descriptor.package.suite
                || scope.root != descriptor.package.root
                || scope.length != Some(descriptor.package.length)
            {
                return Err(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH));
            }
        }
        if descriptor.package.suite != 1 {
            // The package root is blake3 over the entry sequence; any other
            // suite is not a package this CLI builds or receives.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        self.manifest.descriptor = Some(descriptor);
        Ok(true)
    }

    pub(crate) fn take_seal(&mut self, seal_bytes: Vec<u8>) -> Result<bool, Fault> {
        let Some(descriptor) = &self.manifest.descriptor else {
            // The descriptor leads the announcement; a seal without one is
            // out of sequence.
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        };
        if let Some(existing) = &self.manifest.seal_bytes {
            if *existing == seal_bytes {
                return Ok(false);
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
            self.manifest.seal_bytes = Some(seal_bytes);
            return Ok(true);
        }
        self.manifest.page_digests = crate::seal_page_digests(&seal)
            .map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        self.manifest.spans = manifest_spans(seal.final_page_count);
        self.manifest.seal_bytes = Some(seal_bytes);
        self.request_pages()?;
        Ok(true)
    }

    /// Issues the next manifest span, one at a time: page arrival order is
    /// what indexes the digest check, so spans stay strictly sequential.
    pub(crate) fn request_pages(&mut self) -> Result<(), Fault> {
        let Some(descriptor) = &self.manifest.descriptor else {
            return Ok(());
        };
        let manifest_id = descriptor.manifest_id;
        if let Some((first_page, page_count)) =
            self.manifest.spans.get(self.manifest.next_span).copied()
            && self.manifest.pages_received == first_page
        {
            let request_id =
                Self::request_identifier(&mut self.rail.next_request).map_err(Fault::Local)?;
            Self::queue_request(
                &mut self.rail.pending,
                &TypedFrame::ManifestRequest(ManifestRequest {
                    request_id,
                    manifest_id,
                    first_page,
                    page_count,
                }),
            )
            .map_err(Fault::Local)?;
            self.manifest.next_span += 1;
        }
        Ok(())
    }

    pub(crate) fn take_page(&mut self, page_bytes: &[u8]) -> Result<bool, Fault> {
        if self.secondary {
            // A page this rail never asked for; the manifest on disk is
            // the primary's and already validated.
            return Ok(false);
        }
        if self.manifest.seal_bytes.is_none() {
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        let page = vot_manifest::decode_page(page_bytes)
            .map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        let index = page.index;
        let slot = usize::try_from(index).map_err(|_| Fault::Peer(error_code::MANIFEST_INVALID))?;
        let Some(committed) = self.manifest.page_digests.get(slot) else {
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        };
        if committed != blake3::hash(page_bytes).as_bytes() {
            // Not the page the seal committed to at this index.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        if index < self.manifest.pages_received {
            // An exact duplicate of a page already taken is idempotent.
            return Ok(false);
        }
        if index > self.manifest.pages_received {
            // The control stream is ordered; a gap is the server's doing.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        crate::write_new_synced(
            &crate::manifest_page_path(&self.bundle.join(MANIFEST_DIRECTORY), index),
            page_bytes,
        )
        .map_err(Fault::Local)?;
        self.manifest.pages_received = self
            .manifest
            .pages_received
            .checked_add(1)
            .ok_or(Fault::Local(Error::InvalidBundle))?;
        self.request_pages()?;
        if Some(self.manifest.pages_received)
            == self.manifest.descriptor.as_ref().map(|d| d.page_count)
        {
            self.finish_manifest()?;
        }
        Ok(true)
    }

    /// Writes the seal, validates the whole manifest the way `receive`
    /// does, and plans the objects it names.
    pub(crate) fn finish_manifest(&mut self) -> Result<(), Fault> {
        let seal_bytes = self
            .manifest
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
        let mut seen = BTreeMap::new();
        let mut objects = Vec::new();
        let mut entries = Vec::new();
        while let Some(record) = reader.next_record().map_err(Fault::Local)? {
            let (root, length) = match record.storage {
                Storage::Direct => (record.logical_root, record.logical_length),
                Storage::Pack { root, length, .. } => (root, length),
            };
            let at = if let Some(at) = seen.get(&root).copied() {
                at
            } else {
                objects.push(PlannedObject::fresh(frames::ObjectId {
                    suite: crate::suite_id(record.suite),
                    root,
                    length,
                }));
                let at = objects.len() - 1;
                seen.insert(root, at);
                at
            };
            objects[at].entries.push(record.clone());
            entries.push(record);
        }
        require_push_objects(
            self.receiver
                .session()
                .extension_negotiated(vot_codec::extension_id::PUSH),
            objects.len(),
        )?;
        if let Some(hook) = &self.seams.manifest
            && hook(self.receive_session, summary, &entries).is_err()
        {
            return Err(Fault::Peer(error_code::ADMISSION_DENIED));
        }
        // The store learns the whole plan in one reservation; a store
        // continuing a different package refuses here. What it already
        // holds seeds the handout.
        let directory_resume = self.seams.sink.is_none();
        if directory_resume && let Some(store) = &self.store {
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
            active: BTreeMap::new(),
            low: 0,
            next_open: 0,
            window: self.window,
            placed_before: 0,
            carried_before: 0,
            abandoned: false,
            sealing: false,
            store: directory_resume.then(|| self.store.clone()).flatten(),
            finished: false,
        })));
        Ok(())
    }

    /// Moves the object plan forward: a covered object is synced and left
    /// behind, another is opened into the window, and the last seals the
    /// bundle.
    ///
    /// Every rail runs this. Admission and abandonment are per-rail; the
    /// transition on an object goes to whichever rail sees its coverage
    /// whole first, and that object's `syncing` keeps file work outside the
    /// lock without duplication.
    pub(crate) fn advance(&mut self) -> Result<(), Error> {
        // The handle apart from self, so the receiver and the bundle stay
        // reachable while the plan is held under its lock.
        let Some(shared) = self.plan.clone() else {
            return Ok(());
        };
        if self.secondary && self.manifest.descriptor.is_none() {
            // A rail admits and asks only once the server has answered
            // for the pinned package.
            return Ok(());
        }
        // Counted by the plan itself, so a cursor that stops moving fails
        // here rather than spinning.
        let objects = shared
            .lock()
            .map_err(|_| Error::InvalidBundle)?
            .objects
            .len();
        for _ in 0..advance_passes(objects) {
            let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
            // Forget partial accounts for objects the window no longer
            // holds, so the receiver is bounded by what is in flight, not
            // by everything this rail touched. An index below the cursor
            // has already left the window, so absence is the whole test.
            let forgotten: Vec<(usize, SubjectId)> = self
                .rail
                .admitted
                .iter()
                .filter(|(index, _)| !plan.active.contains_key(index))
                .map(|(index, subject)| (*index, *subject))
                .collect();
            for (index, subject) in forgotten {
                if !self.receiver.is_verified(subject) {
                    self.receiver.abandon(subject);
                }
                self.rail.admitted.remove(&index);
            }
            // Admit every object in the window to this rail, and take the
            // first one that is whole and nobody is syncing.
            let mut settled = None;
            for (index, active) in &plan.active {
                let length = plan
                    .objects
                    .get(*index)
                    .ok_or(Error::InvalidBundle)?
                    .object
                    .length;
                if !self.rail.admitted.contains_key(index) {
                    self.receiver
                        .admit(active.subject, Box::new(Arc::clone(&active.sink)))?;
                    self.rail.admitted.insert(*index, active.subject);
                }
                // Complete when shared coverage spans the object, or this
                // rail's receiver verified it.
                let whole =
                    active.covered.is_complete(length) || self.receiver.is_verified(active.subject);
                if whole && !active.syncing {
                    settled = Some((*index, active.subject, length));
                    break;
                }
            }
            if let Some((at, subject, length)) = settled {
                // Durable before the window drops it, so a completed fetch
                // never names bytes that were only in the page cache.
                // Synced outside the lock: the other rails keep booking and
                // asking while the file flushes.
                let active = plan.active.get_mut(&at).ok_or(Error::InvalidBundle)?;
                active.syncing = true;
                let sink = Arc::clone(&active.sink);
                let hook = active.complete.clone();
                let receive_session = active.receive_session;
                let store = plan.store.clone();
                let completed = plan.objects.get(at).map(|planned| ReceiveObject {
                    object: planned.object,
                    entries: planned.entries.clone(),
                });
                drop(plan);
                let synced = sink.flush();
                if synced.is_ok() {
                    // The whole object is now durable; a resume never asks
                    // for it again.
                    if let Some(store) = &store
                        && let Ok(mut store) = store.lock()
                    {
                        let mut units = UnitRanges::new();
                        units.extend_units(0..total_units_of(length));
                        let _ = store.checkpoint_units(subject, total_units_of(length), &units);
                    }
                }
                let outcome = synced.and_then(|()| {
                    if let (Some(hook), Some(completed)) = (&hook, &completed) {
                        hook(receive_session, completed)?;
                    }
                    Ok(())
                });
                let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                if let Some(active) = plan.active.get_mut(&at) {
                    active.syncing = false;
                }
                if outcome.is_err() {
                    plan.abandoned = true;
                }
                outcome?;
                plan.placed_before = plan.placed_before.saturating_add(length);
                plan.active.remove(&at);
                plan.objects[at].done = true;
                continue;
            }
            plan.advance_cursor();
            if plan.low == plan.objects.len() {
                if plan.finished || plan.sealing {
                    return Ok(());
                }
                // The seal on the bundle, outside the lock like any sync.
                // The store goes first: a completed bundle looks exactly
                // as one fetched without a store, and the directory sync
                // behind it is what makes the removal durable too.
                plan.sealing = true;
                drop(plan);
                let removed = remove_store_files(&self.bundle);
                let synced =
                    removed.and_then(|()| crate::sync_directories(&self.bundle).map(|_| ()));
                let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                plan.sealing = false;
                if synced.is_err() {
                    plan.abandoned = true;
                }
                synced?;
                plan.store = None;
                plan.finished = true;
                return Ok(());
            }
            if plan.abandoned {
                // Cancellation drains the window under this lock and
                // discards what it drained; an object opened after it
                // would be a sink nothing owns.
                return Ok(());
            }
            if plan.in_flight() >= plan.window || plan.next_open == plan.objects.len() {
                return Ok(());
            }
            // Taken under the lock before anything is dropped, so exactly
            // one rail opens each index however long its sink factory or
            // its completion hook runs outside the lock. This is what the
            // cursor comparison after a hook used to stand for, and it is
            // the whole of the one-rail-per-index invariant.
            let at = plan.next_open;
            plan.next_open += 1;
            let planned = plan.objects.get(at).ok_or(Error::InvalidBundle)?;
            let object = planned.object;
            let mut whole_from_before = planned.fully_resumed();
            let mut planned_resumed = planned.resumed.clone();
            let receive_object = ReceiveObject {
                object,
                entries: planned.entries.clone(),
            };
            let path = self
                .bundle
                .join("objects")
                .join(crate::object_name(&object.root));
            let custom = if let Some(factory) = &self.seams.sink {
                let stale = match vot_platform_fs::guard_staging_file(&path) {
                    Ok(file) => Some(file),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        plan.abandoned = true;
                        return Err(error.into());
                    }
                };
                drop(plan);
                let chosen = factory(self.receive_session, &receive_object);
                plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                if chosen.is_err() {
                    plan.abandoned = true;
                }
                let chosen = chosen?;
                if plan.abandoned {
                    drop(plan);
                    return discard_open(chosen);
                }
                if !planned_resumed.is_empty() {
                    let subject = SubjectId::try_from(object).map_err(|_| Error::InvalidBundle)?;
                    if let Some(store) = &plan.store {
                        store
                            .lock()
                            .map_err(|_| Error::InvalidBundle)?
                            .reset(subject)
                            .map_err(resume_failure)?;
                    }
                    plan.objects[at].resumed.clear();
                    planned_resumed.clear();
                    whole_from_before = false;
                }
                if let Some(stale) = stale {
                    if let Err(error) = vot_platform_fs::remove_file_handle(&stale, &path) {
                        plan.abandoned = true;
                        return Err(error.into());
                    }
                    whole_from_before = false;
                }
                let Some(chosen) = chosen else {
                    plan.objects[at].done = true;
                    continue;
                };
                Some(chosen)
            } else {
                None
            };
            if custom_flush_due(object.length, whole_from_before, path.exists())
                && let Some(sink) = &custom
            {
                drop(plan);
                let synced = sink.flush();
                plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                if synced.is_err() {
                    plan.abandoned = true;
                }
                synced?;
                if plan.abandoned {
                    drop(plan);
                    return discard_open(custom);
                }
            }
            if object.length == 0 {
                // Nothing to fetch or verify; the empty object simply is.
                // The lock is held, so exactly one rail writes it; a
                // resumed fetch finds its own earlier write and moves on.
                if custom.is_none() && !path.exists() {
                    crate::write_new_synced(&path, &[])?;
                }
                drop(plan);
                let completed = self
                    .seams
                    .complete
                    .as_ref()
                    .map_or(Ok(()), |hook| hook(self.receive_session, &receive_object));
                plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                if completed.is_err() {
                    plan.abandoned = true;
                }
                completed?;
                plan.objects[at].done = true;
                if plan.abandoned {
                    // Durable and told to its consumer, so it counts
                    // toward the cursor and is never discarded.
                    return Ok(());
                }
                continue;
            }
            if whole_from_before && path.exists() {
                // Durable whole from a previous fetch: nothing to admit
                // or ask for, and the store already says so.
                drop(plan);
                let completed = self
                    .seams
                    .complete
                    .as_ref()
                    .map_or(Ok(()), |hook| hook(self.receive_session, &receive_object));
                plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
                if completed.is_err() {
                    plan.abandoned = true;
                }
                completed?;
                plan.placed_before = plan.placed_before.saturating_add(object.length);
                plan.carried_before = plan.carried_before.saturating_add(object.length);
                plan.objects[at].done = true;
                if plan.abandoned {
                    // Durable and told to its consumer, so it counts
                    // toward the cursor and is never discarded.
                    return Ok(());
                }
                continue;
            }
            let subject = SubjectId::try_from(object).map_err(|_| Error::InvalidBundle)?;
            let resumed = if path.exists() {
                planned_resumed
            } else {
                // The checkpoint outlived its file; clear the store too,
                // or a later resume would trust bytes nobody placed.
                if !plan.objects[at].resumed.is_empty() {
                    if let Some(store) = &plan.store
                        && let Ok(mut store) = store.lock()
                    {
                        store.reset(subject).map_err(resume_failure)?;
                    }
                    plan.objects[at].resumed.clear();
                }
                BTreeMap::new()
            };
            let seeded: u64 = resumed.values().sum();
            plan.carried_before = plan.carried_before.saturating_add(seeded);
            let durable = plan.store.as_ref().map(|store| DurableHook {
                plan: Arc::downgrade(&shared),
                store: Arc::clone(store),
                subject,
            });
            let sink = Arc::new(if let Some(custom) = custom {
                CountingSink::custom(custom)
            } else if path.exists() {
                CountingSink::resume(&path, object.length, seeded, durable)?
            } else {
                CountingSink::create(&path, object.length, durable)?
            });
            self.receiver.admit(subject, Box::new(Arc::clone(&sink)))?;
            self.rail.admitted.insert(at, subject);
            plan.active.insert(
                at,
                ActiveObject {
                    sink,
                    complete: self.seams.complete.clone(),
                    receive_session: self.receive_session,
                    subject,
                    next_offset: 0,
                    // The resumed extents seed both accounts: coverage, so
                    // the object completes when the gaps do, and the skip
                    // set, so the handout never asks for what is placed.
                    covered: CoverageMap::seeded(resumed.clone()),
                    skip: resumed,
                    syncing: false,
                },
            );
        }
        Err(Error::InvalidBundle)
    }

    /// Asks for as much of the object as this rail may have outstanding.
    ///
    /// Each span is committed only once its frame is queued, so a failure
    /// between the two leaves the span owed. The lock across the pair
    /// prevents two takers from framing the same span.
    ///
    /// Pacing is per rail, against what this rail's own receiver has taken
    /// off the carrier: a rail asking on another's arrivals would overdraw
    /// its own receiver. Credit returns as a cover's records land rather
    /// than when its proof holds, so the next span leaves while the current
    /// one is still arriving; the proof still gates placement and coverage.
    pub(crate) fn issue_ranges(&mut self) -> Result<(), Error> {
        let Some(shared) = self.plan.clone() else {
            return Ok(());
        };
        if self.secondary && self.manifest.descriptor.is_none() {
            return Ok(());
        }
        // Counted rather than conditioned on the queue length, so the pass
        // is bounded by the cap itself and no span can spin it.
        for _ in 0..OUTSTANDING_COVERS {
            let outstanding = self
                .rail
                .taken_bytes
                .saturating_sub(self.receiver.arrived_range_bytes());
            if outstanding >= self.rail.window_bytes {
                return Ok(());
            }
            let mut plan = shared.lock().map_err(|_| Error::InvalidBundle)?;
            let Some((at, object, offset, length)) = plan.next_span()? else {
                return Ok(());
            };
            let request_id = Self::request_identifier(&mut self.rail.next_request)?;
            Self::queue_request(
                &mut self.rail.pending,
                &TypedFrame::RangeRequest(RangeRequest {
                    request_id,
                    object,
                    offset,
                    length,
                }),
            )?;
            plan.take(at, offset, length)?;
            self.rail.taken_bytes = self.rail.taken_bytes.saturating_add(length);
            self.report.progress = self.report.progress.saturating_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;

    #[test]
    fn an_empty_transfer_plan_is_only_invalid_under_push() {
        assert!(require_push_objects(false, 0).is_ok());
        assert!(require_push_objects(true, 1).is_ok());
        assert!(matches!(
            require_push_objects(true, 0),
            Err(Fault::Peer(error_code::MANIFEST_INVALID))
        ));
    }
}
