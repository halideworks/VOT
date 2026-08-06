//! Fetching one bundle over a session: the request half of ADR-0030.
//!
//! A [`BundleFetcher`] opens a session, takes the announced descriptor and
//! seal, holds every manifest page to the seal's commitments as it writes
//! them, validates the written manifest with the same chain walk `receive`
//! trusts, and then fetches every stored object the manifest names:
//! sequentially per object, ranges pipelined, each range root-verified by
//! the receiver before its bytes are placed through a [`FileSink`] into
//! `objects/`. The output is a bundle directory `receive_bundle` consumes
//! unchanged; nothing about publication is reimplemented here.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vot_codec::frames::{
    self, MAX_MANIFEST_REQUEST_PAGES, MAX_REQUESTED_RANGE, ManifestRequest, PackageDescriptor,
    RangeRequest, TypedFrame,
};
use vot_codec::{DecodeLimits, Settings, error_code};
use vot_scheduler::session::SessionReceiver;
use vot_scheduler::{FileSink, ReliableReceiver};
use vot_session::{Authentication, Session};
use vot_transport_api::{Event, MAX_CONTROL_FRAME_PAYLOAD, SubjectId, TransportAdapter};

use crate::serve::is_backpressure;
use crate::{Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage};

/// Range requests the fetcher keeps queued, and the covers it prices into
/// staging for them.
///
/// An object has no bound worth queueing whole: at four mebibytes a
/// request, a large one is hundreds of thousands of frames built before
/// the first is sent. So the fetcher issues this many and no more, and
/// refills as the carrier takes them. Two keeps the next request already
/// at the server while it answers the current one, which is what the wire
/// needs; the server's own outbound budget paces the answers.
const OUTSTANDING_COVERS: usize = 2;

/// The credit this end advertises: the covers it asked for, which is what
/// the server may have in flight towards it.
const FETCH_CREDIT_BYTES: u64 = OUTSTANDING_COVERS as u64 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// What the receiver may stage: that credit plus the verifier's group
/// reservation, so a cover arriving at the advertised limit still has room
/// to be verified rather than refused.
const FETCH_STAGING_BYTES: u64 = FETCH_CREDIT_BYTES + vot_verifier::GROUP_SIZE as u64;

// The credit is what it advertises, and the limit clears it by a group: a
// limit at or under the advertised credit would refuse a conforming answer
// for want of room rather than for anything wrong with it.
const _: () = assert!(FETCH_CREDIT_BYTES == 8_519_680);
const _: () = assert!(FETCH_STAGING_BYTES == 8_585_216);

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

/// Why a frame could not be taken: the server broke protocol under a
/// registered close code, the package is not the pinned one, or this end
/// failed on its own.
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

/// One stored object the manifest names, in fetch order.
struct PlannedObject {
    object: frames::ObjectId,
}

/// The objects still owed once the manifest is validated.
struct FetchPlan {
    summary: PackageSummary,
    objects: Vec<PlannedObject>,
    current: usize,
    /// The sink the current object's verified ranges flow into, kept for
    /// the sync that makes its bytes durable before the fetch moves on.
    active: Option<Arc<FileSink>>,
    /// Where the current object's next range request starts.
    next_offset: u64,
    finished: bool,
}

/// One fetch: a client session, the receiver verifying its ranges, and the
/// bundle directory being written.
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
    plan: Option<FetchPlan>,
    pending: VecDeque<Vec<u8>>,
    next_request: u64,
    closed: Option<u16>,
    /// Set once the carrier reported it had gone, so every later pass says
    /// so too rather than only the pass that saw it.
    disconnected: bool,
    /// Set once nothing further will be asked for, whatever ended it.
    stopped: bool,
}

/// Page spans of at most what one `MANIFEST_REQUEST` may name.
///
/// Counted by what the page count needs, not by the cursor: a span that
/// does not advance would otherwise grow this until the allocator gave up,
/// and the seal that gave the count is what bounds the answer.
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
/// A proof the server could not back is the server's fault. This end's own
/// storage and budget failures are not, and closing those as
/// `PROOF_INVALID` would tell a server its proof was bad about a bundle it
/// served correctly, which is the one thing the code is read for.
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
    /// Opens the session and the bundle directory the fetch will fill.
    ///
    /// The optional pin is the package root this fetch will accept; without
    /// it the fetch records what the server announced and the pin lives in
    /// the receipt step, as ADR-0030 settles.
    pub fn begin(adapter: A, bundle: &Path, pin: Option<[u8; 32]>) -> Result<Self, Error> {
        if bundle.exists() {
            return Err(Error::DestinationExists);
        }
        fs::create_dir_all(bundle.join(MANIFEST_DIRECTORY))?;
        fs::create_dir_all(bundle.join("objects"))?;
        let mut session = Session::client(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            // The client ignores the nonce; it is the server's freshness.
            Authentication::NotRequired { nonce: [0; 32] },
        );
        session.begin()?;
        let receiver =
            ReliableReceiver::new(FETCH_STAGING_BYTES, FETCH_CREDIT_BYTES, FETCH_CREDIT_BYTES)?;
        Ok(Self {
            receiver: SessionReceiver::new(session, receiver),
            bundle: bundle.to_owned(),
            pin,
            descriptor: None,
            seal_bytes: None,
            page_digests: Vec::new(),
            pages_received: 0,
            spans: Vec::new(),
            next_span: 0,
            plan: None,
            pending: VecDeque::new(),
            next_request: 0,
            closed: None,
            disconnected: false,
            stopped: false,
        })
    }

    /// The validated package, once the manifest has been.
    #[must_use]
    pub fn package(&self) -> Option<PackageSummary> {
        self.plan.as_ref().map(|plan| plan.summary)
    }

    /// The session under the fetch, for the loop that waits on its carrier.
    pub fn session_mut(&mut self) -> &mut Session<A> {
        self.receiver.session_mut()
    }

    /// Whether requests are queued for the carrier or still to be issued,
    /// either of which is work another pass can do without waiting.
    ///
    /// A fetch that has stopped owes nothing: a lingering backlog would tell
    /// a driving loop to keep servicing a session that cannot progress.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.stopped && (!self.pending.is_empty() || self.owes_ranges())
    }

    /// Forgets what is owed, because nothing more will be asked or answered.
    fn stop(&mut self) {
        self.pending.clear();
        self.stopped = true;
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
        self.drain()?;
        loop {
            match self.receiver.poll() {
                Ok(Some(Event::Control(bytes))) => {
                    if let Err(fault) = self.dispatch(&bytes) {
                        return self.fail(fault);
                    }
                }
                Ok(Some(Event::Disconnected(_))) => {
                    self.disconnected = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => return self.receive_failed(error),
            }
        }
        // Advanced before the carrier is judged: a pass that takes the last
        // object's bytes and the disconnect together has a whole bundle,
        // and reporting the carrier over it would throw away a finished
        // fetch.
        self.advance()?;
        if self.complete() {
            self.stop();
            return Ok(FetchStatus::Complete);
        }
        if self.disconnected {
            self.stop();
            return Ok(FetchStatus::Disconnected);
        }
        // Topped up before the drain, not after: refilling what the carrier
        // has just taken would put a pass's worth of requests on the wire
        // each time round instead of the covers this fetch means to have
        // outstanding.
        self.issue_ranges()?;
        self.drain()?;
        self.receiver.session_mut().flush()?;
        Ok(FetchStatus::Active)
    }

    fn complete(&self) -> bool {
        self.plan.as_ref().is_some_and(|plan| plan.finished)
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
                objects.push(PlannedObject {
                    object: frames::ObjectId {
                        suite: crate::suite_id(record.suite),
                        root,
                        length,
                    },
                });
            }
        }
        self.plan = Some(FetchPlan {
            summary,
            objects,
            current: 0,
            active: None,
            next_offset: 0,
            finished: false,
        });
        Ok(())
    }

    /// Moves the object plan forward: a verified object is synced and left
    /// behind, the next one is admitted and its ranges requested, and the
    /// last one seals the bundle with a directory sync.
    fn advance(&mut self) -> Result<(), Error> {
        // Counted by the plan itself: every pass either returns or leaves
        // one more object behind, so needing more passes than the plan
        // names objects means the cursor is not moving.
        let objects = self.plan.as_ref().map_or(0, |plan| plan.objects.len());
        for _ in 0..=objects {
            let Some(plan) = &mut self.plan else {
                return Ok(());
            };
            if let Some(sink) = &plan.active {
                let planned = plan.objects.get(plan.current).ok_or(Error::InvalidBundle)?;
                if !self.receiver.is_verified(subject_of(planned)) {
                    return Ok(());
                }
                // Durable before the fetch moves on, so a completed fetch
                // never names bytes that were only in the page cache.
                sink.file().sync_all()?;
                plan.active = None;
                plan.current += 1;
            }
            if plan.current == plan.objects.len() {
                if !plan.finished {
                    crate::sync_directories(&self.bundle)?;
                    plan.finished = true;
                }
                return Ok(());
            }
            let planned = &plan.objects[plan.current];
            let path = self
                .bundle
                .join("objects")
                .join(crate::object_name(&planned.object.root));
            if planned.object.length == 0 {
                // Nothing to fetch or verify; the empty object simply is.
                crate::write_new_synced(&path, &[])?;
                plan.current += 1;
                continue;
            }
            let subject = subject_of(planned);
            let sink = Arc::new(FileSink::create(&path, planned.object.length)?);
            self.receiver.admit(subject, Box::new(Arc::clone(&sink)))?;
            plan.active = Some(sink);
            plan.next_offset = 0;
            self.issue_ranges()?;
            return Ok(());
        }
        Err(Error::InvalidBundle)
    }

    /// Tops the queue back up to [`OUTSTANDING_COVERS`] requests for the
    /// object being fetched, so an object of any length is asked for a
    /// couple of covers at a time rather than all at once.
    fn issue_ranges(&mut self) -> Result<(), Error> {
        let Some(plan) = &mut self.plan else {
            return Ok(());
        };
        if plan.active.is_none() {
            return Ok(());
        }
        let object = plan
            .objects
            .get(plan.current)
            .ok_or(Error::InvalidBundle)?
            .object;
        // Counted rather than conditioned on the queue length, so the pass
        // is bounded by the cap itself and no span can spin it.
        for _ in self.pending.len()..OUTSTANDING_COVERS {
            let Some((offset, length)) = range_span(plan.next_offset, object.length) else {
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
            plan.next_offset = offset.checked_add(length).ok_or(Error::InvalidBundle)?;
        }
        Ok(())
    }

    /// Whether the object being fetched still has ranges left to ask for.
    ///
    /// The cursor alone answers it: a plan past its last object has no
    /// current one, and an object about to be admitted owes every range it
    /// has, which is what the pass admitting it goes on to issue.
    fn owes_ranges(&self) -> bool {
        self.plan.as_ref().is_some_and(|plan| {
            plan.objects
                .get(plan.current)
                .is_some_and(|planned| plan.next_offset < planned.object.length)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, discard, not_required, patterned,
        pump,
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

    /// Rounds a fetch in these tests may take before it is not progressing.
    ///
    /// The longest of them settles in well under a hundred: a round moves
    /// every frame both ends have, and the largest object is four covers.
    /// Tight on purpose, so a fetch that stops progressing fails here in a
    /// second rather than running until something else stops it.
    const ROUND_BUDGET: usize = 500;

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
            // However long the objects are, the fetch asks for a couple of
            // covers at a time rather than queueing an object whole.
            assert!(
                fetcher.pending.len() <= OUTSTANDING_COVERS,
                "the request queue outgrew its cap"
            );
            if status != FetchStatus::Active {
                return Ok(status);
            }
            pump(
                fetcher.session_mut().driver(),
                serving.driver(),
                &mut sequence,
            );
            loop {
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
        // The ADR's step-3 test: everything the CLI builds crosses the wire
        // and publishes unchanged. A packed pair, a direct object big
        // enough for several range requests, and an empty file.
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

        // The fetched bundle is the built bundle, byte for byte.
        assert_same_tree(&bundle, &output);

        // And the existing receive publishes it unchanged.
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
    }

    #[test]
    fn a_tampered_record_ends_the_fetch_as_proof_invalid() {
        // Three covers, so the fetch still has one to ask for when the
        // proof fails: a close that left it owed would tell a driving loop
        // to keep servicing a session that cannot progress.
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
        // The code says whose fault it was, and a server told PROOF_INVALID
        // about a bundle it served correctly is told the one thing the code
        // exists to say, wrongly.
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
        // Nothing a build stores is zero length, because an empty file
        // packs. A manifest can still name one, and the receiver refuses to
        // begin a subject of no length, so the fetch writes it itself.
        let (_, summary) = built_bundle("emptyobj", &[("a.txt", patterned(1000))]);
        let output = temporary("emptyobj-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        let empty = frames::ObjectId {
            suite: 1,
            root: *blake3::hash(&[]).as_bytes(),
            length: 0,
        };
        fetcher.plan = Some(FetchPlan {
            summary,
            objects: vec![PlannedObject { object: empty }],
            current: 0,
            active: None,
            next_offset: 0,
            finished: false,
        });
        fetcher.advance().unwrap();

        let path = output.join("objects").join(crate::object_name(&empty.root));
        assert!(fs::read(&path).unwrap().is_empty(), "the empty object is");
        assert!(fetcher.complete(), "and the plan is done with it");
        assert!(
            !fetcher.has_backlog(),
            "nothing was asked for on its account"
        );
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
        // A carrier that has gone is gone for every later pass, not only
        // the one that saw it go.
        assert_eq!(fetcher.service().unwrap(), FetchStatus::Disconnected);
        assert!(!fetcher.has_backlog(), "and nothing is still owed");
    }

    #[test]
    fn a_disconnect_that_arrives_with_the_last_bytes_still_completes() {
        // A server that closes as soon as it has served leaves the records
        // and the disconnect for one pass to take. The bundle is whole, and
        // reporting the carrier over it would throw a finished fetch away.
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
            if !fetcher.has_backlog() && fetcher.plan.as_ref().is_some_and(|p| p.active.is_some()) {
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
        // A manifest past 8,192 pages takes more than one request, which no
        // bundle a test can build reaches: that many pages is millions of
        // entries. The cursor is driven directly instead.
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

        // It is asked for once the pages of the span before it have arrived,
        // because arrival order is what indexes the digest check.
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
    }

    #[test]
    fn a_seal_must_answer_the_descriptor_in_every_field() {
        // The seal is the only thing that names the pages, so a seal that
        // answers a different package than the descriptor announced would
        // put this fetch on a manifest the pin never covered. Each field
        // the two share has to agree on its own.
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

        // The second page before the first is a gap the control stream
        // cannot have made, so it is the server's doing.
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
        // Backpressure holds a request for the next pass. Anything else is
        // this end failing, and holding it would hide that forever.
        let (bundle, _) = built_bundle("sendfail", &[("a.txt", patterned(1000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("sendfail-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        announce(&server, &mut session, &mut connection, &mut fetcher);
        fetcher.session_mut().driver().fail_sends_with = Some(vot_transport_api::Error::Backend);
        let outcome = fetcher.service();
        assert!(matches!(outcome, Err(Error::Session(_))));
    }

    #[test]
    fn ranges_still_to_ask_for_are_backlog() {
        // Three covers, so after the two the fetch keeps in flight there is
        // still one owed: that is work the driving loop must not wait on the
        // carrier for.
        let (bundle, _) = built_bundle("backlog", &[("big.bin", patterned(8_500_000))]);
        let (server, mut session, mut connection) = serving(&bundle);
        let output = temporary("backlog-fetched");
        let mut fetcher = BundleFetcher::begin(Loopback::default(), &output, None).unwrap();
        assert!(!fetcher.has_backlog(), "nothing is owed before a plan");

        let mut sequence = announce(&server, &mut session, &mut connection, &mut fetcher);
        let mut admitted = false;
        for _ in 0..ROUND_BUDGET {
            round(
                &server,
                &mut session,
                &mut connection,
                &mut fetcher,
                &mut sequence,
            );
            if fetcher
                .plan
                .as_ref()
                .is_some_and(|plan| plan.active.is_some())
            {
                admitted = true;
                break;
            }
        }
        assert!(admitted, "the object was never admitted");
        assert!(fetcher.has_backlog(), "a third cover is still to ask for");

        let status =
            run_to_end(&server, &mut session, &mut connection, &mut fetcher, false).unwrap();
        assert_eq!(status, FetchStatus::Complete);
        assert!(!fetcher.has_backlog(), "and nothing is owed at the end");
        discard(&[&bundle, &output]);
    }

    #[test]
    fn an_existing_destination_is_refused() {
        let existing = temporary("occupied");
        fs::create_dir_all(&existing).unwrap();
        let outcome = BundleFetcher::begin(Loopback::default(), &existing, None);
        assert!(matches!(outcome, Err(Error::DestinationExists)));
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
        // Walking the cursor covers the object exactly once, and stops.
        // Counted by what the length can need, so a span that does not
        // advance ends the walk with a wrong answer here rather than
        // filling memory until something else stops it.
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
