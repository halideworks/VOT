//! Serving one bundle over a session.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use vot_codec::frames::{
    self, DataRecord, ManifestRequest, PackageDescriptor, ProofBundle, RangeRequest, TypedFrame,
};
use vot_codec::{DecodeLimits, error_code, frame_type};
use vot_session::{ErrorKind, Session};
use vot_transport_api::{
    Event, MAX_CONTROL_FRAME_PAYLOAD, Payload, StreamId, TransportAdapter, shared_payload,
};
use vot_verifier::{GROUP_SIZE, StreamVerifier, Suite};

use crate::{Error, MANIFEST_DIRECTORY, MANIFEST_SEAL, ManifestReader, PackageSummary, Storage};

/// The reliable lane every data record rides.
const RECORD_LANE: StreamId = StreamId(1);

/// Plaintext bytes per data record. Bounded by the codec record limit and the
/// largest cover across the bundle's record cap.
const RECORD_PLAINTEXT_BYTES: usize = 258_048;

/// Outbound budget. Bounds the queue against a peer pipelining faster than it drains.
const OUTBOUND_BUDGET_BYTES: u64 = 2 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// Request identities remembered for replay detection. An exact duplicate is
/// re-answered; a duplicate identifier with different content is a protocol error.
const REMEMBERED_REQUESTS: usize = 64;

/// One bundle, opened and proved once, answering any number of sessions.
pub struct BundleServer {
    package: PackageSummary,
    manifest_id: [u8; 16],
    page_count: u64,
    /// Page digest by index, to check pages read later against the seal.
    page_digests: Vec<[u8; 32]>,
    manifest_directory: PathBuf,
    /// The descriptor and seal frames, encoded once, announced at readiness.
    announcement: [Payload; 2],
    objects: BTreeMap<[u8; 32], ServedObject>,
}

/// One stored object: its wire identity, proving layer, and file.
struct ServedObject {
    object: frames::ObjectId,
    layer: ProverLayer,
    path: PathBuf,
    witness: Witness,
}

/// A file's length and modification time at open, for cheap mutation detection.
/// Not a proof: a rewrite that restores both is missed, but the peer verifies
/// every range against the object root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Witness {
    length: u64,
    /// `None` where the platform reports no modification time.
    modified: Option<SystemTime>,
}

impl Witness {
    fn of(file: &File) -> Result<Self, Error> {
        let metadata = file.metadata()?;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    /// True when no write is reported since the witness was taken.
    fn reports_untouched(&self, current: &Self) -> bool {
        self.modified.is_some() && self == current
    }
}

/// The chaining-value layer a range is proved from without the object.
enum ProverLayer {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

impl ProverLayer {
    fn empty(suite: Suite) -> Self {
        match suite {
            Suite::Blake3Bao64 => Self::Blake3(vot_proof_blake3::GroupCvs::new()),
            Suite::Sha256Bep52 => Self::Sha256(vot_proof_sha256::PieceHashes::new()),
        }
    }

    fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        match self {
            Self::Blake3(cvs) => cvs.push(group).map_err(|_| Error::Proof),
            Self::Sha256(pieces) => pieces.push(group).map_err(|_| Error::Proof),
        }
    }

    /// Whether the bytes read back match what the layer was built from.
    ///
    /// The cover starts on a group boundary; the first group is at
    /// `covered_offset / GROUP_SIZE`.
    fn holds(&self, covered_offset: u64, plaintext: &[u8]) -> bool {
        if covered_offset % GROUP_SIZE as u64 != 0 {
            return false;
        }
        let Ok(first) = usize::try_from(covered_offset / GROUP_SIZE as u64) else {
            return false;
        };
        plaintext
            .chunks(GROUP_SIZE)
            .enumerate()
            .all(|(offset, group)| match first.checked_add(offset) {
                Some(index) => match self {
                    Self::Blake3(cvs) => cvs.holds(index, group),
                    Self::Sha256(pieces) => pieces.holds(index, group),
                },
                None => false,
            })
    }

    /// Proves a range, returning the group-aligned cover it is proved under.
    fn prove(&self, offset: u64, length: u64) -> Result<(u64, u64, Vec<u8>), Error> {
        match self {
            Self::Blake3(cvs) => vot_proof_blake3::prove_with(cvs, offset, length)
                .map(|cover| (cover.covered_offset, cover.covered_length, cover.proof))
                .map_err(|_| Error::Proof),
            Self::Sha256(pieces) => vot_proof_sha256::prove_with(pieces, offset, length)
                .map(|cover| (cover.covered_offset, cover.covered_length, cover.proof))
                .map_err(|_| Error::Proof),
        }
    }
}

/// Per-session serving state, fresh for every accepted carrier.
pub struct ServeConnection {
    announced: bool,
    remembered: VecDeque<Remembered>,
    pending: VecDeque<Outbound>,
    pending_bytes: u64,
    /// Owed manifest pages as `(next, end)`. Paced rather than queued at once;
    /// a request may name thousands of pages.
    manifest_cursor: Option<(u64, u64)>,
    budget: u64,
    closed: Option<u16>,
    /// Answers queued this session, only ever increasing.
    progress: u64,
    /// Answers the carrier has taken, which the outbound budget may hide.
    handed_over: u64,
}

impl Default for ServeConnection {
    fn default() -> Self {
        Self {
            announced: false,
            remembered: VecDeque::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            manifest_cursor: None,
            budget: OUTBOUND_BUDGET_BYTES,
            closed: None,
            progress: 0,
            handed_over: 0,
        }
    }
}

struct Remembered {
    frame_type: u64,
    request_id: [u8; 16],
    digest: [u8; 32],
}

enum Outbound {
    Control(Payload),
    Record(Payload),
}

/// What one service pass left the session as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeStatus {
    /// The session is live; call again once the carrier reports an event.
    Active,
    /// The carrier ended the session.
    Disconnected,
    /// This end closed the session under a registered code.
    Closed(u16),
}

/// Why an answer could not be built: the peer broke protocol under a
/// registered close code, or this end failed on its own.
enum Fault {
    Peer(u16),
    Local(Error),
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

impl ServeConnection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer bytes queued but not yet accepted by the carrier.
    #[must_use]
    pub fn pending_answer_bytes(&self) -> u64 {
        self.pending_bytes
    }

    /// Whether answers are still owed: queued frames or unpaged manifest pages.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.pending.is_empty() || self.manifest_cursor.is_some()
    }

    /// Records the close and drops pending answers.
    fn close_with(&mut self, code: u16) {
        self.closed = Some(code);
        self.pending.clear();
        self.pending_bytes = 0;
        self.manifest_cursor = None;
    }

    /// Admits a request as new or an exact replay, which is re-answered.
    fn admit_request(
        &mut self,
        frame_type: u64,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Fault> {
        let digest = *blake3::hash(bytes).as_bytes();
        if let Some(seen) = self
            .remembered
            .iter()
            .find(|seen| seen.frame_type == frame_type && seen.request_id == request_id)
        {
            if seen.digest == digest {
                // Rebuild reproduces it: the bundle identity derives from the request bytes.
                return Ok(());
            }
            return Err(Fault::Peer(error_code::REPLAY_REJECTED));
        }
        if self.remembered.len() == REMEMBERED_REQUESTS {
            self.remembered.pop_front();
        }
        self.remembered.push_back(Remembered {
            frame_type,
            request_id,
            digest,
        });
        Ok(())
    }

    /// Queued plus handed-over answers, only ever increasing. Both are needed:
    /// the outbound budget can stall queuing while the carrier still drains,
    /// or vice versa.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.progress.saturating_add(self.handed_over)
    }

    fn queue_control(&mut self, frame: Payload) {
        self.progress = self.progress.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(frame.len() as u64);
        self.pending.push_back(Outbound::Control(frame));
    }

    fn queue_record(&mut self, record: Payload) {
        self.progress = self.progress.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(record.len() as u64);
        self.pending.push_back(Outbound::Record(record));
    }

    /// Hands queued answers to the session until the carrier refuses one.
    fn drain<A: TransportAdapter>(&mut self, session: &mut Session<A>) -> Result<(), Error> {
        while let Some(outbound) = self.pending.front() {
            let result = match outbound {
                Outbound::Control(frame) => session.send_control(frame),
                Outbound::Record(record) => {
                    session.send_reliable_shared(RECORD_LANE, record.clone())
                }
            };
            match result {
                Ok(()) => {
                    if let Some(sent) = self.pending.pop_front() {
                        let bytes = match sent {
                            Outbound::Control(frame) => frame.len(),
                            Outbound::Record(record) => record.len(),
                        };
                        self.pending_bytes = self.pending_bytes.saturating_sub(bytes as u64);
                    }
                    // Progress even under a stalled budget.
                    self.handed_over = self.handed_over.saturating_add(1);
                }
                // Backpressure: retry next pass.
                Err(error) if is_backpressure(&error) => break,
                Err(error) if matches!(error.kind(), ErrorKind::FrameExceedsLimit { .. }) => {
                    // Peer limits too small for this server's answers.
                    let _ = session.driver().close(error_code::FRAME_TOO_LARGE);
                    self.close_with(error_code::FRAME_TOO_LARGE);
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// Ends a failed dispatch: a peer fault closes the session under its code,
/// and a mutated bundle tells the peer why before erring locally.
fn fail<A: TransportAdapter>(
    fault: Fault,
    session: &mut Session<A>,
    connection: &mut ServeConnection,
) -> Result<ServeStatus, Error> {
    match fault {
        Fault::Peer(code) => {
            // The session cannot close itself; the carrier does.
            let _ = session.driver().close(code);
            connection.close_with(code);
            Ok(ServeStatus::Closed(code))
        }
        Fault::Local(error) => {
            if matches!(error, Error::SourceMutation) {
                // Tell the peer why before the local error surfaces.
                let _ = session.driver().close(error_code::SOURCE_MUTATED);
                connection.close_with(error_code::SOURCE_MUTATED);
            }
            Err(error)
        }
    }
}

/// Whether a session refusal means "retry after the backend drains".
pub(crate) fn is_backpressure(error: &vot_session::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Transport(vot_transport_api::Error::OutboundQueueFull)
            | ErrorKind::HandshakeUnsent { .. }
    )
}

fn encoded(frame: &TypedFrame) -> Result<Payload, Error> {
    let mut wire = Vec::new();
    frames::encode(frame, &mut wire)?;
    Ok(shared_payload(&wire))
}

impl BundleServer {
    /// Opens a bundle for serving: the chain walk `receive_bundle` trusts,
    /// then a proving layer per stored object, built once.
    pub fn open(bundle: &Path) -> Result<Self, Error> {
        let package = crate::scan_manifest(bundle)?;
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        // Bounded by the SEAL frame limit: a larger seal could never be announced.
        let seal_limit = vot_codec::registered_payload_limit(vot_codec::frame_type::SEAL)
            .unwrap_or(vot_manifest::MAX_PAGE_BYTES);
        let seal_bytes =
            crate::read_bounded_file(&manifest_directory.join(MANIFEST_SEAL), seal_limit)?;
        let seal = vot_manifest::decode_seal(&seal_bytes).map_err(|_| Error::InvalidBundle)?;
        let page_digests = crate::seal_page_digests(&seal)?;

        // Map manifest entries to their stored objects.
        let mut reader = ManifestReader::open(bundle)?;
        let mut wanted: BTreeMap<[u8; 32], (Suite, u64)> = BTreeMap::new();
        while let Some(record) = reader.next_record()? {
            let (root, length) = match record.storage {
                Storage::Direct => (record.logical_root, record.logical_length),
                Storage::Pack { root, length, .. } => (root, length),
            };
            match wanted.entry(root) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((record.suite, length));
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if *entry.get() != (record.suite, length) {
                        return Err(Error::InvalidBundle);
                    }
                }
            }
        }
        let objects_directory = bundle.join("objects");
        let mut objects = BTreeMap::new();
        for (root, (suite, length)) in wanted {
            objects.insert(
                root,
                ServedObject::build(&objects_directory, root, suite, length)?,
            );
        }

        let descriptor = TypedFrame::PackageDescriptor(PackageDescriptor {
            package: frames::ObjectId {
                suite: seal.package.suite,
                root: seal.package.root,
                length: seal.package.length,
            },
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
        });
        let announcement = [
            encoded(&descriptor)?,
            encoded(&TypedFrame::Seal(seal_bytes))?,
        ];
        Ok(Self {
            package,
            manifest_id: seal.manifest_id,
            page_count: seal.final_page_count,
            page_digests,
            manifest_directory,
            announcement,
            objects,
        })
    }

    /// The package this server answers for.
    #[must_use]
    pub const fn package(&self) -> PackageSummary {
        self.package
    }

    /// One non-blocking pass: drains queued answers, reads events up to the
    /// outbound budget, and answers every request.
    pub fn service<A: TransportAdapter>(
        &self,
        session: &mut Session<A>,
        connection: &mut ServeConnection,
    ) -> Result<ServeStatus, Error> {
        if let Some(code) = connection.closed {
            return Ok(ServeStatus::Closed(code));
        }
        connection.drain(session)?;
        loop {
            if let Some(code) = connection.closed {
                return Ok(ServeStatus::Closed(code));
            }
            if let Err(fault) = self.pump_manifest(connection) {
                return fail(fault, session, connection);
            }
            if connection.pending_bytes >= connection.budget {
                break;
            }
            match session.poll() {
                Ok(Some(Event::Control(bytes))) => {
                    // Announce before the first answer.
                    self.ensure_announced(connection, session.is_ready());
                    if let Err(fault) = self.dispatch(&bytes, connection) {
                        return fail(fault, session, connection);
                    }
                }
                Ok(Some(Event::Disconnected(_))) => return Ok(ServeStatus::Disconnected),
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.ensure_announced(connection, session.is_ready());
                    break;
                }
                Err(error) => {
                    if error.kind().is_peer_fault() {
                        // The session already closed; record the code.
                        let code = error.close_code();
                        connection.closed = Some(code);
                        return Ok(ServeStatus::Closed(code));
                    }
                    return Err(error.into());
                }
            }
        }
        connection.drain(session)?;
        if let Some(code) = connection.closed {
            return Ok(ServeStatus::Closed(code));
        }
        session.flush()?;
        Ok(ServeStatus::Active)
    }

    fn ensure_announced(&self, connection: &mut ServeConnection, ready: bool) {
        if connection.announced || !ready {
            return;
        }
        for frame in &self.announcement {
            connection.queue_control(frame.clone());
        }
        connection.announced = true;
    }

    /// Answers one control frame, or ignores one that is not a request.
    fn dispatch(&self, bytes: &[u8], connection: &mut ServeConnection) -> Result<(), Fault> {
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
            // One event carries one frame; trailing bytes are a protocol error.
            return Err(Fault::Peer(error_code::MALFORMED_FRAME));
        }
        match frame {
            TypedFrame::ManifestRequest(request) => {
                connection.admit_request(
                    frame_type::MANIFEST_REQUEST,
                    request.request_id,
                    bytes,
                )?;
                self.answer_manifest(&request, connection)
            }
            TypedFrame::RangeRequest(request) => {
                connection.admit_request(frame_type::RANGE_REQUEST, request.request_id, bytes)?;
                self.answer_range(&request, bytes, connection)
            }
            // A well-formed frame this engine does not answer yet.
            _ => Ok(()),
        }
    }

    fn answer_manifest(
        &self,
        request: &ManifestRequest,
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        if request.manifest_id != self.manifest_id {
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        let end = request
            .first_page
            .checked_add(request.page_count)
            .ok_or(Fault::Peer(error_code::MANIFEST_INVALID))?;
        if end > self.page_count {
            // Asking past the announced page count.
            return Err(Fault::Peer(error_code::MANIFEST_INVALID));
        }
        // A cursor, not queued frames: pages are paced by the budget.
        connection.manifest_cursor = Some((request.first_page, end));
        Ok(())
    }

    /// Queues owed manifest pages while the outbound budget lasts.
    fn pump_manifest(&self, connection: &mut ServeConnection) -> Result<(), Fault> {
        while let Some((next, end)) = connection.manifest_cursor {
            if connection.pending_bytes >= connection.budget {
                break;
            }
            let bytes = crate::read_bounded_file(
                &crate::manifest_page_path(&self.manifest_directory, next),
                vot_manifest::MAX_PAGE_BYTES,
            )?;
            let slot = usize::try_from(next).map_err(|_| Error::InvalidBundle)?;
            if self.page_digests.get(slot) != Some(blake3::hash(&bytes).as_bytes()) {
                // Page changed on disk since the seal.
                return Err(Fault::Local(Error::SourceMutation));
            }
            connection.queue_control(encoded(&TypedFrame::ManifestPage(bytes))?);
            let following = next.checked_add(1).ok_or(Error::InvalidBundle)?;
            connection.manifest_cursor = if following == end {
                None
            } else {
                Some((following, end))
            };
        }
        Ok(())
    }

    fn answer_range(
        &self,
        request: &RangeRequest,
        request_bytes: &[u8],
        connection: &mut ServeConnection,
    ) -> Result<(), Fault> {
        let served = self
            .objects
            .get(&request.object.root)
            .ok_or(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH))?;
        if served.object != request.object {
            return Err(Fault::Peer(error_code::OBJECT_IDENTITY_MISMATCH));
        }
        // The codec bounded the request; the cover expands it to group boundaries.
        let (covered_offset, covered_length, proof) =
            served.layer.prove(request.offset, request.length)?;
        let plaintext = served.read_covered(covered_offset, covered_length)?;
        // Bundle identity derives from the request bytes, for replay detection.
        let mut bundle_id = [0u8; 16];
        bundle_id.copy_from_slice(&blake3::hash(request_bytes).as_bytes()[..16]);
        let chunks = plaintext.chunks(RECORD_PLAINTEXT_BYTES);
        let bundle = TypedFrame::ProofBundle(ProofBundle {
            request_id: request.request_id,
            bundle_id,
            object: served.object,
            requested_offset: request.offset,
            requested_length: request.length,
            covered_offset,
            covered_length,
            data_record_count: chunks.len() as u64,
            total_plaintext_length: covered_length,
            proof,
        });
        connection.queue_control(encoded(&bundle)?);
        let mut offset = covered_offset;
        for (index, chunk) in plaintext.chunks(RECORD_PLAINTEXT_BYTES).enumerate() {
            let record = TypedFrame::DataRecord(DataRecord {
                bundle_id,
                record_index: index as u64,
                plaintext_offset: offset,
                plaintext_length: chunk.len() as u64,
                compression: 0,
                encoded: chunk.to_vec(),
            });
            connection.queue_record(encoded(&record)?);
            offset = offset.saturating_add(chunk.len() as u64);
        }
        Ok(())
    }
}

impl ServedObject {
    /// Streams the object once, verifying its root while keeping only the
    /// chaining values a proof needs.
    fn build(objects: &Path, root: [u8; 32], suite: Suite, length: u64) -> Result<Self, Error> {
        let path = objects.join(crate::object_name(&root));
        let mut file = File::open(&path)?;
        // Take the witness before reading: a mid-read write would otherwise
        // stamp into the witness.
        let witness = Witness::of(&file)?;
        let mut verifier = StreamVerifier::new(suite);
        let mut layer = ProverLayer::empty(suite);
        let mut group = vec![0u8; GROUP_SIZE];
        let mut remaining = length;
        while remaining > 0 {
            let take = usize::try_from(remaining.min(GROUP_SIZE as u64))
                .map_err(|_| Error::InvalidBundle)?;
            file.read_exact(&mut group[..take]).map_err(short_read)?;
            verifier.update(&group[..take])?;
            layer.push(&group[..take])?;
            remaining -= take as u64;
        }
        // Trailing bytes mean the file is not the object it is named as.
        if file.read(&mut [0u8; 1])? != 0 {
            return Err(Error::RootMismatch);
        }
        if verifier.finish()? != root {
            return Err(Error::RootMismatch);
        }
        Ok(Self {
            object: frames::ObjectId {
                suite: crate::suite_id(suite),
                root,
                length,
            },
            layer,
            path,
            witness,
        })
    }

    /// Reads the cover's bytes and checks they match what the layer was built
    /// from. Uses the witness stat first; falls back to hashing only when
    /// metadata can't vouch for the file.
    fn read_covered(&self, offset: u64, length: u64) -> Result<Vec<u8>, Error> {
        let mut file = File::open(&self.path).map_err(missing_object)?;
        file.seek(SeekFrom::Start(offset))?;
        let size = usize::try_from(length).map_err(|_| Error::InvalidBundle)?;
        let mut plaintext = vec![0u8; size];
        file.read_exact(&mut plaintext).map_err(short_read)?;
        if self.witness.reports_untouched(&Witness::of(&file)?) {
            return Ok(plaintext);
        }
        if !self.layer.holds(offset, &plaintext) {
            return Err(Error::SourceMutation);
        }
        Ok(plaintext)
    }
}

/// A missing object is treated as a source mutation: the peer is told why
/// rather than left waiting.
fn missing_object(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        Error::SourceMutation
    } else {
        Error::Io(error)
    }
}

/// A file shorter than its layer promised was mutated after open.
fn short_read(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        Error::SourceMutation
    } else {
        Error::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_bundle_with_suite;
    use crate::harness::{
        Loopback, built_bundle, control_event, decode_control, not_required, patterned,
    };
    use crate::tests::temporary;
    use std::collections::BTreeSet;
    use std::fs;
    use vot_codec::Settings;
    use vot_manifest::StorageRef;
    use vot_scheduler::ReliableReceiver;
    use vot_transport_api::SubjectId;

    /// A ready server session with handshake replies cleared.
    fn ready_session() -> Session<Loopback> {
        ready_session_with(Settings::default())
    }

    /// The same under the peer settings a test needs.
    fn ready_session_with(peer: Settings) -> Session<Loopback> {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        server.begin().unwrap();
        push_handshake_with(&mut server, peer);
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());
        server.driver().control.clear();
        server
    }

    /// Queues a client's opening frames into the server's carrier.
    fn push_handshake(server: &mut Session<Loopback>) {
        push_handshake_with(server, Settings::default());
    }

    fn push_handshake_with(server: &mut Session<Loopback>, peer: Settings) {
        let mut client =
            Session::client(Loopback::default(), peer, BTreeSet::new(), not_required());
        client.begin().unwrap();
        for frame in std::mem::take(&mut client.driver().control) {
            server
                .driver()
                .events
                .push_back(Event::Control(shared_payload(&frame)));
        }
    }

    /// Pairs proof bundles with their records, consumed in wire order.
    fn served_answers(session: &mut Session<Loopback>) -> Vec<(ProofBundle, Vec<DataRecord>)> {
        let control = std::mem::take(&mut session.driver().control);
        let records = std::mem::take(&mut session.driver().records);
        let mut answers: Vec<(ProofBundle, Vec<DataRecord>)> = Vec::new();
        for frame in &control {
            if let TypedFrame::ProofBundle(bundle) = decode_control(frame) {
                answers.push((bundle, Vec::new()));
            }
        }
        let mut stream = records.iter();
        for (bundle, carried) in &mut answers {
            for _ in 0..bundle.data_record_count {
                let (lane, bytes) = stream.next().expect("a bundle short of its records");
                assert_eq!(*lane, RECORD_LANE, "records ride the record lane");
                let TypedFrame::DataRecord(record) = decode_control(bytes) else {
                    panic!("the record lane carried something else");
                };
                assert_eq!(record.bundle_id, bundle.bundle_id);
                carried.push(record);
            }
        }
        assert!(stream.next().is_none(), "records past every bundle");
        answers
    }

    /// Verifies an answer against the object root and returns its bytes.
    fn verified_bytes(
        object: frames::ObjectId,
        bundle: &ProofBundle,
        records: &[DataRecord],
    ) -> Vec<u8> {
        let subject = SubjectId {
            suite: object.suite,
            root: object.root,
            length: object.length,
        };
        ReliableReceiver::verify_typed_bundle(subject, bundle, records).unwrap();
        let mut ordered: Vec<&DataRecord> = records.iter().collect();
        ordered.sort_by_key(|record| record.record_index);
        let mut assembled = Vec::new();
        for record in ordered {
            assembled.extend_from_slice(&record.encoded);
        }
        assembled
    }

    /// The stored objects the served pages name: direct objects and packs.
    fn stored_objects(pages: &[Vec<u8>]) -> (BTreeMap<[u8; 32], frames::ObjectId>, bool, bool) {
        let mut objects = BTreeMap::new();
        let (mut saw_direct, mut saw_pack) = (false, false);
        for bytes in pages {
            let page = vot_manifest::decode_page(bytes).unwrap();
            for entry in page.entries {
                let stored = match entry.storage.unwrap() {
                    StorageRef::Direct(object) => {
                        saw_direct = true;
                        object
                    }
                    StorageRef::Pack { pack, .. } => {
                        saw_pack = true;
                        pack
                    }
                };
                objects.insert(
                    stored.root,
                    frames::ObjectId {
                        suite: stored.suite,
                        root: stored.root,
                        length: stored.length,
                    },
                );
            }
        }
        (objects, saw_direct, saw_pack)
    }

    #[test]
    fn a_ready_session_is_announced_and_a_whole_bundle_is_served() {
        let (bundle, summary) = built_bundle(
            "whole",
            &[
                ("a.txt", patterned(1000)),
                ("nested/b.bin", patterned(150_000)),
                ("big.bin", patterned(300_000)),
            ],
        );
        let server = BundleServer::open(&bundle).unwrap();
        assert_eq!(server.package(), summary);
        let mut session = ready_session();
        let mut connection = ServeConnection::new();

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(connection.pending_answer_bytes(), 0);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len(), 2, "the announcement is the descriptor and seal");
        let TypedFrame::PackageDescriptor(descriptor) = decode_control(&sent[0]) else {
            panic!("the descriptor leads");
        };
        assert_eq!(descriptor.package.root, summary.root);
        assert_eq!(descriptor.package.suite, 1);
        assert_eq!(descriptor.package.length, summary.logical_length);
        assert_eq!(descriptor.manifest_id, summary.root[..16]);
        let TypedFrame::Seal(seal_bytes) = decode_control(&sent[1]) else {
            panic!("the seal follows");
        };
        assert_eq!(
            seal_bytes,
            fs::read(bundle.join("manifest/seal.cbor")).unwrap()
        );

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: descriptor.manifest_id,
                    first_page: 0,
                    page_count: descriptor.page_count,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len() as u64, descriptor.page_count);
        let mut pages = Vec::new();
        for (index, frame) in sent.iter().enumerate() {
            let TypedFrame::ManifestPage(bytes) = decode_control(frame) else {
                panic!("a page answer that is not a page");
            };
            assert_eq!(
                bytes,
                fs::read(bundle.join(format!("manifest/{index:016}.cbor"))).unwrap(),
                "the served page is the disk page"
            );
            pages.push(bytes);
        }

        let (objects, saw_direct, saw_pack) = stored_objects(&pages);
        assert!(saw_direct && saw_pack, "both storage kinds are exercised");
        for (request_index, object) in objects.values().enumerate() {
            let identifier = u8::try_from(10 + request_index).unwrap();
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object: *object,
                    offset: 0,
                    length: object.length,
                })));
            let status = server.service(&mut session, &mut connection).unwrap();
            assert_eq!(status, ServeStatus::Active);
            let answers = served_answers(&mut session);
            assert_eq!(answers.len(), 1);
            let (bundle_frame, records) = &answers[0];
            assert_eq!(bundle_frame.request_id, [identifier; 16]);
            let assembled = verified_bytes(*object, bundle_frame, records);
            let expected = fs::read(
                bundle
                    .join("objects")
                    .join(crate::object_name(&object.root)),
            )
            .unwrap();
            assert_eq!(assembled, expected, "the whole object arrived verified");
        }
        assert!(session.driver().closed.is_none());
    }

    #[test]
    fn an_unaligned_range_is_proved_under_its_group_cover() {
        let (bundle, _) = built_bundle("cover", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // Mid-object: cover snaps to group boundaries.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 70_000,
                length: 50_000,
            })));
        // Tail: cover clipped to object end.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [2; 16],
                object,
                offset: 250_000,
                length: 50_000,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 2);
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();

        let (mid, mid_records) = &answers[0];
        assert_eq!(mid.covered_offset, 65_536);
        assert_eq!(mid.covered_length, 65_536);
        let bytes = verified_bytes(object, mid, mid_records);
        assert_eq!(bytes, disk[65_536..131_072]);

        let (tail, tail_records) = &answers[1];
        assert_eq!(tail.covered_offset, 196_608);
        assert_eq!(tail.covered_length, 300_000 - 196_608);
        let bytes = verified_bytes(object, tail, tail_records);
        assert_eq!(bytes, disk[196_608..]);
    }

    #[test]
    fn an_exact_duplicate_is_reanswered_and_a_conflict_ends_the_session() {
        let (bundle, _) = built_bundle("replay", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        let request = TypedFrame::RangeRequest(RangeRequest {
            request_id: [3; 16],
            object,
            offset: 0,
            length: 100_000,
        });
        session.driver().events.push_back(control_event(&request));
        session.driver().events.push_back(control_event(&request));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 2, "an exact replay is answered again");
        assert_eq!(
            answers[0].0, answers[1].0,
            "identically: the identity derives from the request"
        );

        let conflicting = TypedFrame::RangeRequest(RangeRequest {
            request_id: [3; 16],
            object,
            offset: 65_536,
            length: 100_000,
        });
        session
            .driver()
            .events
            .push_back(control_event(&conflicting));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::REPLAY_REJECTED),
            "the same identifier with different content is a protocol error"
        );
        assert_eq!(session.driver().closed, Some(error_code::REPLAY_REJECTED));
        // The close is remembered without another look at the carrier.
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::REPLAY_REJECTED));
    }

    #[test]
    fn a_request_for_an_object_not_served_ends_the_session() {
        let (bundle, _) = built_bundle("unknown", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [4; 16],
                object: frames::ObjectId {
                    suite: 2,
                    root: [9; 32],
                    length: 100,
                },
                offset: 0,
                length: 100,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::OBJECT_IDENTITY_MISMATCH)
        );

        // The right root under the wrong identity is not the same object.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [5; 16],
                object: frames::ObjectId {
                    length: object.length + 1,
                    ..object
                },
                offset: 0,
                length: 100,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::OBJECT_IDENTITY_MISMATCH)
        );
    }

    #[test]
    fn a_manifest_request_beyond_the_seal_ends_the_session() {
        let (bundle, _) = built_bundle("pages", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [6; 16],
                    manifest_id: [0xaa; 16],
                    first_page: 0,
                    page_count: 1,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MANIFEST_INVALID));

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [7; 16],
                    manifest_id: server.manifest_id,
                    first_page: server.page_count,
                    page_count: 1,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MANIFEST_INVALID));
    }

    #[test]
    fn control_frames_that_are_not_requests_are_refused_or_skipped() {
        let (bundle, _) = built_bundle("frames", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();

        // Bytes that decode to nothing end the session.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&[0xff; 8])));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MALFORMED_FRAME));

        // Trailing bytes after one whole frame are not a second frame.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        frames::encode(
            &TypedFrame::ManifestRequest(ManifestRequest {
                request_id: [8; 16],
                manifest_id: server.manifest_id,
                first_page: 0,
                page_count: 1,
            }),
            &mut wire,
        )
        .unwrap();
        wire.push(0);
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::MALFORMED_FRAME));

        // An unknown critical frame is refused under its own code.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        vot_codec::encode_frame(0x7fff, &[], &mut wire).unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            status,
            ServeStatus::Closed(error_code::UNKNOWN_CRITICAL_FRAME)
        );

        // An unknown optional frame is skipped and the session lives on.
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        let mut wire = Vec::new();
        vot_codec::encode_frame(0x7ffe, &[], &mut wire).unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&wire)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(session.driver().closed.is_none());
    }

    #[test]
    fn handing_an_answer_to_the_carrier_is_progress() {
        let (bundle, _) = built_bundle("slow-peer", &[("big.bin", patterned(4_300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for identifier in 0..4u8 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 4_194_304,
                })));
        }
        session.driver().refuse_sends = usize::MAX;
        server.service(&mut session, &mut connection).unwrap();
        assert!(connection.pending_answer_bytes() >= OUTBOUND_BUDGET_BYTES);
        // No more requests to read; any progress change is handover only.
        session.driver().events.clear();

        let stalled = connection.progress();
        server.service(&mut session, &mut connection).unwrap();
        assert_eq!(
            connection.progress(),
            stalled,
            "a carrier that takes nothing is not progress"
        );

        let taken = |session: &mut Session<Loopback>| {
            session.driver().records.len() + session.driver().control.len()
        };
        let before = taken(&mut session);
        session.driver().refuse_sends = 0;
        server.service(&mut session, &mut connection).unwrap();
        let moved = taken(&mut session) - before;
        assert!(moved > 0, "the carrier took answers");
        assert_eq!(
            connection.progress() - stalled,
            moved as u64,
            "every answer handed over counts once"
        );
    }

    #[test]
    fn backpressure_holds_answers_and_the_budget_stops_reading() {
        let (bundle, _) = built_bundle("budget", &[("big.bin", patterned(4_300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        for identifier in 0..4u8 {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 4_194_304,
                })));
        }
        // Carrier refuses all sends; budget stops reading.
        session.driver().refuse_sends = usize::MAX;
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(connection.pending_answer_bytes() >= OUTBOUND_BUDGET_BYTES);
        assert_eq!(
            session.driver().events.len(),
            1,
            "the budget left one request unread"
        );

        session.driver().refuse_sends = 0;
        let mut passes = 0;
        while session.driver().events.front().is_some() || connection.pending_answer_bytes() > 0 {
            let status = server.service(&mut session, &mut connection).unwrap();
            assert_eq!(status, ServeStatus::Active);
            passes += 1;
            assert!(passes <= 8, "draining must converge");
        }
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 4, "every request was answered exactly once");
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();
        for (bundle_frame, records) in &answers {
            assert_eq!(
                records.len(),
                17,
                "a full-size request fills the codec's record cap"
            );
            let bytes = verified_bytes(object, bundle_frame, records);
            assert_eq!(bytes, disk[..4_194_304]);
        }
    }

    #[test]
    fn the_announcement_precedes_an_answer_arriving_in_the_same_pass() {
        let (bundle, _) = built_bundle("order", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        push_handshake(&mut session);
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: 1,
            })));

        let mut connection = ServeConnection::new();
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let mut kinds = Vec::new();
        for frame in &session.driver().control {
            match frames::decode(
                frame,
                DecodeLimits {
                    max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
                    max_frames: 1,
                },
            ) {
                Ok((TypedFrame::PackageDescriptor(_), _)) => kinds.push("descriptor"),
                Ok((TypedFrame::Seal(_), _)) => kinds.push("seal"),
                Ok((TypedFrame::ProofBundle(_), _)) => kinds.push("bundle"),
                _ => {}
            }
        }
        assert_eq!(kinds, ["descriptor", "seal", "bundle"]);
    }

    #[test]
    fn a_blake3_bundle_round_trips_the_same_way() {
        let source = temporary("blake3-source");
        let bundle = temporary("blake3-bundle");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("big.bin"), patterned(300_000)).unwrap();
        build_bundle_with_suite(&source, &bundle, Suite::Blake3Bao64).unwrap();
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        assert_eq!(object.suite, 1);

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 1);
        let bytes = verified_bytes(object, &answers[0].0, &answers[0].1);
        let disk = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();
        assert_eq!(bytes, disk);
    }

    #[test]
    fn open_refuses_an_object_that_is_not_what_its_name_claims() {
        let (bundle, _) = built_bundle("mutated", &[("big.bin", patterned(300_000))]);
        let objects = bundle.join("objects");
        let name = fs::read_dir(&objects).unwrap().next().unwrap().unwrap();
        let path = name.path();
        let original = fs::read(&path).unwrap();

        let mut flipped = original.clone();
        flipped[0] ^= 1;
        fs::write(&path, &flipped).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::RootMismatch)
        ));

        fs::write(&path, &original[..100_000]).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::SourceMutation)
        ));

        let mut extended = original.clone();
        extended.push(0);
        fs::write(&path, &extended).unwrap();
        assert!(matches!(
            BundleServer::open(&bundle),
            Err(Error::RootMismatch)
        ));

        fs::remove_file(&path).unwrap();
        assert!(matches!(BundleServer::open(&bundle), Err(Error::Io(_))));

        fs::write(&path, &original).unwrap();
        assert!(BundleServer::open(&bundle).is_ok());
    }

    #[test]
    fn a_page_mutated_after_open_is_not_served() {
        let (bundle, _) = built_bundle("page-mutated", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let page = bundle.join("manifest").join(format!("{0:016}.cbor", 0));
        let mut bytes = fs::read(&page).unwrap();
        bytes[0] ^= 1;
        fs::write(&page, &bytes).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [9; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: 1,
                },
            )));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        // The peer is told why before the local error surfaces.
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::SOURCE_MUTATED));
    }

    #[test]
    fn a_manifest_answer_is_paced_by_the_outbound_budget() {
        let (bundle, _) = built_bundle("paced", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        connection.budget = 1;

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: server.page_count,
                },
            )));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(
            sent.len(),
            2,
            "the announcement went out, the pages are still owed"
        );
        assert!(connection.has_backlog(), "the cursor holds the answer");

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        let sent = std::mem::take(&mut session.driver().control);
        assert_eq!(sent.len(), 1, "one page per pass under a one-byte budget");
        let TypedFrame::ManifestPage(bytes) = decode_control(&sent[0]) else {
            panic!("the owed page arrived");
        };
        assert_eq!(
            bytes,
            fs::read(bundle.join(format!("manifest/{:016}.cbor", 0))).unwrap()
        );
        assert!(!connection.has_backlog(), "nothing further is owed");

        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert!(session.driver().control.is_empty(), "and nothing repeats");
    }

    #[test]
    fn answers_the_peer_cannot_carry_close_the_session() {
        let (bundle, _) = built_bundle("narrow", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        // Peer's record limit too small for this server's answers.
        let mut session = ready_session_with(Settings {
            max_data_record_payload: 64 * 1024,
            ..Settings::default()
        });
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::FRAME_TOO_LARGE));
        assert_eq!(session.driver().closed, Some(error_code::FRAME_TOO_LARGE));
        assert!(
            !connection.has_backlog(),
            "nothing stays owed after a close"
        );
    }

    #[test]
    fn a_send_failure_that_is_not_backpressure_surfaces() {
        let (bundle, _) = built_bundle("failing", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();

        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: 100,
            })));
        session.driver().fail_sends_with = Some(vot_transport_api::Error::Backend);
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::Session(_))));
    }

    #[test]
    fn the_replay_window_evicts_the_oldest_request() {
        let (bundle, _) = built_bundle("window", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // One more distinct request than the window holds.
        for identifier in 0..=u8::try_from(REMEMBERED_REQUESTS).unwrap() {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: [identifier; 16],
                    object,
                    offset: 0,
                    length: 1,
                })));
        }
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(served_answers(&mut session).len(), REMEMBERED_REQUESTS + 1);

        // The first identifier was evicted, so different content under it is
        // a new request rather than a conflict.
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [0; 16],
                object,
                offset: 0,
                length: 2,
            })));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Active);
        assert_eq!(served_answers(&mut session).len(), 1);
        assert!(session.driver().closed.is_none());
    }

    #[test]
    fn a_conflict_on_an_older_remembered_request_is_still_caught() {
        let (bundle, _) = built_bundle("older", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();

        // Two distinct requests, then a conflict on the older one: the
        // window has to hold more than the newest entry to catch it.
        for (identifier, length) in [([1; 16], 1u64), ([2; 16], 1), ([1; 16], 2)] {
            session
                .driver()
                .events
                .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                    request_id: identifier,
                    object,
                    offset: 0,
                    length,
                })));
        }
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(error_code::REPLAY_REJECTED));
        assert!(!connection.has_backlog(), "a close forgets what was owed");
    }

    #[test]
    fn entries_sharing_one_stored_object_are_served_from_one_layer() {
        // Identical files name the same direct object; open has to read that
        // as one served object, not a conflict.
        let (bundle, _) = built_bundle(
            "shared",
            &[
                ("a.bin", patterned(300_000)),
                ("copy.bin", patterned(300_000)),
            ],
        );
        let server = BundleServer::open(&bundle).unwrap();
        let objects: Vec<frames::ObjectId> = server
            .objects
            .values()
            .map(|served| served.object)
            .collect();
        let direct: Vec<&frames::ObjectId> = objects
            .iter()
            .filter(|object| object.length == 300_000)
            .collect();
        assert_eq!(direct.len(), 1, "two identical entries, one stored object");

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object: *direct[0],
                offset: 0,
                length: direct[0].length,
            })));
        server.service(&mut session, &mut connection).unwrap();
        let answers = served_answers(&mut session);
        assert_eq!(answers.len(), 1);
        let bytes = verified_bytes(*direct[0], &answers[0].0, &answers[0].1);
        assert_eq!(bytes, patterned(300_000));
    }

    #[test]
    fn a_spilled_manifest_is_served_page_by_page_in_order() {
        // One entry past the per-page cap spills the manifest to two pages.
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
        let (bundle, _) = built_bundle("spilled", &named);
        let server = BundleServer::open(&bundle).unwrap();
        assert_eq!(server.page_count, 2, "the manifest spilled");

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        connection.budget = 1;
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::ManifestRequest(
                ManifestRequest {
                    request_id: [1; 16],
                    manifest_id: server.manifest_id,
                    first_page: 0,
                    page_count: 2,
                },
            )));
        server.service(&mut session, &mut connection).unwrap();
        session.driver().control.clear();
        assert!(connection.has_backlog(), "both pages are still owed");

        // One page per pass under a one-byte budget, in index order.
        for index in 0..2u64 {
            server.service(&mut session, &mut connection).unwrap();
            let sent = std::mem::take(&mut session.driver().control);
            assert_eq!(sent.len(), 1, "page {index} arrives alone");
            let TypedFrame::ManifestPage(bytes) = decode_control(&sent[0]) else {
                panic!("a page answer that is not a page");
            };
            assert_eq!(
                bytes,
                fs::read(bundle.join(format!("manifest/{index:016}.cbor"))).unwrap()
            );
        }
        assert!(!connection.has_backlog(), "nothing further is owed");
        server.service(&mut session, &mut connection).unwrap();
        assert!(session.driver().control.is_empty(), "and nothing repeats");
    }

    #[test]
    fn a_disconnect_ends_the_pass() {
        let (bundle, _) = built_bundle("gone", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(9)));
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Disconnected);
    }

    #[test]
    fn a_peer_fault_in_the_session_is_recorded_with_its_code() {
        let (bundle, _) = built_bundle("fault", &[("a.txt", patterned(1000))]);
        let server = BundleServer::open(&bundle).unwrap();
        // Garbage before readiness; the session closes.
        let mut session = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            not_required(),
        );
        session.begin().unwrap();
        session
            .driver()
            .events
            .push_back(Event::Control(shared_payload(&[0xff; 8])));
        let mut connection = ServeConnection::new();
        let status = server.service(&mut session, &mut connection).unwrap();
        let carrier_code = session.driver().closed.expect("the session closed");
        assert_eq!(status, ServeStatus::Closed(carrier_code));
        assert_eq!(carrier_code, error_code::MALFORMED_FRAME);
        let status = server.service(&mut session, &mut connection).unwrap();
        assert_eq!(status, ServeStatus::Closed(carrier_code));
    }

    #[test]
    fn an_object_truncated_after_open_is_reported_and_closed() {
        let (bundle, _) = built_bundle("shrunk", &[("big.bin", patterned(300_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let path = bundle
            .join("objects")
            .join(crate::object_name(&object.root));
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..100]).unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
    }

    /// Writes a test may make before a file's modification time reports one.
    const REWRITE_ATTEMPTS: usize = 1024;

    #[test]
    fn an_untouched_file_is_served_without_rehashing_it() {
        // The witness stands in for hashing; an empty layer still serves.
        let (bundle, _) = built_bundle("untouched", &[("big.bin", patterned(150_000))]);
        let mut server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values_mut().next().unwrap();
        assert!(
            stored
                .witness
                .reports_untouched(&Witness::of(&File::open(&stored.path).unwrap()).unwrap()),
            "nothing has touched the file"
        );
        stored.layer = ProverLayer::Blake3(vot_proof_blake3::GroupCvs::new());

        let bytes = server
            .objects
            .values()
            .next()
            .unwrap()
            .read_covered(0, GROUP_SIZE as u64)
            .unwrap();
        assert_eq!(bytes.len(), GROUP_SIZE);

        // And once the metadata cannot vouch for it, the content decides.
        let stored = server.objects.values_mut().next().unwrap();
        stored.witness.modified = None;
        let outcome = server
            .objects
            .values()
            .next()
            .unwrap()
            .read_covered(0, GROUP_SIZE as u64);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
    }

    #[test]
    fn an_object_removed_after_open_is_reported_and_closed() {
        // An object removed between open and the request.
        let (bundle, _) = built_bundle("removed", &[("big.bin", patterned(150_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        fs::remove_file(
            bundle
                .join("objects")
                .join(crate::object_name(&object.root)),
        )
        .unwrap();

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
    }

    #[test]
    fn a_witness_reports_a_file_that_changed() {
        let directory = temporary("witness");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("f.bin");
        fs::write(&path, patterned(1000)).unwrap();
        let file = File::open(&path).unwrap();
        let taken = Witness::of(&file).unwrap();
        assert!(taken.reports_untouched(&Witness::of(&file).unwrap()));

        fs::write(&path, patterned(2000)).unwrap();
        let after = Witness::of(&File::open(&path).unwrap()).unwrap();
        assert_ne!(taken, after);
        assert!(!taken.reports_untouched(&after));

        // No modification time means the witness proves nothing.
        let silent = Witness {
            length: taken.length,
            modified: None,
        };
        assert!(!silent.reports_untouched(&silent));
    }

    #[test]
    fn an_object_rewritten_in_place_after_open_is_reported_and_closed() {
        // Length-preserving rewrite; change in the second group.
        let (bundle, _) = built_bundle("rewritten", &[("big.bin", patterned(150_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let object = server.objects.values().next().unwrap().object;
        let path = bundle
            .join("objects")
            .join(crate::object_name(&object.root));
        let mut rewritten = fs::read(&path).unwrap();
        rewritten[100_000] ^= 1;
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        // Retry writes until the modification time moves; a write may land
        // in the same tick.
        let mut reported = false;
        for _ in 0..REWRITE_ATTEMPTS {
            fs::write(&path, &rewritten).unwrap();
            if fs::metadata(&path).unwrap().modified().unwrap() != before {
                reported = true;
                break;
            }
        }
        assert!(reported, "the modification time never moved");
        assert_eq!(fs::metadata(&path).unwrap().len(), object.length);

        let mut session = ready_session();
        let mut connection = ServeConnection::new();
        session
            .driver()
            .events
            .push_back(control_event(&TypedFrame::RangeRequest(RangeRequest {
                request_id: [1; 16],
                object,
                offset: 0,
                length: object.length,
            })));
        let outcome = server.service(&mut session, &mut connection);
        assert!(matches!(outcome, Err(Error::SourceMutation)));
        assert_eq!(session.driver().closed, Some(error_code::SOURCE_MUTATED));
        assert!(
            session.driver().records.is_empty(),
            "no byte of the rewritten object was served"
        );
    }

    #[test]
    fn a_cover_is_held_to_the_groups_it_starts_at() {
        // Indexed by the cover's own offset, not zero-based.
        let (bundle, _) = built_bundle("indexed", &[("big.bin", patterned(200_000))]);
        let server = BundleServer::open(&bundle).unwrap();
        let stored = server.objects.values().next().unwrap();
        let bytes = fs::read(
            bundle
                .join("objects")
                .join(crate::object_name(&stored.object.root)),
        )
        .unwrap();
        let group = GROUP_SIZE as u64;

        assert!(stored.layer.holds(0, &bytes[..GROUP_SIZE]));
        assert!(
            stored
                .layer
                .holds(group, &bytes[GROUP_SIZE..2 * GROUP_SIZE])
        );
        assert!(stored.layer.holds(2 * group, &bytes[2 * GROUP_SIZE..]));
        assert!(stored.layer.holds(0, &bytes));
        // The second group's bytes, offered as the first, are not it.
        assert!(!stored.layer.holds(0, &bytes[GROUP_SIZE..2 * GROUP_SIZE]));
        // A cover that does not start on a group boundary names no group.
        assert!(!stored.layer.holds(1, &bytes[..GROUP_SIZE]));
    }
}
