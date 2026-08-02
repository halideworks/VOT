//! Drives a [`ReliableReceiver`] from a negotiated session.
//!
//! A session moves frames. A receiver turns proof-bearing ranges into verified
//! state. Nothing joined them, so a live carrier carried opaque records and
//! verified nothing.
//!
//! Records and their bundle arrive as separate frames and in either order, so
//! this holds whichever comes first and hands the receiver a complete bundle.
//! Held, not unbounded: a peer that sends records for a bundle it never
//! completes would otherwise grow this without limit.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vot_codec::frames::{DataRecord, ProofBundle, TypedFrame};
use vot_session::Session;
use vot_transport_api::{Event, SubjectId, TransportAdapter};

use crate::{Error, ReliableReceiver};

/// The most one admitted bundle can hold: its proof, bounded per frame by the
/// negotiated control ceiling, plus every record it can declare.
///
/// A byte bound below this refuses a conforming transfer partway through, so it
/// is the floor for the admitted budget rather than a target.
pub const MAX_PENDING_BUNDLE_BYTES: usize = vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD
    + vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE * vot_transport_api::MAX_DATA_RECORD_BYTES;

/// The most one bundle can hold before its proof has arrived.
pub const MAX_ORPHAN_BUNDLE_BYTES: usize =
    vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE * vot_transport_api::MAX_DATA_RECORD_BYTES;

/// Admitted bundles held while the rest of their records arrive.
pub const DEFAULT_PENDING_BUNDLES: usize = 4;

/// Bytes held for admitted bundles that are not complete.
pub const DEFAULT_PENDING_BUNDLE_BYTES: usize = DEFAULT_PENDING_BUNDLES * MAX_PENDING_BUNDLE_BYTES;

/// Bundles held for records that arrived before their proof.
pub const DEFAULT_ORPHAN_BUNDLES: usize = 2;

/// Bytes held for records that arrived before their proof.
pub const DEFAULT_ORPHAN_BYTES: usize = DEFAULT_ORPHAN_BUNDLES * MAX_ORPHAN_BUNDLE_BYTES;

/// Delivered bundle identities remembered so an exact replay stays idempotent.
pub const REMEMBERED_BUNDLES: usize = 64;

/// What a delivered bundle covered.
///
/// `spec/wire.md` section 5 deduplicates on request and range identity, so this
/// is what a replay is compared against. The proof bytes are not kept: the
/// subject is already verified and no proof arriving afterwards can change
/// that, so a replay is either the same range or a conflicting one.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Delivered {
    subject: SubjectId,
    covered_offset: u64,
    covered_length: u64,
}

impl Delivered {
    fn of(bundle: &ProofBundle) -> Self {
        Self {
            subject: SubjectId {
                suite: bundle.object.suite,
                root: bundle.object.root,
                length: bundle.object.length,
            },
            covered_offset: bundle.covered_offset,
            covered_length: bundle.covered_length,
        }
    }
}

/// A bundle and the records that belong to it, in whichever order they came.
#[derive(Default)]
struct Pending {
    bundle: Option<ProofBundle>,
    records: Vec<DataRecord>,
}

impl Pending {
    /// The bytes this bundle is holding, proof and records alike.
    ///
    /// Summed on demand rather than kept alongside the frames, so the total and
    /// what it describes cannot disagree.
    fn bytes(&self) -> usize {
        let proof = self.bundle.as_ref().map_or(0, |bundle| bundle.proof.len());
        proof
            + self
                .records
                .iter()
                .map(|held| held.encoded.len())
                .sum::<usize>()
    }

    /// Whether every record the bundle declares has arrived.
    fn complete(&self) -> bool {
        self.bundle
            .as_ref()
            .is_some_and(|bundle| self.records.len() as u64 == bundle.data_record_count)
    }
}

/// Whether a control frame is the proof that describes a range.
fn is_proof_bundle(frame: &[u8]) -> bool {
    vot_codec::decode_varint(frame)
        .is_ok_and(|(frame_type, _)| frame_type == vot_codec::frame_type::PROOF_BUNDLE)
}

/// A receiver fed by a session over a real carrier.
pub struct SessionReceiver<A> {
    session: Session<A>,
    receiver: ReliableReceiver,
    pending: BTreeMap<[u8; 16], Pending>,
    pending_bundle_limit: usize,
    pending_byte_limit: usize,
    orphan_bundle_limit: usize,
    orphan_byte_limit: usize,
    /// Subjects the caller has authorised. Nothing here decides that: the
    /// authentication and authorization frames are unimplemented, so a subject
    /// is admitted by an explicit call rather than by a peer asking.
    admitted: BTreeSet<SubjectId>,
    delivered: VecDeque<([u8; 16], Delivered)>,
    credit_applied: bool,
}

impl<A: TransportAdapter> SessionReceiver<A> {
    /// Joins a session to a receiver.
    #[must_use]
    pub fn new(session: Session<A>, receiver: ReliableReceiver) -> Self {
        Self {
            session,
            receiver,
            pending: BTreeMap::new(),
            pending_bundle_limit: DEFAULT_PENDING_BUNDLES,
            pending_byte_limit: DEFAULT_PENDING_BUNDLE_BYTES,
            orphan_bundle_limit: DEFAULT_ORPHAN_BUNDLES,
            orphan_byte_limit: DEFAULT_ORPHAN_BYTES,
            admitted: BTreeSet::new(),
            delivered: VecDeque::new(),
            credit_applied: false,
        }
    }

    /// Sets how much state this will hold for admitted bundles.
    ///
    /// # Errors
    /// Rejects a bound that cannot hold one whole bundle, which would refuse a
    /// conforming transfer partway through rather than bound it.
    pub fn set_pending_limits(&mut self, bundles: usize, bytes: usize) -> Result<(), Error> {
        if bundles == 0 || bytes < MAX_PENDING_BUNDLE_BYTES {
            return Err(Error::Staging(
                vot_transport_api::Error::InvalidConfiguration,
            ));
        }
        self.pending_bundle_limit = bundles;
        self.pending_byte_limit = bytes;
        Ok(())
    }

    /// Sets how much state this will hold for records that arrived before
    /// their proof.
    ///
    /// # Errors
    /// Rejects a bound that cannot hold one whole bundle's records.
    pub fn set_orphan_limits(&mut self, bundles: usize, bytes: usize) -> Result<(), Error> {
        if bundles == 0 || bytes < MAX_ORPHAN_BUNDLE_BYTES {
            return Err(Error::Staging(
                vot_transport_api::Error::InvalidConfiguration,
            ));
        }
        self.orphan_bundle_limit = bundles;
        self.orphan_byte_limit = bytes;
        Ok(())
    }

    /// Authorises a subject and opens range state for it.
    ///
    /// # Errors
    /// Propagates a receiver that cannot begin the subject.
    pub fn admit(&mut self, subject: SubjectId) -> Result<(), Error> {
        self.receiver.begin_ranges(subject)?;
        self.admitted.insert(subject);
        Ok(())
    }

    /// Whether every byte of `subject` has been verified.
    #[must_use]
    pub fn is_verified(&self, subject: SubjectId) -> bool {
        self.receiver.is_verified(subject)
    }

    /// Whether the receiver's credit reached the backend.
    ///
    /// False on a backend with no dynamic receive credit, which is every one
    /// today, so a caller can tell an applied credit from a dropped one.
    #[must_use]
    pub const fn credit_applied(&self) -> bool {
        self.credit_applied
    }

    /// Borrows the session, for negotiation state and diagnostics.
    pub const fn session(&self) -> &Session<A> {
        &self.session
    }

    /// Borrows the session mutably, for the code that drives the carrier.
    pub const fn session_mut(&mut self) -> &mut Session<A> {
        &mut self.session
    }

    /// Bundles waiting for the rest of their records.
    #[must_use]
    pub fn pending_bundles(&self) -> usize {
        self.pending.len()
    }

    /// Bundles holding records whose proof has not arrived.
    #[must_use]
    pub fn orphan_bundles(&self) -> usize {
        self.held(true).0
    }

    /// Bytes held for bundles that are not complete.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.values().map(Pending::bytes).sum()
    }

    /// Returns the next event the application should see.
    ///
    /// A proof-bearing frame is consumed here and never surfaces: it becomes
    /// verified state or an error. Everything else passes through.
    ///
    /// # Errors
    /// Reports a session failure, a proof that did not verify, an unadmitted
    /// subject, or more incomplete bundle state than this will hold.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        while let Some(event) = self.session.poll().map_err(Error::Session)? {
            match event {
                Event::Connected(connection) => {
                    self.receiver.connected(connection);
                    return Ok(Some(Event::Connected(connection)));
                }
                Event::Disconnected(connection) => {
                    self.receiver.disconnected(connection);
                    return Ok(Some(Event::Disconnected(connection)));
                }
                Event::Acknowledged(ack) => {
                    self.receiver.acknowledged(ack);
                    return Ok(Some(Event::Acknowledged(ack)));
                }
                // A lane carries payload and nothing else, which the session
                // enforces, so every frame reaching here is a record.
                Event::Reliable { bytes, .. } => self.accept_record(&bytes)?,
                // The proof that describes a range is bounded by the control
                // ceiling, not the record limit, so it arrives here rather
                // than on the lane its records travel.
                Event::Control(bytes) if is_proof_bundle(&bytes) => self.accept_bundle(&bytes)?,
                other => return Ok(Some(other)),
            }
        }
        Ok(None)
    }

    /// Feeds one record from a lane.
    fn accept_record(&mut self, frame: &[u8]) -> Result<(), Error> {
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: vot_transport_api::MAX_DATA_RECORD_BYTES,
            max_frames: 1,
        };
        let (typed, _) =
            vot_codec::frames::decode(frame, limits).map_err(|_| Error::ProofInvalid)?;
        match typed {
            TypedFrame::DataRecord(record) => self.hold_record(record),
            // Unreachable while the session holds a lane to one type, and a
            // silent success here would hide it if that changed.
            _ => Err(Error::ProofInvalid),
        }
    }

    /// Feeds one proof from the control stream.
    fn accept_bundle(&mut self, frame: &[u8]) -> Result<(), Error> {
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: usize::try_from(
                self.session.local_settings().max_control_frame_payload,
            )
            .map_err(|_| Error::LengthExceeded)?,
            max_frames: 1,
        };
        let (typed, _) =
            vot_codec::frames::decode(frame, limits).map_err(|_| Error::ProofInvalid)?;
        match typed {
            TypedFrame::ProofBundle(bundle) => self.hold_bundle(bundle),
            _ => Err(Error::ProofInvalid),
        }
    }

    fn hold_bundle(&mut self, bundle: ProofBundle) -> Result<(), Error> {
        let subject = SubjectId {
            suite: bundle.object.suite,
            root: bundle.object.root,
            length: bundle.object.length,
        };
        // Checked before anything is stored, so an unauthorised peer cannot
        // spend this endpoint's memory by naming an object it may not have.
        if !self.admitted.contains(&subject) {
            return Err(Error::UnknownObject);
        }
        let id = bundle.bundle_id;
        if let Some((_, prior)) = self.delivered.iter().find(|(seen, _)| *seen == id) {
            // Already delivered. An exact replay is idempotent; a different
            // range under the same identity is a conflicting duplicate.
            return if *prior == Delivered::of(&bundle) {
                Ok(())
            } else {
                Err(Error::ProofInvalid)
            };
        }
        if let Some(held) = self
            .pending
            .get(&id)
            .and_then(|pending| pending.bundle.as_ref())
        {
            // spec/wire.md section 5: request and range identity deduplicate,
            // and only a conflicting duplicate is rejected.
            return if *held == bundle {
                Ok(())
            } else {
                Err(Error::ProofInvalid)
            };
        }
        if self
            .pending
            .get(&id)
            .is_some_and(|pending| pending.records.len() as u64 > bundle.data_record_count)
        {
            // More records than the proof covers. Without this the entry can
            // never reach its declared count and never leaves.
            return Err(Error::ProofInvalid);
        }
        // The records already held move to the admitted budget along with the
        // proof, so the reservation covers the whole entry rather than the
        // frame that happens to complete it.
        let carried = self.pending.get(&id).map_or(0, Pending::bytes);
        let bytes = bundle
            .proof
            .len()
            .checked_add(carried)
            .ok_or(Error::LengthExceeded)?;
        self.reserve(&id, bytes, false)?;
        self.pending.entry(id).or_default().bundle = Some(bundle);
        self.deliver(id)
    }

    fn hold_record(&mut self, record: DataRecord) -> Result<(), Error> {
        let id = record.bundle_id;
        if self.delivered.iter().any(|(seen, _)| *seen == id) {
            // Its bundle is verified and gone. Holding the record would leave
            // an entry that can never complete, which is also what a replayed
            // record would cost this endpoint.
            return Ok(());
        }
        let orphan = self
            .pending
            .get(&id)
            .is_none_or(|pending| pending.bundle.is_none());
        if let Some(pending) = self.pending.get(&id) {
            if let Some(held) = pending
                .records
                .iter()
                .find(|held| held.record_index == record.record_index)
            {
                return if *held == record {
                    Ok(())
                } else {
                    Err(Error::ProofInvalid)
                };
            }
            let declared = pending.bundle.as_ref().map_or(
                vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE,
                |bundle| {
                    usize::try_from(bundle.data_record_count)
                        .unwrap_or(vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE)
                },
            );
            if pending.records.len() >= declared {
                return Err(Error::ProofInvalid);
            }
        }
        self.reserve(&id, record.encoded.len(), orphan)?;
        self.pending.entry(id).or_default().records.push(record);
        self.deliver(id)
    }

    /// Counts the entries in one budget and the bytes they hold.
    fn held(&self, orphan: bool) -> (usize, usize) {
        self.pending
            .values()
            .filter(|pending| pending.bundle.is_none() == orphan)
            .fold((0, 0), |(count, bytes), pending| {
                (count + 1, bytes + pending.bytes())
            })
    }

    /// Reserves room for a frame belonging to `id`.
    ///
    /// Records that arrive before their proof name no subject, so nothing can
    /// authorise them. They hold their own budget, and a peer filling it with
    /// records for bundles it never sends cannot crowd out an admitted one.
    fn reserve(&mut self, id: &[u8; 16], bytes: usize, orphan: bool) -> Result<(), Error> {
        let (count_limit, byte_limit) = if orphan {
            (self.orphan_bundle_limit, self.orphan_byte_limit)
        } else {
            (self.pending_bundle_limit, self.pending_byte_limit)
        };
        let (count, held) = self.held(orphan);
        let known = self
            .pending
            .get(id)
            .is_some_and(|pending| pending.bundle.is_none() == orphan);
        if !known && count >= count_limit {
            return Err(Error::PendingBundlesExhausted);
        }
        let next = held.checked_add(bytes).ok_or(Error::LengthExceeded)?;
        if next > byte_limit {
            return Err(Error::PendingBundlesExhausted);
        }
        Ok(())
    }

    /// Hands a complete bundle to the receiver.
    fn deliver(&mut self, id: [u8; 16]) -> Result<(), Error> {
        let Some(pending) = self.pending.get(&id) else {
            return Ok(());
        };
        if !pending.complete() {
            return Ok(());
        }
        let Some(pending) = self.pending.remove(&id) else {
            return Ok(());
        };
        let Some(bundle) = pending.bundle else {
            return Ok(());
        };
        if self.delivered.len() == REMEMBERED_BUNDLES {
            self.delivered.pop_front();
        }
        self.delivered.push_back((id, Delivered::of(&bundle)));
        let subject = SubjectId {
            suite: bundle.object.suite,
            root: bundle.object.root,
            length: bundle.object.length,
        };
        self.receiver
            .receive_typed_bundle(subject, &bundle, &pending.records)?;
        // The receiver promotes a subject to verified once every byte is
        // covered, and reports a length mismatch until then, which is what a
        // partly covered object looks like rather than a failure.
        match self.receiver.finish_ranges(subject) {
            Ok(()) | Err(Error::LengthMismatch) => {}
            Err(error) => return Err(error),
        }
        // Credit follows verified state, so it is pushed once the receiver has
        // released what the bundle was holding.
        let credit = self.receiver.advertised_credit();
        self.credit_applied = self.session.driver().set_receive_credit(credit).is_ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use vot_codec::frames::{ObjectId, encode};
    use vot_transport_api::{Payload, StreamId};
    use vot_verifier::Suite;

    /// A backend that hands back whatever the test queues.
    #[derive(Default)]
    struct Loopback {
        sent: Vec<Vec<u8>>,
        events: VecDeque<Event>,
        credit: Vec<u64>,
        refuse_credit: bool,
    }

    impl TransportAdapter for Loopback {
        fn send_control(&mut self, frame: &[u8]) -> Result<(), vot_transport_api::Error> {
            self.sent.push(frame.to_vec());
            Ok(())
        }

        fn send_reliable(
            &mut self,
            _stream: StreamId,
            _record: &[u8],
        ) -> Result<(), vot_transport_api::Error> {
            Ok(())
        }

        fn poll(&mut self) -> Option<Event> {
            self.events.pop_front()
        }

        fn set_receive_credit(&mut self, bytes: u64) -> Result<(), vot_transport_api::Error> {
            if self.refuse_credit {
                return Err(vot_transport_api::Error::Unsupported);
            }
            self.credit.push(bytes);
            Ok(())
        }
    }

    /// One frame on a lane, which is how a record reaches a session.
    /// Delivers a frame the way the session would: payload on a lane, the
    /// proof that describes it on the control stream.
    fn carried(bytes: &[u8]) -> Event {
        if is_proof_bundle(bytes) {
            Event::Control(Payload::from(bytes))
        } else {
            Event::Reliable {
                stream: StreamId(1),
                sequence: 1,
                bytes: Payload::from(bytes),
            }
        }
    }

    fn wire(frame: &TypedFrame) -> Vec<u8> {
        let mut out = Vec::new();
        encode(frame, &mut out).unwrap();
        out
    }

    /// An object, its subject, and a bundle covering all of it in two records.
    fn object() -> (SubjectId, ProofBundle, Vec<DataRecord>) {
        object_of(0x5a, [2; 16])
    }

    fn object_of(fill: u8, id: [u8; 16]) -> (SubjectId, ProofBundle, Vec<DataRecord>) {
        let unit = usize::try_from(crate::RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![fill; unit * 2];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = ProofBundle {
            request_id: [1; 16],
            bundle_id: id,
            object: ObjectId {
                suite: subject.suite,
                root: subject.root,
                length: subject.length,
            },
            requested_offset: 0,
            requested_length: subject.length,
            covered_offset: proof.covered_offset,
            covered_length: proof.data.len() as u64,
            data_record_count: 2,
            total_plaintext_length: proof.data.len() as u64,
            proof: proof.proof,
        };
        let records = vec![
            DataRecord {
                bundle_id: id,
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: crate::RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[..unit].to_vec(),
            },
            DataRecord {
                bundle_id: id,
                record_index: 1,
                plaintext_offset: crate::RANGE_UNIT_BYTES,
                plaintext_length: crate::RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[unit..].to_vec(),
            },
        ];
        (subject, bundle, records)
    }

    /// A ready session over a loopback, with its receiver.
    fn ready() -> SessionReceiver<Loopback> {
        ready_with(Loopback::default())
    }

    /// The same over a given backend.
    fn ready_with(backend: Loopback) -> SessionReceiver<Loopback> {
        let mut session = Session::server(
            backend,
            vot_codec::Settings::default(),
            std::collections::BTreeSet::new(),
            vot_session::Authentication::Unimplemented,
        );
        session.begin().unwrap();
        // Driven to readiness through the client's frames, which is the only
        // way a session reaches it.
        let mut client = Session::client(
            Loopback::default(),
            vot_codec::Settings::default(),
            std::collections::BTreeSet::new(),
            vot_session::Authentication::Unimplemented,
        );
        client.begin().unwrap();
        for frame in std::mem::take(&mut client.driver().sent) {
            session
                .driver()
                .events
                .push_back(Event::Control(Payload::from(frame.as_slice())));
        }
        session.poll().unwrap();
        assert!(session.is_ready());
        SessionReceiver::new(
            session,
            ReliableReceiver::new(1 << 20, 1 << 16, 1 << 16).unwrap(),
        )
    }

    #[test]
    fn a_bundle_and_its_records_become_verified_state() {
        // Nothing joined a session to a receiver, so a live carrier moved
        // records and verified nothing.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        assert!(!driver.is_verified(subject));

        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }

        // Proof-bearing frames are consumed rather than handed to the caller.
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 0, "the bundle was delivered");
        assert!(driver.is_verified(subject));
        assert!(driver.credit_applied());
    }

    #[test]
    fn records_arriving_before_their_bundle_are_held() {
        // The two are separate frames with no ordering between them.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 1, "held for the bundle");
        let held: usize = records.iter().map(|record| record.encoded.len()).sum();
        assert_eq!(driver.pending_bytes(), held);
        assert!(!driver.is_verified(subject));

        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));
        assert_eq!(driver.pending_bundles(), 0);
        // A delivered bundle releases exactly what it held. A total that drifts
        // high would eventually refuse a peer that is within its bound.
        assert_eq!(driver.pending_bytes(), 0);
    }

    #[test]
    fn a_subject_nobody_admitted_is_refused_before_anything_is_held() {
        // Authorization is the caller's, and an unadmitted peer must not be
        // able to spend this endpoint's memory by naming an object.
        let (_subject, bundle, _records) = object();
        let mut driver = ready();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        assert_eq!(driver.poll().unwrap_err(), Error::UnknownObject);
        assert_eq!(driver.pending_bundles(), 0);
    }

    #[test]
    fn held_bundle_state_is_bounded() {
        let (subject, _bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        driver
            .set_orphan_limits(1, MAX_ORPHAN_BUNDLE_BYTES)
            .unwrap();

        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(records[0].clone()))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 1);

        // A record for a second bundle is one bundle too many.
        let mut other = records[0].clone();
        other.bundle_id = [9; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(other))));
        assert_eq!(driver.poll().unwrap_err(), Error::PendingBundlesExhausted);

        // The bound itself is allowed, and one below it would refuse a
        // conforming transfer partway through rather than bound it.
        assert!(
            driver
                .set_pending_limits(1, MAX_PENDING_BUNDLE_BYTES)
                .is_ok()
        );
        assert!(
            driver
                .set_pending_limits(0, MAX_PENDING_BUNDLE_BYTES)
                .is_err()
        );
        assert!(
            driver
                .set_pending_limits(1, MAX_PENDING_BUNDLE_BYTES - 1)
                .is_err()
        );
        assert!(
            driver
                .set_orphan_limits(0, MAX_ORPHAN_BUNDLE_BYTES)
                .is_err()
        );
        assert!(
            driver
                .set_orphan_limits(1, MAX_ORPHAN_BUNDLE_BYTES - 1)
                .is_err()
        );
    }

    #[test]
    fn a_held_bundle_is_charged_for_its_proof() {
        // The proof is bounded per frame by the negotiated control ceiling, so
        // without this the aggregate is that ceiling times the bundle count and
        // the byte bound reports none of it.
        let (subject, bundle, records) = object();
        let proof = bundle.proof.len();
        assert!(proof > 0);
        let mut driver = ready();
        driver.admit(subject).unwrap();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bytes(), proof);

        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(records[0].clone()))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bytes(), proof + records[0].encoded.len());
    }

    #[test]
    fn a_delivered_bundle_releases_only_its_own_bytes() {
        // Release subtracts from a total shared with every other held bundle,
        // so an over-subtraction here is invisible unless something else is
        // still holding.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();

        let mut stray = records[0].clone();
        stray.bundle_id = [9; 16];
        let stray_bytes = stray.encoded.len();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(stray))));
        assert_eq!(driver.poll().unwrap(), None);

        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));
        assert_eq!(driver.pending_bundles(), 1, "the stray is still held");
        assert_eq!(driver.pending_bytes(), stray_bytes);
    }

    #[test]
    fn the_held_byte_bound_is_exact() {
        // The byte bound is what limits memory. A count alone would let a peer
        // hold a bundle's worth of records under one identifier.
        let records_per_bundle = vot_codec::frames::MAX_DATA_RECORDS_PER_BUNDLE;
        assert_eq!(
            MAX_ORPHAN_BUNDLE_BYTES,
            records_per_bundle * vot_transport_api::MAX_DATA_RECORD_BYTES
        );
        assert_eq!(
            MAX_PENDING_BUNDLE_BYTES,
            vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD + MAX_ORPHAN_BUNDLE_BYTES
        );
        assert_eq!(
            DEFAULT_PENDING_BUNDLE_BYTES,
            DEFAULT_PENDING_BUNDLES * MAX_PENDING_BUNDLE_BYTES
        );
        assert_eq!(
            DEFAULT_ORPHAN_BYTES,
            DEFAULT_ORPHAN_BUNDLES * MAX_ORPHAN_BUNDLE_BYTES
        );

        let (subject, _bundle, records) = object();
        let unit = usize::try_from(crate::RANGE_UNIT_BYTES).unwrap();
        let limit = MAX_ORPHAN_BUNDLE_BYTES;
        let fits = limit / unit;

        let mut driver = ready();
        driver.admit(subject).unwrap();
        // A generous bundle count, so only the byte bound can refuse anything.
        driver.set_orphan_limits(fits + 4, limit).unwrap();
        for index in 0..fits {
            let mut record = records[0].clone();
            record.bundle_id = [u8::try_from(index).unwrap(); 16];
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bytes(), limit, "the bound itself is held");

        let mut extra = records[0].clone();
        extra.bundle_id = [0xff; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(extra))));
        assert_eq!(driver.poll().unwrap_err(), Error::PendingBundlesExhausted);
        assert_eq!(driver.pending_bytes(), limit, "a refusal holds nothing");
    }

    #[test]
    fn records_without_a_proof_cannot_crowd_out_an_admitted_bundle() {
        // A DATA_RECORD names a bundle and no subject, so nothing can
        // authorise one that arrives first. They hold their own budget.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        driver
            .set_orphan_limits(1, MAX_ORPHAN_BUNDLE_BYTES)
            .unwrap();
        assert_eq!(driver.orphan_bundles(), 0, "nothing is held yet");

        let mut stray = records[0].clone();
        stray.bundle_id = [9; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(stray))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.orphan_bundles(), 1, "the orphan budget is full");
        assert_eq!(driver.pending_bundles(), 1);

        // A second record for the same bundle is not a second bundle, so a
        // full count does not refuse it.
        let mut second = records[1].clone();
        second.bundle_id = [9; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(second))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.orphan_bundles(), 1);

        // The admitted budget is untouched, so the real transfer still runs.
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));
        assert_eq!(driver.orphan_bundles(), 1, "only the stray is left");
    }

    #[test]
    fn an_exact_duplicate_is_ignored_and_a_conflicting_one_is_refused() {
        // spec/wire.md section 5: exact duplicates deduplicate, and only a
        // conflicting duplicate is an error. A retry is not an attack.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        for frame in [
            TypedFrame::ProofBundle(bundle.clone()),
            TypedFrame::ProofBundle(bundle.clone()),
            TypedFrame::DataRecord(records[0].clone()),
            TypedFrame::DataRecord(records[0].clone()),
        ] {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&frame)));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 1);
        assert_eq!(
            driver.pending_bytes(),
            bundle.proof.len() + records[0].encoded.len(),
            "a duplicate is held once"
        );

        let mut conflicting = records[0].clone();
        conflicting.encoded[0] ^= 0xff;
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(conflicting))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn more_records_than_the_proof_covers_are_refused() {
        // complete() tests equality, so an entry holding more records than its
        // bundle declares would never complete and never leave.
        let (subject, bundle, records) = object();
        let declared = usize::try_from(bundle.data_record_count).unwrap();
        assert_eq!(declared, records.len());
        let mut driver = ready();
        driver.admit(subject).unwrap();

        // One record past the declared count, before the proof arrives, so the
        // count is not known when it is held.
        for index in 0..=declared {
            let mut record = records[0].clone();
            record.record_index = index as u64;
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn credit_that_the_backend_refuses_is_reported_as_not_applied() {
        // No backend carries dynamic receive credit today, so a caller has to
        // be able to tell an applied credit from a dropped one.
        let (subject, bundle, records) = object();
        let mut driver = ready_with(Loopback {
            refuse_credit: true,
            ..Loopback::default()
        });
        driver.admit(subject).unwrap();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject), "the range still verified");
        assert!(!driver.credit_applied(), "and the credit did not apply");
        assert!(driver.session().adapter().credit.is_empty());
    }

    /// Pushes a bundle and its records the way the session would carry them.
    fn push_object(
        driver: &mut SessionReceiver<Loopback>,
        bundle: &ProofBundle,
        records: &[DataRecord],
    ) {
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(bundle.clone()))));
        for record in records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
    }

    #[test]
    fn a_control_frame_that_is_not_a_proof_passes_through() {
        // Only the proof is consumed here. Swallowing the rest of the control
        // stream would silently drop everything the application waits on.
        let mut driver = ready();
        let mut frame = Vec::new();
        vot_codec::encode_frame(vot_codec::frame_type::PING, &[], &mut frame).unwrap();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(Event::Control(Payload::from(frame.as_slice())));
        assert!(matches!(driver.poll().unwrap(), Some(Event::Control(_))));
    }

    #[test]
    fn more_than_one_delivered_bundle_is_remembered() {
        // The memory is a queue with a bound. Evicting on every delivery would
        // leave only the last one, and the replay of anything earlier would
        // fail.
        let (first_subject, first_bundle, first_records) = object();
        let (second_subject, second_bundle, second_records) = object_of(0x17, [3; 16]);
        let mut driver = ready();
        driver.admit(first_subject).unwrap();
        driver.admit(second_subject).unwrap();
        push_object(&mut driver, &first_bundle, &first_records);
        push_object(&mut driver, &second_bundle, &second_records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(first_subject) && driver.is_verified(second_subject));

        // The older of the two is replayed, so a memory of one is not enough.
        push_object(&mut driver, &first_bundle, &first_records);
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 0, "the replay held nothing");
    }

    #[test]
    fn a_replay_of_a_delivered_bundle_is_idempotent() {
        // The pending entry is gone and the subject's range state is closed, so
        // without a memory of what was delivered a protocol-required retry is
        // reassembled and fails with UnknownObject.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        let frames: Vec<Vec<u8>> = std::iter::once(wire(&TypedFrame::ProofBundle(bundle.clone())))
            .chain(
                records
                    .iter()
                    .map(|record| wire(&TypedFrame::DataRecord(record.clone()))),
            )
            .collect();
        for _ in 0..2 {
            for frame in &frames {
                driver
                    .session_mut()
                    .driver()
                    .events
                    .push_back(carried(frame));
            }
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));
        assert_eq!(driver.pending_bundles(), 0, "the replay held nothing");

        // A different object under the same identity is still a conflict.
        let mut conflicting = bundle;
        conflicting.object.root = [9; 32];
        driver
            .admit(SubjectId {
                suite: conflicting.object.suite,
                root: conflicting.object.root,
                length: conflicting.object.length,
            })
            .unwrap();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(conflicting))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn a_bundle_that_conflicts_with_a_held_one_is_refused() {
        let (subject, bundle, _records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        let mut conflicting = bundle.clone();
        conflicting.proof[0] ^= 0xff;
        for frame in [
            TypedFrame::ProofBundle(bundle),
            TypedFrame::ProofBundle(conflicting),
        ] {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&frame)));
        }
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }
}
