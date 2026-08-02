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

use std::collections::{BTreeMap, BTreeSet};

use vot_codec::frames::{DataRecord, ProofBundle, TypedFrame};
use vot_session::Session;
use vot_transport_api::{Event, SubjectId, TransportAdapter};

use crate::{Error, ReliableReceiver};

/// Bundles held while their records arrive.
pub const DEFAULT_PENDING_BUNDLES: usize = 8;

/// Record bytes held for bundles that are not complete.
pub const DEFAULT_PENDING_BUNDLE_BYTES: usize =
    DEFAULT_PENDING_BUNDLES * vot_transport_api::MAX_DATA_RECORD_BYTES;

/// A bundle and the records that belong to it, in whichever order they came.
#[derive(Default)]
struct Pending {
    bundle: Option<ProofBundle>,
    records: Vec<DataRecord>,
}

impl Pending {
    /// The record bytes this bundle is holding.
    ///
    /// Summed on demand rather than kept alongside `records`, so the total and
    /// the records it describes cannot disagree.
    fn bytes(&self) -> usize {
        self.records.iter().map(|held| held.encoded.len()).sum()
    }

    /// Whether every record the bundle declares has arrived.
    fn complete(&self) -> bool {
        self.bundle
            .as_ref()
            .is_some_and(|bundle| self.records.len() as u64 == bundle.data_record_count)
    }
}

/// A receiver fed by a session over a real carrier.
pub struct SessionReceiver<A> {
    session: Session<A>,
    receiver: ReliableReceiver,
    pending: BTreeMap<[u8; 16], Pending>,
    pending_bytes: usize,
    pending_bundle_limit: usize,
    pending_byte_limit: usize,
    /// Subjects the caller has authorised. Nothing here decides that: the
    /// authentication and authorization frames are unimplemented, so a subject
    /// is admitted by an explicit call rather than by a peer asking.
    admitted: BTreeSet<SubjectId>,
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
            pending_bytes: 0,
            pending_bundle_limit: DEFAULT_PENDING_BUNDLES,
            pending_byte_limit: DEFAULT_PENDING_BUNDLE_BYTES,
            admitted: BTreeSet::new(),
            credit_applied: false,
        }
    }

    /// Sets how much incomplete bundle state this will hold.
    ///
    /// # Errors
    /// Rejects a bound that cannot hold one maximum record, which would refuse
    /// a conforming peer rather than bound it.
    pub fn set_pending_limits(&mut self, bundles: usize, bytes: usize) -> Result<(), Error> {
        if bundles == 0 || bytes < vot_transport_api::MAX_DATA_RECORD_BYTES {
            return Err(Error::Staging(
                vot_transport_api::Error::InvalidConfiguration,
            ));
        }
        self.pending_bundle_limit = bundles;
        self.pending_byte_limit = bytes;
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

    /// Record bytes held for bundles that are not complete.
    #[must_use]
    pub const fn pending_bytes(&self) -> usize {
        self.pending_bytes
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
                // A lane carries a proof-bearing range and nothing else, which
                // the session enforces, so every record reaching here is one.
                Event::Reliable { bytes, .. } => self.accept_record(&bytes)?,
                other => return Ok(Some(other)),
            }
        }
        Ok(None)
    }

    /// Feeds one frame from a lane.
    fn accept_record(&mut self, frame: &[u8]) -> Result<(), Error> {
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: vot_transport_api::MAX_DATA_RECORD_BYTES,
            max_frames: 1,
        };
        let (typed, _) =
            vot_codec::frames::decode(frame, limits).map_err(|_| Error::ProofInvalid)?;
        match typed {
            TypedFrame::ProofBundle(bundle) => self.hold_bundle(bundle),
            TypedFrame::DataRecord(record) => self.hold_record(record),
            // Unreachable while the session holds a lane to these two types,
            // and a silent success here would hide it if that changed.
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
        self.reserve(&id, 0)?;
        let pending = self.pending.entry(id).or_default();
        if pending.bundle.is_some() {
            // spec/wire.md section 5: request and range identity deduplicate,
            // and a conflicting duplicate is rejected.
            return Err(Error::ProofInvalid);
        }
        pending.bundle = Some(bundle);
        self.deliver(id)
    }

    fn hold_record(&mut self, record: DataRecord) -> Result<(), Error> {
        let id = record.bundle_id;
        let bytes = record.encoded.len();
        self.reserve(&id, bytes)?;
        let pending = self.pending.entry(id).or_default();
        if pending
            .records
            .iter()
            .any(|held| held.record_index == record.record_index)
        {
            return Err(Error::ProofInvalid);
        }
        pending.records.push(record);
        self.pending_bytes += bytes;
        self.deliver(id)
    }

    /// Reserves room for a frame belonging to `id`.
    fn reserve(&mut self, id: &[u8; 16], bytes: usize) -> Result<(), Error> {
        if !self.pending.contains_key(id) && self.pending.len() >= self.pending_bundle_limit {
            return Err(Error::PendingBundlesExhausted);
        }
        let next = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or(Error::LengthExceeded)?;
        if next > self.pending_byte_limit {
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
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.bytes());
        let Some(bundle) = pending.bundle else {
            return Ok(());
        };
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
    fn lane(bytes: &[u8]) -> Event {
        Event::Reliable {
            stream: StreamId(1),
            sequence: 1,
            bytes: Payload::from(bytes),
        }
    }

    fn wire(frame: &TypedFrame) -> Vec<u8> {
        let mut out = Vec::new();
        encode(frame, &mut out).unwrap();
        out
    }

    /// An object, its subject, and a bundle covering all of it in two records.
    fn object() -> (SubjectId, ProofBundle, Vec<DataRecord>) {
        let unit = usize::try_from(crate::RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x5a; unit * 2];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
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
                bundle_id: [2; 16],
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: crate::RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[..unit].to_vec(),
            },
            DataRecord {
                bundle_id: [2; 16],
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
            .push_back(lane(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(lane(&wire(&TypedFrame::DataRecord(record.clone()))));
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
                .push_back(lane(&wire(&TypedFrame::DataRecord(record.clone()))));
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
            .push_back(lane(&wire(&TypedFrame::ProofBundle(bundle))));
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
            .push_back(lane(&wire(&TypedFrame::ProofBundle(bundle))));
        assert_eq!(driver.poll().unwrap_err(), Error::UnknownObject);
        assert_eq!(driver.pending_bundles(), 0);
    }

    #[test]
    fn held_bundle_state_is_bounded() {
        let (subject, _bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        driver.set_pending_limits(1, 1 << 20).unwrap();

        driver
            .session_mut()
            .driver()
            .events
            .push_back(lane(&wire(&TypedFrame::DataRecord(records[0].clone()))));
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 1);

        // A record for a second bundle is one bundle too many.
        let mut other = records[0].clone();
        other.bundle_id = [9; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(lane(&wire(&TypedFrame::DataRecord(other))));
        assert_eq!(driver.poll().unwrap_err(), Error::PendingBundlesExhausted);

        // A bound that cannot hold one maximum record would refuse a peer that
        // did nothing wrong.
        assert!(driver.set_pending_limits(0, 1 << 20).is_err());
        assert!(driver.set_pending_limits(1, 1).is_err());
    }

    #[test]
    fn the_held_byte_bound_is_exact() {
        // The byte bound is what limits memory. A count alone would let a peer
        // hold a bundle's worth of records under one identifier.
        assert_eq!(
            DEFAULT_PENDING_BUNDLE_BYTES,
            DEFAULT_PENDING_BUNDLES * vot_transport_api::MAX_DATA_RECORD_BYTES
        );
        let (subject, _bundle, records) = object();
        let unit = usize::try_from(crate::RANGE_UNIT_BYTES).unwrap();
        let limit = vot_transport_api::MAX_DATA_RECORD_BYTES;
        let fits = limit / unit;

        let mut driver = ready();
        driver.admit(subject).unwrap();
        // A generous bundle count, so only the byte bound can refuse anything.
        driver.set_pending_limits(fits + 4, limit).unwrap();
        for index in 0..fits {
            let mut record = records[0].clone();
            record.bundle_id = [u8::try_from(index).unwrap(); 16];
            driver
                .session_mut()
                .driver()
                .events
                .push_back(lane(&wire(&TypedFrame::DataRecord(record))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bytes(), limit, "the bound itself is held");

        let mut extra = records[0].clone();
        extra.bundle_id = [0xff; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(lane(&wire(&TypedFrame::DataRecord(extra))));
        assert_eq!(driver.poll().unwrap_err(), Error::PendingBundlesExhausted);
        assert_eq!(driver.pending_bytes(), limit, "a refusal holds nothing");

        // The smallest usable bound is one maximum record. One below it would
        // refuse a peer that did nothing wrong.
        let mut limits = ready();
        assert!(limits.set_pending_limits(1, limit).is_ok());
        assert!(limits.set_pending_limits(1, limit - 1).is_err());
        assert!(limits.set_pending_limits(0, limit).is_err());
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
            .push_back(lane(&wire(&TypedFrame::ProofBundle(bundle))));
        for record in &records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(lane(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject), "the range still verified");
        assert!(!driver.credit_applied(), "and the credit did not apply");
        assert!(driver.session().adapter().credit.is_empty());
    }

    #[test]
    fn a_duplicate_record_or_bundle_is_refused() {
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject).unwrap();
        for _ in 0..2 {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(lane(&wire(&TypedFrame::DataRecord(records[0].clone()))));
        }
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);

        let mut fresh = ready();
        fresh.admit(subject).unwrap();
        for _ in 0..2 {
            fresh
                .session_mut()
                .driver()
                .events
                .push_back(lane(&wire(&TypedFrame::ProofBundle(bundle.clone()))));
        }
        assert_eq!(fresh.poll().unwrap_err(), Error::ProofInvalid);
    }
}
