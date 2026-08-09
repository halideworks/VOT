//! Drives a [`ReliableReceiver`] from a negotiated session.
//!
//! Records and bundles arrive as separate frames in either order. This holds
//! whichever comes first, bounded, and hands the receiver a complete bundle.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vot_codec::frames::{DataRecord, ProofBundle, TypedFrame};
use vot_session::Session;
use vot_transport_api::{Event, SubjectId, TransportAdapter};

use crate::{Error, RangeSink, ReliableReceiver};

/// Max bytes one bundle can hold. A lower bound would refuse a conforming
/// transfer partway through.
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

/// Framing identity of one delivered record. Used for idempotent replay checks.
#[derive(Clone, Copy, Eq, PartialEq)]
struct DeliveredRecord {
    record_index: u64,
    plaintext_offset: u64,
    plaintext_length: u64,
    compression: u8,
    encoded_length: usize,
}

impl DeliveredRecord {
    fn of(record: &DataRecord) -> Self {
        Self {
            record_index: record.record_index,
            plaintext_offset: record.plaintext_offset,
            plaintext_length: record.plaintext_length,
            compression: record.compression,
            encoded_length: record.encoded.len(),
        }
    }
}

/// Delivered bundle: frame hash and record identities. A replay differing
/// anywhere on the wire is a conflicting duplicate.
#[derive(Clone, Eq, PartialEq)]
struct Delivered {
    identity: [u8; 32],
    records: Vec<DeliveredRecord>,
}

impl Delivered {
    fn of(identity: [u8; 32], records: &[DataRecord]) -> Self {
        Self {
            identity,
            records: records.iter().map(DeliveredRecord::of).collect(),
        }
    }
}

/// A bundle and the records that belong to it, in whichever order they came.
#[derive(Default)]
struct Pending {
    bundle: Option<ProofBundle>,
    /// The hash of the frame the bundle arrived in, kept for the replay check.
    identity: Option<[u8; 32]>,
    records: Vec<DataRecord>,
}

impl Pending {
    /// Bytes held for this bundle, summed on demand.
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

    /// Which budget this entry occupies: a record without its proof names no
    /// subject, so nothing has authorized it yet.
    fn is_orphan(&self) -> bool {
        self.bundle.is_none()
    }
}

/// The pending map and its two budgets, admitted and orphan, owned together.
/// Every insertion, migration, and removal is a transition here that settles
/// the counters it affects, and a recomputation assertion holds them to the
/// map after each one. Callers never touch the map directly.
struct PendingBundles {
    entries: BTreeMap<[u8; 16], Pending>,
    admitted_bundles: usize,
    admitted_bytes: usize,
    orphan_bundles: usize,
    orphan_bytes: usize,
    bundle_limit: usize,
    byte_limit: usize,
    orphan_bundle_limit: usize,
    orphan_byte_limit: usize,
}

impl Default for PendingBundles {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            admitted_bundles: 0,
            admitted_bytes: 0,
            orphan_bundles: 0,
            orphan_bytes: 0,
            bundle_limit: DEFAULT_PENDING_BUNDLES,
            byte_limit: DEFAULT_PENDING_BUNDLE_BYTES,
            orphan_bundle_limit: DEFAULT_ORPHAN_BUNDLES,
            orphan_byte_limit: DEFAULT_ORPHAN_BYTES,
        }
    }
}

impl PendingBundles {
    fn get(&self, id: &[u8; 16]) -> Option<&Pending> {
        self.entries.get(id)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Bytes held across both budgets.
    fn bytes(&self) -> usize {
        self.admitted_bytes + self.orphan_bytes
    }

    const fn orphan_count(&self) -> usize {
        self.orphan_bundles
    }

    /// Refuses `bytes` more in one budget, counting a new entry unless the
    /// identity already occupies that budget. Checked before any mutation, so
    /// a refused frame changes nothing.
    fn refuse_over_budget(&self, id: &[u8; 16], bytes: usize, orphan: bool) -> Result<(), Error> {
        let (count_limit, byte_limit, count, held) = if orphan {
            (
                self.orphan_bundle_limit,
                self.orphan_byte_limit,
                self.orphan_bundles,
                self.orphan_bytes,
            )
        } else {
            (
                self.bundle_limit,
                self.byte_limit,
                self.admitted_bundles,
                self.admitted_bytes,
            )
        };
        let known = self
            .entries
            .get(id)
            .is_some_and(|pending| pending.is_orphan() == orphan);
        if !known && count >= count_limit {
            return Err(Error::PendingBundlesExhausted);
        }
        let next = held.checked_add(bytes).ok_or(Error::LengthExceeded)?;
        if next > byte_limit {
            return Err(Error::PendingBundlesExhausted);
        }
        Ok(())
    }

    /// Attaches a proof to its entry, migrating any records held under the
    /// orphan budget into the admitted one along with it. The admitted budget
    /// is checked for the proof and the carried records together, so the
    /// reservation covers the whole entry rather than the frame that happens
    /// to complete it.
    fn attach_bundle(&mut self, bundle: ProofBundle, identity: [u8; 32]) -> Result<(), Error> {
        let id = bundle.bundle_id;
        let carried = self.entries.get(&id).map_or(0, Pending::bytes);
        let bytes = bundle
            .proof
            .len()
            .checked_add(carried)
            .ok_or(Error::LengthExceeded)?;
        self.refuse_over_budget(&id, bytes, false)?;
        let entry = self.entries.entry(id).or_default();
        let was_orphan = entry.is_orphan();
        let existed = entry.bundle.is_some() || !entry.records.is_empty();
        entry.bundle = Some(bundle);
        entry.identity = Some(identity);
        if existed && was_orphan {
            self.orphan_bundles -= 1;
            self.orphan_bytes -= carried;
        }
        self.admitted_bundles += 1;
        self.admitted_bytes += bytes;
        self.assert_accounted();
        Ok(())
    }

    /// Holds one record under whichever budget its entry occupies.
    fn append_record(&mut self, record: DataRecord) -> Result<(), Error> {
        let id = record.bundle_id;
        let orphan = self.entries.get(&id).is_none_or(Pending::is_orphan);
        let bytes = record.encoded.len();
        self.refuse_over_budget(&id, bytes, orphan)?;
        let entry = self.entries.entry(id).or_default();
        let opened = entry.bundle.is_none() && entry.records.is_empty();
        entry.records.push(record);
        if orphan {
            self.orphan_bundles += usize::from(opened);
            self.orphan_bytes += bytes;
        } else {
            self.admitted_bytes += bytes;
        }
        self.assert_accounted();
        Ok(())
    }

    /// Removes an entry whose contents can no longer be used, releasing its
    /// whole budget.
    fn remove(&mut self, id: &[u8; 16]) -> Option<Pending> {
        let pending = self.entries.remove(id)?;
        if pending.is_orphan() {
            self.orphan_bundles -= 1;
            self.orphan_bytes -= pending.bytes();
        } else {
            self.admitted_bundles -= 1;
            self.admitted_bytes -= pending.bytes();
        }
        self.assert_accounted();
        Some(pending)
    }

    /// Takes an entry only once every record its bundle declares has arrived.
    fn take_complete(&mut self, id: &[u8; 16]) -> Option<Pending> {
        if !self.get(id).is_some_and(Pending::complete) {
            return None;
        }
        self.remove(id)
    }

    /// The counters recomputed from the map, in tests and debug builds.
    fn assert_accounted(&self) {
        #[cfg(debug_assertions)]
        {
            let orphan: (usize, usize) = self
                .entries
                .values()
                .filter(|pending| pending.is_orphan())
                .fold((0, 0), |(count, bytes), pending| {
                    (count + 1, bytes + pending.bytes())
                });
            let admitted: (usize, usize) = self
                .entries
                .values()
                .filter(|pending| !pending.is_orphan())
                .fold((0, 0), |(count, bytes), pending| {
                    (count + 1, bytes + pending.bytes())
                });
            debug_assert_eq!((self.orphan_bundles, self.orphan_bytes), orphan);
            debug_assert_eq!((self.admitted_bundles, self.admitted_bytes), admitted);
        }
    }
}

/// Whether a control frame is the proof that describes a range.
fn is_proof_bundle(frame: &[u8]) -> bool {
    vot_codec::decode_varint(frame)
        .is_ok_and(|(frame_type, _)| frame_type == vot_codec::frame_type::PROOF_BUNDLE)
}

/// A complete bundle handed to a caller for off-thread verification.
#[derive(Debug)]
pub struct CompletedBundle {
    id: [u8; 16],
    identity: [u8; 32],
    subject: SubjectId,
    bundle: ProofBundle,
    records: Vec<DataRecord>,
}

impl CompletedBundle {
    /// The object this bundle covers a range of.
    #[must_use]
    pub const fn subject(&self) -> SubjectId {
        self.subject
    }

    /// The proof, for [`ReliableReceiver::verify_typed_bundle`].
    #[must_use]
    pub const fn bundle(&self) -> &ProofBundle {
        &self.bundle
    }

    /// The records the proof covers, in arrival order.
    #[must_use]
    pub fn records(&self) -> &[DataRecord] {
        &self.records
    }
}

/// Max completed bundles undrained before `poll` stops reading.
pub const DEFAULT_DEFERRED_BUNDLES: usize = 4;

/// A receiver fed by a session over a real carrier.
pub struct SessionReceiver<A> {
    session: Session<A>,
    receiver: ReliableReceiver,
    /// Complete bundles this receiver has not proved, because the caller
    /// asked to prove them itself. Empty unless [`Self::defer_proving`].
    completed: VecDeque<CompletedBundle>,
    deferred_limit: usize,
    deferring: bool,
    pending: PendingBundles,
    remembered_bundle_limit: usize,
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
            completed: VecDeque::new(),
            deferred_limit: DEFAULT_DEFERRED_BUNDLES,
            deferring: false,
            pending: PendingBundles::default(),
            remembered_bundle_limit: REMEMBERED_BUNDLES,
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
        self.pending.bundle_limit = bundles;
        self.pending.byte_limit = bytes;
        Ok(())
    }

    /// Sets how many delivered bundle identities are remembered.
    ///
    /// Forgetting one costs nothing beyond the conflict check: a replay of a
    /// verified subject is idempotent whether or not its identity is still
    /// held.
    ///
    /// # Errors
    /// Rejects a bound of zero, which would forget every identity at once.
    pub fn set_remembered_bundles(&mut self, bundles: usize) -> Result<(), Error> {
        if bundles == 0 {
            return Err(Error::Staging(
                vot_transport_api::Error::InvalidConfiguration,
            ));
        }
        self.remembered_bundle_limit = bundles;
        let excess = self.delivered.len().saturating_sub(bundles);
        self.delivered.drain(..excess);
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
        self.pending.orphan_bundle_limit = bundles;
        self.pending.orphan_byte_limit = bytes;
        Ok(())
    }

    /// Authorises a subject, opens range state for it, and registers where
    /// its verified bytes go (ADR-0029).
    ///
    /// # Errors
    /// Propagates a receiver that cannot begin the subject.
    pub fn admit(&mut self, subject: SubjectId, sink: Box<dyn RangeSink>) -> Result<(), Error> {
        self.receiver.begin_ranges(subject, sink)?;
        self.admitted.insert(subject);
        Ok(())
    }

    /// Whether every byte of `subject` has been verified.
    #[must_use]
    pub fn is_verified(&self, subject: SubjectId) -> bool {
        self.receiver.is_verified(subject)
    }

    /// Forgets an incomplete range transfer whose object is whole elsewhere
    /// (ADR-0031: the shared plan's coverage completes it, not any one
    /// rail's receiver). The subject stays admitted, so a straggling replay
    /// drains as a replay rather than ending the session as an unknown
    /// object. Answers whether there was anything to forget.
    pub fn abandon(&mut self, subject: SubjectId) -> bool {
        self.receiver.abandon_ranges(subject)
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

    /// Complete bundles a deferring caller has not yet taken.
    #[must_use]
    pub fn completed_bundles(&self) -> usize {
        self.completed.len()
    }

    /// The byte bound on admitted bundles that are not complete, so a
    /// caller that derives it can hold the derivation to account.
    #[must_use]
    pub const fn pending_byte_limit(&self) -> usize {
        self.pending.byte_limit
    }

    /// The byte bound on records that arrived before their proof.
    #[must_use]
    pub const fn orphan_byte_limit(&self) -> usize {
        self.pending.orphan_byte_limit
    }

    /// The bound on what [`Self::take_completed`] may owe at once.
    #[must_use]
    pub const fn deferred_limit(&self) -> usize {
        self.deferred_limit
    }

    /// Delivered bundle identities still remembered.
    #[must_use]
    pub fn remembered_bundles(&self) -> usize {
        self.delivered.len()
    }

    /// Bundles holding records whose proof has not arrived.
    #[must_use]
    pub fn orphan_bundles(&self) -> usize {
        self.pending.orphan_count()
    }

    /// Bytes held for bundles that are not complete.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.bytes()
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
        while self.completed.len() < self.deferred_limit {
            let Some(event) = self.session.poll().map_err(Error::Session)? else {
                return Ok(None);
            };
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
            // Hashed as it arrived. Canonical encoding is mandatory, so the
            // same bundle always produces the same bytes, and nothing has to
            // choose which fields count as its identity.
            TypedFrame::ProofBundle(bundle) => {
                self.hold_bundle(bundle, *blake3::hash(frame).as_bytes())
            }
            _ => Err(Error::ProofInvalid),
        }
    }

    fn hold_bundle(&mut self, bundle: ProofBundle, identity: [u8; 32]) -> Result<(), Error> {
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
            // Already delivered. An exact replay is idempotent; anything else
            // under the same bundle identifier is a conflicting duplicate. The
            // records it covers are compared as they arrive.
            return if prior.identity == identity {
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
            // More records than the proof covers. The records held under this
            // identity are unusable, and left in place they would occupy the
            // budget for the rest of the session: nothing else can complete
            // an entry whose proof was refused.
            self.pending.remove(&id);
            return Err(Error::ProofInvalid);
        }
        self.pending.attach_bundle(bundle, identity)?;
        self.deliver(id)
    }

    fn hold_record(&mut self, record: DataRecord) -> Result<(), Error> {
        let id = record.bundle_id;
        if let Some((_, prior)) = self.delivered.iter().find(|(seen, _)| *seen == id) {
            // Its bundle is verified and gone, so holding this would leave an
            // entry that can never complete. An exact retry is idempotent and
            // anything else conflicts with what was verified.
            return if prior.records.contains(&DeliveredRecord::of(&record)) {
                Ok(())
            } else {
                Err(Error::ProofInvalid)
            };
        }
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
        self.pending.append_record(record)?;
        self.deliver(id)
    }

    /// Hands a complete bundle to the receiver.
    fn deliver(&mut self, id: [u8; 16]) -> Result<(), Error> {
        let Some(pending) = self.pending.take_complete(&id) else {
            return Ok(());
        };
        let (Some(bundle), Some(identity)) = (pending.bundle, pending.identity) else {
            return Ok(());
        };
        let subject = SubjectId {
            suite: bundle.object.suite,
            root: bundle.object.root,
            length: bundle.object.length,
        };
        let delivered = Delivered::of(identity, &pending.records);
        // A cover for a subject already verified never goes to the caller:
        // the caller places what it proves through the sink of the object it
        // is currently fetching, and a late or replayed cover for a finished
        // object would land in the wrong file. The inline path below is what
        // the receiver has always done with one: check its proof, write
        // nothing, and leave the subject as verified as it was.
        if self.deferring && !self.receiver.is_verified(subject) {
            // The caller proves and places it, then hands the witness back to
            // [`Self::settle`], which does the bookkeeping below.
            self.completed.push_back(CompletedBundle {
                id,
                identity,
                subject,
                bundle,
                records: pending.records,
            });
            return Ok(());
        }
        // A bundle whose identity is still remembered never reaches here, so a
        // replay arriving here is one whose identity was evicted. The receiver
        // checks its proof either way and treats a verified subject as
        // unchanged, which is what makes the bound on that memory harmless.
        self.receiver
            .receive_typed_bundle(subject, &bundle, &pending.records)?;
        self.after_admission(id, delivered, subject)
    }

    /// The bookkeeping every admission path shares, after verification and
    /// writing have already succeeded through their own entry points.
    fn after_admission(
        &mut self,
        id: [u8; 16],
        delivered: Delivered,
        subject: SubjectId,
    ) -> Result<(), Error> {
        // Remembered only once the receiver has accepted it. A bundle that
        // failed verification must stay retryable under its own identity.
        self.remember(id, delivered);
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

    /// Hands proving and placing to the caller instead of doing them here.
    ///
    /// A bundle then leaves through [`Self::take_completed`] and comes back
    /// through [`Self::settle`]. Everything the receiver knows about
    /// admission, replay, and credit still happens here and in that order;
    /// what moves is the verification and the sink write, which is where the
    /// time goes.
    pub const fn defer_proving(&mut self, defer: bool) {
        self.deferring = defer;
    }

    /// Bounds what [`Self::take_completed`] may owe at once.
    ///
    /// # Errors
    /// Rejects zero, which would stop the receiver reading anything.
    pub const fn set_deferred_limit(&mut self, bundles: usize) -> Result<(), Error> {
        if bundles == 0 {
            return Err(Error::PendingBundlesExhausted);
        }
        self.deferred_limit = bundles;
        Ok(())
    }

    /// Takes a bundle the caller is to prove and place.
    pub fn take_completed(&mut self) -> Option<CompletedBundle> {
        self.completed.pop_front()
    }

    /// Books a bundle the caller proved and placed.
    ///
    /// The same bookkeeping the inline path does once the proof has held:
    /// the extent is admitted, the identity remembered so a replay is
    /// idempotent, the subject promoted once every byte is covered, and the
    /// credit pushed back to the peer.
    ///
    /// # Errors
    /// Surfaces what admission refused. A bundle whose proof did not hold is
    /// never settled: the caller reports that failure instead.
    pub fn settle(
        &mut self,
        completed: &CompletedBundle,
        written: crate::WrittenRange,
    ) -> Result<(), Error> {
        self.receiver.admit_written_range(written)?;
        self.after_admission(
            completed.id,
            Delivered::of(completed.identity, &completed.records),
            completed.subject,
        )
    }

    /// Records a bundle identity, evicting the oldest when the bound is met.
    fn remember(&mut self, id: [u8; 16], delivered: Delivered) {
        let excess = self
            .delivered
            .len()
            .saturating_add(1)
            .saturating_sub(self.remembered_bundle_limit);
        self.delivered.drain(..excess);
        self.delivered.push_back((id, delivered));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscardSink;
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
            vot_session::Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        session.begin().unwrap();
        // Driven to readiness through the client's frames, which is the only
        // way a session reaches it.
        let mut client = Session::client(
            Loopback::default(),
            vot_codec::Settings::default(),
            std::collections::BTreeSet::new(),
            vot_session::Authentication::NotRequired { nonce: [0x5a; 32] },
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
    fn an_abandoned_subject_is_forgotten_once_and_admissible_again() {
        // ADR-0031: a rail forgets an object the shared plan completed
        // elsewhere. The answer says whether there was anything to forget,
        // and the freed state is what lets the subject be admitted again.
        let (subject, _, _) = object();
        let mut driver = ready();
        assert!(!driver.abandon(subject), "nothing admitted, nothing owed");
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        assert!(driver.abandon(subject));
        assert!(!driver.abandon(subject), "forgotten once");
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
    }

    #[test]
    fn a_bundle_and_its_records_become_verified_state() {
        // Nothing joined a session to a receiver, so a live carrier moved
        // records and verified nothing.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
    fn a_deferred_bundle_reaches_the_same_state_by_the_caller_s_hand() {
        // The caller proves and places it off this thread and hands the
        // witness back, and the subject ends up exactly as verified as the
        // inline path leaves it.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        driver.defer_proving(true);

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
        assert!(
            !driver.is_verified(subject),
            "nothing is verified until the caller proves it"
        );

        let completed = driver.take_completed().expect("a bundle to prove");
        assert!(driver.take_completed().is_none(), "one bundle, taken once");
        let range = ReliableReceiver::verify_typed_bundle(
            completed.subject(),
            completed.bundle(),
            completed.records(),
        )
        .expect("the proof holds");
        let written = range.write_to(&DiscardSink).expect("the sink takes it");
        driver.settle(&completed, written).unwrap();

        assert!(driver.is_verified(subject));
        assert!(driver.credit_applied());
    }

    #[test]
    fn a_deferred_cover_for_a_verified_subject_never_reaches_the_caller() {
        // The caller places what it proves through the sink of the object
        // it is currently fetching, so a late cover for a finished object
        // must take the inline path: proof checked, nothing written,
        // nothing enqueued. Handed out, it would land in another object's
        // file.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        driver.defer_proving(true);
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
        let completed = driver.take_completed().expect("a bundle to prove");
        let range = ReliableReceiver::verify_typed_bundle(
            completed.subject(),
            completed.bundle(),
            completed.records(),
        )
        .expect("the proof holds");
        let written = range.write_to(&DiscardSink).expect("the sink takes it");
        driver.settle(&completed, written).unwrap();
        assert!(driver.is_verified(subject));

        // The same object again under a fresh bundle identity, which is
        // what an evicted replay or a retrying server looks like.
        let (_, again, again_records) = object_of(0x5a, [9; 16]);
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(again))));
        for record in &again_records {
            driver
                .session_mut()
                .driver()
                .events
                .push_back(carried(&wire(&TypedFrame::DataRecord(record.clone()))));
        }
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(
            driver.completed_bundles(),
            0,
            "a verified subject's cover is never owed to the caller"
        );
        assert!(driver.take_completed().is_none());
        assert!(driver.is_verified(subject));
        assert!(driver.credit_applied());
    }

    #[test]
    fn a_caller_that_owes_proofs_is_not_given_more_to_read() {
        // The pending budget stops holding a bundle the moment it completes,
        // so the handover is what bounds a caller that stops draining.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        driver.defer_proving(true);
        assert_eq!(
            driver.deferred_limit(),
            DEFAULT_DEFERRED_BUNDLES,
            "the default bound, before anyone set one"
        );
        assert_eq!(driver.completed_bundles(), 0, "nothing owed yet");
        driver.set_deferred_limit(1).unwrap();
        assert_eq!(driver.deferred_limit(), 1, "the bound is what was set");
        assert_eq!(
            driver.set_deferred_limit(0),
            Err(Error::PendingBundlesExhausted),
            "a limit of none would read nothing ever"
        );

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
        // A second frame behind the first, which must stay unread while the
        // caller owes one.
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(records[0].clone()))));

        assert_eq!(driver.poll().unwrap(), None);
        // The first poll stops the moment the owed bundle completes: the
        // frame behind it is still queued. A gate off by one reads it here,
        // which on a live carrier is a receiver that runs ahead of the
        // caller it is owed by.
        assert_eq!(
            driver.session_mut().driver().events.len(),
            1,
            "the frame behind the completed bundle was read early"
        );
        let queued = driver.session_mut().driver().events.len();
        assert_eq!(driver.poll().unwrap(), None, "still owed, still not read");
        assert_eq!(
            driver.session_mut().driver().events.len(),
            queued,
            "the carrier's queue did not move while a proof was owed"
        );
        assert_eq!(driver.completed_bundles(), 1, "one bundle owed");
        assert!(driver.take_completed().is_some());
        assert_eq!(driver.completed_bundles(), 0, "taken, no longer owed");
    }

    #[test]
    fn records_arriving_before_their_bundle_are_held() {
        // The two are separate frames with no ordering between them.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
    #[should_panic(expected = "assertion `left == right` failed")]
    fn a_drifted_budget_fails_the_recomputation() {
        let mut pending = PendingBundles::default();
        let (_, _, records) = object();
        pending.append_record(records[0].clone()).unwrap();
        // The only way the counters and the map can disagree is a bug;
        // simulate one.
        pending.orphan_bytes += 1;
        pending.assert_accounted();
    }

    #[test]
    fn held_bundle_state_is_bounded() {
        let (subject, _bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
        // conforming transfer partway through rather than bound it. What
        // was set is what is held, byte for byte.
        assert!(
            driver
                .set_pending_limits(1, MAX_PENDING_BUNDLE_BYTES)
                .is_ok()
        );
        assert_eq!(driver.pending_byte_limit(), MAX_PENDING_BUNDLE_BYTES);
        assert!(
            driver
                .set_orphan_limits(1, MAX_ORPHAN_BUNDLE_BYTES + 7)
                .is_ok()
        );
        assert_eq!(driver.orphan_byte_limit(), MAX_ORPHAN_BUNDLE_BYTES + 7);
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();

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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();

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
        // Nothing else can complete an entry whose proof was refused, so it
        // would hold its budget for the rest of the session.
        assert_eq!(driver.pending_bundles(), 0);
        assert_eq!(driver.pending_bytes(), 0);
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
    fn a_replay_is_idempotent_even_after_its_identity_is_forgotten() {
        // The memory of delivered identities is bounded, so a long session
        // forgets. What makes that harmless is the verified subject: its range
        // state is closed, so a replay is repeated rather than reassembled.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));

        driver.set_remembered_bundles(1).unwrap();
        assert_eq!(driver.remembered_bundles(), 1);
        assert!(driver.set_remembered_bundles(0).is_err());

        driver.delivered.clear();
        assert_eq!(driver.remembered_bundles(), 0);
        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.pending_bundles(), 0, "the replay held nothing");
        assert!(driver.is_verified(subject));
        assert_eq!(driver.remembered_bundles(), 1, "and it is remembered again");
    }

    #[test]
    fn the_memory_of_delivered_identities_is_bounded() {
        // Unbounded, a long session would grow this without limit.
        let (first_subject, first_bundle, first_records) = object();
        let (second_subject, second_bundle, second_records) = object_of(0x17, [3; 16]);
        let mut driver = ready();
        driver.set_remembered_bundles(1).unwrap();
        driver.admit(first_subject, Box::new(DiscardSink)).unwrap();
        driver.admit(second_subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &first_bundle, &first_records);
        push_object(&mut driver, &second_bundle, &second_records);
        assert_eq!(driver.poll().unwrap(), None);
        assert_eq!(driver.remembered_bundles(), 1, "the bound holds");
        assert!(driver.is_verified(first_subject) && driver.is_verified(second_subject));
    }

    #[test]
    fn a_bundle_that_failed_verification_is_still_retryable() {
        // Remembering it before the receiver accepted it would make the
        // corrected retry look like a replay and never verify anything.
        let (subject, bundle, records) = object();
        let mut broken = records.clone();
        broken[1].encoded[0] ^= 0xff;
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &bundle, &broken);
        assert!(
            driver.poll().is_err(),
            "the proof did not cover those bytes"
        );
        assert!(!driver.is_verified(subject));

        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject), "the retry verified");
    }

    #[test]
    fn a_record_conflicting_with_a_delivered_bundle_is_refused() {
        // spec/wire.md section 5: exact range bytes deduplicate and a
        // conflicting identity is rejected, which does not stop at delivery.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));

        // The same record again is a retry.
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(records[0].clone()))));
        assert_eq!(driver.poll().unwrap(), None);

        // A record the delivered bundle never covered is not.
        let mut conflicting = records[0].clone();
        conflicting.record_index = 9;
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::DataRecord(conflicting))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn more_than_one_delivered_bundle_is_remembered() {
        // The memory is a queue with a bound. Evicting on every delivery would
        // leave only the last one, and the replay of anything earlier would
        // fail.
        let (first_subject, first_bundle, first_records) = object();
        let (second_subject, second_bundle, second_records) = object_of(0x17, [3; 16]);
        let mut driver = ready();
        driver.admit(first_subject, Box::new(DiscardSink)).unwrap();
        driver.admit(second_subject, Box::new(DiscardSink)).unwrap();
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
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
            .admit(
                SubjectId {
                    suite: conflicting.object.suite,
                    root: conflicting.object.root,
                    length: conflicting.object.length,
                },
                Box::new(DiscardSink),
            )
            .unwrap();
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(conflicting))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn a_replay_differing_anywhere_is_a_conflict() {
        // The identity is the frame, not a chosen set of fields, so a bundle
        // reusing an identifier with different request metadata is refused
        // even when its subject and covered range match.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));

        let mut relabelled = bundle;
        relabelled.request_id = [0xaa; 16];
        driver
            .session_mut()
            .driver()
            .events
            .push_back(carried(&wire(&TypedFrame::ProofBundle(relabelled))));
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
    }

    #[test]
    fn a_bundle_for_a_verified_subject_still_has_to_verify() {
        // A subject with no range state left must not become a hole: an
        // identifier this has never seen is not a replay, and accepting one
        // unchecked would let a peer have arbitrary proof bytes remembered as
        // delivered.
        let (subject, bundle, records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
        push_object(&mut driver, &bundle, &records);
        assert_eq!(driver.poll().unwrap(), None);
        assert!(driver.is_verified(subject));
        let remembered = driver.remembered_bundles();

        let mut forged = bundle;
        forged.bundle_id = [0x5e; 16];
        forged.proof[0] ^= 0xff;
        let forged_records: Vec<DataRecord> = records
            .iter()
            .map(|record| DataRecord {
                bundle_id: forged.bundle_id,
                ..record.clone()
            })
            .collect();
        push_object(&mut driver, &forged, &forged_records);
        assert_eq!(driver.poll().unwrap_err(), Error::ProofInvalid);
        assert_eq!(
            driver.remembered_bundles(),
            remembered,
            "an unverified bundle is not remembered"
        );
    }

    #[test]
    fn a_bundle_that_conflicts_with_a_held_one_is_refused() {
        let (subject, bundle, _records) = object();
        let mut driver = ready();
        driver.admit(subject, Box::new(DiscardSink)).unwrap();
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
