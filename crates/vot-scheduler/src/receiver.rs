//! Root-verified receive state, keyed by subject identity.

use super::{
    BTreeMap, BTreeSet, Check, ConnectionId, Error, PathStats, Permit, RangeSink, RangeState,
    SinkError, StagingCapacity, StreamVerifier, SubjectId, TransportAck, VERIFIER_RESERVATION,
    assemble_ordered, check_range_proof, coverage_error, subject_id, suite, validate_typed_bundle,
    verify_typed_bundle,
};
use vot_verifier::ExpectedObject;

pub(super) struct ActiveObject {
    verifier: StreamVerifier,
    received: u64,
    reservation: Permit,
}

/// Receiver state is keyed by subject identity and outlives connections.
pub struct ReliableReceiver {
    pub(super) staging: StagingCapacity,
    pub(super) active: BTreeMap<SubjectId, ActiveObject>,
    pub(super) range_active: BTreeMap<SubjectId, RangeState>,
    pub(super) verified: BTreeSet<SubjectId>,
    pub(super) connections: BTreeSet<ConnectionId>,
    pub(super) ack_count: u64,
    pub(super) peak_staging: u64,
}

impl ReliableReceiver {
    /// Whether the staging ledger has stopped granting, and the way back.
    ///
    /// A release past what is held poisons the ledger. Every reservation is
    /// a permit that releases itself once, so nothing here can reach that
    /// state; the hook remains for the day something does, since a poisoned
    /// ledger refuses every later reservation. Rebuilding forgets what is
    /// outstanding, so it is only safe with nothing outstanding: this
    /// refuses while any object is in flight, which is the only moment the
    /// receiver can tell that no permit is live.
    ///
    /// Returns whether the ledger was rebuilt.
    pub fn recover_accounting(&mut self) -> bool {
        if !self.staging.is_poisoned() || !self.active.is_empty() || !self.range_active.is_empty() {
            return false;
        }
        self.staging = self.staging.rebuilt();
        true
    }

    /// # Errors
    /// Rejects invalid staging configuration.
    pub fn new(staging_limit: u64, bdp_target: u64, configured_max: u64) -> Result<Self, Error> {
        Ok(Self {
            staging: StagingCapacity::new(staging_limit, bdp_target, configured_max)?,
            active: BTreeMap::new(),
            range_active: BTreeMap::new(),
            verified: BTreeSet::new(),
            connections: BTreeSet::new(),
            ack_count: 0,
            peak_staging: 0,
        })
    }

    pub fn connected(&mut self, connection: ConnectionId) {
        self.connections.insert(connection);
    }

    pub fn disconnected(&mut self, connection: ConnectionId) {
        self.connections.remove(&connection);
    }

    /// # Errors
    /// Rejects duplicate active objects. Verified objects are idempotent.
    pub fn begin(&mut self, subject: SubjectId) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        if self.active.contains_key(&subject) || self.range_active.contains_key(&subject) {
            return Err(Error::AlreadyReceiving);
        }
        let verifier = StreamVerifier::new(suite(subject.suite())?);
        let reservation = self.staging.reserve(VERIFIER_RESERVATION)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.active.insert(
            subject,
            ActiveObject {
                verifier,
                received: 0,
                reservation,
            },
        );
        Ok(())
    }

    /// Opens range state for a subject and registers where its bytes go.
    ///
    /// # Errors
    /// Rejects duplicate active objects and invalid suite or empty-object ranges.
    pub fn begin_ranges(
        &mut self,
        subject: SubjectId,
        sink: Box<dyn RangeSink>,
    ) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        if self.active.contains_key(&subject) || self.range_active.contains_key(&subject) {
            return Err(Error::AlreadyReceiving);
        }
        let _ = suite(subject.suite())?;
        if subject.length() == 0 {
            return Err(Error::LengthMismatch);
        }
        let reservation = self.staging.reserve(VERIFIER_RESERVATION)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.range_active.insert(
            subject,
            RangeState::new(subject.length(), sink, reservation),
        );
        Ok(())
    }

    /// Accepts a proof-bearing, 64 KiB-aligned range in any arrival order.
    ///
    /// # Errors
    /// Rejects malformed proofs, duplicate-independent bounds violations, and
    /// records that are not covered by the subject root.
    pub fn receive_range(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: &[u8],
        proof: &[u8],
    ) -> Result<(), Error> {
        self.receive_verified_range(subject, covered_offset, data, proof, false)
    }

    fn receive_verified_range(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: &[u8],
        proof: &[u8],
        caller_reserved: bool,
    ) -> Result<(), Error> {
        let replay = self.verified.contains(&subject);
        if !replay && !self.range_active.contains_key(&subject) {
            return Err(Error::UnknownObject);
        }
        let verified = check_range_proof(subject, covered_offset, data, proof)?;
        self.insert_checked_range(
            subject_id(verified.object()),
            verified.covered_offset(),
            verified.data(),
            caller_reserved,
        )
    }

    /// Books a range whose proof [`check_range_proof`] has already held:
    /// writes it to the subject's sink, then records its extent (ADR-0029).
    ///
    /// Staging covers the bytes for the span of the write and no longer.
    /// `caller_reserved` says the caller holds its own reservation for them
    /// instead and will release it itself.
    fn insert_checked_range(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: &[u8],
        caller_reserved: bool,
    ) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        let bytes = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
        let active = self
            .range_active
            .get_mut(&subject)
            .ok_or(Error::UnknownObject)?;
        let Check::New(booking) = active
            .coverage
            .check(covered_offset, bytes)
            .map_err(coverage_error)?
        else {
            return Ok(());
        };
        let hold = if caller_reserved {
            None
        } else {
            Some(self.staging.reserve(bytes)?)
        };
        self.peak_staging = self.peak_staging.max(self.staging.used());
        active.sink.write_at(covered_offset, data)?;
        drop(hold);
        booking.commit();
        Ok(())
    }

    /// Books a range whose bytes are already placed. Only the extent is
    /// recorded; no bytes or sink access needed.
    ///
    /// # Errors
    /// Rejects an unknown subject, an overlap with an accepted range, or a
    /// fragment budget the range does not fit.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "admission spends the witness; handing it back would invite re-admitting it"
    )]
    pub fn admit_written_range(&mut self, range: WrittenRange) -> Result<(), Error> {
        if self.verified.contains(&range.subject) {
            return Ok(());
        }
        let active = self
            .range_active
            .get_mut(&range.subject)
            .ok_or(Error::UnknownObject)?;
        let Check::New(booking) = active
            .coverage
            .check(range.covered_offset, range.bytes)
            .map_err(coverage_error)?
        else {
            return Ok(());
        };
        booking.commit();
        Ok(())
    }

    /// Checks a decoded proof bundle without touching receiver state. Pure:
    /// the returned witness enables off-thread verification.
    ///
    /// # Errors
    /// Rejects identity conflicts, duplicate or missing records, unsupported
    /// compression, and proof or range failures.
    pub fn verify_typed_bundle(
        subject: SubjectId,
        bundle: &vot_codec::frames::ProofBundle,
        records: &[vot_codec::frames::DataRecordRef<'_>],
    ) -> Result<VerifiedRange, Error> {
        Ok(VerifiedRange {
            inner: verify_typed_bundle(subject, bundle, records)?,
        })
    }

    /// Books a range already proved by [`Self::verify_typed_bundle`].
    ///
    /// # Errors
    /// Rejects an unknown subject, an overlap with an accepted range, a
    /// staging budget the range does not fit, or a sink that refused it.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "admission spends the witness; handing it back would invite re-admitting it"
    )]
    pub fn admit_verified_range(&mut self, range: VerifiedRange) -> Result<(), Error> {
        self.insert_checked_range(
            subject_id(range.inner.object()),
            range.inner.covered_offset(),
            range.inner.data(),
            false,
        )
    }

    /// Accepts a decoded proof bundle whose records may arrive out of order.
    ///
    /// The bundle proof authenticates the complete covered range. Records are
    /// reassembled only after their bounded metadata is checked, and no
    /// transport acknowledgement is consulted.
    ///
    /// # Errors
    /// Rejects identity conflicts, duplicate or missing records, unsupported
    /// compression, and proof or range failures.
    pub fn receive_typed_bundle(
        &mut self,
        subject: SubjectId,
        bundle: &vot_codec::frames::ProofBundle,
        records: &[vot_codec::frames::DataRecordRef<'_>],
    ) -> Result<(), Error> {
        let validated = validate_typed_bundle(subject, bundle, records)?;
        let covered_bytes = validated.covered_length();
        let _hold = self.staging.reserve(covered_bytes)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        let data = assemble_ordered(validated)?;
        self.receive_verified_range(subject, bundle.covered_offset, &data, &bundle.proof, true)
    }
    /// Completes a range transfer only after every 64 KiB unit is root verified.
    ///
    /// # Errors
    /// Rejects unknown or incomplete range transfers.
    pub fn finish_ranges(&mut self, subject: SubjectId) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        let complete = self
            .range_active
            .get(&subject)
            .map(|active| active.coverage.is_complete(subject.length()))
            .ok_or(Error::UnknownObject)?;
        if !complete {
            return Err(Error::LengthMismatch);
        }
        drop(
            self.range_active
                .remove(&subject)
                .ok_or(Error::UnknownObject)?,
        );
        self.verified.insert(subject);
        Ok(())
    }

    /// Forgets an incomplete range transfer, releasing what it reserved.
    /// Used when a rail's object completes elsewhere. Returns whether anything
    /// was held; a verified subject stays verified.
    pub fn abandon_ranges(&mut self, subject: SubjectId) -> bool {
        self.range_active.remove(&subject).is_some()
    }

    /// # Errors
    /// Rejects oversized records, unknown objects, bounds violations, or hash errors.
    pub fn receive(&mut self, subject: SubjectId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record).map_err(|error| match error {
            vot_transport_api::Error::RecordTooLarge => Error::RecordTooLarge,
            other => Error::Staging(other),
        })?;
        let bytes = u64::try_from(record.len()).map_err(|_| Error::LengthExceeded)?;
        // An empty record stages nothing, and the ledger refuses a zero permit
        // as a configuration error, which this is not.
        let _hold = if bytes == 0 {
            None
        } else {
            Some(self.staging.reserve(bytes)?)
        };
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.receive_reserved(subject, record, bytes)
    }

    fn receive_reserved(
        &mut self,
        subject: SubjectId,
        record: &[u8],
        bytes: u64,
    ) -> Result<(), Error> {
        let active = self.active.get_mut(&subject).ok_or(Error::UnknownObject)?;
        let received = active
            .received
            .checked_add(bytes)
            .ok_or(Error::LengthExceeded)?;
        if received > subject.length() {
            return Err(Error::LengthExceeded);
        }
        active.verifier.update(record)?;
        active.received = received;
        Ok(())
    }

    /// # Errors
    /// Rejects incomplete content or a root mismatch.
    pub fn finish(&mut self, subject: SubjectId) -> Result<(), Error> {
        if self.verified.contains(&subject) {
            return Ok(());
        }
        let active = self.active.remove(&subject).ok_or(Error::UnknownObject)?;
        drop(active.reservation);
        if active.received != subject.length() {
            return Err(Error::LengthMismatch);
        }
        let expected =
            ExpectedObject::new(suite(subject.suite())?, subject.root(), subject.length());
        active.verifier.finish(expected)?;
        self.verified.insert(subject);
        Ok(())
    }

    /// ACKs are transport telemetry only and cannot alter object state.
    pub fn acknowledged(&mut self, _ack: TransportAck) {
        self.ack_count = self.ack_count.saturating_add(1);
    }

    #[must_use]
    pub fn is_verified(&self, subject: SubjectId) -> bool {
        self.verified.contains(&subject)
    }

    #[must_use]
    pub fn advertised_credit(&self) -> u64 {
        self.staging.advertised_credit()
    }

    /// Updates staging credit from the backend's current path measurements.
    pub fn observe_path_stats(&mut self, stats: PathStats) {
        let bdp_target = match (
            stats.pacing_rate_bps,
            stats.smoothed_rtt_us,
            stats.congestion_window_bytes,
        ) {
            (Some(rate), Some(rtt), _) => rate
                .checked_mul(rtt)
                .map(|bits| bits / 8_000_000)
                .filter(|bytes| *bytes > 0),
            (_, _, Some(cwnd)) if cwnd > 0 => Some(cwnd),
            _ => None,
        };
        if let Some(bdp_target) = bdp_target {
            self.staging.set_bdp_target(bdp_target);
        }
    }

    #[must_use]
    pub const fn peak_staging(&self) -> u64 {
        self.peak_staging
    }

    #[must_use]
    pub const fn ack_count(&self) -> u64 {
        self.ack_count
    }

    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

/// A range whose proof has held. Only [`ReliableReceiver::verify_typed_bundle`]
/// builds one; holding it is holding the verification.
pub struct VerifiedRange {
    inner: vot_verified_range::VerifiedRange,
}

impl std::fmt::Debug for VerifiedRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRange")
            .field("subject", &subject_id(self.inner.object()))
            .field("covered_offset", &self.inner.covered_offset())
            .field("data", &self.inner.data())
            .finish()
    }
}

impl VerifiedRange {
    /// The verified bytes this range carries.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.inner.data().len() as u64
    }

    /// Whether the range carries nothing, which verification never produces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.data().is_empty()
    }

    /// Places the verified bytes and returns the witness admission takes.
    ///
    /// # Errors
    /// Surfaces the sink's refusal; this witness stays usable for a retry.
    pub fn write_to(&self, sink: &dyn RangeSink) -> Result<WrittenRange, SinkError> {
        sink.write_at(self.inner.covered_offset(), self.inner.data())?;
        Ok(WrittenRange {
            subject: subject_id(self.inner.object()),
            covered_offset: self.inner.covered_offset(),
            bytes: self.inner.data().len() as u64,
        })
    }
}

/// A range whose proof held and bytes are already placed. Admission books
/// the extent without the bytes.
#[derive(Debug)]
pub struct WrittenRange {
    pub(super) subject: SubjectId,
    pub(super) covered_offset: u64,
    pub(super) bytes: u64,
}
