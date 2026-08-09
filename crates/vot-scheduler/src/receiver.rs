//! Root-verified receive state, keyed by subject identity.

use super::{
    BTreeMap, BTreeSet, ConnectionId, Error, PathStats, RangeSink, RangeState, SinkError,
    StagingCapacity, StreamVerifier, SubjectId, TransportAck, VERIFIER_RESERVATION,
    assemble_ordered, check_range_proof, suite, validate_typed_bundle,
};

pub(super) struct ActiveObject {
    verifier: StreamVerifier,
    received: u64,
}

/// Releases a transient staging hold on every exit, including panic.
pub(super) struct StagingHold<'capacity> {
    staging: &'capacity mut StagingCapacity,
    bytes: u64,
}

impl Drop for StagingHold<'_> {
    fn drop(&mut self) {
        self.staging.release(self.bytes);
    }
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
    /// An over-release poisons the ledger, which is a bug in this crate's
    /// accounting rather than anything a peer did, and a poisoned ledger
    /// refuses every later reservation. Rebuilding forgets what is
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
        let verifier = StreamVerifier::new(suite(subject.suite)?);
        self.staging.reserve(VERIFIER_RESERVATION)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.active.insert(
            subject,
            ActiveObject {
                verifier,
                received: 0,
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
        let _ = suite(subject.suite)?;
        if subject.length == 0 {
            return Err(Error::LengthMismatch);
        }
        self.staging.reserve(VERIFIER_RESERVATION)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        self.range_active.insert(
            subject,
            RangeState {
                extents: BTreeMap::new(),
                bytes: 0,
                sink,
            },
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
        check_range_proof(subject, covered_offset, data, proof)?;
        self.insert_checked_range(subject, covered_offset, data, caller_reserved)
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
            .get(&subject)
            .ok_or(Error::UnknownObject)?;
        let Some(booking) = active.check(covered_offset, bytes)? else {
            return Ok(());
        };
        let reserved = if caller_reserved {
            0
        } else {
            self.staging.reserve(bytes)?;
            bytes
        };
        let hold = StagingHold {
            staging: &mut self.staging,
            bytes: reserved,
        };
        self.peak_staging = self.peak_staging.max(hold.staging.used());
        active.sink.write_at(covered_offset, data)?;
        drop(hold);
        let active = self
            .range_active
            .get_mut(&subject)
            .ok_or(Error::UnknownObject)?;
        active.book(covered_offset, &booking);
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
            .get(&range.subject)
            .ok_or(Error::UnknownObject)?;
        let Some(booking) = active.check(range.covered_offset, range.bytes)? else {
            return Ok(());
        };
        let active = self
            .range_active
            .get_mut(&range.subject)
            .ok_or(Error::UnknownObject)?;
        active.book(range.covered_offset, &booking);
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
        records: &[vot_codec::frames::DataRecord],
    ) -> Result<VerifiedRange, Error> {
        let ordered = validate_typed_bundle(subject, bundle, records)?;
        let data = assemble_ordered(bundle, &ordered)?;
        check_range_proof(subject, bundle.covered_offset, &data, &bundle.proof)?;
        Ok(VerifiedRange {
            subject,
            covered_offset: bundle.covered_offset,
            data,
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
        self.insert_checked_range(range.subject, range.covered_offset, &range.data, false)
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
        records: &[vot_codec::frames::DataRecord],
    ) -> Result<(), Error> {
        let ordered = validate_typed_bundle(subject, bundle, records)?;
        let covered_bytes = bundle.covered_length;
        // Released after reassembly and sink write; bytes live in the sink now.
        self.staging.reserve(covered_bytes)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        let result = (|| {
            let data = assemble_ordered(bundle, &ordered)?;
            self.receive_verified_range(subject, bundle.covered_offset, &data, &bundle.proof, true)
        })();
        self.staging.release(covered_bytes);
        result
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
            .map(|active| active.bytes == subject.length)
            .ok_or(Error::UnknownObject)?;
        if !complete {
            return Err(Error::LengthMismatch);
        }
        self.range_active
            .remove(&subject)
            .ok_or(Error::UnknownObject)?;
        self.staging.release(VERIFIER_RESERVATION);
        self.verified.insert(subject);
        Ok(())
    }

    /// Forgets an incomplete range transfer, releasing what it reserved.
    /// Used when a rail's object completes elsewhere. Returns whether anything
    /// was held; a verified subject stays verified.
    pub fn abandon_ranges(&mut self, subject: SubjectId) -> bool {
        if self.range_active.remove(&subject).is_none() {
            return false;
        }
        self.staging.release(VERIFIER_RESERVATION);
        true
    }

    /// # Errors
    /// Rejects oversized records, unknown objects, bounds violations, or hash errors.
    pub fn receive(&mut self, subject: SubjectId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record).map_err(|error| match error {
            vot_transport_api::Error::RecordTooLarge => Error::RecordTooLarge,
            other => Error::Staging(other),
        })?;
        let bytes = u64::try_from(record.len()).map_err(|_| Error::LengthExceeded)?;
        self.staging.reserve(bytes)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        let result = self.receive_reserved(subject, record, bytes);
        self.staging.release(bytes);
        result
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
        if received > subject.length {
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
        self.staging.release(VERIFIER_RESERVATION);
        if active.received != subject.length {
            return Err(Error::LengthMismatch);
        }
        if active.verifier.finish()? != subject.root {
            return Err(Error::RootMismatch);
        }
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
#[derive(Debug)]
pub struct VerifiedRange {
    pub(super) subject: SubjectId,
    pub(super) covered_offset: u64,
    pub(super) data: Vec<u8>,
}

impl VerifiedRange {
    /// The verified bytes this range carries.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Whether the range carries nothing, which verification never produces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Places the verified bytes and returns the witness admission takes.
    ///
    /// # Errors
    /// Surfaces the sink's refusal; this witness stays usable for a retry.
    pub fn write_to(&self, sink: &dyn RangeSink) -> Result<WrittenRange, SinkError> {
        sink.write_at(self.covered_offset, &self.data)?;
        Ok(WrittenRange {
            subject: self.subject,
            covered_offset: self.covered_offset,
            bytes: self.data.len() as u64,
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
