//! Reliable single-rail transfer planning and root-verified receive state.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet};

use vot_transport_api::{ConnectionId, PathStats, StagingCapacity, SubjectId, TransportAck};

pub mod session;
use vot_verifier::{GROUP_SIZE, StreamVerifier, Suite};

/// Range granularity a proof covers, from spec/proofs.md.
pub const RANGE_UNIT_BYTES: u64 = 65_536;
const MAX_PROOF_RANGE_BYTES: u64 = 4_259_840;

const VERIFIER_RESERVATION: u64 = GROUP_SIZE as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownObject,
    AlreadyReceiving,
    RecordTooLarge,
    LengthExceeded,
    LengthMismatch,
    RootMismatch,
    Staging(vot_transport_api::Error),
    Verification(vot_verifier::VerifyError),
    ProofInvalid,
    UnsupportedCompression,
    /// The session failed before a frame could be interpreted.
    Session(vot_session::Error),
    /// More incomplete bundle state than this receiver will hold.
    PendingBundlesExhausted,
}

impl From<vot_transport_api::Error> for Error {
    fn from(error: vot_transport_api::Error) -> Self {
        Self::Staging(error)
    }
}

impl From<vot_verifier::VerifyError> for Error {
    fn from(error: vot_verifier::VerifyError) -> Self {
        Self::Verification(error)
    }
}

struct ActiveObject {
    verifier: StreamVerifier,
    received: u64,
}

/// Accepted ranges for one object.
///
/// `segments` is kept non-overlapping and every range covers whole 64 KiB
/// units, so `bytes` alone decides completeness: a set of disjoint ranges
/// inside `[0, length)` totalling `length` bytes can only be the whole object.
/// Tracking coverage as an explicit per-unit set would cost one entry per
/// 64 KiB — sixteen million of them for a terabyte object — to say the same
/// thing.
#[derive(Default)]
struct RangeState {
    segments: BTreeMap<u64, Vec<u8>>,
    bytes: u64,
}

/// Receiver state is keyed by subject identity and outlives connections.
pub struct ReliableReceiver {
    staging: StagingCapacity,
    active: BTreeMap<SubjectId, ActiveObject>,
    range_active: BTreeMap<SubjectId, RangeState>,
    verified: BTreeSet<SubjectId>,
    connections: BTreeSet<ConnectionId>,
    ack_count: u64,
    peak_staging: u64,
}

impl ReliableReceiver {
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

    /// # Errors
    /// Rejects duplicate active objects and invalid suite or empty-object ranges.
    pub fn begin_ranges(&mut self, subject: SubjectId) -> Result<(), Error> {
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
        self.range_active.insert(subject, RangeState::default());
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
        self.receive_verified_range(subject, covered_offset, data, proof)
    }

    fn receive_verified_range(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: &[u8],
        proof: &[u8],
    ) -> Result<(), Error> {
        self.receive_verified_range_impl(subject, covered_offset, Cow::Borrowed(data), proof, false)
    }

    fn receive_verified_range_owned(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: Vec<u8>,
        proof: &[u8],
    ) -> Result<(), Error> {
        self.receive_verified_range_impl(subject, covered_offset, Cow::Owned(data), proof, true)
    }

    fn receive_verified_range_impl(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: Cow<'_, [u8]>,
        proof: &[u8],
        staging_reserved: bool,
    ) -> Result<(), Error> {
        check_range_proof(subject, covered_offset, data.as_ref(), proof)?;
        self.insert_checked_range(subject, covered_offset, data, staging_reserved)
    }

    /// Books a range whose proof [`check_range_proof`] has already held.
    fn insert_checked_range(
        &mut self,
        subject: SubjectId,
        covered_offset: u64,
        data: Cow<'_, [u8]>,
        staging_reserved: bool,
    ) -> Result<(), Error> {
        // A subject whose every byte is verified has no range state left, but a
        // peer may still replay a range it already sent. The replay is checked
        // like any other and then changes nothing.
        let replay = self.verified.contains(&subject);
        if !replay && !self.range_active.contains_key(&subject) {
            return Err(Error::UnknownObject);
        }
        let bytes = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
        let covered_end = covered_offset
            .checked_add(bytes)
            .ok_or(Error::LengthExceeded)?;
        if replay {
            if staging_reserved {
                self.staging.release(bytes);
            }
            return Ok(());
        }
        let next_bytes = {
            let active = self
                .range_active
                .get(&subject)
                .ok_or(Error::UnknownObject)?;
            if let Some(existing) = active.segments.get(&covered_offset) {
                if existing.as_slice() == data.as_ref() {
                    if staging_reserved {
                        self.staging.release(bytes);
                    }
                    return Ok(());
                }
                return Err(Error::ProofInvalid);
            }
            // Accepted segments never overlap, so only the two neighbours of the
            // new offset can conflict. A linear scan would be quadratic across a
            // large object's quarter-million segments.
            let overlaps_earlier = active
                .segments
                .range(..covered_offset)
                .next_back()
                .is_some_and(|(offset, segment)| {
                    let end =
                        offset.saturating_add(u64::try_from(segment.len()).unwrap_or(u64::MAX));
                    covered_offset < end
                });
            let overlaps_later = active
                .segments
                .range(covered_offset..)
                .next()
                .is_some_and(|(offset, _)| *offset < covered_end);
            if overlaps_earlier || overlaps_later {
                return Err(Error::LengthMismatch);
            }
            active
                .bytes
                .checked_add(bytes)
                .ok_or(Error::LengthExceeded)?
        };
        let reserved_here = if staging_reserved {
            false
        } else {
            self.staging.reserve(bytes)?;
            self.peak_staging = self.peak_staging.max(self.staging.used());
            true
        };
        let Some(active) = self.range_active.get_mut(&subject) else {
            if reserved_here {
                self.staging.release(bytes);
            }
            return Err(Error::UnknownObject);
        };
        active.bytes = next_bytes;
        active.segments.insert(covered_offset, data.into_owned());
        Ok(())
    }

    /// Checks a decoded proof bundle without touching receiver state.
    ///
    /// Pure, which is what lets a caller spread verification across threads:
    /// the returned witness carries the verified bytes and can only be built
    /// here, so [`Self::admit_verified_range`] books it without holding the
    /// proof again. Staging is not consulted; what a caller holds between
    /// verifying and admitting is that caller's own bound to keep.
    ///
    /// # Errors
    /// Rejects identity conflicts, duplicate or missing records, unsupported
    /// compression, and proof or range failures.
    pub fn verify_typed_bundle(
        subject: SubjectId,
        bundle: &vot_codec::frames::ProofBundle,
        records: &[vot_codec::frames::DataRecord],
    ) -> Result<VerifiedRange, Error> {
        bundle.validate().map_err(|_| Error::ProofInvalid)?;
        if bundle.object.suite != subject.suite
            || bundle.object.root != subject.root
            || bundle.object.length != subject.length
            || bundle.data_record_count != records.len() as u64
        {
            return Err(Error::LengthMismatch);
        }
        let mut ordered = BTreeMap::new();
        for record in records {
            record.validate().map_err(|_| Error::ProofInvalid)?;
            if record.bundle_id != bundle.bundle_id {
                return Err(Error::ProofInvalid);
            }
            if record.compression != 0 {
                return Err(Error::UnsupportedCompression);
            }
            if ordered.insert(record.record_index, record).is_some() {
                return Err(Error::LengthMismatch);
            }
        }
        let covered_bytes = bundle.covered_length;
        let capacity = usize::try_from(covered_bytes).map_err(|_| Error::LengthExceeded)?;
        let mut data = Vec::with_capacity(capacity);
        for index in 0..bundle.data_record_count {
            let record = ordered.get(&index).ok_or(Error::LengthMismatch)?;
            let expected_offset = bundle
                .covered_offset
                .checked_add(u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?)
                .ok_or(Error::LengthExceeded)?;
            if record.plaintext_offset != expected_offset {
                return Err(Error::LengthMismatch);
            }
            data.extend_from_slice(&record.encoded);
        }
        if data.len() as u64 != covered_bytes {
            return Err(Error::LengthMismatch);
        }
        check_range_proof(subject, bundle.covered_offset, &data, &bundle.proof)?;
        Ok(VerifiedRange {
            subject,
            covered_offset: bundle.covered_offset,
            data,
        })
    }

    /// Books a range [`Self::verify_typed_bundle`] already proved.
    ///
    /// # Errors
    /// Rejects an unknown subject, an overlap with an accepted range, a
    /// conflicting duplicate, or a staging budget the range does not fit.
    pub fn admit_verified_range(&mut self, range: VerifiedRange) -> Result<(), Error> {
        let admitted = self.insert_checked_range(
            range.subject,
            range.covered_offset,
            Cow::Owned(range.data),
            false,
        );
        if admitted.is_ok() {
            self.peak_staging = self.peak_staging.max(self.staging.used());
        }
        admitted
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
        bundle.validate().map_err(|_| Error::ProofInvalid)?;
        if bundle.object.suite != subject.suite
            || bundle.object.root != subject.root
            || bundle.object.length != subject.length
            || bundle.data_record_count != records.len() as u64
        {
            return Err(Error::LengthMismatch);
        }
        let mut ordered = BTreeMap::new();
        for record in records {
            record.validate().map_err(|_| Error::ProofInvalid)?;
            if record.bundle_id != bundle.bundle_id {
                return Err(Error::ProofInvalid);
            }
            if record.compression != 0 {
                return Err(Error::UnsupportedCompression);
            }
            if ordered.insert(record.record_index, record).is_some() {
                return Err(Error::LengthMismatch);
            }
        }
        let covered_bytes = bundle.covered_length;
        let capacity = usize::try_from(covered_bytes).map_err(|_| Error::LengthExceeded)?;
        self.staging.reserve(covered_bytes)?;
        self.peak_staging = self.peak_staging.max(self.staging.used());
        let result = (|| {
            let mut data = Vec::with_capacity(capacity);
            for index in 0..bundle.data_record_count {
                let record = ordered.get(&index).ok_or(Error::LengthMismatch)?;
                let expected_offset = bundle
                    .covered_offset
                    .checked_add(u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?)
                    .ok_or(Error::LengthExceeded)?;
                if record.plaintext_offset != expected_offset {
                    return Err(Error::LengthMismatch);
                }
                data.extend_from_slice(&record.encoded);
            }
            if data.len() as u64 != covered_bytes {
                return Err(Error::LengthMismatch);
            }
            self.receive_verified_range_owned(subject, bundle.covered_offset, data, &bundle.proof)
        })();
        if result.is_err() {
            self.staging.release(covered_bytes);
        }
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
        let active = self
            .range_active
            .remove(&subject)
            .ok_or(Error::UnknownObject)?;
        self.staging
            .release(active.bytes.saturating_add(VERIFIER_RESERVATION));
        self.verified.insert(subject);
        Ok(())
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

/// A range whose proof has held against its subject's root.
///
/// Only [`ReliableReceiver::verify_typed_bundle`] builds one, so holding a
/// value of this type is holding the verification itself; admission books
/// the bytes without seeing the proof again.
#[derive(Debug)]
pub struct VerifiedRange {
    subject: SubjectId,
    covered_offset: u64,
    data: Vec<u8>,
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
}

/// Holds a range's bounds and its proof against the subject's root.
///
/// Pure: nothing here reads or writes receiver state, which is what lets a
/// caller run it on any thread and admit the result on the one that owns
/// the receiver.
///
/// # Errors
/// Rejects a range outside the subject, off the 64 KiB unit grid other than
/// at the object's end, oversized or empty, or whose proof does not hold.
fn check_range_proof(
    subject: SubjectId,
    covered_offset: u64,
    data: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    let bytes = u64::try_from(data.len()).map_err(|_| Error::LengthExceeded)?;
    if bytes == 0 || bytes > MAX_PROOF_RANGE_BYTES {
        return Err(Error::RecordTooLarge);
    }
    let covered_end = covered_offset
        .checked_add(bytes)
        .ok_or(Error::LengthExceeded)?;
    if covered_offset % RANGE_UNIT_BYTES != 0 || covered_end > subject.length {
        return Err(Error::LengthExceeded);
    }
    // A range covers whole 64 KiB units unless it ends the object, the same
    // rule `PROOF_BUNDLE` validation applies on the wire. Both proof suites
    // enforce it too, but stating it here is what lets completion be decided
    // from the accepted byte total alone.
    if covered_end < subject.length && bytes % RANGE_UNIT_BYTES != 0 {
        return Err(Error::LengthExceeded);
    }
    match suite(subject.suite)? {
        Suite::Blake3Bao64 => {
            vot_proof_blake3::verify(&subject.root, subject.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
        Suite::Sha256Bep52 => {
            vot_proof_sha256::verify(&subject.root, subject.length, covered_offset, data, proof)
                .map_err(|_| Error::ProofInvalid)?;
        }
    }
    Ok(())
}

fn suite(id: u16) -> Result<Suite, Error> {
    match id {
        1 => Ok(Suite::Blake3Bao64),
        2 => Ok(Suite::Sha256Bep52),
        _ => Err(Error::UnknownObject),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Job {
    pub priority: u8,
    pub sequence: u64,
    pub subject: SubjectId,
}

impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering {
        (Reverse(self.priority), self.sequence, self.subject).cmp(&(
            Reverse(other.priority),
            other.sequence,
            other.subject,
        ))
    }
}

impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic highest-priority-first planner with FIFO tie breaking.
#[derive(Default)]
pub struct Planner {
    jobs: BTreeSet<Job>,
    next_sequence: u64,
}

impl Planner {
    pub fn push(&mut self, job: Job) {
        let mut job = job;
        job.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.jobs.insert(job);
    }

    pub fn pop(&mut self) -> Option<Job> {
        self.jobs.pop_first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vot_transport_api::{Event, StreamId, TransportAdapter};
    use vot_transport_sim::{Impairment, SimulatorAdapter};

    fn subject(bytes: &[u8]) -> SubjectId {
        SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, bytes).unwrap(),
            length: bytes.len() as u64,
        }
    }

    fn assert_typed_bundle_error(
        subject: SubjectId,
        bundle: &vot_codec::frames::ProofBundle,
        records: &[vot_codec::frames::DataRecord],
        expected: Error,
    ) {
        let staging_limit = VERIFIER_RESERVATION + bundle.covered_length;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver.begin_ranges(subject).unwrap();
        assert_eq!(
            receiver.receive_typed_bundle(subject, bundle, records),
            Err(expected)
        );
    }

    #[test]
    fn reliable_transfer_uses_transport_adapter_contract() {
        let bytes = vec![0x5a; 700_000];
        let subject = subject(&bytes);
        let mut adapter = SimulatorAdapter::default();
        adapter.set_receive_credit(400_000).unwrap();
        for record in bytes.chunks(256 * 1024) {
            adapter.send_reliable(StreamId(7), record).unwrap();
        }
        assert_eq!(adapter.pending_submissions(), 4);
        adapter.flush().unwrap();
        assert_eq!(adapter.receive_credit(), 400_000);

        let mut receiver = ReliableReceiver::new(400_000, 256_000, 400_000).unwrap();
        assert_eq!(receiver.advertised_credit(), 256_000);
        receiver.connected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 1);
        receiver.begin(subject).unwrap();
        let mut events = Vec::new();
        assert_eq!(adapter.poll_batch(&mut events, 8), 3);
        for event in events {
            let Event::Reliable { bytes, .. } = event else {
                panic!("simulator emitted a non-reliable event");
            };
            receiver.receive(subject, &bytes).unwrap();
        }
        receiver.finish(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.peak_staging(), 256 * 1024 + VERIFIER_RESERVATION);
    }

    #[test]
    fn reordered_and_duplicated_delivery_still_verifies_every_range() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        // Each unit carries its own index so the receiver can recover the
        // covered offset from a record that arrived out of order.
        let mut bytes = Vec::with_capacity(unit * 3);
        for index in 0..3_u8 {
            bytes.extend(std::iter::repeat_n(index, unit));
        }
        let subject = subject(&bytes);

        let mut adapter = SimulatorAdapter::with_impairment(Impairment {
            reorder_depth: 2,
            duplicate_every: 2,
            ..Impairment::default()
        })
        .unwrap();
        // One stream per range, which is how ranges are fetched concurrently.
        // A stream is never reordered against itself, so this is the only
        // arrangement in which out-of-order arrival is a real carrier outcome.
        for (index, record) in bytes.chunks(unit).enumerate() {
            adapter
                .send_reliable(StreamId(7 + index as u64), record)
                .unwrap();
        }
        adapter.flush().unwrap();

        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        receiver.begin_ranges(subject).unwrap();
        let mut arrivals = Vec::new();
        while let Some(event) = adapter.poll() {
            let Event::Reliable { bytes: record, .. } = event else {
                panic!("simulator emitted a non-reliable event");
            };
            let index = u64::from(record[0]);
            let offset = index * RANGE_UNIT_BYTES;
            let proof = vot_proof_blake3::prove(&bytes, offset, RANGE_UNIT_BYTES).unwrap();
            receiver
                .receive_range(subject, offset, &record, &proof.proof)
                .unwrap();
            arrivals.push(index);
        }
        // Out of order, with a duplicate the receiver absorbed idempotently.
        assert_eq!(arrivals.len(), 4);
        assert_ne!(arrivals, vec![0, 1, 2, 2], "delivery was not reordered");
        assert_eq!(
            {
                let mut sorted = arrivals.clone();
                sorted.sort_unstable();
                sorted.dedup();
                sorted
            },
            vec![0, 1, 2]
        );
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));
        // The duplicate was not charged twice against staging.
        assert_eq!(
            receiver.peak_staging(),
            3 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION
        );
    }

    #[test]
    fn duplicate_begin_modes_are_rejected_while_active() {
        let object = subject(b"duplicate");
        let mut sequential =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        sequential.begin(object).unwrap();
        assert_eq!(sequential.begin(object), Err(Error::AlreadyReceiving));

        let mut ranged =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        ranged.begin_ranges(object).unwrap();
        assert_eq!(ranged.begin_ranges(object), Err(Error::AlreadyReceiving));
    }

    #[test]
    fn finish_ranges_requires_every_byte_of_the_object() {
        let object = SubjectId {
            suite: 1,
            root: [0; 32],
            length: 2 * RANGE_UNIT_BYTES,
        };
        let mut receiver =
            ReliableReceiver::new(4 * VERIFIER_RESERVATION, 1, 4 * VERIFIER_RESERVATION).unwrap();
        receiver.range_active.insert(
            object,
            RangeState {
                segments: BTreeMap::new(),
                bytes: RANGE_UNIT_BYTES,
            },
        );
        assert_eq!(receiver.finish_ranges(object), Err(Error::LengthMismatch));
        receiver.range_active.insert(
            object,
            RangeState {
                segments: BTreeMap::new(),
                bytes: 2 * RANGE_UNIT_BYTES,
            },
        );
        receiver.finish_ranges(object).unwrap();
        assert!(receiver.is_verified(object));
    }

    #[test]
    fn a_partial_unit_cannot_stand_in_for_a_whole_one() {
        // Both proof suites already reject a range that stops mid-unit before
        // the end of the object. The receiver rejects it first, so deciding
        // completion from `bytes` alone rests on a rule this crate enforces
        // rather than on a property of the proof crates.
        let bytes = vec![0x11; usize::try_from(2 * RANGE_UNIT_BYTES).unwrap()];
        let object = subject(&bytes);
        let prefix = vot_proof_blake3::prove(&bytes, 0, 1024).unwrap();
        let staging = 4 * RANGE_UNIT_BYTES + VERIFIER_RESERVATION;
        let mut receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        receiver.begin_ranges(object).unwrap();
        assert_eq!(
            receiver.receive_range(object, 0, &bytes[..1024], &prefix.proof),
            Err(Error::LengthExceeded)
        );

        // The final range may be short, because it ends the object.
        let short = vec![0x22; usize::try_from(RANGE_UNIT_BYTES).unwrap() + 7];
        let short_object = subject(&short);
        let tail_offset = RANGE_UNIT_BYTES;
        let tail = vot_proof_blake3::prove(&short, tail_offset, 7).unwrap();
        let mut tail_receiver = ReliableReceiver::new(staging, RANGE_UNIT_BYTES, staging).unwrap();
        tail_receiver.begin_ranges(short_object).unwrap();
        tail_receiver
            .receive_range(
                short_object,
                tail_offset,
                &short[usize::try_from(tail_offset).unwrap()..],
                &tail.proof,
            )
            .unwrap();
    }

    #[test]
    fn path_stats_update_staging_bdp_target() {
        let mut receiver = ReliableReceiver::new(4096, 1, 4096).unwrap();
        assert_eq!(receiver.advertised_credit(), 1);
        receiver.observe_path_stats(PathStats {
            pacing_rate_bps: Some(8_000_000),
            smoothed_rtt_us: Some(1_000),
            congestion_window_bytes: None,
            mtu_bytes: Some(1500),
        });
        assert_eq!(receiver.advertised_credit(), 1_000);
        receiver.observe_path_stats(PathStats {
            pacing_rate_bps: None,
            smoothed_rtt_us: None,
            congestion_window_bytes: Some(2_048),
            mtu_bytes: Some(1500),
        });
        assert_eq!(receiver.advertised_credit(), 2_048);

        let mut zero_bdp = ReliableReceiver::new(4096, 1, 4096).unwrap();
        zero_bdp.observe_path_stats(PathStats {
            pacing_rate_bps: Some(1),
            smoothed_rtt_us: Some(1),
            congestion_window_bytes: None,
            mtu_bytes: None,
        });
        assert_eq!(zero_bdp.advertised_credit(), 1);
        zero_bdp.observe_path_stats(PathStats {
            pacing_rate_bps: None,
            smoothed_rtt_us: None,
            congestion_window_bytes: Some(0),
            mtu_bytes: None,
        });
        assert_eq!(zero_bdp.advertised_credit(), 1);
    }

    #[test]
    fn verified_state_survives_disconnect_and_ack_has_no_assurance_effect() {
        let bytes = b"verified object";
        let subject = subject(bytes);
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.connected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 1);
        receiver.begin(subject).unwrap();
        assert_eq!(receiver.ack_count(), 0);
        receiver.acknowledged(TransportAck::new(4, 99));
        assert!(!receiver.is_verified(subject));
        receiver.receive(subject, bytes).unwrap();
        receiver.finish(subject).unwrap();
        receiver.disconnected(ConnectionId(1));
        assert_eq!(receiver.connection_count(), 0);
        receiver.connected(ConnectionId(2));
        assert_eq!(receiver.connection_count(), 1);
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.ack_count(), 1);
    }

    #[test]
    fn mismatched_root_and_overrun_are_rejected() {
        let bytes = b"expected";
        let mut wrong = subject(bytes);
        wrong.root[0] ^= 1;
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.begin(wrong).unwrap();
        receiver.receive(wrong, bytes).unwrap();
        assert_eq!(receiver.finish(wrong), Err(Error::RootMismatch));

        let short = SubjectId {
            length: 2,
            ..subject(b"ab")
        };
        receiver.begin(short).unwrap();
        assert_eq!(receiver.receive(short, b"abc"), Err(Error::LengthExceeded));
    }

    #[test]
    fn planner_is_priority_then_fifo() {
        let first = subject(b"a");
        let second = subject(b"b");
        let mut planner = Planner::default();
        planner.push(Job {
            priority: 0,
            sequence: 0,
            subject: first,
        });
        planner.push(Job {
            priority: 9,
            sequence: 1,
            subject: second,
        });
        let higher = Job {
            priority: 9,
            sequence: 1,
            subject: second,
        };
        let lower = Job {
            priority: 0,
            sequence: 0,
            subject: first,
        };
        assert_eq!(higher.partial_cmp(&lower), Some(Ordering::Less));
        assert_eq!(planner.pop().unwrap().subject, second);
        assert_eq!(planner.pop().unwrap().subject, first);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn range_validation_and_ownership_boundaries_are_explicit() {
        let unit = usize::try_from(RANGE_UNIT_BYTES).unwrap();
        let bytes = vec![0x5a; unit * 3];
        let range_subject = subject(&bytes);
        let make_receiver = || {
            ReliableReceiver::new(
                8 * VERIFIER_RESERVATION,
                8 * VERIFIER_RESERVATION,
                8 * VERIFIER_RESERVATION,
            )
            .unwrap()
        };

        let mut receiver = make_receiver();
        receiver.begin_ranges(range_subject).unwrap();
        assert_eq!(
            receiver.receive_range(range_subject, 0, &[], &[]),
            Err(Error::RecordTooLarge)
        );
        let too_large = vec![0; usize::try_from(MAX_PROOF_RANGE_BYTES + 1).unwrap()];
        assert_eq!(
            receiver.receive_range(range_subject, 0, &too_large, &[]),
            Err(Error::RecordTooLarge)
        );

        let large_range_subject = SubjectId {
            suite: 1,
            root: [0; 32],
            length: MAX_PROOF_RANGE_BYTES,
        };
        let exact_max = vec![0; usize::try_from(MAX_PROOF_RANGE_BYTES).unwrap()];
        let mut exact_receiver = make_receiver();
        exact_receiver.begin_ranges(large_range_subject).unwrap();
        assert_eq!(
            exact_receiver.receive_range(large_range_subject, 0, &exact_max, &[]),
            Err(Error::ProofInvalid)
        );

        let one = &bytes[..unit];
        let first_proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut misaligned = make_receiver();
        misaligned.begin_ranges(range_subject).unwrap();
        assert_eq!(
            misaligned.receive_range(range_subject, 1, one, &[]),
            Err(Error::LengthExceeded)
        );

        let exact_range_subject = subject(one);
        let exact_proof = vot_proof_blake3::prove(one, 0, RANGE_UNIT_BYTES).unwrap();
        let mut exact_end = make_receiver();
        exact_end.begin_ranges(exact_range_subject).unwrap();
        exact_end
            .receive_range(exact_range_subject, 0, one, &exact_proof.proof)
            .unwrap();

        let mut duplicate = make_receiver();
        duplicate.begin_ranges(range_subject).unwrap();
        duplicate
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();
        duplicate
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();

        let first_two = &bytes[..unit * 2];
        let overlap_data = &bytes[unit..unit * 2];
        let first_two_proof = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES * 2).unwrap();
        let overlap_proof =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let mut overlap = make_receiver();
        overlap.begin_ranges(range_subject).unwrap();
        overlap
            .receive_range(range_subject, 0, first_two, &first_two_proof.proof)
            .unwrap();
        assert_eq!(
            overlap.receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                overlap_data,
                &overlap_proof.proof
            ),
            Err(Error::LengthMismatch)
        );

        let mut overlap_from_below = make_receiver();
        overlap_from_below.begin_ranges(range_subject).unwrap();
        overlap_from_below
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                overlap_data,
                &overlap_proof.proof,
            )
            .unwrap();
        assert_eq!(
            overlap_from_below.receive_range(range_subject, 0, first_two, &first_two_proof.proof),
            Err(Error::LengthMismatch)
        );

        let second_proof =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let mut adjacent = make_receiver();
        adjacent.begin_ranges(range_subject).unwrap();
        adjacent
            .receive_range(range_subject, 0, one, &first_proof.proof)
            .unwrap();
        adjacent
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                &bytes[unit..unit * 2],
                &second_proof.proof,
            )
            .unwrap();

        let mut middle = make_receiver();
        middle.begin_ranges(range_subject).unwrap();
        middle
            .receive_range(
                range_subject,
                RANGE_UNIT_BYTES,
                &bytes[unit..unit * 2],
                &second_proof.proof,
            )
            .unwrap();
        assert_eq!(middle.range_active[&range_subject].bytes, RANGE_UNIT_BYTES);
        assert_eq!(
            middle.range_active[&range_subject]
                .segments
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![RANGE_UNIT_BYTES]
        );
        assert_eq!(
            middle.finish_ranges(range_subject),
            Err(Error::LengthMismatch)
        );
    }

    #[test]
    fn proof_bearing_ranges_accept_out_of_order_for_both_suites() {
        let bytes = vec![0x5a; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];

        let blake_subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let second_blake =
            vot_proof_blake3::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let first_blake = vot_proof_blake3::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut blake_receiver = ReliableReceiver::new(
            4 * VERIFIER_RESERVATION,
            2 * VERIFIER_RESERVATION,
            4 * VERIFIER_RESERVATION,
        )
        .unwrap();
        blake_receiver.begin_ranges(blake_subject).unwrap();
        blake_receiver
            .receive_range(
                blake_subject,
                second_blake.covered_offset,
                &second_blake.data,
                &second_blake.proof,
            )
            .unwrap();
        blake_receiver
            .receive_range(
                blake_subject,
                first_blake.covered_offset,
                &first_blake.data,
                &first_blake.proof,
            )
            .unwrap();
        blake_receiver.finish_ranges(blake_subject).unwrap();
        assert!(blake_receiver.is_verified(blake_subject));

        let sha_subject = SubjectId {
            suite: 2,
            root: vot_verifier::root(Suite::Sha256Bep52, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let second_sha =
            vot_proof_sha256::prove(&bytes, RANGE_UNIT_BYTES, RANGE_UNIT_BYTES).unwrap();
        let first_sha = vot_proof_sha256::prove(&bytes, 0, RANGE_UNIT_BYTES).unwrap();
        let mut sha_receiver = ReliableReceiver::new(
            4 * VERIFIER_RESERVATION,
            2 * VERIFIER_RESERVATION,
            4 * VERIFIER_RESERVATION,
        )
        .unwrap();
        sha_receiver.begin_ranges(sha_subject).unwrap();
        sha_receiver
            .receive_range(
                sha_subject,
                second_sha.covered_offset,
                &second_sha.data,
                &second_sha.proof,
            )
            .unwrap();
        sha_receiver
            .receive_range(
                sha_subject,
                first_sha.covered_offset,
                &first_sha.data,
                &first_sha.proof,
            )
            .unwrap();
        sha_receiver.finish_ranges(sha_subject).unwrap();
        assert!(sha_receiver.is_verified(sha_subject));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn typed_wire_bundle_reassembles_records_before_root_verification() {
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = vot_codec::frames::ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object: vot_codec::frames::ObjectId {
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
        let records = [
            vot_codec::frames::DataRecord {
                bundle_id: [4; 16],
                record_index: 1,
                plaintext_offset: RANGE_UNIT_BYTES,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[usize::try_from(RANGE_UNIT_BYTES).unwrap()..].to_vec(),
            },
            vot_codec::frames::DataRecord {
                bundle_id: [4; 16],
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: RANGE_UNIT_BYTES,
                compression: 0,
                encoded: bytes[..usize::try_from(RANGE_UNIT_BYTES).unwrap()].to_vec(),
            },
        ];
        let mut bundle_wire = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::ProofBundle(bundle.clone()),
            &mut bundle_wire,
        )
        .unwrap();
        let (bundle_frame, bundle_used) =
            vot_codec::frames::decode(&bundle_wire, vot_codec::DecodeLimits::default()).unwrap();
        assert_eq!(bundle_used, bundle_wire.len());
        let vot_codec::frames::TypedFrame::ProofBundle(bundle) = bundle_frame else {
            panic!("wire frame was not a proof bundle");
        };
        let mut decoded_records = Vec::with_capacity(records.len());
        for record in &records {
            let mut record_wire = Vec::new();
            vot_codec::frames::encode(
                &vot_codec::frames::TypedFrame::DataRecord(record.clone()),
                &mut record_wire,
            )
            .unwrap();
            let (record_frame, record_used) =
                vot_codec::frames::decode(&record_wire, vot_codec::DecodeLimits::default())
                    .unwrap();
            assert_eq!(record_used, record_wire.len());
            let vot_codec::frames::TypedFrame::DataRecord(record) = record_frame else {
                panic!("wire frame was not a data record");
            };
            decoded_records.push(record);
        }

        let staging_limit = VERIFIER_RESERVATION + bytes.len() as u64;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver.begin_ranges(subject).unwrap();
        assert_eq!(receiver.advertised_credit(), bytes.len() as u64);
        receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        assert_eq!(receiver.advertised_credit(), 0);
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));
        assert_eq!(receiver.advertised_credit(), staging_limit);

        let mut bad_bundle = bundle.clone();
        bad_bundle.object.suite = 2;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.object.root[0] ^= 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.object.length += 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records, Error::LengthMismatch);
        bad_bundle = bundle.clone();
        bad_bundle.data_record_count -= 1;
        assert_typed_bundle_error(subject, &bad_bundle, &records[..1], Error::LengthMismatch);

        let mut bad_records = records.to_vec();
        bad_records[1].plaintext_offset = RANGE_UNIT_BYTES;
        assert_typed_bundle_error(subject, &bundle, &bad_records, Error::LengthMismatch);

        let duplicate_limit = VERIFIER_RESERVATION + 2 * bundle.covered_length;
        let mut duplicate_receiver =
            ReliableReceiver::new(duplicate_limit, duplicate_limit, duplicate_limit).unwrap();
        duplicate_receiver.begin_ranges(subject).unwrap();
        duplicate_receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        let credit_before_duplicate = duplicate_receiver.advertised_credit();
        duplicate_receiver
            .receive_typed_bundle(subject, &bundle, &decoded_records)
            .unwrap();
        assert_eq!(
            duplicate_receiver.advertised_credit(),
            credit_before_duplicate
        );
    }

    #[test]
    fn a_witness_verifies_off_thread_and_admits_on_it() {
        // The two-phase surface: verification is pure and can run anywhere;
        // admission books what the witness proves without seeing the proof
        // again, and refuses what verification never touched.
        let bytes = vec![0x3c; usize::try_from(RANGE_UNIT_BYTES * 2).unwrap()];
        let subject = SubjectId {
            suite: 1,
            root: vot_verifier::root(Suite::Blake3Bao64, &bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
        let bundle = vot_codec::frames::ProofBundle {
            request_id: [3; 16],
            bundle_id: [4; 16],
            object: vot_codec::frames::ObjectId {
                suite: subject.suite,
                root: subject.root,
                length: subject.length,
            },
            requested_offset: 0,
            requested_length: subject.length,
            covered_offset: proof.covered_offset,
            covered_length: proof.data.len() as u64,
            data_record_count: 1,
            total_plaintext_length: proof.data.len() as u64,
            proof: proof.proof,
        };
        let records = [vot_codec::frames::DataRecord {
            bundle_id: [4; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: bytes.len() as u64,
            compression: 0,
            encoded: bytes.clone(),
        }];

        // Verified on another thread, as the parallel receiver runs it.
        let range = std::thread::scope(|scope| {
            scope
                .spawn(|| ReliableReceiver::verify_typed_bundle(subject, &bundle, &records))
                .join()
                .expect("a verifier thread")
        })
        .expect("a verified range");
        assert_eq!(range.len(), bytes.len() as u64);
        assert!(!range.is_empty());

        let staging_limit = VERIFIER_RESERVATION + bytes.len() as u64;
        let mut receiver =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        receiver.begin_ranges(subject).unwrap();
        let credit_before = receiver.advertised_credit();
        receiver.admit_verified_range(range).unwrap();
        assert!(
            receiver.advertised_credit() < credit_before,
            "admission never charged staging"
        );
        receiver.finish_ranges(subject).unwrap();
        assert!(receiver.is_verified(subject));

        // A corrupt payload never becomes a witness.
        let mut bad_records = records.to_vec();
        bad_records[0].encoded[0] ^= 1;
        assert!(matches!(
            ReliableReceiver::verify_typed_bundle(subject, &bundle, &bad_records),
            Err(Error::ProofInvalid)
        ));

        // A witness for a subject no receiver opened is refused at admission.
        let stray = ReliableReceiver::verify_typed_bundle(subject, &bundle, &records).unwrap();
        let mut closed =
            ReliableReceiver::new(staging_limit, staging_limit, staging_limit).unwrap();
        assert!(matches!(
            closed.admit_verified_range(stray),
            Err(Error::UnknownObject)
        ));

        // A replayed witness changes nothing, the duplicate rule ranges keep.
        let again = ReliableReceiver::verify_typed_bundle(subject, &bundle, &records).unwrap();
        let credit_verified = receiver.advertised_credit();
        receiver.admit_verified_range(again).unwrap();
        assert_eq!(receiver.advertised_credit(), credit_verified);
    }

    #[test]
    fn sha256_suite_transfer_is_verified() {
        let bytes = b"sha256 tree content";
        let subject = SubjectId {
            suite: 2,
            root: vot_verifier::root(Suite::Sha256Bep52, bytes).unwrap(),
            length: bytes.len() as u64,
        };
        let mut receiver = ReliableReceiver::new(2 * VERIFIER_RESERVATION, 1024, 1024).unwrap();
        receiver.begin(subject).unwrap();
        receiver.receive(subject, bytes).unwrap();
        receiver.finish(subject).unwrap();
        assert!(receiver.is_verified(subject));
    }

    #[test]
    fn active_verifiers_are_bounded_by_staging_capacity() {
        let first = subject(b"first");
        let second = subject(b"second");
        let mut receiver = ReliableReceiver::new(
            VERIFIER_RESERVATION,
            VERIFIER_RESERVATION,
            VERIFIER_RESERVATION,
        )
        .unwrap();
        receiver.begin(first).unwrap();
        assert_eq!(receiver.advertised_credit(), 0);
        assert_eq!(
            receiver.begin(second),
            Err(Error::Staging(vot_transport_api::Error::StagingExhausted))
        );
        receiver.receive(first, b"first").unwrap_err();
        assert_eq!(receiver.finish(first), Err(Error::LengthMismatch));
        receiver.begin(second).unwrap();
    }
}
