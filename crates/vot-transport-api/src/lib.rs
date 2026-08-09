//! Backend-neutral VOT transport contract and bounded receiver credit.

#![forbid(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const ALPN: &[u8] = b"vot-draft-05";
pub const MIN_CONTROL_FRAME_PAYLOAD: usize = vot_codec::MIN_CONTROL_FRAME_PAYLOAD;
pub const MAX_CONTROL_FRAME_PAYLOAD: usize = vot_codec::DEFAULT_MAX_UNKNOWN_PAYLOAD;
pub const MAX_DATA_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
/// A VOT frame has at most two eight-byte QUIC-varint envelope fields.
pub const MAX_FRAME_ENVELOPE_BYTES: usize = 16;
pub const MAX_CONTROL_FRAME_WIRE_BYTES: usize =
    MAX_CONTROL_FRAME_PAYLOAD + MAX_FRAME_ENVELOPE_BYTES;
pub const MAX_DATA_RECORD_WIRE_BYTES: usize = MAX_DATA_RECORD_BYTES + MAX_FRAME_ENVELOPE_BYTES;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StreamId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

/// A transport acknowledgement is delivery evidence only.
///
/// ```compile_fail
/// use vot_journal::DurableWitness;
/// use vot_transport_api::TransportAck;
///
/// let durable: DurableWitness = TransportAck::new(1, 10).into();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAck {
    stream: StreamId,
    sequence: u64,
}

impl TransportAck {
    #[must_use]
    pub const fn new(stream: u64, sequence: u64) -> Self {
        Self {
            stream: StreamId(stream),
            sequence,
        }
    }

    #[must_use]
    pub const fn stream(self) -> StreamId {
        self.stream
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramSendState {
    Queued,
    Sent,
    Acknowledged,
    SuspectedLost,
    Canceled,
}

/// A payload whose allocation can be shared between the transport driver and
/// application workers.
pub type Payload = Arc<[u8]>;

#[must_use]
pub fn shared_payload(bytes: &[u8]) -> Payload {
    Arc::from(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Connected(ConnectionId),
    Disconnected(ConnectionId),
    Control(Payload),
    Reliable {
        stream: StreamId,
        sequence: u64,
        bytes: Payload,
    },
    Acknowledged(TransportAck),
    DatagramState {
        context: u64,
        state: DatagramSendState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfiguration,
    RecordTooLarge,
    OutboundQueueFull,
    InboundQueueFull,
    StagingExhausted,
    ArithmeticOverflow,
    Unsupported,
    Backend,
    /// A peer used more lanes than this endpoint advertised it would carry.
    LaneLimitExceeded,
    /// A ledger released more than it held. Nothing it reports afterwards can
    /// be trusted, so it grants nothing until it is rebuilt.
    AccountingPoisoned,
}

/// A batch that stopped part way through.
///
/// `admitted` is how many records the adapter took, which is not the same as
/// how many went out: every adapter here submits into a queue that a later
/// `flush` drains, and a carrier torn down before that flush drops what it
/// still holds. So this says which records the adapter now owns, and a
/// caller deciding what to resend has to know whether the carrier survived.
/// Resending from zero duplicates; resending from `admitted` after a
/// teardown loses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchFailure {
    /// How many records of the batch the adapter took ownership of.
    ///
    /// Zero for every adapter this workspace ships, because they share one
    /// preflight that checks the whole batch's count and bytes before any of
    /// it is submitted, and nothing between that check and the loop can
    /// fail. The field exists for an adapter whose backend can refuse part
    /// way, and reporting it is how such an adapter says so rather than
    /// silently leaving the caller to guess. This crate's tests build one to
    /// hold the default implementation to that.
    pub admitted: usize,
    /// What stopped the rest.
    pub error: Error,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathStats {
    /// Smoothed round-trip time in microseconds, when available.
    pub smoothed_rtt_us: Option<u64>,
    /// Current congestion window in bytes, when available.
    pub congestion_window_bytes: Option<u64>,
    /// Current path MTU in bytes, when available.
    pub mtu_bytes: Option<u64>,
    /// Current pacing rate in bits per second, when available.
    pub pacing_rate_bps: Option<u64>,
    /// Packets declared lost over the connection's lifetime, when counted.
    pub lost_packets: Option<u64>,
    /// Of the declared losses, how many a later ACK disproved. Spurious losses
    /// indicate a detector issue; the rest are real drops.
    pub spurious_lost_packets: Option<u64>,
    /// Packets this endpoint transmitted, when counted. Each retransmission
    /// counts as its own packet. Cross-engine comparison is approximate.
    pub packets_sent: Option<u64>,
    /// Packets this endpoint received, when counted.
    pub packets_received: Option<u64>,
}

/// Latched event signal for [`TransportAdapter::wait_for_event`]. A raise
/// wakes a subsequent wait so events queued between poll and wait are not missed.
#[derive(Debug, Default)]
pub struct EventSignal {
    raised: Mutex<bool>,
    arrived: Condvar,
}

impl EventSignal {
    /// Records that an event was queued and wakes any waiter.
    pub fn raise(&self) {
        if let Ok(mut raised) = self.raised.lock() {
            *raised = true;
        }
        self.arrived.notify_all();
    }

    /// Returns once [`EventSignal::raise`] has been called since the last
    /// wait consumed it, or after `bound`. May return early spuriously.
    pub fn wait(&self, bound: Duration) {
        let Ok(mut raised) = self.raised.lock() else {
            return;
        };
        if !*raised {
            let Ok((woken, _)) = self.arrived.wait_timeout(raised, bound) else {
                return;
            };
            raised = woken;
        }
        *raised = false;
    }
}

pub trait TransportAdapter {
    /// # Errors
    /// Reports a backend or protocol limit failure.
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error>;

    /// Sends an already shared control payload without an adapter-side copy.
    ///
    /// # Errors
    /// Propagates backend or protocol limit failures.
    fn send_control_shared(&mut self, frame: Payload) -> Result<(), Error> {
        self.send_control(&frame)
    }

    /// # Errors
    /// Rejects records larger than 256 KiB and backend failures.
    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error>;

    /// Sends an already shared reliable payload. Adapters can override this to
    /// avoid another application-level copy.
    ///
    /// # Errors
    /// Propagates backend or protocol limit failures.
    fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.send_reliable(stream, &record)
    }

    /// Checks a reliable batch without changing adapter state.
    ///
    /// # Errors
    /// Rejects protocol-limit or queue-capacity failures before submission.
    fn preflight_reliable_batch(
        &self,
        _stream: StreamId,
        records: &[Payload],
    ) -> Result<(), Error> {
        for record in records {
            validate_data_record(record)?;
        }
        Ok(())
    }

    /// Submits a batch before the caller requests a backend flush.
    ///
    /// Not atomic. Preflight rejects the whole batch before anything is
    /// submitted, but a backend that fails part way has already taken the
    /// records before it, and no default implementation over a per-record
    /// send can unsend them. [`BatchFailure::admitted`] says how many, and
    /// its documentation says what that does and does not mean. An adapter
    /// whose backend submits atomically overrides this and reports
    /// `admitted: 0` on every failure, which is what every adapter here
    /// does by construction.
    ///
    /// # Errors
    /// Reports the first backend or protocol limit failure, with the count
    /// of records the adapter took. Preflight failures report zero.
    fn send_reliable_batch(
        &mut self,
        stream: StreamId,
        records: &[Payload],
    ) -> Result<(), BatchFailure> {
        self.preflight_reliable_batch(stream, records)
            .map_err(|error| BatchFailure { admitted: 0, error })?;
        for (admitted, record) in records.iter().enumerate() {
            self.send_reliable_shared(stream, record.clone())
                .map_err(|error| BatchFailure { admitted, error })?;
        }
        Ok(())
    }

    /// Sends an experimental unreliable datagram.
    ///
    /// # Errors
    /// Returns `Error::Unsupported` when the backend has no datagram path.
    fn send_datagram(&mut self, _context: u64, _payload: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// Flushes pending application submissions into the backend.
    ///
    /// # Errors
    /// Reports a backend failure.
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Returns the next backend event without blocking.
    fn poll(&mut self) -> Option<Event>;

    /// Blocks until an event may be available, or for at most `bound`.
    /// Spurious returns are allowed. Always bounded, never indefinite.
    #[allow(
        clippy::disallowed_methods,
        reason = "the default is a sleep by contract; the simulator's ban on \
                  sleeping guards its own deterministic code, and its adapter \
                  is never waited on because it delivers before flush returns"
    )]
    fn wait_for_event(&mut self, bound: Duration) {
        std::thread::sleep(bound);
    }

    /// Drains at most limit events without changing their ordering.
    fn poll_batch(&mut self, out: &mut Vec<Event>, limit: usize) -> usize {
        let mut drained = 0;
        while drained < limit {
            let Some(event) = self.poll() else {
                break;
            };
            out.push(event);
            drained += 1;
        }
        drained
    }

    /// Returns backend path measurements when available.
    fn path_stats(&self) -> Option<PathStats> {
        None
    }

    /// # Errors
    /// Reports a backend failure. Credit is absolute, not additive.
    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error>;

    /// Ends the session under a registered `spec/registries.md` close code,
    /// for a peer that broke the protocol.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the backend cannot signal a code.
    fn close(&mut self, _code: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The limits this endpoint will hold a peer to, so a caller can check that
    /// what it advertises is what the carrier enforces.
    fn receive_limits(&self) -> Option<ReceiveLimits> {
        None
    }

    /// Applies the peer's advertised control-frame limit to what is sent.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the backend enforces no such bound,
    /// and [`Error::InvalidConfiguration`] for a limit outside the protocol
    /// range.
    fn set_control_payload_limit(&mut self, _limit: usize) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

/// Limits an endpoint advertises and enforces. Built against the inbound
/// queue capacity so advertised limits are always deliverable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveLimits {
    control_payload: usize,
    lanes: usize,
}

impl ReceiveLimits {
    /// Derives the limits from what a session will advertise.
    ///
    /// # Errors
    /// Rejects a control-frame limit outside the protocol range or larger than
    /// the queue can hold with its envelope, and a lane limit that does not
    /// fit.
    pub fn advertised(
        settings: &vot_codec::Settings,
        inbound_byte_capacity: usize,
    ) -> Result<Self, Error> {
        for (setting, value) in settings.advertised() {
            if !vot_codec::setting_in_range(setting, value) {
                return Err(Error::InvalidConfiguration);
            }
        }
        let control_payload = usize::try_from(settings.max_control_frame_payload)
            .map_err(|_| Error::InvalidConfiguration)?;
        validate_control_payload_limit(control_payload)?;
        let record_payload = usize::try_from(settings.max_data_record_payload)
            .map_err(|_| Error::InvalidConfiguration)?;
        for payload in [control_payload, record_payload] {
            let wire = payload
                .checked_add(MAX_FRAME_ENVELOPE_BYTES)
                .ok_or(Error::ArithmeticOverflow)?;
            if wire > inbound_byte_capacity {
                return Err(Error::InvalidConfiguration);
            }
        }
        let lanes = usize::try_from(settings.reliable_lane_limit)
            .map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self {
            control_payload,
            lanes,
        })
    }

    /// The control-frame payload this endpoint will reassemble.
    #[must_use]
    pub const fn control_payload(self) -> usize {
        self.control_payload
    }

    /// Peer lanes this endpoint will carry at once.
    #[must_use]
    pub const fn lanes(self) -> usize {
        self.lanes
    }

    /// Whether these limits match what `settings` advertises.
    #[must_use]
    pub fn match_settings(self, settings: &vot_codec::Settings) -> bool {
        u64::try_from(self.control_payload) == Ok(settings.max_control_frame_payload)
            && u64::try_from(self.lanes) == Ok(settings.reliable_lane_limit)
    }
}

/// Sole source of truth for receiver staging usage and advertised credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingCapacity {
    limit: u64,
    used: u64,
    bdp_target: u64,
    configured_max: u64,
    poisoned: bool,
}

impl StagingCapacity {
    /// # Errors
    /// Rejects zero limits or a configured maximum above the staging limit.
    pub const fn new(limit: u64, bdp_target: u64, configured_max: u64) -> Result<Self, Error> {
        if limit == 0 || configured_max == 0 || configured_max > limit {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            limit,
            used: 0,
            bdp_target,
            configured_max,
            poisoned: false,
        })
    }

    /// # Errors
    /// Rejects arithmetic overflow, a reservation beyond the hard limit, or a
    /// ledger that has already over-released.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::AccountingPoisoned);
        }
        let next = self
            .used
            .checked_add(bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        if next > self.limit {
            return Err(Error::StagingExhausted);
        }
        self.used = next;
        Ok(())
    }

    /// Gives back a reservation.
    ///
    /// Releasing more than is held is a bug in the caller's accounting, not a
    /// condition to absorb: subtracting to zero would hand out capacity
    /// nobody earned. The ledger poisons instead and grants nothing
    /// afterwards, until [`StagingCapacity::rebuilt`] replaces it. This
    /// returns nothing because one of its callers is a `Drop`, which has
    /// nowhere to put a failure.
    ///
    /// A poisoned ledger reads as fully used rather than fully free. What is
    /// actually outstanding is no longer known, and of the two wrong answers
    /// the one that grants nothing is the safe one.
    pub const fn release(&mut self, bytes: u64) {
        if let Some(used) = self.used.checked_sub(bytes) {
            self.used = used;
        } else {
            self.used = self.limit;
            self.poisoned = true;
        }
    }

    /// A ledger with this one's configuration and nothing outstanding.
    ///
    /// The way back from a poisoned ledger, and the only one: what it holds
    /// cannot be trusted, so recovery means starting the accounting over
    /// rather than adjusting it. Only for a caller that has torn down
    /// everything holding a reservation, since every live permit is
    /// forgotten.
    #[must_use]
    pub const fn rebuilt(&self) -> Self {
        Self {
            limit: self.limit,
            used: 0,
            bdp_target: self.bdp_target,
            configured_max: self.configured_max,
            poisoned: false,
        }
    }

    /// Whether this ledger has released more than it held.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Updates the current BDP target while preserving the configured hard cap.
    pub fn set_bdp_target(&mut self, bdp_target: u64) {
        self.bdp_target = bdp_target;
    }

    /// What is held. A poisoned ledger reports its whole limit, because what
    /// it actually holds is no longer known and that is the answer that
    /// grants nothing.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// What is free. A poisoned ledger has nothing free: it does not know
    /// what it holds, and reporting the limit as available is how the
    /// over-release would become capacity somebody spends.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        if self.poisoned {
            return 0;
        }
        self.limit.saturating_sub(self.used)
    }

    /// Credit is a pure function of the current staging state, and a
    /// poisoned ledger has no remaining capacity to derive it from.
    #[must_use]
    pub fn advertised_credit(&self) -> u64 {
        let target = self.bdp_target.min(self.configured_max);
        self.remaining().min(target)
    }
}

/// Validates the wire length of a reliable `DATA_RECORD` submission.
///
/// # Errors
/// Returns [`Error::RecordTooLarge`] when the encoded record exceeds the
/// payload limit plus the bounded envelope.
pub fn validate_data_record(record: &[u8]) -> Result<(), Error> {
    if record.len() > MAX_DATA_RECORD_WIRE_BYTES {
        Err(Error::RecordTooLarge)
    } else {
        Ok(())
    }
}

/// The most a backend may send under a peer's advertised limit.
/// Capped at the smaller of the peer limit and the outbound queue.
#[must_use]
pub fn effective_send_limit(peer_limit: usize, outbound_byte_capacity: usize) -> usize {
    // Clamped to protocol minimum.
    peer_limit
        .min(outbound_byte_capacity.saturating_sub(MAX_FRAME_ENVELOPE_BYTES))
        .max(MIN_CONTROL_FRAME_PAYLOAD)
}

/// Validates a negotiated control-frame payload limit.
///
/// # Errors
/// Returns [`Error::InvalidConfiguration`] when the limit is below the
/// protocol minimum or exceeds the codec hard maximum.
pub fn validate_control_payload_limit(limit: usize) -> Result<(), Error> {
    if (MIN_CONTROL_FRAME_PAYLOAD..=vot_codec::HARD_MAX_FRAME_PAYLOAD).contains(&limit) {
        Ok(())
    } else {
        Err(Error::InvalidConfiguration)
    }
}

/// Validates the wire length of a control-frame submission.
///
/// # Errors
/// Returns [`Error::InvalidConfiguration`] for an invalid negotiated limit,
/// [`Error::ArithmeticOverflow`] for an unrepresentable wire bound, or
/// [`Error::RecordTooLarge`] when the frame is too large.
pub fn validate_control_frame(frame: &[u8], payload_limit: usize) -> Result<(), Error> {
    validate_control_payload_limit(payload_limit)?;
    let wire_limit = payload_limit
        .checked_add(MAX_FRAME_ENVELOPE_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    if frame.len() > wire_limit {
        Err(Error::RecordTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct ContractAdapter {
        controls: Vec<Vec<u8>>,
        reliable: Vec<(StreamId, Vec<u8>)>,
        events: VecDeque<Event>,
        credits: Vec<u64>,
        /// How many reliable records this backend takes before it starts
        /// failing. `None` takes everything.
        reliable_failures_after: Option<usize>,
    }

    impl TransportAdapter for ContractAdapter {
        fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
            self.controls.push(frame.to_vec());
            Ok(())
        }

        fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
            if self.reliable_failures_after == Some(self.reliable.len()) {
                return Err(Error::Backend);
            }
            self.reliable.push((stream, record.to_vec()));
            Ok(())
        }

        fn poll(&mut self) -> Option<Event> {
            self.events.pop_front()
        }

        fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
            self.credits.push(bytes);
            Ok(())
        }
    }

    #[test]
    fn flow_credit_is_derived_from_remaining_staging() {
        let mut staging = StagingCapacity::new(1024, 800, 900).unwrap();
        assert_eq!(staging.advertised_credit(), 800);
        staging.reserve(400).unwrap();
        assert_eq!(staging.used(), 400);
        assert_eq!(staging.advertised_credit(), 624);
        staging.reserve(600).unwrap();
        assert_eq!(staging.advertised_credit(), 24);
        assert_eq!(staging.reserve(25), Err(Error::StagingExhausted));
        assert_eq!(staging.used(), 1000);
        staging.release(600);
        assert_eq!(staging.advertised_credit(), 624);
        staging.release(400);
        assert_eq!(staging.advertised_credit(), 800);

        let mut exact = StagingCapacity::new(10, 10, 10).unwrap();
        exact.reserve(10).unwrap();
        assert_eq!(exact.used(), 10);
        assert_eq!(exact.advertised_credit(), 0);
    }

    #[test]
    fn releasing_more_than_was_held_poisons_the_ledger() {
        let mut staging = StagingCapacity::new(1024, 800, 900).unwrap();
        staging.reserve(400).unwrap();
        staging.release(400);
        assert!(!staging.is_poisoned(), "an exact release is not an error");
        assert_eq!(staging.advertised_credit(), 800);

        // The second release of the same reservation would have handed out
        // 400 bytes nobody earned.
        staging.release(400);
        assert!(staging.is_poisoned());
        assert_eq!(
            (
                staging.used(),
                staging.remaining(),
                staging.advertised_credit()
            ),
            (1024, 0, 0),
            "a poisoned ledger reads as fully used, not fully free"
        );
        assert_eq!(staging.reserve(1), Err(Error::AccountingPoisoned));

        // From a nonzero hold, so the assignment on the poisoning branch is
        // observed doing something rather than confirming what was already
        // true.
        let mut holding = StagingCapacity::new(1024, 800, 900).unwrap();
        holding.reserve(400).unwrap();
        holding.release(700);
        assert!(holding.is_poisoned());
        assert_eq!(holding.used(), 1024, "the over-release read as free space");

        // And the way back, which is a new ledger rather than an adjusted
        // one: what a poisoned ledger holds is not known well enough to fix.
        let fresh = holding.rebuilt();
        assert!(!fresh.is_poisoned());
        assert_eq!(fresh.used(), 0);
        assert_eq!(fresh.advertised_credit(), 800);
    }

    #[test]
    fn a_batch_that_stops_part_way_reports_what_the_backend_took() {
        let mut adapter = ContractAdapter {
            reliable_failures_after: Some(2),
            ..ContractAdapter::default()
        };
        let records = [
            shared_payload(b"one"),
            shared_payload(b"two"),
            shared_payload(b"three"),
        ];
        assert_eq!(
            adapter.send_reliable_batch(StreamId(1), &records),
            Err(BatchFailure {
                admitted: 2,
                error: Error::Backend
            })
        );
        assert_eq!(
            adapter.reliable.len(),
            2,
            "the count reported is the count the backend has"
        );
    }

    #[test]
    fn records_are_bounded_before_a_backend_sees_them() {
        assert_eq!(MIN_CONTROL_FRAME_PAYLOAD, 1024);
        assert_eq!(MAX_DATA_RECORD_BYTES, 262_144);
        assert_eq!(MAX_FRAME_ENVELOPE_BYTES, 16);
        assert_eq!(MAX_DATA_RECORD_WIRE_BYTES, 262_160);
        assert_eq!(
            validate_data_record(&vec![0; MAX_DATA_RECORD_WIRE_BYTES]),
            Ok(())
        );
        assert_eq!(
            validate_data_record(&vec![0; MAX_DATA_RECORD_WIRE_BYTES + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            validate_control_frame(
                &vec![0; MAX_CONTROL_FRAME_WIRE_BYTES],
                MAX_CONTROL_FRAME_PAYLOAD
            ),
            Ok(())
        );
        assert_eq!(
            validate_control_frame(
                &vec![0; MAX_CONTROL_FRAME_WIRE_BYTES + 1],
                MAX_CONTROL_FRAME_PAYLOAD
            ),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            validate_control_payload_limit(MIN_CONTROL_FRAME_PAYLOAD),
            Ok(())
        );
        assert_eq!(
            validate_control_payload_limit(MIN_CONTROL_FRAME_PAYLOAD - 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_control_payload_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD),
            Ok(())
        );
        assert_eq!(
            validate_control_payload_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD + 1),
            Err(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn advertised_limits_have_to_fit_the_queue_that_holds_them() {
        let settings = |control: u64, lanes: u64| vot_codec::Settings {
            max_control_frame_payload: control,
            reliable_lane_limit: lanes,
            ..vot_codec::Settings::default()
        };
        let capacity = 4 * 1024 * 1024;
        let largest = capacity - MAX_FRAME_ENVELOPE_BYTES;

        let limits = ReceiveLimits::advertised(&settings(largest as u64, 16), capacity).unwrap();
        assert_eq!(limits.control_payload(), largest);
        assert_eq!(limits.lanes(), 16);
        assert!(limits.match_settings(&settings(largest as u64, 16)));
        assert!(!limits.match_settings(&settings(largest as u64, 15)));
        assert!(!limits.match_settings(&settings(largest as u64 - 1, 16)));

        assert_eq!(
            ReceiveLimits::advertised(
                &vot_codec::Settings {
                    max_control_frame_payload: MIN_CONTROL_FRAME_PAYLOAD as u64,
                    max_data_record_payload: 64 * 1024,
                    ..vot_codec::Settings::default()
                },
                64 * 1024,
            ),
            Err(Error::InvalidConfiguration)
        );
        assert!(
            ReceiveLimits::advertised(
                &vot_codec::Settings {
                    max_control_frame_payload: MIN_CONTROL_FRAME_PAYLOAD as u64,
                    max_data_record_payload: 64 * 1024,
                    ..vot_codec::Settings::default()
                },
                64 * 1024 + MAX_FRAME_ENVELOPE_BYTES,
            )
            .is_ok()
        );

        assert_eq!(
            ReceiveLimits::advertised(&settings(largest as u64 + 1, 16), capacity),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            ReceiveLimits::advertised(
                &settings(MIN_CONTROL_FRAME_PAYLOAD as u64 - 1, 16),
                capacity
            ),
            Err(Error::InvalidConfiguration)
        );
        for lanes in [0, 257] {
            assert_eq!(
                ReceiveLimits::advertised(&settings(largest as u64, lanes), capacity),
                Err(Error::InvalidConfiguration),
                "{lanes} lanes"
            );
        }
        for lanes in [1_u64, 256] {
            assert_eq!(
                ReceiveLimits::advertised(&settings(largest as u64, lanes), capacity)
                    .unwrap()
                    .lanes(),
                usize::try_from(lanes).unwrap()
            );
        }
    }

    #[test]
    fn a_send_bound_never_exceeds_what_the_backend_can_queue() {
        let capacity = 4 * 1024 * 1024;
        assert_eq!(
            effective_send_limit(64 * 1024, capacity),
            64 * 1024,
            "a peer under the capacity is taken as it stands"
        );
        assert_eq!(
            effective_send_limit(16 * 1024 * 1024, capacity),
            capacity - MAX_FRAME_ENVELOPE_BYTES,
            "and one over it is clamped to what fits"
        );
        assert_eq!(
            effective_send_limit(capacity - MAX_FRAME_ENVELOPE_BYTES, capacity),
            capacity - MAX_FRAME_ENVELOPE_BYTES
        );
        assert_eq!(effective_send_limit(1024, 0), MIN_CONTROL_FRAME_PAYLOAD);
        assert_eq!(
            effective_send_limit(
                MIN_CONTROL_FRAME_PAYLOAD,
                MIN_CONTROL_FRAME_PAYLOAD + MAX_FRAME_ENVELOPE_BYTES - 1
            ),
            MIN_CONTROL_FRAME_PAYLOAD
        );
        assert_eq!(
            validate_control_payload_limit(effective_send_limit(1024, 0)),
            Ok(())
        );
    }

    #[test]
    fn invalid_capacity_configuration_is_rejected() {
        assert_eq!(
            StagingCapacity::new(0, 1, 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            StagingCapacity::new(10, 1, 11),
            Err(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn transport_ack_retains_delivery_coordinates() {
        let ack = TransportAck::new(17, 42);
        assert_eq!(ack.stream(), StreamId(17));
        assert_eq!(ack.sequence(), 42);
    }

    #[test]
    fn default_transport_methods_delegate_and_bound_batches() {
        assert_eq!(ALPN, b"vot-draft-05");
        assert_eq!(
            MAX_CONTROL_FRAME_PAYLOAD,
            vot_codec::DEFAULT_MAX_UNKNOWN_PAYLOAD
        );
        assert_eq!(MAX_DATAGRAM_BYTES, 64 * 1024);

        let payload = shared_payload(b"control");
        assert_eq!(&*payload, b"control");

        let mut adapter = ContractAdapter::default();
        adapter.send_control_shared(payload).unwrap();
        assert_eq!(adapter.controls, vec![b"control".to_vec()]);

        let records = [shared_payload(b"one"), shared_payload(b"two")];
        adapter
            .send_reliable_shared(StreamId(7), records[0].clone())
            .unwrap();
        adapter
            .send_reliable_batch(StreamId(7), &records[1..])
            .unwrap();
        assert_eq!(
            adapter.reliable,
            vec![
                (StreamId(7), b"one".to_vec()),
                (StreamId(7), b"two".to_vec()),
            ]
        );

        let mut preflight = ContractAdapter::default();
        let invalid_records = [
            shared_payload(b"accepted only after preflight"),
            shared_payload(&vec![0; MAX_DATA_RECORD_WIRE_BYTES + 1]),
        ];
        assert_eq!(
            preflight.send_reliable_batch(StreamId(8), &invalid_records),
            Err(BatchFailure {
                admitted: 0,
                error: Error::RecordTooLarge
            })
        );
        assert!(preflight.reliable.is_empty());

        assert_eq!(
            adapter.send_datagram(9, b"unreliable"),
            Err(Error::Unsupported)
        );
        assert_eq!(adapter.flush(), Ok(()));
        assert_eq!(adapter.path_stats(), None);

        assert_eq!(
            adapter.close(vot_codec::error_code::MALFORMED_FRAME),
            Err(Error::Unsupported)
        );
        assert_eq!(adapter.receive_limits(), None);
        assert_eq!(
            adapter.set_control_payload_limit(MAX_CONTROL_FRAME_PAYLOAD),
            Err(Error::Unsupported)
        );

        adapter.events.push_back(Event::Connected(ConnectionId(1)));
        adapter
            .events
            .push_back(Event::Disconnected(ConnectionId(1)));
        adapter
            .events
            .push_back(Event::Acknowledged(TransportAck::new(7, 1)));
        let mut events = Vec::new();
        assert_eq!(adapter.poll_batch(&mut events, 2), 2);
        assert_eq!(events.len(), 2);
        assert_eq!(adapter.poll_batch(&mut events, 2), 1);
        assert_eq!(events.len(), 3);
        assert_eq!(adapter.poll_batch(&mut events, 0), 0);
        assert!(adapter.poll().is_none());
    }

    #[test]
    fn bdp_target_updates_are_observable_through_credit() {
        let mut staging = StagingCapacity::new(1024, 1, 900).unwrap();
        assert_eq!(staging.advertised_credit(), 1);
        staging.set_bdp_target(800);
        assert_eq!(staging.advertised_credit(), 800);
        staging.reserve(300).unwrap();
        assert_eq!(staging.advertised_credit(), 724);
    }

    const WAIT_BOUND: Duration = Duration::from_millis(40);

    const PROMPT: Duration = Duration::from_secs(2);
    const LONG_BOUND: Duration = Duration::from_secs(5);

    #[test]
    fn the_default_wait_sleeps_the_bound_out() {
        let mut adapter = ContractAdapter::default();
        let started = std::time::Instant::now();
        adapter.wait_for_event(WAIT_BOUND);
        assert!(started.elapsed() >= WAIT_BOUND);
    }

    #[test]
    fn a_raise_before_the_wait_is_not_slept_past() {
        let signal = EventSignal::default();
        signal.raise();
        let started = std::time::Instant::now();
        signal.wait(LONG_BOUND);
        assert!(started.elapsed() < PROMPT);
    }

    #[test]
    fn an_unraised_wait_lasts_the_bound_and_a_consumed_latch_does_not_linger() {
        let signal = EventSignal::default();
        let started = std::time::Instant::now();
        signal.wait(WAIT_BOUND);
        assert!(started.elapsed() >= WAIT_BOUND);

        signal.raise();
        signal.wait(WAIT_BOUND);
        let started = std::time::Instant::now();
        signal.wait(WAIT_BOUND);
        assert!(started.elapsed() >= WAIT_BOUND);
    }

    #[test]
    fn a_raise_wakes_a_parked_waiter() {
        let signal = Arc::new(EventSignal::default());
        let raiser = Arc::clone(&signal);
        let waker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            raiser.raise();
        });
        let started = std::time::Instant::now();
        signal.wait(LONG_BOUND);
        assert!(started.elapsed() < PROMPT);
        waker.join().unwrap();
    }
}
