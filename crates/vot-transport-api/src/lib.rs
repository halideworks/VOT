//! Backend-neutral VOT transport contract and bounded receiver credit.

#![forbid(unsafe_code)]

use std::sync::Arc;

pub const ALPN: &[u8] = b"vot-draft-03";
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
    /// Implementations with bounded queues must include their available queue
    /// capacity in this check so `send_reliable_batch` cannot partially enqueue.
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
    /// The preflight is required to be side-effect free; a failure therefore
    /// leaves the adapter unchanged and never accepts only a prefix of `records`.
    ///
    /// # Errors
    /// Propagates the first backend or protocol limit failure.
    fn send_reliable_batch(&mut self, stream: StreamId, records: &[Payload]) -> Result<(), Error> {
        self.preflight_reliable_batch(stream, records)?;
        for record in records {
            self.send_reliable_shared(stream, record.clone())?;
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
}

/// Sole source of truth for receiver staging usage and advertised credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingCapacity {
    limit: u64,
    used: u64,
    bdp_target: u64,
    configured_max: u64,
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
        })
    }

    /// # Errors
    /// Rejects arithmetic overflow or a reservation beyond the hard limit.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Error> {
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

    pub fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }

    /// Updates the current BDP target while preserving the configured hard cap.
    pub fn set_bdp_target(&mut self, bdp_target: u64) {
        self.bdp_target = bdp_target;
    }

    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Credit is a pure function of the current staging state.
    #[must_use]
    pub fn advertised_credit(&self) -> u64 {
        let target = self.bdp_target.min(self.configured_max);
        self.remaining().min(target)
    }
}

/// Validates the wire length of a reliable DATA_RECORD submission.
///
/// The protocol limit applies to the encoded frame payload. The bounded
/// envelope is allowed in addition to that payload limit.
pub fn validate_data_record(record: &[u8]) -> Result<(), Error> {
    if record.len() > MAX_DATA_RECORD_WIRE_BYTES {
        Err(Error::RecordTooLarge)
    } else {
        Ok(())
    }
}

/// Validates a negotiated control-frame payload limit.
pub fn validate_control_payload_limit(limit: usize) -> Result<(), Error> {
    if limit == 0 || limit > vot_codec::HARD_MAX_FRAME_PAYLOAD {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

/// Validates the wire length of a control-frame submission.
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
    }

    impl TransportAdapter for ContractAdapter {
        fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
            self.controls.push(frame.to_vec());
            Ok(())
        }

        fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
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
    fn records_are_bounded_before_a_backend_sees_them() {
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
            validate_control_payload_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD + 1),
            Err(Error::InvalidConfiguration)
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
        assert_eq!(ALPN, b"vot-draft-03");
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
            Err(Error::RecordTooLarge)
        );
        assert!(preflight.reliable.is_empty());

        assert_eq!(
            adapter.send_datagram(9, b"unreliable"),
            Err(Error::Unsupported)
        );
        assert_eq!(adapter.flush(), Ok(()));
        assert_eq!(adapter.path_stats(), None);

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
}
