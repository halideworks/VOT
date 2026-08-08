//! quiche transport backend: lane/stream mapping, receive limits, and carrier
//! state. The pump (socket, connection, timer) is behind the `live` feature.

use vot_transport_api::{
    ConnectionId, DatagramSendState, Error, Event, PathStats, Payload, ReceiveLimits, StreamId,
    TransportAck, TransportAdapter, shared_payload,
};
use vot_transport_queue::Queue;

pub use vot_transport_queue::Command;

#[cfg(feature = "live")]
pub mod live;

/// Control stream: QUIC stream zero (first client bidirectional).
pub const CONTROL_STREAM_ID: u64 = 0;

/// Where peer-initiated lanes are reported. Offset to avoid collision with
/// self-opened lanes.
pub const PEER_LANE_BASE: u64 = 1 << 62;

/// The lane the control stream is reported under, which no application may open.
pub const CONTROL_LANE: u64 = u64::MAX - 1;

/// The highest peer lane, one below the control lane.
pub const PEER_LANE_LAST: u64 = CONTROL_LANE - 1;

/// Whether `lane` is reserved (control or peer lane).
#[must_use]
pub const fn is_reserved_lane(lane: u64) -> bool {
    lane >= PEER_LANE_BASE
}

/// Which side of the connection this endpoint is. Determines stream ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

/// The QUIC stream a lane this endpoint opens is carried on. Client lanes
/// start at stream 4 (stream 0 is control); server lanes start at stream 1.
///
/// # Errors
/// Rejects a reserved lane, and a lane with no stream identifier left.
pub const fn stream_for_lane(lane: u64, role: Role) -> Result<u64, Error> {
    if is_reserved_lane(lane) {
        return Err(Error::InvalidConfiguration);
    }
    if lane > MAX_LANE {
        return Err(Error::ArithmeticOverflow);
    }
    Ok(match role {
        Role::Client => (lane + 1) * 4,
        Role::Server => lane * 4 + 1,
    })
}

/// The largest lane a QUIC stream identifier exists for.
pub const MAX_LANE: u64 = MAX_STREAM_ID / 4 - 1;

const _: () = assert!((MAX_LANE + 1) * 4 <= MAX_STREAM_ID);
const _: () = assert!(MAX_LANE * 4 < MAX_STREAM_ID);
const _: () = assert!(MAX_LANE < PEER_LANE_BASE);

/// The largest stream identifier a QUIC varint carries, from RFC 9000.
pub const MAX_STREAM_ID: u64 = (1 << 62) - 1;

/// Whether `stream` was opened by this endpoint. Checks QUIC low bits for
/// initiator and directionality.
#[must_use]
pub const fn locally_initiated(stream: u64, role: Role) -> bool {
    matches!((role, stream % 4), (Role::Client, 0) | (Role::Server, 1))
}

/// Which lane a stream maps to: control, self-opened, or peer (offset).
///
/// # Errors
/// Rejects a stream identifier no QUIC varint carries.
pub const fn lane_for_stream(stream: u64, role: Role) -> Result<u64, Error> {
    if stream > MAX_STREAM_ID {
        return Err(Error::LaneLimitExceeded);
    }
    if stream == CONTROL_STREAM_ID {
        return Ok(CONTROL_LANE);
    }
    if locally_initiated(stream, role) {
        // Inverse of stream_for_lane.
        return Ok(match role {
            Role::Client => stream / 4 - 1,
            Role::Server => stream / 4,
        });
    }
    Ok(PEER_LANE_BASE + stream)
}

const _: () = assert!(PEER_LANE_BASE + MAX_STREAM_ID <= PEER_LANE_LAST);

/// Most this backend's inbound queue holds for one event.
///
/// [`ReceiveLimits`] is built against it, so an endpoint cannot advertise a
/// control frame this backend could never enqueue.
pub const INBOUND_BYTE_CAPACITY: usize = vot_transport_queue::INBOUND_BYTE_CAPACITY;

/// Max bytes held across all streams for in-flight frames. Sized for a burst
/// of the largest frames.
pub const MAX_ASSEMBLY_BYTES: usize = 16 * vot_transport_framing::MAX_PARTIAL_CONTROL_FRAME;

/// What the pump reports before translation to [`Event`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEvent {
    Connected(u64),
    Disconnected(u64),
    Control(Payload),
    Reliable {
        lane: u64,
        sequence: u64,
        bytes: Payload,
    },
    Acknowledged {
        lane: u64,
        sequence: u64,
    },
    /// A datagram this endpoint handed to the carrier.
    DatagramSent {
        context: u64,
    },
    /// A datagram the carrier would not take.
    DatagramDropped {
        context: u64,
    },
}

/// Holds the bounded queue every adapter has and translates what the pump
/// reports.
#[derive(Clone, Debug)]
pub struct QuicheAdapter {
    queue: Queue,
    path: Option<(ConnectionId, PathStats)>,
    role: Role,
}

impl Default for QuicheAdapter {
    fn default() -> Self {
        Self {
            queue: Queue::default(),
            path: None,
            role: Role::Client,
        }
    }
}

impl QuicheAdapter {
    /// An adapter for the side of the connection this endpoint is on.
    #[must_use]
    pub fn for_role(role: Role) -> Self {
        Self {
            role,
            ..Self::default()
        }
    }

    /// Which side this endpoint is, which decides the streams it may open.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Creates an adapter with explicit inbound and outbound queue limits.
    ///
    /// # Errors
    /// Rejects a zero command-count or byte limit.
    pub fn with_queue_limits(command_count: usize, command_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            queue: Queue::with_limits(command_count, command_bytes)?,
            path: None,
            role: Role::Client,
        })
    }

    /// Applies what this endpoint advertised.
    pub const fn set_receive_limits(&mut self, limits: ReceiveLimits) {
        self.queue.set_receive_limits(limits);
    }

    /// Queues what the pump reported, after enforcing protocol and memory
    /// bounds.
    ///
    /// # Errors
    /// Rejects oversized records, arithmetic overflow, or a full inbound queue.
    pub fn record_native_event(&mut self, event: NativeEvent) -> Result<(), Error> {
        self.try_record_native_event(event)
            .map_err(|(_, error)| error)
    }

    /// Queues what the pump reported, handing the event back when the inbound
    /// queue is full. The pump retries on the next pass.
    ///
    /// # Errors
    /// Returns the event alongside the reason it was refused.
    pub fn try_record_native_event(
        &mut self,
        event: NativeEvent,
    ) -> Result<(), (NativeEvent, Error)> {
        // Drop path sample on disconnect, but only after the event is taken.
        let disconnected = match &event {
            NativeEvent::Disconnected(id) => Some(ConnectionId(*id)),
            _ => None,
        };
        match self.queue.try_admit_event(translate(event.clone())) {
            Ok(()) => {
                if let Some(id) = disconnected {
                    self.invalidate_path_stats(id);
                }
                Ok(())
            }
            Err((_, error)) => Err((event, error)),
        }
    }

    /// Records the most recent path sample. Discarded on disconnect so a stale
    /// path cannot seed a new connection.
    pub fn record_path_stats(&mut self, connection: ConnectionId, stats: PathStats) {
        self.path = Some((connection, stats));
    }

    fn invalidate_path_stats(&mut self, connection: ConnectionId) {
        if self
            .path
            .is_some_and(|(recorded, _)| recorded == connection)
        {
            self.path = None;
        }
    }

    /// Submissions taken but not yet handed to the carrier.
    #[must_use]
    pub fn pending_commands(&self) -> usize {
        self.queue.pending_commands()
    }

    pub fn next_command(&mut self) -> Option<Command> {
        self.queue.next_command()
    }

    /// Gives the pump one submission at a time. Failed submissions stay queued.
    ///
    /// # Errors
    /// Returns the first error the pump reports.
    pub fn drain_commands<F, E>(&mut self, submit: F) -> Result<(), E>
    where
        F: FnMut(Command) -> Result<(), E>,
    {
        self.queue.drain_commands(submit)
    }
}

/// Reads what the pump observed as the event the queue carries.
fn translate(event: NativeEvent) -> Event {
    match event {
        NativeEvent::Connected(id) => Event::Connected(ConnectionId(id)),
        NativeEvent::Disconnected(id) => Event::Disconnected(ConnectionId(id)),
        NativeEvent::Control(bytes) => Event::Control(bytes),
        NativeEvent::Reliable {
            lane,
            sequence,
            bytes,
        } => Event::Reliable {
            stream: StreamId(lane),
            sequence,
            bytes,
        },
        NativeEvent::Acknowledged { lane, sequence } => {
            Event::Acknowledged(TransportAck::new(lane, sequence))
        }
        NativeEvent::DatagramSent { context } => Event::DatagramState {
            context,
            state: DatagramSendState::Sent,
        },
        NativeEvent::DatagramDropped { context } => Event::DatagramState {
            context,
            state: DatagramSendState::Canceled,
        },
    }
}

impl TransportAdapter for QuicheAdapter {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.send_control_shared(shared_payload(frame))
    }

    fn send_control_shared(&mut self, frame: Payload) -> Result<(), Error> {
        self.queue.send_control(frame)
    }

    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record)?;
        self.send_reliable_shared(stream, shared_payload(record))
    }

    fn preflight_reliable_batch(&self, stream: StreamId, records: &[Payload]) -> Result<(), Error> {
        // Lane validity is checked here, not at the pump, so partial
        // submission batches are rejected upfront.
        stream_for_lane(stream.0, self.role)?;
        self.queue.preflight_reliable_batch(records)
    }

    fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        stream_for_lane(stream.0, self.role)?;
        self.queue.send_reliable(stream, record)
    }

    fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
        self.queue.send_datagram(context, payload)
    }

    fn poll(&mut self) -> Option<Event> {
        self.queue.poll()
    }

    /// No-op: quiche manages connection flow control internally. The bound is
    /// set at construction via [`ReceiveLimits`].
    fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// Applies the peer-negotiated control-frame payload ceiling.
    fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
        self.queue.set_control_send_limit(limit)
    }

    fn receive_limits(&self) -> Option<ReceiveLimits> {
        self.queue.receive_limits()
    }

    fn path_stats(&self) -> Option<PathStats> {
        self.path.map(|(_, stats)| stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_side_opens_its_own_streams_for_the_records_it_sends() {
        assert_eq!(CONTROL_STREAM_ID, 0);
        assert_eq!(stream_for_lane(0, Role::Client), Ok(4));
        assert_eq!(stream_for_lane(1, Role::Client), Ok(8));
        assert_eq!(stream_for_lane(0, Role::Server), Ok(1));
        assert_eq!(stream_for_lane(1, Role::Server), Ok(5));

        for lane in 0..64 {
            for role in [Role::Client, Role::Server] {
                let stream = stream_for_lane(lane, role).expect("a lane this side opens");
                assert_ne!(stream, CONTROL_STREAM_ID, "lane {lane} as {role:?}");
                assert!(
                    locally_initiated(stream, role),
                    "lane {lane} as {role:?} is this side's to open"
                );
                assert_eq!(
                    lane_for_stream(stream, role),
                    Ok(lane),
                    "the lane comes back as {role:?}"
                );
                let peer = match role {
                    Role::Client => Role::Server,
                    Role::Server => Role::Client,
                };
                assert!(!locally_initiated(stream, peer));
                assert!(is_reserved_lane(lane_for_stream(stream, peer).unwrap()));
            }
        }

        for stream in 0..64 {
            assert!(
                !(locally_initiated(stream, Role::Client)
                    && locally_initiated(stream, Role::Server))
            );
        }
    }

    #[test]
    fn every_stream_identifier_a_peer_may_use_has_a_lane() {
        assert_eq!(MAX_STREAM_ID, 4_611_686_018_427_387_903);
        assert_eq!(MAX_STREAM_ID, (1 << 62) - 1);
        for role in [Role::Client, Role::Server] {
            assert_eq!(
                lane_for_stream(MAX_STREAM_ID, role),
                Ok(PEER_LANE_BASE + MAX_STREAM_ID),
                "the largest identifier, as {role:?}"
            );
            assert!(lane_for_stream(MAX_STREAM_ID, role).unwrap() <= PEER_LANE_LAST);
            assert_ne!(
                lane_for_stream(MAX_STREAM_ID, role).unwrap(),
                CONTROL_LANE,
                "and never the control lane"
            );
            assert_eq!(
                lane_for_stream(MAX_STREAM_ID + 1, role),
                Err(Error::LaneLimitExceeded),
                "one past it, as {role:?}"
            );
        }
    }

    #[test]
    fn an_adapter_is_the_side_it_was_built_for() {
        assert_eq!(QuicheAdapter::default().role(), Role::Client);
        assert_eq!(QuicheAdapter::for_role(Role::Server).role(), Role::Server);
        assert_eq!(QuicheAdapter::for_role(Role::Client).role(), Role::Client);
    }

    #[test]
    fn a_unidirectional_stream_is_always_the_peers() {
        for stream in [2_u64, 3, 6, 7, 4_002, 4_003] {
            for role in [Role::Client, Role::Server] {
                assert!(!locally_initiated(stream, role), "{stream} as {role:?}");
                assert!(
                    is_reserved_lane(lane_for_stream(stream, role).unwrap()),
                    "{stream} as {role:?}"
                );
            }
        }
    }

    #[test]
    fn the_largest_lane_that_has_a_stream_has_one() {
        assert_eq!(MAX_LANE, MAX_STREAM_ID / 4 - 1);
        for role in [Role::Client, Role::Server] {
            let stream = stream_for_lane(MAX_LANE, role).expect("the last lane");
            assert!(stream <= MAX_STREAM_ID, "{role:?}");
            assert_eq!(lane_for_stream(stream, role), Ok(MAX_LANE), "{role:?}");
            assert_eq!(
                stream_for_lane(MAX_LANE + 1, role),
                Err(Error::ArithmeticOverflow),
                "the first lane whose stream does not fit, as {role:?}"
            );
            assert_eq!(
                stream_for_lane(PEER_LANE_BASE, role),
                Err(Error::InvalidConfiguration),
                "{role:?}"
            );
        }
    }

    #[test]
    fn a_reserved_lane_is_refused_at_submission() {
        let mut adapter = QuicheAdapter::default();
        for lane in [
            PEER_LANE_BASE,
            PEER_LANE_BASE + 1,
            PEER_LANE_LAST,
            CONTROL_LANE,
        ] {
            assert_eq!(
                adapter.send_reliable(StreamId(lane), b"record"),
                Err(Error::InvalidConfiguration),
                "lane {lane:#x}"
            );
            assert_eq!(
                adapter.preflight_reliable_batch(StreamId(lane), &[shared_payload(b"record")]),
                Err(Error::InvalidConfiguration),
                "lane {lane:#x}"
            );
        }
        assert_eq!(adapter.pending_commands(), 0, "nothing refused was taken");
        assert!(adapter.send_reliable(StreamId(0), b"record").is_ok());
        assert_eq!(adapter.pending_commands(), 1);
    }

    #[test]
    fn what_the_pump_reports_reaches_the_caller_in_order() {
        let mut adapter = QuicheAdapter::default();
        for event in [
            NativeEvent::Connected(7),
            NativeEvent::Control(shared_payload(&[0; 8])),
            NativeEvent::Reliable {
                lane: 3,
                sequence: 1,
                bytes: shared_payload(b"record"),
            },
            NativeEvent::Acknowledged {
                lane: 3,
                sequence: 1,
            },
            NativeEvent::DatagramSent { context: 9 },
            NativeEvent::DatagramDropped { context: 10 },
        ] {
            adapter.record_native_event(event).expect("an event");
        }
        assert_eq!(adapter.poll(), Some(Event::Connected(ConnectionId(7))));
        assert_eq!(
            adapter.poll(),
            Some(Event::Control(shared_payload(&[0; 8])))
        );
        assert_eq!(
            adapter.poll(),
            Some(Event::Reliable {
                stream: StreamId(3),
                sequence: 1,
                bytes: shared_payload(b"record"),
            })
        );
        assert_eq!(
            adapter.poll(),
            Some(Event::Acknowledged(TransportAck::new(3, 1)))
        );
        assert_eq!(
            adapter.poll(),
            Some(Event::DatagramState {
                context: 9,
                state: DatagramSendState::Sent,
            })
        );
        assert_eq!(
            adapter.poll(),
            Some(Event::DatagramState {
                context: 10,
                state: DatagramSendState::Canceled,
            })
        );
        assert_eq!(adapter.poll(), None);
    }

    #[test]
    fn an_event_the_queue_cannot_hold_is_handed_back_to_the_pump() {
        let mut adapter = QuicheAdapter::with_queue_limits(1, 1_024).expect("a bounded adapter");
        adapter
            .record_native_event(NativeEvent::Connected(1))
            .expect("an event");
        let refused = NativeEvent::Reliable {
            lane: 0,
            sequence: 1,
            bytes: shared_payload(b"record"),
        };
        assert_eq!(
            adapter.try_record_native_event(refused.clone()),
            Err((refused.clone(), Error::InboundQueueFull))
        );
        assert_eq!(adapter.poll(), Some(Event::Connected(ConnectionId(1))));
        assert_eq!(adapter.try_record_native_event(refused), Ok(()));
        assert!(matches!(adapter.poll(), Some(Event::Reliable { .. })));
        assert_eq!(
            QuicheAdapter::with_queue_limits(0, 1).err(),
            Some(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn a_path_sample_does_not_outlive_its_connection() {
        let mut adapter = QuicheAdapter::default();
        assert_eq!(adapter.path_stats(), None);
        let sample = PathStats {
            smoothed_rtt_us: Some(4_000),
            congestion_window_bytes: Some(65_536),
            mtu_bytes: Some(1_350),
            pacing_rate_bps: Some(1_000_000),
            lost_packets: None,
            spurious_lost_packets: None,
            packets_sent: None,
            packets_received: None,
        };
        adapter.record_path_stats(ConnectionId(1), sample);
        assert_eq!(adapter.path_stats(), Some(sample));

        adapter
            .record_native_event(NativeEvent::Disconnected(2))
            .expect("an event");
        assert_eq!(adapter.path_stats(), Some(sample));

        adapter
            .record_native_event(NativeEvent::Disconnected(1))
            .expect("an event");
        assert_eq!(adapter.path_stats(), None);
    }

    #[test]
    fn a_refused_disconnect_leaves_the_path_sample_where_it_was() {
        let mut adapter = QuicheAdapter::with_queue_limits(1, 1_024).expect("a bounded adapter");
        let sample = PathStats {
            smoothed_rtt_us: Some(1),
            ..PathStats::default()
        };
        adapter.record_path_stats(ConnectionId(1), sample);
        adapter
            .record_native_event(NativeEvent::Connected(1))
            .expect("an event");
        assert_eq!(
            adapter.try_record_native_event(NativeEvent::Disconnected(1)),
            Err((NativeEvent::Disconnected(1), Error::InboundQueueFull))
        );
        assert_eq!(adapter.path_stats(), Some(sample), "still there to be read");

        assert!(adapter.poll().is_some());
        adapter
            .record_native_event(NativeEvent::Disconnected(1))
            .expect("an event");
        assert_eq!(adapter.path_stats(), None);
    }

    #[test]
    fn credit_is_refused_rather_than_accepted_and_ignored() {
        let mut adapter = QuicheAdapter::default();
        assert_eq!(adapter.set_receive_credit(4_096), Err(Error::Unsupported));
        assert_eq!(adapter.pending_commands(), 0, "and nothing was queued");
    }

    #[test]
    fn the_bounds_this_backend_holds_are_the_ones_it_advertises() {
        let mut adapter = QuicheAdapter::default();
        assert_eq!(adapter.receive_limits(), None);
        let advertised = ReceiveLimits::advertised(
            &vot_codec::Settings {
                reliable_lane_limit: 4,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        )
        .expect("limits this backend can hold");
        adapter.set_receive_limits(advertised);
        assert_eq!(adapter.receive_limits(), Some(advertised));

        assert_eq!(
            adapter.set_control_payload_limit(0),
            Err(Error::InvalidConfiguration)
        );
        assert!(
            adapter
                .set_control_payload_limit(vot_transport_api::MIN_CONTROL_FRAME_PAYLOAD)
                .is_ok()
        );

        // Burst capacity for the largest frames on either lane.
        assert_eq!(
            MAX_ASSEMBLY_BYTES,
            16 * vot_transport_framing::MAX_PARTIAL_CONTROL_FRAME
        );
        assert_eq!(
            MAX_ASSEMBLY_BYTES / vot_transport_framing::MAX_PARTIAL_CONTROL_FRAME,
            16
        );
        assert_eq!(INBOUND_BYTE_CAPACITY, 4_194_304);
    }

    #[test]
    fn the_reserved_lane_identifiers_are_the_ones_the_receive_path_reports() {
        assert_eq!(PEER_LANE_BASE, 4_611_686_018_427_387_904);
        assert_eq!(CONTROL_LANE, u64::MAX - 1);
        assert_eq!(CONTROL_LANE, 18_446_744_073_709_551_614);
        assert_eq!(PEER_LANE_LAST, u64::MAX - 2);
        assert_eq!(PEER_LANE_LAST, CONTROL_LANE - 1);
        assert!(is_reserved_lane(PEER_LANE_BASE));
        assert!(is_reserved_lane(CONTROL_LANE));
        assert!(is_reserved_lane(PEER_LANE_LAST));
        assert!(!is_reserved_lane(PEER_LANE_BASE - 1));
    }

    #[test]
    fn a_control_frame_and_a_datagram_are_taken_rather_than_dropped() {
        let mut adapter = QuicheAdapter::default();
        adapter.send_control(b"\x0d\x00").expect("a control frame");
        assert_eq!(adapter.pending_commands(), 1);
        assert_eq!(
            adapter.next_command(),
            Some(Command::Control(shared_payload(b"\x0d\x00")))
        );

        adapter
            .send_control_shared(shared_payload(b"\x0d\x01\x00"))
            .expect("a shared control frame");
        assert_eq!(
            adapter.next_command(),
            Some(Command::Control(shared_payload(b"\x0d\x01\x00")))
        );

        adapter.send_datagram(9, b"datagram").expect("a datagram");
        assert_eq!(
            adapter.next_command(),
            Some(Command::Datagram {
                context: 9,
                bytes: shared_payload(b"datagram"),
            })
        );
        assert_eq!(adapter.pending_commands(), 0);

        assert_eq!(
            adapter.send_datagram(1, &vec![0; vot_transport_api::MAX_DATAGRAM_BYTES + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            adapter.send_control(&vec![
                0;
                vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES + 1
            ]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(adapter.pending_commands(), 0);
    }

    #[test]
    fn a_submission_the_pump_could_not_take_stays_at_the_head() {
        let mut adapter = QuicheAdapter::default();
        adapter
            .send_reliable(StreamId(0), b"first")
            .expect("a record");
        adapter
            .send_reliable(StreamId(0), b"second")
            .expect("a record");
        let result: Result<(), &str> = adapter.drain_commands(|_| Err("the carrier refused"));
        assert_eq!(result, Err("the carrier refused"));
        assert_eq!(adapter.pending_commands(), 2);
        assert_eq!(
            adapter.next_command(),
            Some(Command::Reliable {
                stream: StreamId(0),
                bytes: shared_payload(b"first"),
            })
        );
    }
}
