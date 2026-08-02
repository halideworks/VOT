//! `MsQuic` event bridge for the backend-neutral VOT transport API.

#![deny(unsafe_code)]

use std::collections::VecDeque;

/// Lane reported for records arriving on a peer-initiated stream.
///
/// A driver reads this off `Event::Reliable` to tell a peer-initiated record
/// from one on a lane it opened.
///
/// The peer numbers its own streams, so reusing that numbering here would
/// collide with locally opened lanes.
pub const PEER_STREAM_ID: u64 = u64::MAX;

/// Lane reported for control frames, which arrive on their own stream rather
/// than one of the application's reliable lanes.
pub const CONTROL_LANE: u64 = u64::MAX - 1;

/// Largest number of native events the callback queue will hold.
///
/// Callbacks run on backend worker threads and cannot wait for the driver, so
/// without a bound a peer that sends faster than the driver polls would drive
/// allocation until the process died.
pub const MAX_CALLBACK_EVENTS: usize = 1024;

/// Largest partial frame held on a reliable lane while waiting for the rest.
pub const MAX_PARTIAL_FRAME: usize = vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// Largest partial frame held on the control lane.
///
/// Control frames are four times the size of a data record, so reusing the
/// record bound here would refuse a large `PACKAGE_DESCRIPTOR` the same
/// transport is willing to send. This matches the adapter's default control
/// payload limit, which is what the assembled transport sends under, because a
/// receive bound below the send bound is the asymmetry this exists to avoid.
/// `set_control_payload_limit` can raise the sending side; the assembled
/// transport does not expose it, and whatever does must plumb the negotiated
/// value through to framing rather than leave this constant behind.
pub const MAX_PARTIAL_CONTROL_FRAME: usize = vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES;

/// Returns whether `lane` is one this crate reserves for its own reporting.
#[must_use]
pub const fn is_reserved_lane(lane: u64) -> bool {
    lane == PEER_STREAM_ID || lane == CONTROL_LANE
}

use vot_transport_api::{
    ConnectionId, DatagramSendState, Error, Event, PathStats, Payload, StreamId, TransportAck,
    TransportAdapter, shared_payload,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Control(Payload),
    Reliable { stream: StreamId, bytes: Payload },
    Datagram { context: u64, bytes: Payload },
    ReceiveCredit(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEvent {
    Connected(u64),
    Disconnected(u64),
    Control(Vec<u8>),
    Reliable {
        stream: u64,
        sequence: u64,
        bytes: Vec<u8>,
    },
    Acknowledged {
        stream: u64,
        sequence: u64,
    },
    DatagramState {
        context: u64,
        state: NativeDatagramSendState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDatagramSendState {
    Sent,
    LostSuspect,
    Acknowledged,
    AcknowledgedSpurious,
    Canceled,
}

const DEFAULT_COMMAND_COUNT_LIMIT: usize = 64;
const DEFAULT_COMMAND_BYTE_LIMIT: usize = 4 * 1024 * 1024;

/// Owns a bounded outbound command queue and translates `MsQuic` callbacks.
pub struct MsQuicAdapter {
    commands: VecDeque<Command>,
    command_bytes: usize,
    command_count_limit: usize,
    command_byte_limit: usize,
    control_payload_limit: usize,
    events: VecDeque<Event>,
    event_bytes: usize,
    event_count_limit: usize,
    event_byte_limit: usize,
    path: Option<(ConnectionId, PathStats)>,
}

impl Default for MsQuicAdapter {
    fn default() -> Self {
        Self {
            commands: VecDeque::new(),
            command_bytes: 0,
            command_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            command_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
            control_payload_limit: vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            events: VecDeque::new(),
            event_bytes: 0,
            event_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            event_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
            path: None,
        }
    }
}

impl MsQuicAdapter {
    /// Creates an adapter with explicit inbound and outbound queue limits.
    ///
    /// # Errors
    /// Rejects a zero command-count or byte limit.
    pub fn with_queue_limits(command_count: usize, command_bytes: usize) -> Result<Self, Error> {
        if command_count == 0 || command_bytes == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            command_count_limit: command_count,
            command_byte_limit: command_bytes,
            event_count_limit: command_count,
            event_byte_limit: command_bytes,
            ..Self::default()
        })
    }

    /// Applies the peer-negotiated control-frame payload ceiling.
    ///
    /// # Errors
    /// Rejects zero or out-of-range negotiated payload limits.
    pub fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
        vot_transport_api::validate_control_payload_limit(limit)?;
        self.control_payload_limit = limit;
        Ok(())
    }

    /// Queues a native callback after enforcing protocol and memory bounds.
    ///
    /// # Errors
    /// Rejects oversized records, arithmetic overflow, or a full inbound queue.
    pub fn record_native_event(&mut self, event: NativeEvent) -> Result<(), Error> {
        let next_bytes = self.admit(&event)?;
        self.accept(event, next_bytes);
        Ok(())
    }

    /// Queues a native callback, handing the event back when the inbound queue
    /// is full.
    ///
    /// A driver holding the returned event can retry it later, so backpressure
    /// costs no record and cannot reorder one. `record_native_event` discards
    /// the event on failure, which is fine for a caller that can regenerate it
    /// and wrong for one draining a queue.
    ///
    /// # Errors
    /// Returns the event alongside the reason it was refused.
    pub fn try_record_native_event(
        &mut self,
        event: NativeEvent,
    ) -> Result<(), (NativeEvent, Error)> {
        match self.admit(&event) {
            Ok(next_bytes) => {
                self.accept(event, next_bytes);
                Ok(())
            }
            Err(error) => Err((event, error)),
        }
    }

    /// Checks an event against the protocol and memory bounds, returning the
    /// queue size it would produce.
    fn admit(&self, event: &NativeEvent) -> Result<usize, Error> {
        let payload_len = match event {
            NativeEvent::Control(bytes) => {
                vot_transport_api::validate_control_frame(bytes, self.control_payload_limit)?;
                bytes.len()
            }
            NativeEvent::Reliable { bytes, .. } => {
                vot_transport_api::validate_data_record(bytes)?;
                bytes.len()
            }
            NativeEvent::Connected(_)
            | NativeEvent::Disconnected(_)
            | NativeEvent::Acknowledged { .. }
            | NativeEvent::DatagramState { .. } => 0,
        };
        let next_bytes = self
            .event_bytes
            .checked_add(payload_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if self.events.len() >= self.event_count_limit || next_bytes > self.event_byte_limit {
            return Err(Error::InboundQueueFull);
        }
        Ok(next_bytes)
    }

    /// Translates an admitted event and takes its space.
    fn accept(&mut self, event: NativeEvent, next_bytes: usize) {
        if let NativeEvent::Disconnected(id) = &event {
            self.invalidate_path_stats(ConnectionId(*id));
        }
        self.events.push_back(match event {
            NativeEvent::Connected(id) => Event::Connected(ConnectionId(id)),
            NativeEvent::Disconnected(id) => Event::Disconnected(ConnectionId(id)),
            NativeEvent::Control(bytes) => Event::Control(bytes.into()),
            NativeEvent::Reliable {
                stream,
                sequence,
                bytes,
            } => Event::Reliable {
                stream: StreamId(stream),
                sequence,
                bytes: bytes.into(),
            },
            NativeEvent::Acknowledged { stream, sequence } => {
                Event::Acknowledged(TransportAck::new(stream, sequence))
            }
            NativeEvent::DatagramState { context, state } => Event::DatagramState {
                context,
                state: match state {
                    NativeDatagramSendState::Sent => DatagramSendState::Sent,
                    NativeDatagramSendState::LostSuspect => DatagramSendState::SuspectedLost,
                    NativeDatagramSendState::Acknowledged
                    | NativeDatagramSendState::AcknowledgedSpurious => {
                        DatagramSendState::Acknowledged
                    }
                    NativeDatagramSendState::Canceled => DatagramSendState::Canceled,
                },
            },
        });
        self.event_bytes = next_bytes;
    }

    /// Records a path sample a backend driver read from a live connection.
    ///
    /// The adapter owns no `MsQuic` handle, so path metrics are pushed in the
    /// same direction as native callbacks rather than pulled on demand. Only
    /// the most recent sample is retained, and it is discarded once its
    /// connection disconnects, so a stale path can never seed a new one. A
    /// driver that wants to save a Careful Resume observation must therefore
    /// take it before draining the matching `Disconnected` event.
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

    /// Commands submitted but not yet handed to the backend.
    ///
    /// A driver watches this to know whether a failed flush left work behind.
    #[must_use]
    pub fn pending_commands(&self) -> usize {
        self.commands.len()
    }

    pub fn next_command(&mut self) -> Option<Command> {
        let command = self.commands.pop_front()?;
        self.command_bytes = self.command_bytes.saturating_sub(command.payload_len());
        Some(command)
    }

    /// Gives a backend driver one queued command at a time.
    ///
    /// A failed submission remains at the head of the queue so the driver can
    /// apply its own retry or shutdown policy without silently dropping data.
    ///
    /// # Errors
    /// Returns the first backend error reported by `submit`.
    pub fn drain_commands<F, E>(&mut self, mut submit: F) -> Result<(), E>
    where
        F: FnMut(Command) -> Result<(), E>,
    {
        while let Some(command) = self.commands.front().cloned() {
            submit(command)?;
            let Some(command) = self.commands.pop_front() else {
                break;
            };
            self.command_bytes = self.command_bytes.saturating_sub(command.payload_len());
        }
        Ok(())
    }

    fn enqueue(&mut self, command: Command) -> Result<(), Error> {
        let next_bytes = self
            .command_bytes
            .checked_add(command.payload_len())
            .ok_or(Error::ArithmeticOverflow)?;
        if self.commands.len() >= self.command_count_limit || next_bytes > self.command_byte_limit {
            return Err(Error::OutboundQueueFull);
        }
        self.commands.push_back(command);
        self.command_bytes = next_bytes;
        Ok(())
    }
}

impl Command {
    fn payload_len(&self) -> usize {
        match self {
            Self::Control(bytes) | Self::Reliable { bytes, .. } | Self::Datagram { bytes, .. } => {
                bytes.len()
            }
            Self::ReceiveCredit(_) => 0,
        }
    }
}

impl TransportAdapter for MsQuicAdapter {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.send_control_shared(shared_payload(frame))
    }

    fn send_control_shared(&mut self, frame: Payload) -> Result<(), Error> {
        vot_transport_api::validate_control_frame(&frame, self.control_payload_limit)?;
        self.enqueue(Command::Control(frame))
    }

    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record)?;
        self.send_reliable_shared(stream, shared_payload(record))
    }

    fn preflight_reliable_batch(&self, stream: StreamId, records: &[Payload]) -> Result<(), Error> {
        if is_reserved_lane(stream.0) {
            return Err(Error::InvalidConfiguration);
        }
        let next_bytes = records
            .iter()
            .try_fold(self.command_bytes, |bytes, record| {
                vot_transport_api::validate_data_record(record)?;
                bytes
                    .checked_add(record.len())
                    .ok_or(Error::ArithmeticOverflow)
            })?;
        let next_count = self
            .commands
            .len()
            .checked_add(records.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if next_count > self.command_count_limit || next_bytes > self.command_byte_limit {
            Err(Error::OutboundQueueFull)
        } else {
            Ok(())
        }
    }

    fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        // Reserved lanes name the control stream and peer-initiated records.
        // Accepting one here would open an application stream whose replies
        // were reported as the wrong kind.
        if is_reserved_lane(stream.0) {
            return Err(Error::InvalidConfiguration);
        }
        vot_transport_api::validate_data_record(&record)?;
        self.enqueue(Command::Reliable {
            stream,
            bytes: record,
        })
    }

    fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > vot_transport_api::MAX_DATAGRAM_BYTES {
            return Err(Error::RecordTooLarge);
        }
        self.enqueue(Command::Datagram {
            context,
            bytes: shared_payload(payload),
        })
    }

    fn poll(&mut self) -> Option<Event> {
        let event = self.events.pop_front()?;
        self.event_bytes = self.event_bytes.saturating_sub(event_payload_len(&event));
        Some(event)
    }

    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
        self.enqueue(Command::ReceiveCredit(bytes))
    }

    fn path_stats(&self) -> Option<PathStats> {
        self.path.map(|(_, stats)| stats)
    }
}

fn event_payload_len(event: &Event) -> usize {
    match event {
        Event::Control(bytes) | Event::Reliable { bytes, .. } => bytes.len(),
        Event::Connected(_)
        | Event::Disconnected(_)
        | Event::Acknowledged(_)
        | Event::DatagramState { .. } => 0,
    }
}

#[cfg(test)]
const fn vot_codec_limit() -> usize {
    vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD
}

#[cfg(feature = "live")]
#[allow(unsafe_code)]
pub mod live {
    //! Narrow ownership helpers around the official `MsQuic` Rust FFI wrapper.

    use std::ffi::c_void;

    use msquic::ffi::QUIC_STATISTICS_V2;
    use std::collections::btree_map::Entry;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use msquic::{
        BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Registration,
        RegistrationConfig, SendFlags, Stream, StreamEvent, StreamOpenFlags, StreamRef,
        StreamStartFlags,
    };

    use vot_transport_api::{ConnectionId, Error, Event, Payload, StreamId, TransportAdapter};

    use super::{
        Command, MAX_CALLBACK_EVENTS, MAX_PARTIAL_CONTROL_FRAME, MAX_PARTIAL_FRAME, MsQuicAdapter,
        NativeEvent, PEER_STREAM_ID,
    };
    use vot_transport_api::PathStats;

    pub struct SendBuffer {
        storage: Box<[u8]>,
        buffers: Box<[BufferRef; 1]>,
    }

    impl SendBuffer {
        fn new(bytes: &[u8]) -> Self {
            let storage: Box<[u8]> = bytes.into();
            let buffers = Box::new([BufferRef::from(storage.as_ref())]);
            Self { storage, buffers }
        }
    }

    /// Reports a measured statistic, treating an unmeasured zero as absent.
    fn measured(value: u64) -> Option<u64> {
        if value == 0 { None } else { Some(value) }
    }

    /// Maps a `QUIC_STATISTICS_V2` sample onto backend-neutral path metrics.
    ///
    /// `MsQuic` reports zero for a statistic it has not measured yet, so those
    /// fields become `None` rather than a congestion window or RTT of zero that
    /// a BDP or Careful Resume consumer would treat as real. `QUIC_STATISTICS_V2`
    /// carries no pacing rate, so that metric is always absent on this backend.
    #[must_use]
    pub fn path_stats_from_statistics(statistics: &QUIC_STATISTICS_V2) -> PathStats {
        PathStats {
            smoothed_rtt_us: measured(u64::from(statistics.Rtt)),
            congestion_window_bytes: measured(u64::from(statistics.SendCongestionWindow)),
            mtu_bytes: measured(u64::from(statistics.SendPathMtu)),
            pacing_rate_bps: None,
        }
    }

    /// Reads current path metrics from a live connection.
    ///
    /// # Errors
    /// Propagates an `MsQuic` `GetParam` failure.
    pub fn path_stats(connection: &Connection) -> Result<PathStats, msquic::Status> {
        Ok(path_stats_from_statistics(&connection.get_stats_v2()?))
    }

    /// A connected `MsQuic` client that satisfies the backend-neutral adapter.
    ///
    /// Ownership is the whole design here. The registration, configuration,
    /// connection, and every stream are owned by this type and released in that
    /// order, because releasing them in any other order frees something a
    /// callback may still be running against. Callbacks never touch the
    /// adapter: they push native events onto a shared queue, and the driver
    /// thread drains it, which is what ADR-0016 requires.
    pub struct MsQuicTransport {
        adapter: MsQuicAdapter,
        inbound: Arc<Mutex<VecDeque<NativeEvent>>>,
        /// Held back when the adapter's bounded inbound queue is full, so a
        /// record is never dropped and ordering is never broken.
        stalled: Option<NativeEvent>,
        /// Delivery order for received records, shared with the callbacks that
        /// assign it.
        sequence: Arc<AtomicU64>,
        streams: BTreeMap<u64, Stream>,
        /// The first client-initiated bidirectional stream, which `spec/wire.md`
        /// reserves for negotiation. Held apart from the reliable pool so
        /// `StreamId(0)` stays an ordinary application lane.
        control: Option<Stream>,
        connection: Option<Connection>,
        closed: Receiver<()>,
        connection_id: u64,
        _configuration: Arc<Configuration>,
        registration: Registration,
    }

    /// How long teardown waits for `MsQuic` to finish with a connection.
    const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

    impl MsQuicTransport {
        /// Connects to `host:port` and returns a transport ready to send.
        ///
        /// # Errors
        /// Propagates registration, configuration, or connection failures.
        pub fn connect(
            configuration: Arc<Configuration>,
            registration: Registration,
            host: &str,
            port: u16,
            connection_id: u64,
        ) -> Result<Self, msquic::Status> {
            let inbound: Arc<Mutex<VecDeque<NativeEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
            let (closed_tx, closed) = mpsc::channel();
            let sequence = Arc::new(AtomicU64::new(0));
            let callback_inbound = Arc::clone(&inbound);
            let peer_inbound = Arc::clone(&inbound);
            let peer_sequence = Arc::clone(&sequence);
            let connection = Connection::open(
                &registration,
                move |_: ConnectionRef, event: ConnectionEvent| {
                    match event {
                        ConnectionEvent::Connected { .. } => {
                            let _ = push(&callback_inbound, NativeEvent::Connected(connection_id));
                        }
                        ConnectionEvent::PeerStreamStarted { stream, .. } => {
                            // Without adopting these there is no receive path
                            // for anything the peer initiates. Each gets its
                            // own handler, because two peer streams share no
                            // byte ordering and one reassembly buffer between
                            // them would splice their frames together.
                            stream.set_callback_handler(stream_handler(
                                Arc::clone(&peer_inbound),
                                Arc::clone(&peer_sequence),
                                StreamKind::Reliable {
                                    lane: PEER_STREAM_ID,
                                },
                                true,
                            ));
                        }
                        ConnectionEvent::ShutdownComplete { .. } => {
                            let _ =
                                push(&callback_inbound, NativeEvent::Disconnected(connection_id));
                            // Teardown waits on this before releasing the
                            // handle, so a send buffer cannot outlive it.
                            let _ = closed_tx.send(());
                        }
                        _ => {}
                    }
                    Ok(())
                },
            )?;
            connection.start(&configuration, host, port)?;
            Ok(Self {
                adapter: MsQuicAdapter::default(),
                inbound,
                stalled: None,
                sequence,
                streams: BTreeMap::new(),
                control: None,
                connection: Some(connection),
                closed,
                connection_id,
                _configuration: configuration,
                registration,
            })
        }

        /// Samples the live connection and records the result on the driver
        /// thread, which is the only thread allowed to touch the adapter.
        ///
        /// # Errors
        /// Propagates an `MsQuic` `GetParam` failure.
        pub fn sample_path(&mut self) -> Result<(), msquic::Status> {
            let Some(connection) = self.connection.as_ref() else {
                return Ok(());
            };
            let stats = path_stats(connection)?;
            self.adapter
                .record_path_stats(ConnectionId(self.connection_id), stats);
            Ok(())
        }

        /// Commands still queued for the backend.
        #[must_use]
        pub fn pending_commands(&self) -> usize {
            self.adapter.pending_commands()
        }

        /// Moves native events into the adapter, stopping at the first the
        /// bounded queue will not take.
        fn pump(&mut self) {
            if let Some(held) = self.stalled.take() {
                if let Err((held, _)) = self.adapter.try_record_native_event(held) {
                    self.stalled = Some(held);
                    return;
                }
            }
            loop {
                let Some(event) = pop(&self.inbound) else {
                    return;
                };
                if let Err((event, _)) = self.adapter.try_record_native_event(event) {
                    // Held rather than dropped, so backpressure never costs a
                    // record and never reorders one.
                    self.stalled = Some(event);
                    return;
                }
            }
        }
    }

    /// What a stream carries, which decides both the frame bound applied to it
    /// and the kind of event its bytes become.
    ///
    /// Carried explicitly rather than inferred from the lane number, so an
    /// application stream can never be mistaken for the control stream.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum StreamKind {
        /// The negotiation stream `spec/wire.md` reserves.
        Control,
        /// An application lane, reported under `lane`.
        Reliable { lane: u64 },
    }

    impl StreamKind {
        /// Largest partial frame this kind of stream may hold.
        const fn partial_frame_limit(self) -> usize {
            match self {
                Self::Control => MAX_PARTIAL_CONTROL_FRAME,
                Self::Reliable { .. } => MAX_PARTIAL_FRAME,
            }
        }

        /// Largest payload a frame on this kind of stream may declare.
        const fn payload_limit(self) -> usize {
            match self {
                Self::Control => vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
                Self::Reliable { .. } => vot_transport_api::MAX_DATA_RECORD_BYTES,
            }
        }
    }

    /// Per-stream reassembly state.
    ///
    /// QUIC preserves a byte stream, not message boundaries, and `spec/wire.md`
    /// permits a frame to be split across callbacks or several to arrive in
    /// one. Treating a callback buffer as a record would deliver truncated or
    /// combined ones. Each stream owns its own state, because bytes from two
    /// streams share no ordering and combining them would build frames that
    /// were never sent.
    struct Framing {
        pending: Vec<u8>,
        kind: StreamKind,
    }

    impl Framing {
        const fn new(kind: StreamKind) -> Self {
            Self {
                pending: Vec::new(),
                kind,
            }
        }

        /// Adds received bytes and returns every complete frame now available.
        ///
        /// # Errors
        /// Reports a frame that can never complete, either because it is
        /// malformed or because it exceeds the largest frame this lane allows,
        /// which would otherwise stall the stream for ever.
        fn accept(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
            self.pending.extend_from_slice(bytes);
            let limits = vot_codec::DecodeLimits {
                max_unknown_payload: self.kind.payload_limit(),
                max_frames: 1,
            };
            let mut frames = Vec::new();
            let mut offset = 0;
            loop {
                match vot_codec::decode_one(&self.pending[offset..], limits) {
                    Ok((_, consumed)) => {
                        frames.push(self.pending[offset..offset + consumed].to_vec());
                        offset += consumed;
                    }
                    // More bytes will finish it, so keep what we have.
                    Err(vot_codec::DecodeError::Incomplete { .. }) => break,
                    Err(_) => return Err(Error::Backend),
                }
            }
            self.pending.drain(..offset);
            // The bound belongs to the frame still being assembled, not to the
            // read that delivered it. A read that coalesces the tail of one
            // frame with the head of the next is legal, and checking before
            // draining would refuse it.
            if self.pending.len() > self.kind.partial_frame_limit() {
                return Err(Error::RecordTooLarge);
            }
            Ok(frames)
        }
    }

    /// Builds the callback installed on one stream.
    ///
    /// Received bytes become native events rather than being handled inline,
    /// because a callback runs on an `MsQuic` worker thread and the adapter
    /// belongs to the driver thread.
    ///
    /// The result is deliberately not `Clone`: every stream needs reassembly
    /// state of its own, so a handler is built per stream rather than shared.
    fn stream_handler(
        inbound: Arc<Mutex<VecDeque<NativeEvent>>>,
        sequence: Arc<AtomicU64>,
        kind: StreamKind,
        peer_owned: bool,
    ) -> impl FnMut(StreamRef, StreamEvent) -> Result<(), msquic::Status> + 'static {
        let mut framing = Framing::new(kind);
        move |stream: StreamRef, event: StreamEvent| {
            match event {
                StreamEvent::Receive { buffers, .. } => {
                    for buffer in buffers {
                        let frames = framing.accept(buffer.as_bytes()).map_err(|_| {
                            msquic::Status::from(msquic::StatusCode::QUIC_STATUS_ABORTED)
                        })?;
                        for frame in frames {
                            let next = sequence.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                            let event = match kind {
                                StreamKind::Control => NativeEvent::Control(frame),
                                StreamKind::Reliable { lane } => NativeEvent::Reliable {
                                    stream: lane,
                                    sequence: next,
                                    bytes: frame,
                                },
                            };
                            if !push(&inbound, event) {
                                // The queue is full and a callback cannot wait,
                                // so the connection fails loudly instead of
                                // growing without limit.
                                return Err(msquic::Status::from(
                                    msquic::StatusCode::QUIC_STATUS_ABORTED,
                                ));
                            }
                        }
                    }
                }
                StreamEvent::SendComplete { client_context, .. } => {
                    // SAFETY: send_owned produced this context exactly once and
                    // MsQuic delivers SendComplete for it exactly once.
                    unsafe { complete_send(client_context) };
                }
                StreamEvent::PeerSendShutdown if peer_owned => {
                    // Without closing our side the stream never reaches
                    // ShutdownComplete, so its native resources live until the
                    // connection ends and short-lived peer lanes accumulate.
                    stream.shutdown(msquic::StreamShutdownFlags::GRACEFUL, 0)?;
                }
                StreamEvent::ShutdownComplete { .. } if peer_owned => {
                    // SAFETY: MsQuic delivered ShutdownComplete for a
                    // peer-created stream this callback has not adopted before.
                    // Locally opened streams are owned by the pool instead.
                    unsafe { close_peer_stream(&stream) };
                }
                _ => {}
            }
            Ok::<(), msquic::Status>(())
        }
    }

    /// Opens one stream and installs the receive handler on it.
    fn open_stream(
        connection: Option<&Connection>,
        inbound: &Arc<Mutex<VecDeque<NativeEvent>>>,
        sequence: &Arc<AtomicU64>,
        kind: StreamKind,
    ) -> Result<Stream, Error> {
        let connection = connection.ok_or(Error::Backend)?;
        // The caller owns the handle and closes it at teardown, so there is
        // exactly one owner and it is never detached.
        let stream = Stream::open(
            connection,
            StreamOpenFlags::NONE,
            stream_handler(Arc::clone(inbound), Arc::clone(sequence), kind, false),
        )
        .map_err(|_| Error::Backend)?;
        stream
            .start(StreamStartFlags::NONE)
            .map_err(|_| Error::Backend)?;
        Ok(stream)
    }

    /// Returns the application lane for `id`, opening it on first use.
    fn stream_for<'a>(
        streams: &'a mut BTreeMap<u64, Stream>,
        connection: Option<&Connection>,
        inbound: &Arc<Mutex<VecDeque<NativeEvent>>>,
        sequence: &Arc<AtomicU64>,
        id: u64,
    ) -> Result<&'a Stream, Error> {
        match streams.entry(id) {
            Entry::Occupied(slot) => Ok(&*slot.into_mut()),
            Entry::Vacant(slot) => {
                let stream = open_stream(
                    connection,
                    inbound,
                    sequence,
                    StreamKind::Reliable { lane: id },
                )?;
                Ok(&*slot.insert(stream))
            }
        }
    }

    /// Queues an event for the driver. Returns false when the bound is reached.
    fn push(queue: &Arc<Mutex<VecDeque<NativeEvent>>>, event: NativeEvent) -> bool {
        let Ok(mut queue) = queue.lock() else {
            return false;
        };
        if queue.len() >= MAX_CALLBACK_EVENTS {
            return false;
        }
        queue.push_back(event);
        true
    }

    fn pop(queue: &Arc<Mutex<VecDeque<NativeEvent>>>) -> Option<NativeEvent> {
        queue.lock().ok()?.pop_front()
    }

    impl TransportAdapter for MsQuicTransport {
        fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
            self.adapter.send_control(frame)
        }

        fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
            self.adapter.send_reliable(stream, record)
        }

        fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
            self.adapter.send_reliable_shared(stream, record)
        }

        fn preflight_reliable_batch(
            &self,
            stream: StreamId,
            records: &[Payload],
        ) -> Result<(), Error> {
            self.adapter.preflight_reliable_batch(stream, records)
        }

        fn send_datagram(&mut self, _context: u64, _payload: &[u8]) -> Result<(), Error> {
            // Refused here rather than at flush. A queued datagram would sit at
            // the head for ever, because drain_commands keeps a rejected
            // command and nothing can remove it, blocking every control and
            // reliable record behind it.
            Err(Error::Unsupported)
        }

        fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), Error> {
            // Refused at submission for the same reason as datagrams: a queued
            // command this backend cannot carry would sit at the head for ever
            // and block every record behind it. Credit is the receiver's memory
            // bound, so accepting the call and failing later would be worse
            // than saying no. The wrapper exposes no runtime flow-control
            // parameter; the initial window comes from Settings on the
            // Configuration.
            Err(Error::Unsupported)
        }

        fn flush(&mut self) -> Result<(), Error> {
            // Submission happens inside the drain, so a command that cannot be
            // sent stays at the head of the queue and every command after it is
            // still there to retry. Collecting first and sending afterwards
            // would lose them on the first failure.
            let Self {
                adapter,
                inbound,
                sequence,
                streams,
                control,
                connection,
                ..
            } = self;
            let connection = connection.as_ref();
            adapter.drain_commands(|command| match command {
                Command::Reliable { stream, bytes } => {
                    let handle = stream_for(streams, connection, inbound, sequence, stream.0)?;
                    send_owned(handle, &bytes, SendFlags::NONE).map_err(|_| Error::Backend)
                }
                Command::Control(bytes) => {
                    // spec/wire.md puts negotiation on the first
                    // client-initiated bidirectional stream. It is held apart
                    // from the reliable pool, so StreamId(0) remains an
                    // ordinary application lane rather than aliasing control.
                    if control.is_none() {
                        *control = Some(open_stream(
                            connection,
                            inbound,
                            sequence,
                            StreamKind::Control,
                        )?);
                    }
                    let handle = control.as_ref().ok_or(Error::Backend)?;
                    send_owned(handle, &bytes, SendFlags::NONE).map_err(|_| Error::Backend)
                }
                // Unreachable: both are refused at submission so neither can
                // reach the queue, but a silent success here would hide it if
                // that ever changed.
                Command::Datagram { .. } | Command::ReceiveCredit(_) => Err(Error::Unsupported),
            })
        }

        fn poll(&mut self) -> Option<Event> {
            self.pump();
            self.adapter.poll()
        }

        fn path_stats(&self) -> Option<PathStats> {
            self.adapter.path_stats()
        }
    }

    impl Drop for MsQuicTransport {
        fn drop(&mut self) {
            // Streams first: a stream outliving its connection is a use after
            // free, and MsQuic delivers their completions before the
            // connection's own shutdown completes.
            self.streams.clear();
            self.control = None;
            if let Some(connection) = self.connection.take() {
                connection.shutdown(msquic::ConnectionShutdownFlags::NONE, 0);
                // Waiting for ShutdownComplete is what makes the rest safe. A
                // bounded wait, because a hung teardown should not hang a
                // process for ever.
                let _ = self.closed.recv_timeout(SHUTDOWN_WAIT);
                drop(connection);
            }
            self.registration.shutdown();
        }
    }

    /// Opens an actual `MsQuic` registration and validates the linked API table.
    ///
    /// # Errors
    /// Propagates an `MsQuic` registration failure.
    pub fn registration() -> Result<Registration, msquic::Status> {
        Registration::new(&RegistrationConfig::default())
    }

    /// Sends bytes while transferring buffer ownership to the completion callback.
    ///
    /// # Errors
    /// Returns an `MsQuic` error and retains no detached allocation when send fails.
    pub fn send_owned(
        stream: &Stream,
        bytes: &[u8],
        flags: SendFlags,
    ) -> Result<(), msquic::Status> {
        let context = Box::new(SendBuffer::new(bytes));
        let pointer = Box::into_raw(context);
        // SAFETY: pointer owns storage referenced by buffers before MsQuic can
        // invoke SendComplete. A successful call transfers sole ownership to
        // complete_send. An immediate failure cannot produce SendComplete, so
        // this function reconstructs and drops the allocation below.
        let result =
            unsafe { stream.send((*pointer).buffers.as_ref(), flags, pointer.cast::<c_void>()) };
        if result.is_err() {
            // SAFETY: MsQuic rejected the send synchronously and therefore did
            // not accept the context or schedule a SendComplete callback.
            drop(unsafe { Box::from_raw(pointer) });
        }
        result
    }

    /// Reclaims a send allocation returned by `MsQuic` on `SendComplete`.
    ///
    /// # Safety
    /// The context must be the non-null value from one successful `send_owned` call
    /// and must be passed exactly once.
    pub unsafe fn complete_send(context: *const c_void) {
        if !context.is_null() {
            // SAFETY: the caller contract guarantees this pointer came from one
            // successful send_owned call and has not previously been reclaimed.
            let buffer = unsafe { Box::from_raw(context.cast_mut().cast::<SendBuffer>()) };
            debug_assert_eq!(buffer.storage.len(), buffer.buffers[0].as_bytes().len());
        }
    }

    /// Closes a peer-created stream after its shutdown-complete callback.
    ///
    /// # Safety
    /// The stream reference must be in `ShutdownComplete` and not already adopted.
    pub unsafe fn close_peer_stream(stream: &StreamRef) {
        // SAFETY: the caller contract limits adoption to ShutdownComplete and
        // transfers the sole close responsibility to this temporary owner.
        let _ = unsafe { Stream::from_raw(stream.as_raw()) };
    }

    /// Closes a peer-created connection after its shutdown-complete callback.
    ///
    /// # Safety
    /// The connection must be in `ShutdownComplete` and not already adopted.
    pub unsafe fn close_peer_connection(connection: &ConnectionRef) {
        // SAFETY: the caller contract limits adoption to ShutdownComplete and
        // transfers the sole close responsibility to this temporary owner.
        let _ = unsafe { Connection::from_raw(connection.as_raw()) };
    }

    /// Transfers an application-created stream to its callback for final close.
    ///
    /// # Safety
    /// The callback must adopt the stream exactly once at `ShutdownComplete`.
    pub unsafe fn detach_stream(stream: Stream) {
        // SAFETY: ownership is deliberately transferred to the MsQuic callback.
        let _ = unsafe { stream.into_raw() };
    }

    #[cfg(test)]
    mod tests {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::process::Command;
        use std::sync::{Arc, Mutex, mpsc};
        use std::time::{Duration, Instant};

        use msquic::{
            Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Credential,
            CredentialConfig, CredentialFlags, Listener, ListenerEvent, Registration, SendFlags,
            Settings, Status, Stream, StreamEvent, StreamOpenFlags, StreamRef, StreamStartFlags,
        };

        use super::{Framing, MsQuicTransport, StreamKind};

        use super::super::{
            Command as AdapterCommand, MAX_PARTIAL_CONTROL_FRAME, MAX_PARTIAL_FRAME, MsQuicAdapter,
            NativeEvent,
        };
        use super::{close_peer_connection, close_peer_stream, complete_send, detach_stream};
        use vot_transport_api::{
            ConnectionId, Error, Event, MAX_DATA_RECORD_BYTES, StreamId, TransportAdapter,
        };

        fn framed(frame_type: u64, payload: &[u8]) -> Vec<u8> {
            let mut frame = Vec::new();
            vot_codec::encode_frame(frame_type, payload, &mut frame).unwrap();
            frame
        }

        #[test]
        fn a_read_that_coalesces_two_frames_is_not_refused_for_its_size() {
            // A near-maximum record whose tail arrives together with the head of
            // the next frame pushes the buffer past the bound for an instant.
            // Checking before the completed frame is drained refuses a read the
            // peer was entitled to send.
            let big = framed(
                vot_codec::frame_type::DATA_RECORD,
                &vec![0x5a; MAX_DATA_RECORD_BYTES],
            );
            let next = framed(vot_codec::frame_type::DATA_RECORD, &[0x21; 64]);
            assert!(big.len() + next.len() > MAX_PARTIAL_FRAME);

            let mut framing = Framing::new(StreamKind::Reliable { lane: 1 });
            let split = big.len() - 8;
            assert!(framing.accept(&big[..split]).unwrap().is_empty());
            let mut rest = big[split..].to_vec();
            rest.extend_from_slice(&next);
            let frames = framing.accept(&rest).unwrap();
            assert_eq!(frames, vec![big, next]);
        }

        #[test]
        fn a_frame_that_can_never_complete_is_refused_rather_than_held() {
            // Without this the stream stalls for ever on bytes that will never
            // form a frame, and the buffer grows for as long as they arrive.
            let mut framing = Framing::new(StreamKind::Reliable { lane: 1 });
            let head = framed(
                vot_codec::frame_type::PACKAGE_DESCRIPTOR,
                &vec![0x11; MAX_DATA_RECORD_BYTES * 2],
            );
            assert!(matches!(
                framing.accept(&head[..=MAX_PARTIAL_FRAME]),
                Err(Error::RecordTooLarge)
            ));
        }

        #[test]
        fn the_control_lane_reassembles_up_to_the_control_bound() {
            // Control frames are larger than data records, so applying the
            // record bound to the control stream rejects a large
            // PACKAGE_DESCRIPTOR the same transport is willing to send.
            let frame = framed(
                vot_codec::frame_type::PACKAGE_DESCRIPTOR,
                &vec![0x11; MAX_DATA_RECORD_BYTES * 2],
            );
            assert!(frame.len() > MAX_PARTIAL_FRAME);
            assert!(frame.len() <= MAX_PARTIAL_CONTROL_FRAME);

            let mut control = Framing::new(StreamKind::Control);
            let head = frame.len() - 1;
            assert!(control.accept(&frame[..head]).unwrap().is_empty());
            assert_eq!(control.accept(&frame[head..]).unwrap(), vec![frame]);
        }

        #[test]
        fn two_streams_never_share_reassembly_state() {
            // Interleaving halves of two frames through one buffer would splice
            // them into records neither peer sent.
            let first = framed(vot_codec::frame_type::DATA_RECORD, b"first-record");
            let second = framed(vot_codec::frame_type::DATA_RECORD, b"second");
            let mut left = Framing::new(StreamKind::Reliable { lane: 1 });
            let mut right = Framing::new(StreamKind::Reliable { lane: 2 });

            assert!(left.accept(&first[..4]).unwrap().is_empty());
            assert!(right.accept(&second[..4]).unwrap().is_empty());
            assert_eq!(right.accept(&second[4..]).unwrap(), vec![second]);
            assert_eq!(left.accept(&first[4..]).unwrap(), vec![first]);
        }

        fn test_credential() -> Credential {
            let directory = std::env::temp_dir().join(format!("vot-msquic-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let key = directory.join("key.pem");
            let certificate = directory.join("cert.pem");
            if !key.exists() || !certificate.exists() {
                let status = Command::new("openssl")
                    .args([
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-keyout",
                        key.to_str().unwrap(),
                        "-out",
                        certificate.to_str().unwrap(),
                        "-sha256",
                        "-days",
                        "1",
                        "-nodes",
                        "-subj",
                        "/CN=localhost",
                    ])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            Credential::CertificateFile(msquic::CertificateFile::new(
                key.display().to_string(),
                certificate.display().to_string(),
            ))
        }

        /// Builds a client configuration that trusts the test certificate.
        fn client_configuration(registration: &Registration) -> Arc<Configuration> {
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let settings = Settings::new().set_PeerBidiStreamCount(4);
            let configuration = Configuration::open(registration, &alpn, Some(&settings)).unwrap();
            configuration
                .load_credential(
                    &CredentialConfig::new_client()
                        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION),
                )
                .unwrap();
            Arc::new(configuration)
        }

        /// One `DATA_RECORD` frame carrying four payload bytes.
        fn echo_frame() -> Vec<u8> {
            let mut frame = Vec::new();
            vot_codec::encode_frame(vot_codec::frame_type::DATA_RECORD, b"echo", &mut frame)
                .unwrap();
            frame
        }

        /// Starts a listener that collects everything it receives.
        fn echo_listener(
            registration: &Registration,
            received: Arc<Mutex<Vec<u8>>>,
            expected: usize,
            done: mpsc::Sender<()>,
        ) -> (Listener, u16) {
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let settings = Settings::new().set_PeerBidiStreamCount(4);
            let configuration =
                Arc::new(Configuration::open(registration, &alpn, Some(&settings)).unwrap());
            configuration
                .load_credential(
                    &CredentialConfig::new()
                        .set_credential_flags(CredentialFlags::NONE)
                        .set_credential(test_credential()),
                )
                .unwrap();
            let stream_handler = move |stream: StreamRef, event: StreamEvent| {
                match event {
                    StreamEvent::Receive { buffers, .. } => {
                        let mut collected = received.lock().unwrap();
                        for buffer in buffers {
                            collected.extend_from_slice(buffer.as_bytes());
                        }
                        if collected.len() >= expected {
                            // Echo one framed record back, split across two
                            // sends, so the client's reassembly is exercised
                            // rather than its buffer boundaries being trusted.
                            let frame = echo_frame();
                            let (head, tail) = frame.split_at(3);
                            let _ = super::send_owned(&stream, head, SendFlags::NONE);
                            let _ = super::send_owned(&stream, tail, SendFlags::NONE);
                            let _ = done.send(());
                        }
                    }
                    StreamEvent::ShutdownComplete { .. } => {
                        // SAFETY: MsQuic delivered ShutdownComplete for this
                        // peer-created stream and no other owner adopted it.
                        unsafe { close_peer_stream(&stream) };
                    }
                    _ => {}
                }
                Ok::<(), Status>(())
            };
            let connection_handler = move |connection: ConnectionRef, event: ConnectionEvent| {
                match event {
                    ConnectionEvent::PeerStreamStarted { stream, .. } => {
                        stream.set_callback_handler(stream_handler.clone());
                    }
                    ConnectionEvent::ShutdownComplete { .. } => {
                        // SAFETY: unique ShutdownComplete for a peer-created
                        // connection this callback has not adopted before.
                        unsafe { close_peer_connection(&connection) };
                    }
                    _ => {}
                }
                Ok(())
            };
            let listener = Listener::open(registration, move |_, event: ListenerEvent| {
                if let ListenerEvent::NewConnection { connection, .. } = event {
                    connection.set_callback_handler(connection_handler.clone());
                    connection.set_configuration(&configuration)?;
                }
                Ok(())
            })
            .unwrap();
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            listener.start(&alpn, Some(&address)).unwrap();
            let port = listener.get_local_addr().unwrap().port();
            (listener, port)
        }

        #[test]
        fn assembled_transport_delivers_over_localhost() {
            let payload = vec![0x71_u8; 192 * 1024];
            let registration = super::registration().unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let (done_tx, done_rx) = mpsc::channel();
            let (listener, port) =
                echo_listener(&registration, Arc::clone(&received), payload.len(), done_tx);

            let client_registration = super::registration().unwrap();
            let configuration = client_configuration(&client_registration);
            let mut transport =
                MsQuicTransport::connect(configuration, client_registration, "127.0.0.1", port, 11)
                    .unwrap();

            // Wait for the connection through the adapter's own event queue,
            // which is the path a driver uses rather than a side channel.
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut connected = false;
            while Instant::now() < deadline && !connected {
                while let Some(event) = transport.poll() {
                    if matches!(event, Event::Connected(ConnectionId(11))) {
                        connected = true;
                    }
                }
                std::thread::yield_now();
            }
            assert!(connected, "never saw Connected through the adapter");

            // Path metrics come from the live connection, sampled on this
            // thread, and reach the backend-neutral accessor.
            transport.sample_path().unwrap();
            let stats = transport.path_stats().expect("no path stats after connect");
            assert!(stats.smoothed_rtt_us.is_some());
            assert!(stats.congestion_window_bytes.is_some());

            for record in payload.chunks(64 * 1024) {
                transport.send_reliable(StreamId(1), record).unwrap();
            }
            transport.flush().unwrap();
            assert_eq!(
                transport.pending_commands(),
                0,
                "a clean flush queues nothing"
            );
            done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(*received.lock().unwrap(), payload);

            // The peer echoed a record back, so the receive path has to deliver
            // it through poll rather than the transport being send only.
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut echoed = Vec::new();
            while Instant::now() < deadline && echoed.is_empty() {
                while let Some(event) = transport.poll() {
                    if let Event::Reliable {
                        bytes, sequence, ..
                    } = event
                    {
                        assert!(sequence >= 1, "sequence starts at one");
                        echoed.extend_from_slice(&bytes);
                    }
                }
                std::thread::yield_now();
            }
            assert_eq!(
                echoed,
                echo_frame(),
                "nothing arrived through the receive path"
            );

            drop(transport);
            listener.stop();
            drop(listener);
            registration.shutdown();
        }

        #[test]
        fn a_command_the_backend_refuses_stays_queued() {
            // Backpressure only works if a failed flush loses nothing.
            // Collecting commands before submitting would drop the failing one
            // and everything behind it.
            let registration = super::registration().unwrap();
            let configuration = client_configuration(&registration);
            let mut transport = MsQuicTransport::connect(
                configuration,
                super::registration().unwrap(),
                "127.0.0.1",
                1,
                21,
            )
            .unwrap();
            // Nothing is listening, so the send cannot reach a peer.
            transport.send_reliable(StreamId(4), b"never sent").unwrap();
            transport
                .send_reliable(StreamId(5), b"queued behind it")
                .unwrap();
            assert_eq!(transport.pending_commands(), 2);

            // Whatever the backend says, the queue must not shrink on failure.
            for _ in 0..3 {
                if transport.flush().is_ok() {
                    break;
                }
                assert_eq!(transport.pending_commands(), 2);
            }

            // Neither datagrams nor receive credit can be queued at all, so
            // they can never wedge the head of the queue.
            assert_eq!(transport.send_datagram(1, b"x"), Err(Error::Unsupported));
            assert_eq!(transport.set_receive_credit(4096), Err(Error::Unsupported));

            drop(transport);
            drop(registration);
        }

        #[test]
        fn transport_teardown_releases_everything_in_order() {
            // Written before anything was sent through the type, because drop
            // order is where an FFI transport goes wrong: a stream or a send
            // buffer outliving the connection is a use after free, and it will
            // not show up as a test failure, only as a sanitizer report.
            let registration = super::registration().unwrap();
            let configuration = client_configuration(&registration);
            // Nothing is listening, so this exercises teardown of a connection
            // that never completed, which is the harder case.
            let transport = MsQuicTransport::connect(
                Arc::clone(&configuration),
                super::registration().unwrap(),
                "127.0.0.1",
                1,
                7,
            )
            .unwrap();
            drop(transport);

            // And a transport that opened a stream before being dropped.
            let mut with_stream = MsQuicTransport::connect(
                configuration,
                super::registration().unwrap(),
                "127.0.0.1",
                1,
                8,
            )
            .unwrap();
            with_stream
                .send_reliable(StreamId(1), b"never delivered")
                .unwrap();
            // The flush may fail because the connection never came up. What
            // matters is that dropping afterwards is still clean.
            let _ = with_stream.flush();
            drop(with_stream);
            drop(registration);
        }

        #[test]
        #[allow(clippy::too_many_lines)]
        fn localhost_reliable_stream_round_trip() {
            let payload = vec![0x6d; 192 * 1024];
            let expected_length = payload.len();
            let registration = super::registration().unwrap();
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let settings = Settings::new().set_PeerBidiStreamCount(4);

            let server_configuration =
                Configuration::open(&registration, &alpn, Some(&settings)).unwrap();
            server_configuration
                .load_credential(
                    &CredentialConfig::new()
                        .set_credential_flags(CredentialFlags::NONE)
                        .set_credential(test_credential()),
                )
                .unwrap();
            let server_configuration = Arc::new(server_configuration);

            let received = Arc::new(Mutex::new(Vec::new()));
            let (complete_tx, complete_rx) = mpsc::channel();
            let (server_closed_tx, server_closed_rx) = mpsc::channel();
            let (listener_stopped_tx, listener_stopped_rx) = mpsc::channel();
            let stream_received = Arc::clone(&received);
            let server_stream = move |stream: StreamRef, event: StreamEvent| {
                match event {
                    StreamEvent::Receive { buffers, .. } => {
                        let mut received = stream_received.lock().unwrap();
                        for buffer in buffers {
                            received.extend_from_slice(buffer.as_bytes());
                        }
                        if received.len() == expected_length {
                            complete_tx.send(()).unwrap();
                        }
                    }
                    StreamEvent::ShutdownComplete { .. } => {
                        // SAFETY: MsQuic delivered ShutdownComplete for this
                        // peer-created stream and no other owner adopted it.
                        unsafe { close_peer_stream(&stream) };
                    }
                    StreamEvent::PeerSendShutdown => {
                        stream.shutdown(msquic::StreamShutdownFlags::GRACEFUL, 0)?;
                    }
                    _ => {}
                }
                Ok::<(), Status>(())
            };

            let server_connection = move |connection: ConnectionRef, event: ConnectionEvent| {
                match event {
                    ConnectionEvent::PeerStreamStarted { stream, .. } => {
                        stream.set_callback_handler(server_stream.clone());
                    }
                    ConnectionEvent::ShutdownComplete { .. } => {
                        server_closed_tx.send(()).unwrap();
                        // SAFETY: MsQuic delivered ShutdownComplete for this
                        // peer-created connection and no other owner adopted it.
                        unsafe { close_peer_connection(&connection) };
                    }
                    _ => {}
                }
                Ok::<(), Status>(())
            };

            let configuration = Arc::clone(&server_configuration);
            let listener = Listener::open(&registration, move |_, event: ListenerEvent| {
                match event {
                    ListenerEvent::NewConnection { connection, .. } => {
                        connection.set_callback_handler(server_connection.clone());
                        connection.set_configuration(&configuration)?;
                    }
                    ListenerEvent::StopComplete { .. } => {
                        listener_stopped_tx.send(()).unwrap();
                    }
                }
                Ok(())
            })
            .unwrap();
            let listen_address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            listener.start(&alpn, Some(&listen_address)).unwrap();
            let port = listener.get_local_addr().unwrap().port();

            let client_configuration =
                Configuration::open(&registration, &alpn, Some(&settings)).unwrap();
            client_configuration
                .load_credential(
                    &CredentialConfig::new_client()
                        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION),
                )
                .unwrap();

            let mut adapter = MsQuicAdapter::default();
            adapter.send_reliable(StreamId(1), &payload).unwrap();
            let (stream_closed_tx, stream_closed_rx) = mpsc::channel();
            let client_adapter_for_callback = Arc::new(Mutex::new(adapter));
            let sampled_adapter = Arc::clone(&client_adapter_for_callback);
            let (client_closed_tx, client_closed_rx) = mpsc::channel();
            let client_stream = move |stream: StreamRef, event: StreamEvent| {
                match event {
                    StreamEvent::SendComplete { client_context, .. } => {
                        // SAFETY: send_owned returned this exact context once.
                        unsafe { complete_send(client_context) };
                    }
                    StreamEvent::ShutdownComplete { .. } => {
                        stream_closed_tx.send(()).unwrap();
                        // SAFETY: the stream was detached after start and this
                        // is its unique ShutdownComplete callback.
                        unsafe { close_peer_stream(&stream) };
                    }
                    _ => {}
                }
                Ok::<(), Status>(())
            };
            let client_connection = Connection::open(
                &registration,
                move |connection: ConnectionRef, event: ConnectionEvent| {
                    match event {
                        ConnectionEvent::Connected { .. } => {
                            let stream = Stream::open(
                                &connection,
                                StreamOpenFlags::NONE,
                                client_stream.clone(),
                            )?;
                            stream.start(StreamStartFlags::NONE)?;
                            let mut adapter = client_adapter_for_callback.lock().unwrap();
                            adapter.drain_commands(|command| match command {
                                AdapterCommand::Reliable { bytes, .. } => {
                                    super::send_owned(&stream, &bytes, SendFlags::FIN)
                                }
                                AdapterCommand::Control(_)
                                | AdapterCommand::Datagram { .. }
                                | AdapterCommand::ReceiveCredit(_) => Ok(()),
                            })?;
                            // SAFETY: client_stream adopts this handle in its unique
                            // ShutdownComplete callback.
                            unsafe { detach_stream(stream) };
                        }
                        ConnectionEvent::ShutdownComplete { .. } => {
                            client_closed_tx.send(()).unwrap();
                        }
                        _ => {}
                    }
                    Ok(())
                },
            )
            .unwrap();
            client_connection
                .start(&client_configuration, "127.0.0.1", port)
                .unwrap();

            complete_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(*received.lock().unwrap(), payload);
            stream_closed_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap();

            let stats = super::path_stats(&client_connection).unwrap();
            assert!(stats.smoothed_rtt_us.is_some());
            assert!(stats.congestion_window_bytes.is_some());
            assert!(stats.mtu_bytes.is_some());
            assert_eq!(stats.pacing_rate_bps, None);
            {
                let mut adapter = sampled_adapter.lock().unwrap();
                adapter.record_path_stats(ConnectionId(1), stats);
                assert_eq!(adapter.path_stats(), Some(stats));
                adapter
                    .record_native_event(NativeEvent::Disconnected(1))
                    .unwrap();
                assert_eq!(adapter.path_stats(), None);
            }

            client_connection.shutdown(msquic::ConnectionShutdownFlags::NONE, 0);
            client_closed_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            server_closed_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            listener.stop();
            listener_stopped_rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            drop(client_connection);
            drop(client_configuration);
            drop(listener);
            drop(server_configuration);
            registration.shutdown();
            drop(registration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_adapter_preserves_transport_contract() {
        let mut adapter = MsQuicAdapter::default();
        adapter.send_control(b"hello").unwrap();
        adapter
            .send_reliable(StreamId(2), b"verified bytes")
            .unwrap();
        adapter.set_receive_credit(4096).unwrap();
        assert_eq!(
            adapter.next_command(),
            Some(Command::Control(b"hello".to_vec().into()))
        );
        assert_eq!(
            adapter.next_command(),
            Some(Command::Reliable {
                stream: StreamId(2),
                bytes: b"verified bytes".to_vec().into(),
            })
        );
        assert_eq!(adapter.next_command(), Some(Command::ReceiveCredit(4096)));
    }

    #[test]
    fn command_drain_is_retryable_and_preserves_order() {
        let mut adapter = MsQuicAdapter::default();
        adapter.send_control(b"control").unwrap();
        adapter.send_reliable(StreamId(4), b"payload").unwrap();
        let mut attempts = 0;
        assert_eq!(
            adapter.drain_commands(|_| {
                attempts += 1;
                Err::<(), _>(Error::Backend)
            }),
            Err(Error::Backend)
        );
        assert_eq!(attempts, 1);
        assert_eq!(
            adapter.next_command(),
            Some(Command::Control(b"control".to_vec().into()))
        );

        let mut seen = Vec::new();
        adapter
            .drain_commands(|command| {
                seen.push(command);
                Ok::<(), Error>(())
            })
            .unwrap();
        assert_eq!(
            seen,
            vec![Command::Reliable {
                stream: StreamId(4),
                bytes: b"payload".to_vec().into(),
            }]
        );
    }

    #[test]
    fn datagram_send_state_is_exposed_for_later_use() {
        let mut adapter = MsQuicAdapter::default();
        adapter
            .record_native_event(NativeEvent::DatagramState {
                context: 77,
                state: NativeDatagramSendState::LostSuspect,
            })
            .unwrap();
        assert_eq!(
            adapter.poll(),
            Some(Event::DatagramState {
                context: 77,
                state: DatagramSendState::SuspectedLost,
            })
        );
    }

    #[test]
    fn datagram_submission_obeys_the_exact_payload_limit() {
        let mut adapter = MsQuicAdapter::default();
        let exact = vec![0; vot_transport_api::MAX_DATAGRAM_BYTES];
        adapter.send_datagram(9, &exact).unwrap();
        assert_eq!(
            adapter.next_command(),
            Some(Command::Datagram {
                context: 9,
                bytes: exact.into(),
            })
        );

        assert_eq!(
            adapter.send_datagram(10, &vec![0; vot_transport_api::MAX_DATAGRAM_BYTES + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(adapter.next_command(), None);
    }

    #[test]
    fn path_stats_are_unavailable_without_a_native_path() {
        let adapter = MsQuicAdapter::default();
        assert_eq!(adapter.path_stats(), None);
    }

    #[test]
    fn recorded_path_stats_feed_bdp_and_careful_resume_consumers() {
        let mut adapter = MsQuicAdapter::default();
        let sample = PathStats {
            smoothed_rtt_us: Some(18_500),
            congestion_window_bytes: Some(1_048_576),
            mtu_bytes: Some(1350),
            pacing_rate_bps: None,
        };
        adapter.record_path_stats(ConnectionId(7), sample);
        assert_eq!(adapter.path_stats(), Some(sample));
        let stats = adapter.path_stats().unwrap();
        assert_eq!(stats.congestion_window_bytes, Some(1_048_576));
        assert_eq!(stats.smoothed_rtt_us, Some(18_500));
    }

    #[test]
    fn reserved_lanes_cannot_collide_with_an_application_stream() {
        // Control frames and peer-initiated records are reported on lanes of
        // their own. If either collided with the other, or with a stream a
        // caller could name, replies would be classified as the wrong kind.
        assert_ne!(CONTROL_LANE, PEER_STREAM_ID);
        assert_eq!(PEER_STREAM_ID, u64::MAX);
        assert_eq!(CONTROL_LANE, u64::MAX - 1);
        // Zero stays an ordinary application lane.
        assert_ne!(CONTROL_LANE, 0);
        assert_ne!(PEER_STREAM_ID, 0);
        // The bounds are the ones the callback path relies on.
        assert_eq!(MAX_CALLBACK_EVENTS, 1024);
        assert_eq!(
            MAX_PARTIAL_FRAME,
            vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES
        );
        // The control lane reassembles up to what the adapter is willing to
        // send on it. A receive bound below the send bound would refuse a frame
        // this transport produces.
        assert_eq!(
            MAX_PARTIAL_CONTROL_FRAME,
            vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES
        );
        assert_eq!(
            MsQuicAdapter::default().control_payload_limit,
            vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD
        );
    }

    #[test]
    fn a_reserved_lane_is_refused_at_submission() {
        // Both are lanes the receive path reports on. Opening an application
        // stream numbered the same way would have its replies classified as
        // control frames or as peer-initiated records.
        let mut adapter = MsQuicAdapter::default();
        for lane in [CONTROL_LANE, PEER_STREAM_ID] {
            assert!(is_reserved_lane(lane));
            assert!(matches!(
                adapter.send_reliable(StreamId(lane), b"record"),
                Err(Error::InvalidConfiguration)
            ));
            assert!(matches!(
                adapter.send_reliable_shared(StreamId(lane), shared_payload(b"record")),
                Err(Error::InvalidConfiguration)
            ));
            assert!(matches!(
                adapter.preflight_reliable_batch(StreamId(lane), &[shared_payload(b"record")]),
                Err(Error::InvalidConfiguration)
            ));
        }
        assert_eq!(adapter.pending_commands(), 0);
        // The lane one below the reserved pair is ordinary.
        assert!(!is_reserved_lane(CONTROL_LANE - 1));
        adapter
            .send_reliable(StreamId(CONTROL_LANE - 1), b"record")
            .unwrap();
        assert_eq!(adapter.pending_commands(), 1);
    }

    #[test]
    fn queued_command_count_tracks_submission_and_drain() {
        let mut adapter = MsQuicAdapter::default();
        assert_eq!(adapter.pending_commands(), 0);
        adapter.send_control(b"one").unwrap();
        assert_eq!(adapter.pending_commands(), 1);
        adapter.send_reliable(StreamId(2), b"two").unwrap();
        assert_eq!(adapter.pending_commands(), 2);
        adapter.next_command().unwrap();
        assert_eq!(adapter.pending_commands(), 1);
        adapter.drain_commands(|_| Ok::<(), Error>(())).unwrap();
        assert_eq!(adapter.pending_commands(), 0);
    }

    #[test]
    fn a_refused_event_comes_back_so_a_driver_can_retry_it() {
        // record_native_event discards on failure, which is fine for a caller
        // that can regenerate the event and wrong for one draining a queue.
        let mut adapter = MsQuicAdapter::with_queue_limits(1, 4096).unwrap();
        adapter
            .try_record_native_event(NativeEvent::Connected(1))
            .unwrap();

        let refused = NativeEvent::Reliable {
            stream: 3,
            sequence: 9,
            bytes: b"held".to_vec(),
        };
        let (returned, error) = adapter
            .try_record_native_event(refused.clone())
            .expect_err("a full queue must refuse");
        assert_eq!(error, Error::InboundQueueFull);
        assert_eq!(returned, refused, "the event must come back intact");

        // Once space is made, the same event is accepted, in order.
        assert!(matches!(adapter.poll(), Some(Event::Connected(_))));
        adapter.try_record_native_event(returned).unwrap();
        assert!(matches!(
            adapter.poll(),
            Some(Event::Reliable { sequence: 9, .. })
        ));

        // Both entry points agree about what is admissible, and a protocol
        // limit is reported as such rather than as queue pressure.
        let oversized = NativeEvent::Reliable {
            stream: 1,
            sequence: 1,
            bytes: vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1],
        };
        assert_eq!(
            adapter
                .try_record_native_event(oversized.clone())
                .unwrap_err()
                .1,
            Error::RecordTooLarge
        );
        assert_eq!(
            adapter.record_native_event(oversized),
            Err(Error::RecordTooLarge)
        );
    }

    #[test]
    fn path_stats_are_discarded_when_their_connection_disconnects() {
        let mut adapter = MsQuicAdapter::default();
        adapter.record_path_stats(ConnectionId(7), PathStats::default());
        adapter
            .record_native_event(NativeEvent::Disconnected(9))
            .unwrap();
        assert_eq!(adapter.path_stats(), Some(PathStats::default()));
        adapter
            .record_native_event(NativeEvent::Disconnected(7))
            .unwrap();
        assert_eq!(adapter.path_stats(), None);
    }

    #[test]
    fn a_rejected_disconnect_leaves_the_recorded_path_intact() {
        let mut adapter = MsQuicAdapter::with_queue_limits(1, 64).unwrap();
        adapter.record_path_stats(ConnectionId(7), PathStats::default());
        adapter
            .record_native_event(NativeEvent::Connected(7))
            .unwrap();
        assert_eq!(
            adapter.record_native_event(NativeEvent::Disconnected(7)),
            Err(Error::InboundQueueFull)
        );
        assert_eq!(adapter.path_stats(), Some(PathStats::default()));
    }

    #[test]
    fn oversized_reliable_record_is_rejected_before_ffi() {
        let mut adapter = MsQuicAdapter::default();
        assert_eq!(
            adapter.send_reliable(
                StreamId(1),
                &vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1]
            ),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(adapter.next_command(), None);
    }

    #[test]
    fn reliable_batch_preflight_keeps_queue_unchanged_on_count_failure() {
        let mut adapter = MsQuicAdapter::with_queue_limits(2, 100).unwrap();
        adapter.send_reliable(StreamId(1), b"first").unwrap();
        let records = [shared_payload(b"second"), shared_payload(b"third")];
        assert_eq!(
            adapter.send_reliable_batch(StreamId(1), &records),
            Err(Error::OutboundQueueFull)
        );
        assert_eq!(
            adapter.next_command(),
            Some(Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"first"),
            })
        );
        assert_eq!(adapter.next_command(), None);

        let mut exact_count = MsQuicAdapter::with_queue_limits(2, 100).unwrap();
        exact_count.send_reliable(StreamId(1), b"first").unwrap();
        assert_eq!(
            exact_count.send_reliable_batch(StreamId(1), &[shared_payload(b"second")]),
            Ok(())
        );

        let mut exact_bytes = MsQuicAdapter::with_queue_limits(3, 8).unwrap();
        exact_bytes.send_reliable(StreamId(1), b"one").unwrap();
        assert_eq!(
            exact_bytes.send_reliable_batch(StreamId(1), &[shared_payload(b"12345")]),
            Ok(())
        );
    }

    #[test]
    fn reliable_batch_preflight_keeps_queue_unchanged_on_byte_failure() {
        let mut adapter = MsQuicAdapter::with_queue_limits(3, 8).unwrap();
        adapter.send_reliable(StreamId(1), b"one").unwrap();
        let records = [shared_payload(b"two"), shared_payload(b"three")];
        assert_eq!(
            adapter.send_reliable_batch(StreamId(1), &records),
            Err(Error::OutboundQueueFull)
        );
        assert_eq!(
            adapter.next_command(),
            Some(Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"one"),
            })
        );
        assert_eq!(adapter.next_command(), None);
    }

    #[test]
    fn control_frames_obey_the_exact_backend_limit() {
        assert_eq!(vot_codec_limit(), 1_048_576);
        let mut adapter = MsQuicAdapter::default();
        adapter
            .send_control(&vec![
                0;
                vot_codec_limit()
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ])
            .unwrap();
        assert_eq!(
            adapter.send_control(&vec![
                0;
                vot_codec_limit()
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
                    + 1
            ]),
            Err(Error::RecordTooLarge)
        );
    }

    #[test]
    fn negotiated_control_payload_limit_updates_both_directions() {
        let mut adapter = MsQuicAdapter::default();
        assert_eq!(
            adapter.set_control_payload_limit(0),
            Err(Error::InvalidConfiguration)
        );
        adapter.set_control_payload_limit(2 * 1024 * 1024).unwrap();
        adapter
            .send_control(&vec![
                0;
                2 * 1024 * 1024
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ])
            .unwrap();
        assert_eq!(
            adapter.send_control(&vec![
                0;
                2 * 1024 * 1024
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
                    + 1
            ]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            adapter.record_native_event(NativeEvent::Control(vec![
                0;
                2 * 1024 * 1024 + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ])),
            Ok(())
        );
    }

    #[test]
    fn outbound_queue_applies_count_and_byte_backpressure() {
        assert_eq!(DEFAULT_COMMAND_COUNT_LIMIT, 64);
        assert_eq!(DEFAULT_COMMAND_BYTE_LIMIT, 4_194_304);
        assert_eq!(
            MsQuicAdapter::with_queue_limits(0, 1).err(),
            Some(Error::InvalidConfiguration)
        );
        let mut adapter = MsQuicAdapter::with_queue_limits(2, 5).unwrap();
        adapter.send_control(b"123").unwrap();
        adapter.send_reliable(StreamId(1), b"45").unwrap();
        assert_eq!(adapter.set_receive_credit(1), Err(Error::OutboundQueueFull));
        assert_eq!(
            adapter.next_command(),
            Some(Command::Control(b"123".to_vec().into()))
        );
        assert_eq!(adapter.send_control(b"6789"), Err(Error::OutboundQueueFull));
        assert!(matches!(
            adapter.next_command(),
            Some(Command::Reliable { .. })
        ));
        adapter.send_control(b"6789").unwrap();
    }

    #[test]
    fn inbound_queue_applies_record_count_and_byte_backpressure() {
        let mut adapter = MsQuicAdapter::with_queue_limits(2, 5).unwrap();
        adapter
            .record_native_event(NativeEvent::Control(b"123".to_vec()))
            .unwrap();
        adapter
            .record_native_event(NativeEvent::Reliable {
                stream: 1,
                sequence: 2,
                bytes: b"45".to_vec(),
            })
            .unwrap();
        assert_eq!(
            adapter.record_native_event(NativeEvent::DatagramState {
                context: 3,
                state: NativeDatagramSendState::Sent,
            }),
            Err(Error::InboundQueueFull)
        );
        assert!(matches!(adapter.poll(), Some(Event::Control(_))));
        adapter
            .record_native_event(NativeEvent::Control(b"678".to_vec()))
            .unwrap();
        assert!(matches!(adapter.poll(), Some(Event::Reliable { .. })));
        assert!(matches!(adapter.poll(), Some(Event::Control(_))));

        let mut bytes = MsQuicAdapter::with_queue_limits(3, 5).unwrap();
        bytes
            .record_native_event(NativeEvent::Control(b"123".to_vec()))
            .unwrap();
        assert_eq!(
            bytes.record_native_event(NativeEvent::Control(b"456".to_vec())),
            Err(Error::InboundQueueFull)
        );

        let mut oversized = MsQuicAdapter::default();
        oversized
            .record_native_event(NativeEvent::Control(vec![
                0;
                vot_codec_limit() + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ]))
            .unwrap();
        assert!(matches!(oversized.poll(), Some(Event::Control(_))));
        assert_eq!(
            oversized.record_native_event(NativeEvent::Control(vec![
                0;
                vot_codec_limit() + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
                    + 1
            ])),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            oversized.record_native_event(NativeEvent::Reliable {
                stream: 1,
                sequence: 1,
                bytes: vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1],
            }),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(oversized.poll(), None);
    }

    #[cfg(feature = "live")]
    #[test]
    fn official_msquic_api_opens_and_closes() {
        let registration = live::registration().unwrap();
        drop(registration);
    }
}
