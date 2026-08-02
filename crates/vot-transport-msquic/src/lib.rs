//! `MsQuic` event bridge for the backend-neutral VOT transport API.

#![deny(unsafe_code)]

use std::collections::VecDeque;

/// First lane reported for a peer-initiated stream.
///
/// Each gets its own, so interleaving between two peer streams is not mistaken
/// for reordering within one. Above every lane either side can name: a QUIC
/// varint stops at `2^62 - 1`.
pub const PEER_LANE_BASE: u64 = 1 << 62;

/// Lane reported for control frames, which arrive on their own stream rather
/// than one of the application's reliable lanes.
pub const CONTROL_LANE: u64 = u64::MAX - 1;

/// Largest lane a peer-initiated stream can be given.
pub const PEER_LANE_LAST: u64 = CONTROL_LANE - 1;

/// QUIC identifier of the first client-initiated bidirectional stream, which
/// `spec/wire.md` reserves for negotiation.
pub const CONTROL_STREAM_ID: u64 = 0;

/// Largest number of peer-driven events the callback queue will hold.
///
/// Callbacks run on backend worker threads and cannot wait for the driver, so
/// without a bound a peer that sends faster than the driver polls would drive
/// allocation until the process died.
///
/// This bounds records and control frames, which is where a peer sets the pace.
/// Connection lifecycle events are admitted past it, because losing one is not
/// survivable and there are at most two of them per connection.
pub const MAX_CALLBACK_EVENTS: usize = 1024;

/// Largest number of peer-driven payload bytes the callback queue will hold.
///
/// The entry count is not a memory bound on its own. A control frame is four
/// times the size of a data record, so a thousand of them is over a gigabyte
/// held for a peer the driver has not caught up with. This is the bound that
/// actually limits memory; the count limits per-event overhead.
///
/// Sized as a burst of the largest frames either lane carries, which is enough
/// for the driver to be briefly behind without the connection failing.
pub const MAX_CALLBACK_BYTES: usize = 16 * MAX_PARTIAL_CONTROL_FRAME;

/// Largest partial frame held on a reliable lane while waiting for the rest.
pub const MAX_PARTIAL_FRAME: usize = vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// Default control-lane reassembly bound, and what the callback byte budget is
/// sized from. Four times the record bound, so a large `PACKAGE_DESCRIPTOR`
/// this transport would send is not refused on the way in.
///
/// The ceiling, not the bound in force: an assembled transport takes the limit
/// it advertises at construction and holds every stream to that.
pub const MAX_PARTIAL_CONTROL_FRAME: usize = vot_transport_api::MAX_CONTROL_FRAME_WIRE_BYTES;

/// Whether `lane` is reserved. An application may open neither the control
/// lane nor a peer lane: their framing and handles belong to the transport.
#[must_use]
pub const fn is_reserved_lane(lane: u64) -> bool {
    lane >= PEER_LANE_BASE
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
    /// What this endpoint accepts, which is what it advertised. Separate from
    /// the send bound, which is the peer's.
    control_receive_limit: usize,
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
            control_receive_limit: vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            events: VecDeque::new(),
            event_bytes: 0,
            event_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            event_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
            path: None,
        }
    }
}

impl MsQuicAdapter {
    /// Sets what this endpoint accepts, which is what it advertised.
    ///
    /// # Errors
    /// Rejects a limit outside the protocol range.
    pub fn set_control_receive_limit(&mut self, limit: usize) -> Result<(), Error> {
        vot_transport_api::validate_control_payload_limit(limit)?;
        self.control_receive_limit = limit;
        Ok(())
    }

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
                // The receive bound: the peer's limit governs what goes out,
                // not what may arrive.
                vot_transport_api::validate_control_frame(bytes, self.control_receive_limit)?;
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

    /// Applies the peer-negotiated control-frame payload ceiling.
    fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
        vot_transport_api::validate_control_payload_limit(limit)?;
        self.control_payload_limit = limit;
        Ok(())
    }

    fn control_receive_limit(&self) -> Option<usize> {
        Some(self.control_receive_limit)
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use msquic::{
        Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Listener,
        ListenerEvent, Registration, RegistrationConfig, SendFlags, Stream, StreamEvent,
        StreamOpenFlags, StreamRef, StreamStartFlags,
    };

    use vot_transport_api::{ConnectionId, Error, Event, Payload, StreamId, TransportAdapter};

    use super::{
        CONTROL_STREAM_ID, Command, MAX_CALLBACK_BYTES, MAX_CALLBACK_EVENTS, MAX_PARTIAL_FRAME,
        MsQuicAdapter, NativeEvent, PEER_LANE_BASE, PEER_LANE_LAST,
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

    /// Where an endpoint's negotiation stream comes from: opened by the
    /// connecting side, received by the accepting one. The only difference
    /// between the two assembled transports.
    enum Control {
        /// Opened here, and claimed before any application lane so negotiation
        /// keeps QUIC stream zero.
        Opened(Option<Stream>),
        /// Started by the peer and adopted, which is what an accepted
        /// connection sees.
        Adopted(ControlSlot),
    }

    impl Control {
        /// Claims the negotiation stream if this endpoint is the one that opens
        /// it.
        ///
        /// # Errors
        /// Propagates a stream that could not be opened or started.
        fn reserve(
            &mut self,
            connection: Option<&Connection>,
            callbacks: &Callbacks,
        ) -> Result<(), Error> {
            match self {
                Self::Opened(slot) => ensure_control(slot, connection, callbacks),
                // The peer opens this one, so there is nothing to claim.
                Self::Adopted(_) => Ok(()),
            }
        }

        /// Sends a frame on the negotiation stream.
        ///
        /// # Errors
        /// Reports a stream that could not be opened, has not arrived yet, or
        /// refused the send. The caller keeps the frame queued in every case.
        fn send(
            &mut self,
            connection: Option<&Connection>,
            callbacks: &Callbacks,
            bytes: &[u8],
        ) -> Result<(), Error> {
            match self {
                Self::Opened(slot) => {
                    ensure_control(slot, connection, callbacks)?;
                    let handle = slot.as_ref().ok_or(Error::Backend)?;
                    send_owned(handle, bytes, SendFlags::NONE).map_err(|_| Error::Backend)
                }
                Self::Adopted(slot) => {
                    let guard = slot.lock().map_err(|_| Error::Backend)?;
                    // Refused, not dropped: a refused command stays queued and
                    // goes out once the peer opens the stream.
                    let handle = guard.as_ref().ok_or(Error::Backend)?;
                    send_owned(handle, bytes, SendFlags::NONE).map_err(|_| Error::Backend)
                }
            }
        }

        /// The slot a peer-created negotiation stream is adopted into, if this
        /// endpoint is the one that adopts it.
        const fn slot(&self) -> Option<&ControlSlot> {
            match self {
                Self::Adopted(slot) => Some(slot),
                Self::Opened(_) => None,
            }
        }

        /// Releases the handle this endpoint holds, if any.
        fn release(&mut self) {
            match self {
                Self::Opened(slot) => *slot = None,
                Self::Adopted(slot) => {
                    if let Ok(mut slot) = slot.lock() {
                        *slot = None;
                    }
                }
            }
        }
    }

    /// One assembled `MsQuic` connection, whichever side opened it.
    ///
    /// Owns the connection and every stream, released in a fixed order:
    /// anything else frees something a callback may still be running against.
    /// Callbacks never touch the adapter, per ADR-0016.
    struct Carrier {
        adapter: MsQuicAdapter,
        /// Shared with every stream callback: the event queue, the delivery
        /// order, the lane numbering, and the close code a callback asks the
        /// driver to send.
        callbacks: Callbacks,
        /// Held back when the adapter's bounded inbound queue is full, so a
        /// record is never dropped and ordering is never broken.
        stalled: Option<NativeEvent>,
        /// Application lanes opened by this endpoint.
        streams: BTreeMap<u64, Stream>,
        /// The negotiation stream, held apart from the lane pool so
        /// `StreamId(0)` stays an ordinary application lane.
        control: Control,
        connection: Option<Connection>,
        closed: Receiver<()>,
        connection_id: u64,
    }

    /// How long teardown waits for `MsQuic` to finish with a connection.
    const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

    impl Carrier {
        /// Samples the live connection and records the result on the driver
        /// thread, which is the only thread allowed to touch the adapter.
        fn sample_path(&mut self) -> Result<(), msquic::Status> {
            let Some(connection) = self.connection.as_ref() else {
                return Ok(());
            };
            let stats = path_stats(connection)?;
            self.adapter
                .record_path_stats(ConnectionId(self.connection_id), stats);
            Ok(())
        }

        /// Moves native events into the adapter and ends the connection if one
        /// of them can never be admitted.
        fn pump(&mut self) {
            let outcome = pump_events(
                &mut self.adapter,
                &mut self.stalled,
                &self.callbacks.inbound,
            );
            // A callback that rejected a frame left the registered code here,
            // because only the driver may touch connection state. Its code wins
            // over one derived from the adapter's refusal, since it describes
            // what the peer actually did.
            let requested = self.callbacks.close_request.load(Ordering::Relaxed);
            let close = match (requested, outcome) {
                (NO_CLOSE, Pumped::Inadmissible(code)) => Some(code),
                (NO_CLOSE, _) => None,
                (code, _) => Some(code),
            };
            if let Some(close) = close
                && let Some(connection) = self.connection.as_ref()
            {
                // A registered close code rather than a clean shutdown, so the
                // peer learns it violated the contract instead of seeing the
                // transfer end for no stated reason.
                connection.shutdown(msquic::ConnectionShutdownFlags::NONE, close);
                self.callbacks
                    .close_request
                    .store(NO_CLOSE, Ordering::Relaxed);
            }
        }

        /// Submits queued commands to the backend, inside the drain so a
        /// failed command and everything behind it stay queued.
        fn flush(&mut self) -> Result<(), Error> {
            let Self {
                adapter,
                callbacks,
                streams,
                control,
                connection,
                ..
            } = self;
            let connection = connection.as_ref();
            adapter.drain_commands(|command| match command {
                Command::Reliable { stream, bytes } => {
                    // Claimed before any application lane, so negotiation keeps
                    // the first client-initiated bidirectional stream even when
                    // a caller sends a record before a control frame.
                    control.reserve(connection, callbacks)?;
                    let handle = stream_for(streams, connection, callbacks, stream.0)?;
                    send_owned(handle, &bytes, SendFlags::NONE).map_err(|_| Error::Backend)
                }
                Command::Control(bytes) => control.send(connection, callbacks, &bytes),
                // Unreachable: both are refused at submission so neither can
                // reach the queue, but a silent success here would hide it if
                // that ever changed.
                Command::Datagram { .. } | Command::ReceiveCredit(_) => Err(Error::Unsupported),
            })
        }

        /// The registered code the peer closed under, if it named one.
        fn peer_close_code(&self) -> Option<u16> {
            let code = self.callbacks.peer_close.load(Ordering::Relaxed);
            if code == NO_CLOSE {
                return None;
            }
            u16::try_from(code).ok()
        }

        /// Releases everything this connection owns, in the only safe order.
        fn teardown(&mut self) {
            // Streams first: a stream outliving its connection is a use after
            // free, and MsQuic delivers their completions before the
            // connection's own shutdown completes.
            self.streams.clear();
            self.control.release();
            if let Some(connection) = self.connection.take() {
                connection.shutdown(msquic::ConnectionShutdownFlags::NONE, 0);
                // Waiting for ShutdownComplete is what makes the rest safe. A
                // bounded wait, because a hung teardown should not hang a
                // process for ever.
                let _ = self.closed.recv_timeout(SHUTDOWN_WAIT);
                drop(connection);
            }
        }
    }

    impl TransportAdapter for Carrier {
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

        fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
            self.adapter.set_control_payload_limit(limit)
        }

        fn control_receive_limit(&self) -> Option<usize> {
            Some(self.callbacks.control_receive_limit.load(Ordering::Relaxed))
        }

        fn close(&mut self, code: u16) -> Result<(), Error> {
            // Through the close request rather than straight to the connection,
            // so there is one writer for close state and the first code still
            // wins. The pump is what turns it into a shutdown, which keeps
            // connection calls on the driver thread.
            request_close(&self.callbacks.close_request, code);
            self.pump();
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Error> {
            Self::flush(self)
        }

        fn poll(&mut self) -> Option<Event> {
            self.pump();
            self.adapter.poll()
        }

        fn path_stats(&self) -> Option<PathStats> {
            self.adapter.path_stats()
        }
    }

    /// A connected `MsQuic` client that satisfies the backend-neutral adapter.
    ///
    /// Owns its registration and configuration alongside the connection, and
    /// releases them in that order after the connection is gone.
    pub struct MsQuicTransport {
        carrier: Carrier,
        _configuration: Arc<Configuration>,
        registration: Registration,
    }

    impl MsQuicTransport {
        /// Connects to `host:port` and returns a transport ready to send.
        ///
        /// `control_receive_limit` is the largest control-frame payload this
        /// endpoint will reassemble, and is what it must advertise in
        /// `SETTINGS`. Taken here rather than set later because a bound that
        /// arrives after the first byte is a bound the peer already got past.
        ///
        /// # Errors
        /// Propagates registration, configuration, or connection failures.
        pub fn connect(
            configuration: Arc<Configuration>,
            registration: Registration,
            host: &str,
            port: u16,
            connection_id: u64,
            control_receive_limit: usize,
        ) -> Result<Self, msquic::Status> {
            vot_transport_api::validate_control_payload_limit(control_receive_limit).map_err(
                |_| msquic::Status::from(msquic::StatusCode::QUIC_STATUS_INVALID_PARAMETER),
            )?;
            let callbacks = Callbacks::new();
            callbacks
                .control_receive_limit
                .store(control_receive_limit, Ordering::Relaxed);
            let (closed_tx, closed) = mpsc::channel();
            let callback_inbound = Arc::clone(&callbacks.inbound);
            let peer_close = Arc::clone(&callbacks.peer_close);
            let peer_callbacks = callbacks.clone();
            let connection = Connection::open(
                &registration,
                move |_: ConnectionRef, event: ConnectionEvent| {
                    match event {
                        ConnectionEvent::Connected { .. } => {
                            push_lifecycle(
                                &callback_inbound,
                                NativeEvent::Connected(connection_id),
                            );
                        }
                        ConnectionEvent::PeerStreamStarted { stream, .. } => {
                            // Without adopting these there is no receive path
                            // for anything the peer initiates. No control slot:
                            // this endpoint opens the negotiation stream
                            // itself, so the peer cannot start one.
                            adopt_peer_stream(&peer_callbacks, &stream, None);
                        }
                        ConnectionEvent::ShutdownInitiatedByPeer { error_code } => {
                            // Kept so a driver can say why the session ended
                            // rather than only that it did.
                            peer_close.store(error_code, Ordering::Relaxed);
                        }
                        ConnectionEvent::ShutdownComplete { .. } => {
                            // Admitted past the data bound. A saturated queue is
                            // exactly when the connection is most likely to be
                            // torn down, and a driver that never learns it
                            // closed waits on a connection that is gone while
                            // the adapter keeps path statistics for a path that
                            // no longer exists.
                            push_lifecycle(
                                &callback_inbound,
                                NativeEvent::Disconnected(connection_id),
                            );
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
            let mut adapter = MsQuicAdapter::default();
            adapter
                .set_control_receive_limit(control_receive_limit)
                .map_err(|_| {
                    msquic::Status::from(msquic::StatusCode::QUIC_STATUS_INVALID_PARAMETER)
                })?;
            Ok(Self {
                carrier: Carrier {
                    adapter,
                    callbacks,
                    stalled: None,
                    streams: BTreeMap::new(),
                    control: Control::Opened(None),
                    connection: Some(connection),
                    closed,
                    connection_id,
                },
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
            self.carrier.sample_path()
        }

        /// Commands still queued for the backend.
        #[must_use]
        pub fn pending_commands(&self) -> usize {
            self.carrier.adapter.pending_commands()
        }

        /// The registered code the peer closed under, if it named one.
        ///
        /// Present only once the peer has closed with a code of its own; a
        /// clean shutdown or a carrier failure leaves it absent.
        #[must_use]
        pub fn peer_close_code(&self) -> Option<u16> {
            self.carrier.peer_close_code()
        }
    }

    /// How a pump run ended.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Pumped {
        /// The callback queue is empty.
        Drained,
        /// An event is held back until the adapter has room.
        Stalled,
        /// An event could never be admitted, carrying the close code for it.
        Inadmissible(u64),
    }

    /// Moves native events from a callback queue into the adapter.
    ///
    /// A full adapter is the only refusal worth waiting on, because it is the
    /// only one that clears. Every other refusal means the event can never be
    /// admitted, and holding it would wedge the head of the queue for ever, so
    /// the caller ends the connection rather than stalling in silence.
    ///
    /// Split from the connection so the queue behaviour can be exercised
    /// without one.
    fn pump_events(
        adapter: &mut MsQuicAdapter,
        stalled: &mut Option<NativeEvent>,
        inbound: &Arc<Mutex<CallbackQueue>>,
    ) -> Pumped {
        if let Some(held) = stalled.take() {
            match offer(adapter, stalled, held) {
                Pumped::Drained => {}
                outcome => return outcome,
            }
        }
        while let Some(event) = pop(inbound) {
            match offer(adapter, stalled, event) {
                Pumped::Drained => {}
                outcome => return outcome,
            }
        }
        Pumped::Drained
    }

    /// Offers one event to the adapter.
    fn offer(
        adapter: &mut MsQuicAdapter,
        stalled: &mut Option<NativeEvent>,
        event: NativeEvent,
    ) -> Pumped {
        match adapter.try_record_native_event(event) {
            Ok(()) => Pumped::Drained,
            Err((event, Error::InboundQueueFull)) => {
                // Held rather than dropped, so backpressure never costs a
                // record and never reorders one.
                *stalled = Some(event);
                Pumped::Stalled
            }
            Err((_, error)) => Pumped::Inadmissible(close_code(error)),
        }
    }

    /// Maps an inadmissible event onto the wire error registry.
    const fn close_code(error: Error) -> u64 {
        match error {
            Error::RecordTooLarge => vot_codec::error_code::FRAME_TOO_LARGE as u64,
            _ => vot_codec::error_code::RESOURCE_LIMIT as u64,
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
        /// Largest payload a frame on this kind of stream may declare.
        ///
        /// `control` is what this endpoint advertised, which is at most the
        /// compiled-in ceiling and may be less.
        const fn payload_limit(self, control: usize) -> usize {
            match self {
                Self::Control => control,
                Self::Reliable { .. } => vot_transport_api::MAX_DATA_RECORD_BYTES,
            }
        }

        /// Largest partial frame this kind of stream may hold, envelope
        /// included.
        const fn partial_frame_limit(self, control: usize) -> usize {
            match self {
                Self::Control => {
                    control.saturating_add(vot_transport_api::MAX_FRAME_ENVELOPE_BYTES)
                }
                Self::Reliable { .. } => MAX_PARTIAL_FRAME,
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
        /// The control bound this stream reassembles under. A frame already
        /// part-way through keeps the bound its envelope was read under.
        control_limit: Arc<AtomicUsize>,
        /// Payload bytes of a skipped frame still to arrive. They are dropped as
        /// they land rather than buffered, which `spec/wire.md` requires and
        /// which also keeps a peer from parking a lane's worth of memory per
        /// stream by fragmenting a frame nobody will read.
        discarding: usize,
        /// What `pending` currently costs against the shared budget.
        reserved: usize,
        budget: Arc<Mutex<CallbackQueue>>,
        kind: StreamKind,
    }

    impl Framing {
        fn new(
            kind: StreamKind,
            budget: Arc<Mutex<CallbackQueue>>,
            control_limit: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                pending: Vec::new(),
                control_limit,
                discarding: 0,
                reserved: 0,
                budget,
                kind,
            }
        }

        /// Buffers bytes of a frame still arriving, against the shared budget.
        ///
        /// # Errors
        /// Reports a budget the peer has already spent, which is a resource
        /// limit rather than a malformed frame.
        fn hold(&mut self, bytes: &[u8]) -> Result<(), FrameFault> {
            if !bytes.is_empty() {
                let Ok(mut budget) = self.budget.lock() else {
                    return Err(FrameFault::exhausted());
                };
                if !budget.reserve_assembly(bytes.len()) {
                    return Err(FrameFault::exhausted());
                }
                self.reserved += bytes.len();
            }
            self.pending.extend_from_slice(bytes);
            Ok(())
        }

        /// Drops the buffered frame and returns its cost to the budget.
        fn release(&mut self) {
            self.pending.clear();
            if self.reserved != 0 {
                if let Ok(mut budget) = self.budget.lock() {
                    budget.release_assembly(self.reserved);
                }
                self.reserved = 0;
            }
        }

        /// Feeds received bytes to `emit`, one complete frame at a time.
        ///
        /// Frames are handed over as they are parsed rather than collected,
        /// and only a trailing incomplete frame is ever copied into the buffer.
        /// A coalesced read can carry many valid frames at once, so returning
        /// them together would let one callback hold the whole read plus a copy
        /// of every frame in it before the bounded queue saw any of them.
        ///
        /// # Errors
        /// Reports a frame this lane cannot carry, either because it is
        /// malformed, because it is larger than the lane allows, or because it
        /// can never complete, all of which would otherwise stall the stream.
        /// Propagates whatever `emit` reports.
        fn accept(
            &mut self,
            bytes: &[u8],
            mut emit: impl FnMut(&[u8]) -> Result<(), FrameFault>,
        ) -> Result<(), FrameFault> {
            // Once per call, so one carrier read uses one bound.
            let control = self.control_limit.load(Ordering::Relaxed);
            let limits = vot_codec::DecodeLimits {
                max_unknown_payload: self.kind.payload_limit(control),
                max_frames: 1,
            };
            let mut input = bytes;
            loop {
                // Bytes belonging to a frame being skipped never reach the
                // buffer at all.
                if self.discarding != 0 {
                    let dropped = self.discarding.min(input.len());
                    self.discarding -= dropped;
                    input = &input[dropped..];
                    if self.discarding != 0 {
                        return Ok(());
                    }
                }
                if input.is_empty() {
                    return Ok(());
                }

                // A frame already part-way through is completed from the buffer,
                // which is the only place bytes accumulate.
                if !self.pending.is_empty() {
                    let Some(envelope) = self.envelope(limits, control, None)? else {
                        // Not even the header is complete. It is at most a
                        // couple of varints, so take one byte and look again.
                        self.hold(&input[..1])?;
                        input = &input[1..];
                        continue;
                    };
                    let needed = envelope.total_length - self.pending.len();
                    let taken = needed.min(input.len());
                    if envelope.skipped {
                        // The header is buffered but the payload is not, so
                        // only the remainder has to be counted down.
                        self.discarding = needed - taken;
                        self.release();
                        input = &input[taken..];
                        continue;
                    }
                    self.hold(&input[..taken])?;
                    input = &input[taken..];
                    if self.pending.len() < envelope.total_length {
                        return Ok(());
                    }
                    // Released before the frame is queued, so its bytes are
                    // charged once rather than to both accounts at the handover.
                    let complete = std::mem::take(&mut self.pending);
                    self.release();
                    emit(&complete)?;
                    continue;
                }

                // Nothing buffered, so parse straight out of the read.
                let Some(envelope) = self.envelope(limits, control, Some(input))? else {
                    // Only a partial header is left. That is bounded by the
                    // envelope size, not by the payload it describes.
                    self.hold(input)?;
                    return Ok(());
                };
                if input.len() < envelope.total_length {
                    if envelope.skipped {
                        // spec/wire.md step 6: stream-discard exactly the
                        // declared length and never size a buffer from it.
                        self.discarding = envelope.total_length - input.len();
                        return Ok(());
                    }
                    self.hold(input)?;
                    return Ok(());
                }
                if !envelope.skipped {
                    emit(&input[..envelope.total_length])?;
                }
                input = &input[envelope.total_length..];
            }
        }

        /// Reads the next envelope from `input`, or from the buffer when
        /// `input` is `None`, applying this lane's bound to it.
        ///
        /// Returns `None` while the header is still arriving.
        fn envelope(
            &self,
            limits: vot_codec::DecodeLimits,
            control: usize,
            input: Option<&[u8]>,
        ) -> Result<Option<vot_codec::FrameEnvelope>, FrameFault> {
            match vot_codec::peek_envelope(input.unwrap_or(&self.pending), limits) {
                Ok(envelope) => {
                    // The codec bounds a known frame by its registered limit,
                    // which for PROOF_BUNDLE and HAVE is larger than this lane
                    // carries. Without this the frame decodes, reaches the
                    // adapter, is refused there as oversized, and is retried for
                    // ever at the head of the queue.
                    if envelope.total_length > self.kind.partial_frame_limit(control) {
                        return Err(FrameFault::too_large());
                    }
                    Ok(Some(envelope))
                }
                // The type and length have not both arrived yet.
                Err(vot_codec::DecodeError::Incomplete { .. }) => Ok(None),
                // The decoder already knows which registered error this is, and
                // spec/wire.md requires the session to close under that code
                // rather than under a generic transport abort.
                Err(error) => Err(FrameFault::from_decode(&error)),
            }
        }

        /// Bytes currently held for a frame still being assembled.
        #[cfg(test)]
        const fn buffered(&self) -> usize {
            self.pending.len()
        }

        /// Whether a frame is part-way through arriving, whether it is being
        /// assembled or discarded.
        const fn is_assembling(&self) -> bool {
            !self.pending.is_empty() || self.discarding != 0
        }
    }

    impl Drop for Framing {
        fn drop(&mut self) {
            // A peer that resets a stream part-way through a frame destroys this
            // without the frame ever completing. Without returning the
            // reservation those bytes stay charged for ever, and enough resets
            // refuse streams that have done nothing wrong.
            self.release();
        }
    }

    /// A stream's bytes could not be framed, with the code the session closes
    /// under.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FrameFault {
        error: Error,
        close: u16,
    }

    impl FrameFault {
        const fn too_large() -> Self {
            Self {
                error: Error::RecordTooLarge,
                close: vot_codec::error_code::FRAME_TOO_LARGE,
            }
        }

        /// A decoder error, closing under the code the registry gives it.
        fn from_decode(error: &vot_codec::DecodeError) -> Self {
            Self {
                error: Error::Backend,
                close: error.protocol_code(),
            }
        }

        /// The shared budget for frames still arriving is spent.
        const fn exhausted() -> Self {
            Self {
                error: Error::InboundQueueFull,
                close: vot_codec::error_code::RESOURCE_LIMIT,
            }
        }

        /// A frame that ended when the carrier did.
        const fn truncated() -> Self {
            Self {
                error: Error::Backend,
                close: vot_codec::error_code::MALFORMED_FRAME,
            }
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
    ///
    /// `callback_owned` says whether this callback is the stream's only owner:
    /// true for a peer stream nothing is sent back on, false for one a pool
    /// holds, where a graceful close here would end a lane still in use.
    fn stream_handler(
        inbound: Arc<Mutex<CallbackQueue>>,
        sequence: Arc<AtomicU64>,
        close_request: Arc<AtomicU64>,
        control_limit: Arc<AtomicUsize>,
        kind: StreamKind,
        callback_owned: bool,
    ) -> impl FnMut(StreamRef, StreamEvent) -> Result<(), msquic::Status> + 'static {
        let mut framing = Framing::new(kind, Arc::clone(&inbound), control_limit);
        // Set once a fault has ended this stream, so the remaining bytes of a
        // coalesced read are not parsed against state the fault invalidated.
        let mut faulted = false;
        move |stream: StreamRef, event: StreamEvent| {
            match event {
                StreamEvent::Receive { buffers, .. } => {
                    for buffer in buffers {
                        if faulted {
                            break;
                        }
                        // Each frame is offered to the bounded queue as it is
                        // parsed. Collecting them first would let one coalesced
                        // read hold the whole read plus a copy of every frame in
                        // it before the queue's bound applied to any of them.
                        let outcome = framing.accept(buffer.as_bytes(), |frame| {
                            let next = sequence.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                            let event = match kind {
                                StreamKind::Control => NativeEvent::Control(frame.to_vec()),
                                StreamKind::Reliable { lane } => NativeEvent::Reliable {
                                    stream: lane,
                                    sequence: next,
                                    bytes: frame.to_vec(),
                                },
                            };
                            if push(&inbound, event) {
                                Ok(())
                            } else {
                                // The queue is full and a callback cannot
                                // wait, so the connection fails loudly
                                // instead of growing without limit.
                                Err(FrameFault {
                                    error: Error::InboundQueueFull,
                                    close: vot_codec::error_code::RESOURCE_LIMIT,
                                })
                            }
                        });
                        if let Err(fault) = outcome {
                            faulted = true;
                            request_close(&close_request, fault.close);
                        }
                    }
                }
                StreamEvent::SendComplete { client_context, .. } => {
                    // SAFETY: send_owned produced this context exactly once and
                    // MsQuic delivers SendComplete for it exactly once.
                    unsafe { complete_send(client_context) };
                }
                StreamEvent::PeerSendShutdown => {
                    // spec/wire.md: a decoder may report incomplete while more
                    // bytes can still arrive, and it becomes malformed the
                    // moment the carrier declares end of stream. Discarding the
                    // partial frame instead would leave the transfer waiting on
                    // a record the peer already stopped sending.
                    if framing.is_assembling() {
                        faulted = true;
                        request_close(&close_request, FrameFault::truncated().close);
                    } else if callback_owned {
                        // Without closing our side the stream never reaches
                        // ShutdownComplete, so its native resources live until
                        // the connection ends and short-lived peer lanes
                        // accumulate.
                        let _ = stream.shutdown(msquic::StreamShutdownFlags::GRACEFUL, 0);
                    }
                }
                StreamEvent::ShutdownComplete { .. } if callback_owned => {
                    // SAFETY: MsQuic delivered ShutdownComplete for a
                    // peer-created stream this callback has not adopted before.
                    // Streams held in a pool are released by that pool instead.
                    unsafe { close_peer_stream(&stream) };
                }
                _ => {}
            }
            // Always success. MsQuic treats a failure status here as an
            // application bug: a debug build aborts the process, a release
            // build ignores it. The close request is what ends the session.
            Ok::<(), msquic::Status>(())
        }
    }

    /// The state every stream callback shares with the driver.
    #[derive(Clone)]
    struct Callbacks {
        inbound: Arc<Mutex<CallbackQueue>>,
        sequence: Arc<AtomicU64>,
        close_request: Arc<AtomicU64>,
        /// Next lane to hand to a peer-initiated stream. Held as an atomic
        /// because streams are adopted on a backend worker thread.
        peer_lanes: Arc<AtomicU64>,
        /// The registered code the peer closed under. Recorded rather than
        /// reported, since `Disconnected` has no room for it.
        peer_close: Arc<AtomicU64>,
        /// Largest control-frame payload this endpoint will reassemble, so it
        /// is held to what it advertised. Atomic: framing runs on worker
        /// threads.
        control_receive_limit: Arc<AtomicUsize>,
    }

    impl Callbacks {
        /// Fresh callback state for one connection. Never shared: one peer
        /// would otherwise spend another's byte budget.
        fn new() -> Self {
            Self {
                inbound: Arc::new(Mutex::new(CallbackQueue::default())),
                sequence: Arc::new(AtomicU64::new(0)),
                close_request: Arc::new(AtomicU64::new(NO_CLOSE)),
                peer_lanes: Arc::new(AtomicU64::new(PEER_LANE_BASE)),
                peer_close: Arc::new(AtomicU64::new(NO_CLOSE)),
                control_receive_limit: Arc::new(AtomicUsize::new(
                    vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
                )),
            }
        }
    }

    /// Takes the next lane for a peer-initiated stream. `None` once the range
    /// is spent: a wrapped lane would alias a live stream.
    fn allocate_peer_lane(next: &AtomicU64) -> Option<u64> {
        next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |lane| {
            (lane <= PEER_LANE_LAST).then(|| lane + 1)
        })
        .ok()
    }

    /// Decides what a peer-initiated stream carries and which lane it reports.
    ///
    /// The negotiation stream is recognised by its QUIC identifier, not by
    /// arrival order, which nothing guarantees.
    ///
    /// # Errors
    /// Reports the code to close under when the carrier cannot identify the
    /// stream or the lane range is spent.
    fn classify_peer_stream(stream: &StreamRef, next_lane: &AtomicU64) -> Result<StreamKind, u16> {
        // Guessing would parse records as negotiation, or the reverse.
        let id = stream
            .get_stream_id()
            .map_err(|_| vot_codec::error_code::CARRIER_UNAVAILABLE)?;
        if id == CONTROL_STREAM_ID {
            return Ok(StreamKind::Control);
        }
        allocate_peer_lane(next_lane)
            .map(|lane| StreamKind::Reliable { lane })
            .ok_or(vot_codec::error_code::RESOURCE_LIMIT)
    }

    /// The peer-created negotiation stream on an accepted connection, kept
    /// because every frame the receiver sends back goes out on it. Shared:
    /// adopted on a worker thread, sent on by the driver.
    ///
    /// Only this one. Application lanes are receive-only here, so leaving them
    /// to their callbacks keeps stream state from growing with the lane count.
    type ControlSlot = Arc<Mutex<Option<Stream>>>;

    /// Installs the receive handler on a stream the peer started, one per
    /// stream: two peer streams share no byte ordering, so one reassembly
    /// buffer between them would splice their frames together.
    ///
    /// `control` is absent on a connecting endpoint, which opens that stream
    /// itself.
    fn adopt_peer_stream(callbacks: &Callbacks, stream: &StreamRef, control: Option<&ControlSlot>) {
        let kind = match classify_peer_stream(stream, &callbacks.peer_lanes) {
            Ok(kind) => kind,
            Err(close) => return refuse_peer_stream(callbacks, stream, close),
        };
        if kind != StreamKind::Control {
            stream.set_callback_handler(stream_handler(
                Arc::clone(&callbacks.inbound),
                Arc::clone(&callbacks.sequence),
                Arc::clone(&callbacks.close_request),
                Arc::clone(&callbacks.control_receive_limit),
                kind,
                true,
            ));
            return;
        }
        // Ownership settled before a handler exists, so a slot that cannot be
        // taken never leaves a started stream with a callback and no owner.
        let Some(mut slot) = control.and_then(|slot| slot.lock().ok()) else {
            // A connecting endpoint opens this stream itself, so the peer
            // cannot have started it. Either way there is nowhere to reply.
            return refuse_peer_stream(callbacks, stream, vot_codec::error_code::MALFORMED_FRAME);
        };
        if slot.is_some() {
            // One per session: a second would split the handshake.
            return refuse_peer_stream(callbacks, stream, vot_codec::error_code::MALFORMED_FRAME);
        }
        stream.set_callback_handler(stream_handler(
            Arc::clone(&callbacks.inbound),
            Arc::clone(&callbacks.sequence),
            Arc::clone(&callbacks.close_request),
            Arc::clone(&callbacks.control_receive_limit),
            kind,
            false,
        ));
        // SAFETY: MsQuic started this stream, the slot was empty, and no other
        // owner has adopted it. The handler above was installed without
        // callback ownership, so this is the only owner and it releases the
        // handle at teardown.
        let adopted = unsafe { Stream::from_raw(stream.as_raw()) };
        *slot = Some(adopted);
    }

    /// Aborts a peer stream that cannot be accepted and ends the session.
    fn refuse_peer_stream(callbacks: &Callbacks, stream: &StreamRef, close: u16) {
        // Still needs a handler: MsQuic releases the handle only through one.
        stream.set_callback_handler(refused_stream_handler());
        let _ = stream.shutdown(msquic::StreamShutdownFlags::ABORT, u64::from(close));
        request_close(&callbacks.close_request, close);
    }

    /// Handler for a refused peer stream. Reads nothing; releases the handle
    /// when `MsQuic` reports the aborted stream finished.
    fn refused_stream_handler()
    -> impl FnMut(StreamRef, StreamEvent) -> Result<(), msquic::Status> + 'static {
        move |stream: StreamRef, event: StreamEvent| {
            if matches!(event, StreamEvent::ShutdownComplete { .. }) {
                // SAFETY: MsQuic delivered ShutdownComplete for a peer-created
                // stream that was never adopted by any other owner.
                unsafe { close_peer_stream(&stream) };
            }
            Ok(())
        }
    }

    /// Opens one stream and installs the receive handler on it.
    fn open_stream(
        connection: Option<&Connection>,
        callbacks: &Callbacks,
        kind: StreamKind,
    ) -> Result<Stream, Error> {
        let connection = connection.ok_or(Error::Backend)?;
        // The caller owns the handle and closes it at teardown, so there is
        // exactly one owner and it is never detached.
        let stream = Stream::open(
            connection,
            StreamOpenFlags::NONE,
            stream_handler(
                Arc::clone(&callbacks.inbound),
                Arc::clone(&callbacks.sequence),
                Arc::clone(&callbacks.close_request),
                Arc::clone(&callbacks.control_receive_limit),
                kind,
                false,
            ),
        )
        .map_err(|_| Error::Backend)?;
        stream
            .start(StreamStartFlags::NONE)
            .map_err(|_| Error::Backend)?;
        Ok(stream)
    }

    /// Opens the negotiation stream if it is not open yet.
    ///
    /// spec/wire.md reserves the first client-initiated bidirectional stream
    /// for HELLO and SETTINGS. Opening an application lane before it would make
    /// a conforming peer parse records as negotiation, so every path that opens
    /// a stream claims this one first.
    fn ensure_control(
        control: &mut Option<Stream>,
        connection: Option<&Connection>,
        callbacks: &Callbacks,
    ) -> Result<(), Error> {
        if control.is_none() {
            *control = Some(open_stream(connection, callbacks, StreamKind::Control)?);
        }
        Ok(())
    }

    /// Returns the application lane for `id`, opening it on first use.
    fn stream_for<'a>(
        streams: &'a mut BTreeMap<u64, Stream>,
        connection: Option<&Connection>,
        callbacks: &Callbacks,
        id: u64,
    ) -> Result<&'a Stream, Error> {
        match streams.entry(id) {
            Entry::Occupied(slot) => Ok(&*slot.into_mut()),
            Entry::Vacant(slot) => {
                let stream = open_stream(connection, callbacks, StreamKind::Reliable { lane: id })?;
                Ok(&*slot.insert(stream))
            }
        }
    }

    /// The queue between the backend's worker threads and the driver.
    ///
    /// Bounded by payload bytes as well as by entry count. A count on its own is
    /// not a memory bound: the largest control frame is four times the largest
    /// record, so a thousand of them is over a gigabyte held on behalf of a peer
    /// that has sent nothing the driver asked for.
    #[derive(Default)]
    pub struct CallbackQueue {
        events: VecDeque<NativeEvent>,
        bytes: usize,
        /// Bytes held across every stream for frames still arriving. A lane
        /// bound covers one stream; a peer that opens many and leaves a nearly
        /// complete record on each multiplies it by the stream count, which no
        /// per-stream bound can see. Charged to the same budget as queued
        /// events, so `MAX_CALLBACK_BYTES` is what a peer can make this hold.
        assembling: usize,
    }

    impl CallbackQueue {
        /// Peer-driven bytes held, queued and part-way through arriving.
        const fn charged(&self) -> usize {
            self.bytes + self.assembling
        }

        /// Queues a peer-driven event. Returns false when either bound is met.
        fn push(&mut self, event: NativeEvent) -> bool {
            let payload = native_payload_len(&event);
            let Some(next) = self.charged().checked_add(payload) else {
                return false;
            };
            if self.events.len() >= MAX_CALLBACK_EVENTS || next > MAX_CALLBACK_BYTES {
                return false;
            }
            self.events.push_back(event);
            self.bytes += payload;
            true
        }

        /// Charges more partial-frame storage. False when the budget is spent.
        fn reserve_assembly(&mut self, extra: usize) -> bool {
            let Some(next) = self.charged().checked_add(extra) else {
                return false;
            };
            if next > MAX_CALLBACK_BYTES {
                return false;
            }
            self.assembling += extra;
            true
        }

        /// Returns partial-frame storage to the budget.
        fn release_assembly(&mut self, bytes: usize) {
            self.assembling = self.assembling.saturating_sub(bytes);
        }

        /// Queues a connection lifecycle event past both bounds.
        fn push_lifecycle(&mut self, event: NativeEvent) {
            debug_assert_eq!(native_payload_len(&event), 0);
            self.events.push_back(event);
        }

        fn pop(&mut self) -> Option<NativeEvent> {
            let event = self.events.pop_front()?;
            self.bytes = self.bytes.saturating_sub(native_payload_len(&event));
            Some(event)
        }
    }

    /// Bytes an event holds on the queue's behalf.
    fn native_payload_len(event: &NativeEvent) -> usize {
        match event {
            NativeEvent::Control(bytes) | NativeEvent::Reliable { bytes, .. } => bytes.len(),
            NativeEvent::Connected(_)
            | NativeEvent::Disconnected(_)
            | NativeEvent::Acknowledged { .. }
            | NativeEvent::DatagramState { .. } => 0,
        }
    }

    /// Queues an event for the driver. Returns false when a bound is reached.
    fn push(queue: &Arc<Mutex<CallbackQueue>>, event: NativeEvent) -> bool {
        let Ok(mut queue) = queue.lock() else {
            return false;
        };
        queue.push(event)
    }

    /// Queues a connection lifecycle event past the data bounds.
    ///
    /// Those bounds exist to stop a fast peer outrunning the driver, and neither
    /// of these comes from the peer's data. Dropping one is not survivable, so
    /// it is not treated as backpressure.
    ///
    /// The extra growth is two payload-free entries, and that is a bound rather
    /// than a hope: `MsQuicTransport` owns one connection for its whole life and
    /// this queue belongs to that transport, `Connected` is delivered once per
    /// successful handshake, and `ShutdownComplete` is the last event `MsQuic`
    /// delivers for a connection.
    fn push_lifecycle(queue: &Arc<Mutex<CallbackQueue>>, event: NativeEvent) {
        if let Ok(mut queue) = queue.lock() {
            queue.push_lifecycle(event);
        }
    }

    fn pop(queue: &Arc<Mutex<CallbackQueue>>) -> Option<NativeEvent> {
        queue.lock().ok()?.pop()
    }

    /// No close has been requested. The wire registry starts at `0x0101`, so
    /// zero can never be a code a callback meant to send.
    const NO_CLOSE: u64 = 0;

    /// Asks the driver to close the session under a registered code.
    ///
    /// A callback owns no connection handle, and closing from a backend worker
    /// thread would break the rule that only the driver touches connection
    /// state. The first request wins, because the code that describes why the
    /// session ended is the one that ended it.
    fn request_close(close_request: &Arc<AtomicU64>, code: u16) {
        let _ = close_request.compare_exchange(
            NO_CLOSE,
            u64::from(code),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Forwards the adapter contract to the shared carrier, written once so
    /// the two transports cannot drift apart.
    macro_rules! delegate_to_carrier {
        ($transport:ty) => {
            impl TransportAdapter for $transport {
                fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
                    self.carrier.send_control(frame)
                }

                fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
                    self.carrier.send_reliable(stream, record)
                }

                fn send_reliable_shared(
                    &mut self,
                    stream: StreamId,
                    record: Payload,
                ) -> Result<(), Error> {
                    self.carrier.send_reliable_shared(stream, record)
                }

                fn preflight_reliable_batch(
                    &self,
                    stream: StreamId,
                    records: &[Payload],
                ) -> Result<(), Error> {
                    self.carrier.preflight_reliable_batch(stream, records)
                }

                fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
                    self.carrier.send_datagram(context, payload)
                }

                fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
                    self.carrier.set_receive_credit(bytes)
                }

                fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
                    self.carrier.set_control_payload_limit(limit)
                }

                fn control_receive_limit(&self) -> Option<usize> {
                    self.carrier.control_receive_limit()
                }

                fn close(&mut self, code: u16) -> Result<(), Error> {
                    self.carrier.close(code)
                }

                fn flush(&mut self) -> Result<(), Error> {
                    TransportAdapter::flush(&mut self.carrier)
                }

                fn poll(&mut self) -> Option<Event> {
                    self.carrier.poll()
                }

                fn path_stats(&self) -> Option<PathStats> {
                    self.carrier.path_stats()
                }
            }
        };
    }

    delegate_to_carrier!(MsQuicTransport);
    delegate_to_carrier!(AcceptedTransport);

    impl Drop for MsQuicTransport {
        fn drop(&mut self) {
            self.carrier.teardown();
            self.registration.shutdown();
        }
    }

    /// A `MsQuic` connection this endpoint accepted, running the same code as
    /// the connecting side. What differs is the negotiation stream, which
    /// arrives from the peer, and the registration, which is shared with the
    /// listener so an accepted connection can outlive it.
    pub struct AcceptedTransport {
        carrier: Carrier,
        _registration: Arc<Registration>,
    }

    impl AcceptedTransport {
        /// Commands still queued for the backend.
        #[must_use]
        pub fn pending_commands(&self) -> usize {
            self.carrier.adapter.pending_commands()
        }

        /// The registered code the peer closed under, if it named one.
        ///
        /// Present only once the peer has closed with a code of its own; a
        /// clean shutdown or a carrier failure leaves it absent.
        #[must_use]
        pub fn peer_close_code(&self) -> Option<u16> {
            self.carrier.peer_close_code()
        }

        /// The identifier this connection reports lifecycle events under.
        #[must_use]
        pub const fn connection_id(&self) -> u64 {
            self.carrier.connection_id
        }

        /// Samples the live connection and records the result on the driver
        /// thread, which is the only thread allowed to touch the adapter.
        ///
        /// # Errors
        /// Propagates an `MsQuic` `GetParam` failure.
        pub fn sample_path(&mut self) -> Result<(), msquic::Status> {
            self.carrier.sample_path()
        }

        /// Whether the peer has opened the negotiation stream yet. Frames
        /// submitted before it arrives stay queued, so this reports rather
        /// than gates.
        #[must_use]
        pub fn control_stream_open(&self) -> bool {
            self.carrier
                .control
                .slot()
                .and_then(|slot| slot.lock().ok())
                .is_some_and(|slot| slot.is_some())
        }
    }

    impl Drop for AcceptedTransport {
        fn drop(&mut self) {
            // No registration shutdown: the listener owns it and may still be
            // serving other connections.
            self.carrier.teardown();
        }
    }

    /// A listening `MsQuic` endpoint that produces assembled connections, so
    /// both directions of a transfer run the same code.
    pub struct MsQuicServer {
        // First, so it closes before the channel it feeds. Closing waits for
        // callbacks, which is what makes the channel send infallible.
        listener: Listener,
        accepted: Receiver<AcceptedTransport>,
        _configuration: Arc<Configuration>,
        registration: Arc<Registration>,
    }

    impl MsQuicServer {
        /// Starts listening on `address` for the given ALPN.
        ///
        /// # Errors
        /// Propagates a listener that could not be opened or started.
        pub fn listen(
            configuration: Arc<Configuration>,
            registration: Arc<Registration>,
            alpn: &[BufferRef],
            address: &Addr,
            control_receive_limit: usize,
        ) -> Result<Self, msquic::Status> {
            let (accepted_tx, accepted) = mpsc::channel();
            let next_connection_id = Arc::new(AtomicU64::new(1));
            let listener_configuration = Arc::clone(&configuration);
            let listener_registration = Arc::clone(&registration);
            let listener = Listener::open(&registration, move |_, event: ListenerEvent| {
                if let ListenerEvent::NewConnection { connection, .. } = event {
                    let transport = accept_connection(
                        &connection,
                        &listener_configuration,
                        &listener_registration,
                        next_connection_id.fetch_add(1, Ordering::Relaxed),
                        control_receive_limit,
                    )?;
                    // Not inside the assert: dropping the transport here
                    // would run teardown on a worker thread and wait there for
                    // a shutdown the same pool has to deliver.
                    let queued = accepted_tx.send(transport);
                    debug_assert!(queued.is_ok(), "the listener closes before its receiver");
                }
                Ok(())
            })?;
            listener.start(alpn, Some(address))?;
            Ok(Self {
                listener,
                accepted,
                _configuration: configuration,
                registration,
            })
        }

        /// The port the listener bound, which is chosen by the system when the
        /// requested port is zero.
        ///
        /// # Errors
        /// Propagates an `MsQuic` `GetParam` failure.
        pub fn local_port(&self) -> Result<u16, msquic::Status> {
            Ok(self.listener.get_local_addr()?.port())
        }

        /// Takes the next accepted connection without blocking.
        pub fn accept(&mut self) -> Option<AcceptedTransport> {
            self.accepted.try_recv().ok()
        }

        /// A share of the registration these connections belong to.
        #[must_use]
        pub fn registration(&self) -> Arc<Registration> {
            Arc::clone(&self.registration)
        }
    }

    impl Drop for MsQuicServer {
        fn drop(&mut self) {
            // Stopped before it is closed, so no further connection is accepted
            // into a channel that is about to go away.
            self.listener.stop();
        }
    }

    /// Assembles one accepted connection. Runs on a worker thread, so it
    /// installs callbacks and adopts the handle and nothing more.
    fn accept_connection(
        connection: &ConnectionRef,
        configuration: &Arc<Configuration>,
        registration: &Arc<Registration>,
        connection_id: u64,
        control_receive_limit: usize,
    ) -> Result<AcceptedTransport, msquic::Status> {
        let callbacks = Callbacks::new();
        // Before any handler exists, so the bound is in force for the peer's
        // first frame rather than tightened underneath one.
        callbacks
            .control_receive_limit
            .store(control_receive_limit, Ordering::Relaxed);
        let control: ControlSlot = Arc::new(Mutex::new(None));
        let (closed_tx, closed) = mpsc::channel();
        let callback_inbound = Arc::clone(&callbacks.inbound);
        let peer_close = Arc::clone(&callbacks.peer_close);
        let peer_callbacks = callbacks.clone();
        let peer_control = Arc::clone(&control);
        connection.set_callback_handler(move |_: ConnectionRef, event: ConnectionEvent| {
            match event {
                ConnectionEvent::Connected { .. } => {
                    push_lifecycle(&callback_inbound, NativeEvent::Connected(connection_id));
                }
                ConnectionEvent::PeerStreamStarted { stream, .. } => {
                    // Every application lane arrives this way on an accepted
                    // connection, and so does the negotiation stream.
                    adopt_peer_stream(&peer_callbacks, &stream, Some(&peer_control));
                }
                ConnectionEvent::ShutdownInitiatedByPeer { error_code } => {
                    peer_close.store(error_code, Ordering::Relaxed);
                }
                ConnectionEvent::ShutdownComplete { .. } => {
                    push_lifecycle(&callback_inbound, NativeEvent::Disconnected(connection_id));
                    // Teardown waits on this before releasing the handle, so a
                    // send buffer cannot outlive it.
                    let _ = closed_tx.send(());
                }
                _ => {}
            }
            Ok(())
        });
        // Handler first: events can arrive as soon as the configuration is
        // set. A failure here does not adopt the connection, because MsQuic
        // closes one the application refused and closing it here too would
        // close the handle twice. That path leaks the callback context, which
        // beats a double free.
        connection.set_configuration(configuration)?;
        // SAFETY: MsQuic delivered this connection through NewConnection, the
        // configuration was accepted, and no other owner has adopted it. The
        // transport built below is its sole owner and releases it at teardown,
        // so the callback above never closes it.
        let owned = unsafe { Connection::from_raw(connection.as_raw()) };
        let mut adapter = MsQuicAdapter::default();
        adapter
            .set_control_receive_limit(control_receive_limit)
            .map_err(|_| msquic::Status::from(msquic::StatusCode::QUIC_STATUS_INVALID_PARAMETER))?;
        Ok(AcceptedTransport {
            carrier: Carrier {
                adapter,
                callbacks,
                stalled: None,
                streams: BTreeMap::new(),
                control: Control::Adopted(control),
                connection: Some(owned),
                closed,
                connection_id,
            },
            _registration: Arc::clone(registration),
        })
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
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex, OnceLock, mpsc};
        use std::time::{Duration, Instant};

        use msquic::{
            Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Credential,
            CredentialConfig, CredentialFlags, Listener, ListenerEvent, Registration, SendFlags,
            Settings, Status, Stream, StreamEvent, StreamOpenFlags, StreamRef, StreamStartFlags,
        };

        use super::{
            AcceptedTransport, Control, Framing, MsQuicServer, MsQuicTransport, StreamKind,
            allocate_peer_lane,
        };

        use super::super::{
            Command as AdapterCommand, MAX_CALLBACK_BYTES, MAX_CALLBACK_EVENTS,
            MAX_PARTIAL_CONTROL_FRAME, MAX_PARTIAL_FRAME, MsQuicAdapter, NativeEvent,
            PEER_LANE_BASE, PEER_LANE_LAST, is_reserved_lane,
        };
        use super::{close_peer_connection, close_peer_stream, complete_send, detach_stream};
        use vot_transport_api::{
            ConnectionId, Error, Event, MAX_DATA_RECORD_BYTES, StreamId, TransportAdapter,
        };

        use std::collections::BTreeSet;
        use vot_session::Session;

        /// A framing with a budget of its own, for tests that only care about
        /// how one stream parses.
        /// The default control bound, which is what the framing unit tests
        /// measure against unless they are testing the bound itself.
        fn control_bound() -> Arc<AtomicUsize> {
            Arc::new(AtomicUsize::new(
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            ))
        }

        fn lone(kind: StreamKind) -> Framing {
            Framing::new(
                kind,
                Arc::new(Mutex::new(super::CallbackQueue::default())),
                control_bound(),
            )
        }

        /// Drives `accept` and collects what it emitted, which is what the
        /// tests assert on. The transport itself never collects.
        fn collect(framing: &mut Framing, bytes: &[u8]) -> Result<Vec<Vec<u8>>, super::FrameFault> {
            let mut frames = Vec::new();
            framing.accept(bytes, |frame| {
                frames.push(frame.to_vec());
                Ok(())
            })?;
            Ok(frames)
        }

        fn framed(frame_type: u64, payload: &[u8]) -> Vec<u8> {
            let mut frame = Vec::new();
            vot_codec::encode_frame(frame_type, payload, &mut frame).unwrap();
            frame
        }

        #[test]
        fn a_saturated_callback_queue_still_reports_the_disconnect() {
            // A queue is most likely to be full exactly when the connection is
            // being torn down. Dropping the disconnect there leaves the driver
            // waiting on a connection that is gone, holding path statistics for
            // a path that no longer exists.
            let queue = Arc::new(Mutex::new(super::CallbackQueue::default()));
            for sequence in 1..=MAX_CALLBACK_EVENTS as u64 {
                assert!(super::push(
                    &queue,
                    NativeEvent::Reliable {
                        stream: 1,
                        sequence,
                        bytes: b"record".to_vec(),
                    }
                ));
            }
            assert!(
                !super::push(
                    &queue,
                    NativeEvent::Reliable {
                        stream: 1,
                        sequence: 0,
                        bytes: b"record".to_vec(),
                    }
                ),
                "records are refused once the bound is reached"
            );
            super::push_lifecycle(&queue, NativeEvent::Disconnected(11));

            // Drive the driver's own path. The adapter holds far fewer events
            // than the callback queue, so the disconnect only arrives after
            // repeated polling, which is the case that was broken.
            let mut adapter = MsQuicAdapter::default();
            adapter.record_path_stats(ConnectionId(11), vot_transport_api::PathStats::default());
            let mut stalled = None;
            let mut records = 0;
            let mut disconnected = false;
            for _ in 0..MAX_CALLBACK_EVENTS * 2 {
                super::pump_events(&mut adapter, &mut stalled, &queue);
                while let Some(event) = adapter.poll() {
                    match event {
                        Event::Reliable { .. } => records += 1,
                        Event::Disconnected(ConnectionId(11)) => disconnected = true,
                        other => panic!("unexpected event {other:?}"),
                    }
                }
                if disconnected {
                    break;
                }
            }
            assert_eq!(
                records, MAX_CALLBACK_EVENTS,
                "no record was lost on the way"
            );
            assert!(
                disconnected,
                "the driver never learned the connection closed"
            );
            assert_eq!(
                adapter.path_stats(),
                None,
                "path statistics outlived the path"
            );
        }

        #[test]
        fn the_callback_queue_is_bounded_by_bytes_as_well_as_by_count() {
            // Counting entries alone is not a memory bound. A thousand maximum
            // control frames is over a gigabyte, which a peer can queue while
            // the driver is briefly behind.
            let queue = Arc::new(Mutex::new(super::CallbackQueue::default()));
            let frame = vec![0x44; MAX_PARTIAL_CONTROL_FRAME - 64];
            let mut admitted = 0;
            while super::push(&queue, NativeEvent::Control(frame.clone())) {
                admitted += 1;
                assert!(admitted <= MAX_CALLBACK_EVENTS, "the byte bound never bit");
            }
            assert!(
                admitted < MAX_CALLBACK_EVENTS,
                "bytes must run out first for frames this size"
            );
            assert!(admitted * frame.len() <= MAX_CALLBACK_BYTES);

            // Draining returns the capacity, so the bound is backpressure and
            // not a one-way ratchet.
            assert!(super::pop(&queue).is_some());
            assert!(super::push(&queue, NativeEvent::Control(frame)));

            // Payload-free events are still bounded by the count.
            let queue = Arc::new(Mutex::new(super::CallbackQueue::default()));
            for _ in 0..MAX_CALLBACK_EVENTS {
                assert!(super::push(
                    &queue,
                    NativeEvent::Acknowledged {
                        stream: 1,
                        sequence: 1
                    }
                ));
            }
            assert!(!super::push(
                &queue,
                NativeEvent::Acknowledged {
                    stream: 1,
                    sequence: 2
                }
            ));
        }

        #[test]
        fn an_unknown_optional_frame_is_skipped_rather_than_delivered() {
            // spec/wire.md: an unknown optional type is skipped by its
            // validated length. Handing it up would give the application bytes
            // it must ignore and spend queue capacity holding them.
            let optional = framed(0x7ffe, b"ignore me");
            let grease = framed(0x1f00, b"grease");
            let real = framed(vot_codec::frame_type::DATA_RECORD, b"payload");
            assert!(vot_codec::is_grease(0x1f00));

            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            let mut stream = optional.clone();
            stream.extend_from_slice(&grease);
            stream.extend_from_slice(&real);
            assert_eq!(
                collect(&mut framing, &stream).unwrap(),
                vec![real.clone()],
                "only the known frame reaches the application"
            );
            assert!(
                !framing.is_assembling(),
                "the skipped frames were consumed, not left behind"
            );
        }

        #[test]
        fn a_coalesced_read_is_handed_over_frame_by_frame() {
            // MsQuic can deliver one buffer holding many complete frames.
            // Collecting them before offering any to the bounded queue would
            // hold the whole read plus a copy of every frame in it, which is
            // memory the queue's bound never sees.
            let record = framed(vot_codec::frame_type::DATA_RECORD, &vec![0x6b; 32 * 1024]);
            let mut read = Vec::new();
            for _ in 0..64 {
                read.extend_from_slice(&record);
            }
            assert!(read.len() > MAX_CALLBACK_BYTES / 8, "a read worth bounding");

            // accept hands each frame over as it is parsed and cannot return a
            // collection, so it has no way to accumulate them. What is
            // observable from outside is what it retains.
            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            let mut delivered = 0;
            framing
                .accept(&read, |frame| {
                    assert_eq!(frame, record.as_slice());
                    delivered += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(delivered, 64, "every frame reached the queue");
            assert_eq!(
                framing.buffered(),
                0,
                "a read that ends on a frame boundary leaves nothing behind"
            );

            // A trailing partial frame is the only thing ever retained, and it
            // is the partial frame alone rather than the read that carried it.
            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            let mut ragged = read.clone();
            ragged.truncate(read.len() - 16);
            let delivered = collect(&mut framing, &ragged).unwrap();
            assert_eq!(delivered.len(), 63);
            assert_eq!(framing.buffered(), record.len() - 16);
        }

        #[test]
        fn partial_frames_across_streams_share_one_budget() {
            // A lane bound covers one stream. A peer that opens many and parks a
            // nearly complete record on each multiplies it by the stream count,
            // which no per-stream bound can see, so the buffers are charged to
            // the same budget as queued events.
            let budget = Arc::new(Mutex::new(super::CallbackQueue::default()));
            let record = framed(vot_codec::frame_type::DATA_RECORD, &vec![0x5e; 200 * 1024]);
            let head = record[..record.len() - 1].to_vec();
            let tail = record[record.len() - 1..].to_vec();

            // Enough lanes that the shared budget must refuse one, derived from
            // the budget rather than guessed, so the test does not silently stop
            // proving anything if either constant moves.
            let lanes = (MAX_CALLBACK_BYTES / head.len() + 8) as u64;
            let mut streams = Vec::new();
            let mut refused = None;
            for lane in 0..lanes {
                let mut framing = Framing::new(
                    StreamKind::Reliable { lane },
                    Arc::clone(&budget),
                    control_bound(),
                );
                match framing.accept(&head, |_| Ok(())) {
                    Ok(()) => streams.push(framing),
                    Err(fault) => {
                        refused = Some(fault);
                        break;
                    }
                }
            }
            let refused = refused.expect("the shared budget never bit");
            assert_eq!(refused, super::FrameFault::exhausted());
            assert!(
                streams.len() * head.len() <= MAX_CALLBACK_BYTES,
                "held {} bytes across {} streams",
                streams.len() * head.len(),
                streams.len()
            );
            assert!(
                (streams.len() as u64) < lanes,
                "the per-stream bound alone would have allowed all of them"
            );

            // Finishing a frame returns its cost, so the budget is backpressure
            // rather than a leak.
            let mut finished = streams.pop().unwrap();
            assert_eq!(collect(&mut finished, &tail).unwrap(), vec![record]);
            drop(finished);
            let mut recovered = Framing::new(
                StreamKind::Reliable { lane: 999 },
                Arc::clone(&budget),
                control_bound(),
            );
            recovered.accept(&head, |_| Ok(())).unwrap();
        }

        #[test]
        fn a_stream_reset_mid_frame_returns_its_reservation() {
            // A peer resetting a stream part-way through a frame destroys the
            // framing without the frame completing. Bytes left charged would
            // accumulate across resets until streams that had done nothing
            // wrong were refused.
            let budget = Arc::new(Mutex::new(super::CallbackQueue::default()));
            let record = framed(vot_codec::frame_type::DATA_RECORD, &vec![0x3c; 100 * 1024]);
            let head = record[..record.len() - 1].to_vec();

            for reset in 0..8 {
                let mut framing = Framing::new(
                    StreamKind::Reliable { lane: reset },
                    Arc::clone(&budget),
                    control_bound(),
                );
                framing.accept(&head, |_| Ok(())).unwrap();
                assert_eq!(
                    budget.lock().unwrap().charged(),
                    head.len(),
                    "the partial frame is charged while it is held"
                );
                drop(framing);
                assert_eq!(
                    budget.lock().unwrap().charged(),
                    0,
                    "reset {reset} left phantom bytes charged"
                );
            }
        }

        #[test]
        fn a_fragmented_optional_payload_is_discarded_as_it_arrives() {
            // spec/wire.md step 6: stream-discard exactly the declared length
            // and never size a buffer from it. Holding the payload until the
            // frame completed would let a peer park a lane's worth of memory
            // per stream by fragmenting a frame nobody will ever read.
            let payload = vec![0x27; MAX_PARTIAL_FRAME - 128];
            let optional = framed(0x7ffe, &payload);
            let real = framed(vot_codec::frame_type::DATA_RECORD, b"after");

            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            assert!(collect(&mut framing, &optional[..8]).unwrap().is_empty());
            assert!(framing.is_assembling(), "the frame is still arriving");
            assert!(
                framing.buffered() < 64,
                "the discarded payload must not be buffered, held {}",
                framing.buffered()
            );

            // Deliver the rest in pieces, then a real frame right behind it.
            for chunk in optional[8..].chunks(4096) {
                assert!(collect(&mut framing, chunk).unwrap().is_empty());
                assert!(framing.buffered() < 64, "still nothing worth holding");
            }
            assert!(!framing.is_assembling(), "the skip finished exactly");
            assert_eq!(collect(&mut framing, &real).unwrap(), vec![real]);
        }

        #[test]
        fn an_event_that_can_never_be_admitted_ends_the_connection() {
            // Holding it would wedge the head of the queue for ever. The close
            // code comes from the wire registry so the peer is told what it did.
            let queue = Arc::new(Mutex::new(super::CallbackQueue::default()));
            assert!(super::push(
                &queue,
                NativeEvent::Reliable {
                    stream: 1,
                    sequence: 1,
                    bytes: vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1],
                }
            ));
            let mut adapter = MsQuicAdapter::default();
            let mut stalled = None;
            assert_eq!(
                super::pump_events(&mut adapter, &mut stalled, &queue),
                super::Pumped::Inadmissible(u64::from(vot_codec::error_code::FRAME_TOO_LARGE))
            );
            assert!(stalled.is_none(), "an inadmissible event is not retried");

            // A full adapter is the one refusal that is waited on rather than
            // treated as fatal.
            let mut adapter = MsQuicAdapter::with_queue_limits(1, 4096).unwrap();
            let queue = Arc::new(Mutex::new(super::CallbackQueue::default()));
            assert!(super::push(&queue, NativeEvent::Connected(11)));
            assert!(super::push(&queue, NativeEvent::Disconnected(11)));
            assert_eq!(
                super::pump_events(&mut adapter, &mut stalled, &queue),
                super::Pumped::Stalled
            );
            assert_eq!(stalled, Some(NativeEvent::Disconnected(11)));
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

            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            let split = big.len() - 8;
            assert!(collect(&mut framing, &big[..split]).unwrap().is_empty());
            let mut rest = big[split..].to_vec();
            rest.extend_from_slice(&next);
            let frames = collect(&mut framing, &rest).unwrap();
            assert_eq!(frames, vec![big, next]);
        }

        #[test]
        fn a_frame_that_can_never_complete_is_refused_rather_than_held() {
            // Without this the stream stalls for ever on bytes that will never
            // form a frame, and the buffer grows for as long as they arrive.
            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            let head = framed(
                vot_codec::frame_type::PACKAGE_DESCRIPTOR,
                &vec![0x11; MAX_DATA_RECORD_BYTES * 2],
            );
            assert_eq!(
                collect(&mut framing, &head[..=MAX_PARTIAL_FRAME]),
                Err(super::FrameFault::too_large())
            );
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

            let mut control = lone(StreamKind::Control);
            let head = frame.len() - 1;
            assert!(collect(&mut control, &frame[..head]).unwrap().is_empty());
            assert_eq!(collect(&mut control, &frame[head..]).unwrap(), vec![frame]);
        }

        #[test]
        fn a_frame_larger_than_its_lane_is_refused_even_when_the_codec_allows_it() {
            // decode_one bounds a known frame by its registered limit, and
            // PROOF_BUNDLE and HAVE are registered far above what either lane
            // carries. Letting one through would decode cleanly, be refused by
            // the adapter as oversized, and then be retried for ever.
            let oversized = framed(
                vot_codec::frame_type::HAVE,
                &vec![0x33; MAX_PARTIAL_CONTROL_FRAME],
            );
            assert!(
                vot_codec::decode_one(&oversized, vot_codec::DecodeLimits::default()).is_ok(),
                "the codec accepts this frame, which is what makes the lane check necessary"
            );
            // The wire code travels with the refusal, so the peer is closed on
            // FRAME_TOO_LARGE rather than a bare transport abort.
            let fault = super::FrameFault::too_large();
            assert_eq!(fault.error, Error::RecordTooLarge);
            assert_eq!(fault.close, vot_codec::error_code::FRAME_TOO_LARGE);
            assert_eq!(
                collect(&mut lone(StreamKind::Control), &oversized),
                Err(fault)
            );
            assert_eq!(
                collect(&mut lone(StreamKind::Reliable { lane: 1 }), &oversized),
                Err(fault)
            );
        }

        #[test]
        fn end_of_stream_inside_a_frame_is_malformed() {
            // spec/wire.md: incomplete is only provisional while the carrier can
            // still deliver. Once it declares end of stream, a half-arrived
            // frame is malformed, and discarding it silently would leave the
            // transfer waiting on a record the peer stopped sending.
            let frame = framed(vot_codec::frame_type::DATA_RECORD, b"half-sent");
            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            assert!(collect(&mut framing, &frame[..3]).unwrap().is_empty());
            assert!(framing.is_assembling());
            assert_eq!(
                super::FrameFault::truncated().close,
                vot_codec::error_code::MALFORMED_FRAME
            );

            // A frame that landed whole leaves nothing behind, so a FIN there
            // is an ordinary end of stream.
            let mut framing = lone(StreamKind::Reliable { lane: 1 });
            assert_eq!(collect(&mut framing, &frame).unwrap().len(), 1);
            assert!(!framing.is_assembling());
        }

        #[test]
        fn a_decoder_error_keeps_its_registered_code() {
            // Erasing it to a generic abort tells the peer nothing about what it
            // sent. An unknown critical frame in particular has to close under
            // UNKNOWN_CRITICAL_FRAME.
            let mut unknown_critical = Vec::new();
            vot_codec::encode_frame(0x7fff_ffff, b"payload", &mut unknown_critical).unwrap();
            let fault = collect(
                &mut lone(StreamKind::Reliable { lane: 1 }),
                &unknown_critical,
            )
            .unwrap_err();
            assert_eq!(fault.close, vot_codec::error_code::UNKNOWN_CRITICAL_FRAME);
        }

        #[test]
        fn a_close_request_is_kept_until_the_driver_sends_it() {
            // A callback owns no connection handle, so it leaves the code for
            // the driver. The first request wins: the code that ended the
            // session is the one that describes why.
            let request = Arc::new(AtomicU64::new(super::NO_CLOSE));
            super::request_close(&request, vot_codec::error_code::UNKNOWN_CRITICAL_FRAME);
            super::request_close(&request, vot_codec::error_code::MALFORMED_FRAME);
            assert_eq!(
                request.load(Ordering::Relaxed),
                u64::from(vot_codec::error_code::UNKNOWN_CRITICAL_FRAME)
            );
            // Zero can never be a registered code, so it is safe as the absent
            // marker.
            assert_eq!(super::NO_CLOSE, 0);
            assert_ne!(
                u64::from(vot_codec::error_code::MALFORMED_FRAME),
                super::NO_CLOSE
            );
            assert_ne!(
                u64::from(vot_codec::error_code::UNKNOWN_CRITICAL_FRAME),
                super::NO_CLOSE
            );
        }

        #[test]
        fn two_streams_never_share_reassembly_state() {
            // Interleaving halves of two frames through one buffer would splice
            // them into records neither peer sent.
            let first = framed(vot_codec::frame_type::DATA_RECORD, b"first-record");
            let second = framed(vot_codec::frame_type::DATA_RECORD, b"second");
            let mut left = lone(StreamKind::Reliable { lane: 1 });
            let mut right = lone(StreamKind::Reliable { lane: 2 });

            assert!(collect(&mut left, &first[..4]).unwrap().is_empty());
            assert!(collect(&mut right, &second[..4]).unwrap().is_empty());
            assert_eq!(collect(&mut right, &second[4..]).unwrap(), vec![second]);
            assert_eq!(collect(&mut left, &first[4..]).unwrap(), vec![first]);
        }

        #[test]
        fn every_peer_stream_gets_a_lane_of_its_own() {
            // A shared identifier made records from independent streams look
            // like one reordered stream, which on an accepted connection is
            // every application lane there is.
            let next = AtomicU64::new(PEER_LANE_BASE);
            let lanes: Vec<u64> = (0..4).map(|_| allocate_peer_lane(&next).unwrap()).collect();
            assert_eq!(
                lanes,
                vec![
                    PEER_LANE_BASE,
                    PEER_LANE_BASE + 1,
                    PEER_LANE_BASE + 2,
                    PEER_LANE_BASE + 3,
                ]
            );
            for lane in lanes {
                assert!(is_reserved_lane(lane));
            }
        }

        #[test]
        fn a_spent_lane_range_refuses_rather_than_wraps() {
            // Wrapping would alias a live stream and splice two peers' records
            // together, which is worse than refusing the connection.
            let next = AtomicU64::new(PEER_LANE_LAST);
            assert_eq!(allocate_peer_lane(&next), Some(PEER_LANE_LAST));
            assert_eq!(allocate_peer_lane(&next), None);
            // Still refused on every later attempt rather than only the first.
            assert_eq!(allocate_peer_lane(&next), None);
            assert_eq!(next.load(Ordering::Relaxed), PEER_LANE_LAST + 1);
        }

        /// Generates the test certificate exactly once per process.
        ///
        /// Several tests need it and the harness runs them concurrently. An
        /// exists-then-create check let two of them run `openssl` over the same
        /// two paths at once, so one could load a half-written certificate and
        /// fail for reasons that have nothing to do with what it tests.
        fn test_credential() -> Credential {
            static MATERIAL: OnceLock<(String, String)> = OnceLock::new();
            let (key, certificate) = MATERIAL.get_or_init(|| {
                let directory =
                    std::env::temp_dir().join(format!("vot-msquic-{}", std::process::id()));
                std::fs::create_dir_all(&directory).unwrap();
                let key = directory.join("key.pem");
                let certificate = directory.join("cert.pem");
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
                (key.display().to_string(), certificate.display().to_string())
            });
            Credential::CertificateFile(msquic::CertificateFile::new(
                key.clone(),
                certificate.clone(),
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
                    StreamEvent::SendComplete { client_context, .. } => {
                        // send_owned detaches the buffer for MsQuic to hold
                        // until it is done with it, so this is the only place
                        // it can be reclaimed. Without this the listener leaks
                        // one allocation per send, which is what the leak
                        // sanitiser reported once it was pointed at the whole
                        // suite rather than one test.
                        // SAFETY: send_owned produced this context exactly once
                        // and MsQuic delivers SendComplete for it exactly once.
                        unsafe { complete_send(client_context) };
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
            let mut transport = MsQuicTransport::connect(
                configuration,
                client_registration,
                "127.0.0.1",
                port,
                11,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
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

            // No control frame has been sent, only records. spec/wire.md still
            // reserves the first client-initiated bidirectional stream, which is
            // QUIC stream 0, for HELLO and SETTINGS. A conforming peer would
            // parse these records as negotiation if the lane had claimed it.
            let Control::Opened(Some(control)) = &transport.carrier.control else {
                panic!("negotiation stream was never claimed");
            };
            assert_eq!(
                control.get_stream_id().unwrap(),
                0,
                "negotiation must own the first client-initiated bidirectional stream"
            );
            let lane = transport
                .carrier
                .streams
                .values()
                .next()
                .expect("the record lane was never opened");
            assert!(
                lane.get_stream_id().unwrap() > 0,
                "an application lane must come after negotiation"
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

        /// Builds a listening configuration that presents the test certificate.
        fn server_configuration(registration: &Registration) -> Arc<Configuration> {
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let settings = Settings::new().set_PeerBidiStreamCount(8);
            let configuration = Configuration::open(registration, &alpn, Some(&settings)).unwrap();
            configuration
                .load_credential(
                    &CredentialConfig::new()
                        .set_credential_flags(CredentialFlags::NONE)
                        .set_credential(test_credential()),
                )
                .unwrap();
            Arc::new(configuration)
        }

        /// Polls `transport` until `collect` reports it has seen enough, or the
        /// deadline passes.
        fn drive(
            transport: &mut impl TransportAdapter,
            deadline: Instant,
            mut collect: impl FnMut(Event) -> bool,
        ) -> bool {
            while Instant::now() < deadline {
                while let Some(event) = transport.poll() {
                    if collect(event) {
                        return true;
                    }
                }
                std::thread::yield_now();
            }
            false
        }

        #[test]
        fn an_accepted_connection_drives_the_same_transport_as_the_client() {
            // Both directions run production code here. A listener that
            // hand-rolls its own receive stack proves nothing about the one a
            // deployment would use, and that second stack is the one nothing
            // else exercises.
            let registration = Arc::new(super::registration().unwrap());
            let configuration = server_configuration(&registration);
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            let mut server = MsQuicServer::listen(
                Arc::clone(&configuration),
                Arc::clone(&registration),
                &alpn,
                &address,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();
            let port = server.local_port().unwrap();

            let client_registration = super::registration().unwrap();
            let mut client = MsQuicTransport::connect(
                client_configuration(&client_registration),
                client_registration,
                "127.0.0.1",
                port,
                31,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();

            let deadline = Instant::now() + Duration::from_secs(10);
            assert!(
                drive(&mut client, deadline, |event| matches!(
                    event,
                    Event::Connected(ConnectionId(31))
                )),
                "the client never connected"
            );

            let mut accepted: AcceptedTransport = loop {
                assert!(Instant::now() < deadline, "the server never accepted");
                if let Some(accepted) = server.accept() {
                    break accepted;
                }
                std::thread::yield_now();
            };
            assert_eq!(accepted.connection_id(), 1);

            // A control frame and records on two lanes. The lanes are the point:
            // they arrive as two independent peer-created streams, and reporting
            // both under one identifier would make their interleaving look like
            // reordering within one stream.
            let hello = framed(vot_codec::frame_type::PING, b"");
            let first_record = framed(vot_codec::frame_type::DATA_RECORD, b"first-lane");
            let second_record = framed(vot_codec::frame_type::DATA_RECORD, b"second-lane");
            client.send_control(&hello).unwrap();
            client.send_reliable(StreamId(1), &first_record).unwrap();
            client.send_reliable(StreamId(2), &second_record).unwrap();
            client.flush().unwrap();

            let mut control = Vec::new();
            let mut lanes: Vec<(u64, Vec<u8>)> = Vec::new();
            assert!(
                drive(&mut accepted, deadline, |event| {
                    match event {
                        Event::Control(bytes) => control = bytes.to_vec(),
                        Event::Reliable { stream, bytes, .. } => {
                            lanes.push((stream.0, bytes.to_vec()));
                        }
                        _ => {}
                    }
                    !control.is_empty() && lanes.len() == 2
                }),
                "the accepted connection never received the client's frames"
            );

            assert_eq!(control, hello, "the negotiation stream carried the frame");
            lanes.sort_by_key(|(lane, _)| *lane);
            let [(first, first_bytes), (second, second_bytes)] = lanes.as_slice() else {
                unreachable!("exactly two lanes were collected")
            };
            assert_ne!(
                first, second,
                "two peer streams must not share one lane identity"
            );
            for lane in [first, second] {
                assert!(
                    super::super::is_reserved_lane(*lane),
                    "a peer lane must sit outside the range either side can name"
                );
            }
            let mut records = [first_bytes.clone(), second_bytes.clone()];
            records.sort();
            assert_eq!(records, [first_record, second_record]);

            // The reply goes back on the negotiation stream the client opened,
            // which is the only peer stream an accepted connection holds. Every
            // frame a receiver sends, from SETTINGS to PUBLISH_RECEIPT, takes
            // this path.
            assert!(accepted.control_stream_open());
            let reply = framed(vot_codec::frame_type::SETTINGS_ACK, b"");
            accepted.send_control(&reply).unwrap();
            accepted.flush().unwrap();
            assert_eq!(accepted.pending_commands(), 0);

            let mut received = Vec::new();
            assert!(
                drive(&mut client, deadline, |event| {
                    if let Event::Control(bytes) = event {
                        received = bytes.to_vec();
                    }
                    !received.is_empty()
                }),
                "the client never saw the reply"
            );
            assert_eq!(received, reply);

            drop(client);
            drop(accepted);
            drop(server);
        }

        /// What the accepting side advertises and reassembles in the
        /// negotiation tests. Below the connecting side's default, so applying
        /// it is observable.
        const SERVER_CONTROL_LIMIT: usize = 64 * 1024;

        #[test]
        fn two_endpoints_negotiate_over_the_real_carrier_before_any_data_moves() {
            // Everything below runs production code: the assembled client, the
            // assembled server, the session layer over both, and MsQuic in
            // between. Until this existed, negotiation had never been spoken
            // over a carrier, only over an in-memory loopback.
            let registration = Arc::new(super::registration().unwrap());
            let configuration = server_configuration(&registration);
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            let mut listener = MsQuicServer::listen(
                Arc::clone(&configuration),
                Arc::clone(&registration),
                &alpn,
                &address,
                // The accepting side advertises a smaller control-frame bound
                // than the connecting one, so applying it is observable rather
                // than a no-op. The listener is configured with it because the
                // bound has to be in force before the client's first byte.
                SERVER_CONTROL_LIMIT,
            )
            .unwrap();
            let port = listener.local_port().unwrap();

            let client_registration = super::registration().unwrap();
            let transport = MsQuicTransport::connect(
                client_configuration(&client_registration),
                client_registration,
                "127.0.0.1",
                port,
                61,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();

            let peer_settings = vot_codec::Settings {
                max_control_frame_payload: SERVER_CONTROL_LIMIT as u64,
                ..vot_codec::Settings::default()
            };
            let mut client = Session::client(
                transport,
                vot_codec::Settings::default(),
                BTreeSet::from([1]),
            );

            let deadline = Instant::now() + Duration::from_secs(10);
            let mut connected = false;
            while Instant::now() < deadline && !connected {
                while let Some(event) = client.poll().unwrap() {
                    connected |= matches!(event, Event::Connected(ConnectionId(61)));
                }
                std::thread::yield_now();
            }
            assert!(connected, "the client never connected");

            // Nothing may move until the exchange finishes, and it has not
            // started: the client speaks first but has not been told to.
            assert_eq!(client.state(), vot_session::State::Connecting);
            assert!(client.send_reliable(StreamId(1), b"too early").is_err());

            client.begin().unwrap();
            assert_eq!(client.state(), vot_session::State::HelloSent);

            let accepted = loop {
                assert!(Instant::now() < deadline, "the server never accepted");
                if let Some(accepted) = listener.accept() {
                    break accepted;
                }
                std::thread::yield_now();
            };
            let mut server = Session::server(accepted, peer_settings, BTreeSet::new());
            server.begin().unwrap();

            let mut records = Vec::new();
            while Instant::now() < deadline && !(client.is_ready() && server.is_ready()) {
                while let Some(event) = server.poll().unwrap() {
                    if let Event::Reliable { bytes, .. } = event {
                        records.push(bytes.to_vec());
                    }
                }
                while let Some(event) = client.poll().unwrap() {
                    assert!(
                        !matches!(event, Event::Reliable { .. }),
                        "the client asked for nothing back"
                    );
                }
                std::thread::yield_now();
            }
            assert!(client.is_ready(), "the client never reached readiness");
            assert!(server.is_ready(), "the server never reached readiness");

            // The exchange did something rather than only advancing an enum:
            // the peer's advertised maximum is now the bound this side sends
            // control frames under.
            assert_eq!(
                client.peer_settings().map(|s| s.max_control_frame_payload),
                Some(SERVER_CONTROL_LIMIT as u64)
            );
            assert!(client.control_limit_applied());
            assert_eq!(
                server.peer_settings(),
                Some(vot_codec::Settings::default()),
                "the server read the client's advertised limits"
            );

            // And only now will the data plane carry anything.
            let payload = framed(vot_codec::frame_type::DATA_RECORD, b"after negotiation");
            client.send_reliable(StreamId(1), &payload).unwrap();
            client.flush().unwrap();

            while Instant::now() < deadline && records.is_empty() {
                while let Some(event) = server.poll().unwrap() {
                    if let Event::Reliable { bytes, .. } = event {
                        records.push(bytes.to_vec());
                    }
                }
                std::thread::yield_now();
            }
            assert_eq!(records, vec![payload]);

            drop(client);
            drop(server);
            drop(listener);
        }

        /// Brings up a raw connecting transport against a listening server.
        ///
        /// The connecting side is not a `Session`: these tests
        /// need a peer that does things a conforming session would refuse to
        /// do, which is exactly what an independent implementation might send.
        ///
        /// The listener comes back too, because dropping it closes the
        /// registration the accepted connection belongs to.
        fn peer_against_server(
            connection_id: u64,
        ) -> (
            MsQuicServer,
            MsQuicTransport,
            Session<AcceptedTransport>,
            Instant,
        ) {
            let registration = Arc::new(super::registration().unwrap());
            let configuration = server_configuration(&registration);
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            let mut listener = MsQuicServer::listen(
                configuration,
                Arc::clone(&registration),
                &alpn,
                &address,
                SERVER_CONTROL_LIMIT,
            )
            .unwrap();
            let port = listener.local_port().unwrap();

            let client_registration = super::registration().unwrap();
            let mut peer = MsQuicTransport::connect(
                client_configuration(&client_registration),
                client_registration,
                "127.0.0.1",
                port,
                connection_id,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();

            let deadline = Instant::now() + Duration::from_secs(10);
            assert!(
                drive(&mut peer, deadline, |event| matches!(
                    event,
                    Event::Connected(_)
                )),
                "the peer never connected"
            );

            // Nothing is sent here. A frame before the exchange starts is an
            // application frame arriving before negotiation, which the server
            // is right to refuse, and the connection is accepted on the
            // handshake rather than on the first stream.
            let accepted = loop {
                assert!(Instant::now() < deadline, "the server never accepted");
                if let Some(accepted) = listener.accept() {
                    break accepted;
                }
                std::thread::yield_now();
            };
            let server = Session::server(
                accepted,
                vot_codec::Settings {
                    max_control_frame_payload: SERVER_CONTROL_LIMIT as u64,
                    ..vot_codec::Settings::default()
                },
                BTreeSet::new(),
            );
            (listener, peer, server, deadline)
        }

        /// One encoded HELLO from a client on `revision`.
        fn hello_frame(revision: u64) -> Vec<u8> {
            let hello = vot_codec::Hello {
                draft_revision: revision,
                endpoint_role: vot_codec::EndpointRole::Client,
                extensions: BTreeSet::new(),
            };
            let mut payload = Vec::new();
            vot_codec::encode_hello(&hello, &mut payload).unwrap();
            framed(vot_codec::frame_type::HELLO, &payload)
        }

        /// One encoded SETTINGS carrying the defaults.
        fn settings_frame() -> Vec<u8> {
            let mut payload = Vec::new();
            vot_codec::encode_settings(&vot_codec::Settings::default(), &mut payload).unwrap();
            framed(vot_codec::frame_type::SETTINGS, &payload)
        }

        /// Polls a session until it fails or the deadline passes.
        fn drive_session<A: TransportAdapter>(
            session: &mut Session<A>,
            peer: &mut MsQuicTransport,
            deadline: Instant,
            mut done: impl FnMut(&mut Session<A>) -> bool,
        ) -> Option<vot_session::Error> {
            while Instant::now() < deadline {
                match session.poll() {
                    Ok(_) => {}
                    Err(error) => return Some(error),
                }
                while peer.poll().is_some() {}
                if done(session) {
                    return None;
                }
                std::thread::yield_now();
            }
            None
        }

        #[test]
        fn a_registered_close_code_reaches_the_peer() {
            // The code was computed and asserted in unit tests long before
            // anything sent it, so a peer on another draft saw the session end
            // for no stated reason. This is the end-to-end version: the server
            // refuses the revision and the peer reads the registered reason
            // back off the carrier.
            let (listener, mut peer, mut server, deadline) = peer_against_server(71);
            server.begin().unwrap();

            peer.send_control(&hello_frame(vot_codec::DRAFT_REVISION - 1))
                .unwrap();
            peer.flush().unwrap();

            let refused = drive_session(&mut server, &mut peer, deadline, |_| false)
                .expect("the server accepted a HELLO it had to refuse");
            assert_eq!(
                refused.close_code(),
                vot_codec::error_code::UNSUPPORTED_VERSION
            );

            let mut observed = None;
            while Instant::now() < deadline && observed.is_none() {
                while peer.poll().is_some() {}
                observed = peer.peer_close_code();
                std::thread::yield_now();
            }
            assert_eq!(
                observed,
                Some(vot_codec::error_code::UNSUPPORTED_VERSION),
                "the registered code never reached the wire"
            );

            drop(peer);
            drop(server);
            drop(listener);
        }

        #[test]
        fn records_sent_before_readiness_are_held_over_the_real_carrier() {
            // The in-memory version proves the buffer works. Only the carrier
            // proves the race it exists for is real: the negotiation stream and
            // an application lane are different QUIC streams, so nothing orders
            // a record against the frames that make the sender ready.
            let (listener, mut peer, mut server, deadline) = peer_against_server(81);
            server.begin().unwrap();

            let record = framed(vot_codec::frame_type::DATA_RECORD, b"in flight");
            peer.send_control(&hello_frame(vot_codec::DRAFT_REVISION))
                .unwrap();
            // Between the two negotiation frames, which is the worst ordering
            // the carrier can produce and the one a conforming peer can create.
            peer.send_reliable(StreamId(1), &record).unwrap();
            peer.send_control(&settings_frame()).unwrap();
            peer.flush().unwrap();

            // Collected as the session runs, because the held record is
            // released the moment readiness is reached and a second pass would
            // arrive after it.
            let mut held = Vec::new();
            while Instant::now() < deadline && held.is_empty() {
                while let Some(event) = server.poll().unwrap() {
                    if let Event::Reliable { bytes, .. } = event {
                        assert!(
                            server.is_ready(),
                            "a record surfaced before the exchange finished"
                        );
                        held.push(bytes.to_vec());
                    }
                }
                while peer.poll().is_some() {}
                std::thread::yield_now();
            }
            assert!(
                server.is_ready(),
                "a record in flight blocked the exchange behind it"
            );
            assert_eq!(held, vec![record], "a record in flight was lost");

            drop(peer);
            drop(server);
            drop(listener);
        }

        #[test]
        fn a_malformed_peer_frame_ends_the_session_not_the_process() {
            // MsQuic treats a failure status from a receive callback as an
            // application bug: a debug build asserts and aborts, a release
            // build ignores it. Returning one on a decoder fault therefore let
            // any peer end the process with three bytes. The fault has to
            // travel through the close request instead, which is what the
            // driver turns into a registered connection close.
            let registration = Arc::new(super::registration().unwrap());
            let configuration = server_configuration(&registration);
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            let mut server = MsQuicServer::listen(
                Arc::clone(&configuration),
                Arc::clone(&registration),
                &alpn,
                &address,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();
            let port = server.local_port().unwrap();

            let client_registration = super::registration().unwrap();
            let mut client = MsQuicTransport::connect(
                client_configuration(&client_registration),
                client_registration,
                "127.0.0.1",
                port,
                51,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            assert!(drive(&mut client, deadline, |event| matches!(
                event,
                Event::Connected(ConnectionId(51))
            )));

            let mut accepted = loop {
                assert!(Instant::now() < deadline, "the server never accepted");
                if let Some(accepted) = server.accept() {
                    break accepted;
                }
                std::thread::yield_now();
            };

            // Frame type fifteen is odd, so it is critical, and unregistered,
            // so it is unknown. spec/wire.md closes the session under
            // UNKNOWN_CRITICAL_FRAME rather than skipping it.
            let unknown_critical = [0x0f_u8, 0x01, 0x41];
            assert!(vot_codec::is_critical(0x0f));
            assert!(!vot_codec::is_known(0x0f));
            client
                .send_reliable(StreamId(1), &unknown_critical)
                .unwrap();
            client.flush().unwrap();

            assert!(
                drive(&mut accepted, deadline, |event| matches!(
                    event,
                    Event::Disconnected(_)
                )),
                "the session survived a frame it had to reject"
            );
            // The process is still here, which is the whole point.
            assert_eq!(accepted.connection_id(), 1);

            drop(client);
            drop(accepted);
            drop(server);
        }

        #[test]
        fn a_control_frame_stays_queued_until_the_peer_opens_the_stream() {
            // An accepted connection does not open the negotiation stream; the
            // client does. A frame submitted first has to wait for it rather
            // than be lost, because nothing will submit it again.
            let registration = Arc::new(super::registration().unwrap());
            let configuration = server_configuration(&registration);
            let alpn = [BufferRef::from(vot_transport_api::ALPN)];
            let address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            let mut server = MsQuicServer::listen(
                Arc::clone(&configuration),
                Arc::clone(&registration),
                &alpn,
                &address,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();
            let port = server.local_port().unwrap();

            let client_registration = super::registration().unwrap();
            let mut client = MsQuicTransport::connect(
                client_configuration(&client_registration),
                client_registration,
                "127.0.0.1",
                port,
                41,
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            assert!(drive(&mut client, deadline, |event| matches!(
                event,
                Event::Connected(ConnectionId(41))
            )));

            let mut accepted = loop {
                assert!(Instant::now() < deadline, "the server never accepted");
                if let Some(accepted) = server.accept() {
                    break accepted;
                }
                std::thread::yield_now();
            };

            // Nothing has opened the negotiation stream yet, so the frame has
            // nowhere to go and must survive the failed flush.
            assert!(!accepted.control_stream_open());
            let reply = framed(vot_codec::frame_type::SETTINGS_ACK, b"");
            accepted.send_control(&reply).unwrap();
            assert!(accepted.flush().is_err(), "there is no stream to send on");
            assert_eq!(accepted.pending_commands(), 1, "the frame was not lost");

            // The client opens it, and the same queued frame now goes out.
            client
                .send_control(&framed(vot_codec::frame_type::PING, b""))
                .unwrap();
            client.flush().unwrap();
            let mut seen = false;
            assert!(
                drive(&mut accepted, deadline, |event| {
                    seen = matches!(event, Event::Control(_));
                    seen
                }),
                "the negotiation stream never arrived"
            );
            assert!(accepted.control_stream_open());
            accepted.flush().unwrap();
            assert_eq!(accepted.pending_commands(), 0);

            let mut received = Vec::new();
            assert!(
                drive(&mut client, deadline, |event| {
                    if let Event::Control(bytes) = event {
                        received = bytes.to_vec();
                    }
                    !received.is_empty()
                }),
                "the frame queued before the stream existed never arrived"
            );
            assert_eq!(received, reply);

            drop(client);
            drop(accepted);
            drop(server);
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
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
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
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
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
                vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
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
                            let _ = complete_tx.send(());
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
                        let _ = server_closed_tx.send(());
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
                        let _ = listener_stopped_tx.send(());
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
        assert_eq!(CONTROL_LANE, u64::MAX - 1);
        assert!(is_reserved_lane(CONTROL_LANE));
        // Every peer lane sits below the control lane and above every lane
        // either side can name on the wire. A QUIC varint stops one short of
        // the base, so the two ranges cannot meet.
        assert_eq!(PEER_LANE_BASE, vot_codec::MAX_QUIC_VARINT + 1);
        assert_eq!(PEER_LANE_LAST, CONTROL_LANE - 1);
        assert!(!is_reserved_lane(vot_codec::MAX_QUIC_VARINT));
        // Zero stays an ordinary application lane.
        assert!(!is_reserved_lane(0));
        // The bounds are the ones the callback path relies on. The event bound
        // covers peer-driven records and control frames; lifecycle events are
        // admitted past it.
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
        // The byte bound is what actually limits memory, so it is pinned here
        // rather than only where it is used. Sixteen of the largest frames a
        // lane carries: enough for the driver to fall briefly behind, and far
        // below the gigabyte the entry count alone would have allowed, which is
        // the hole it exists to close.
        assert_eq!(MAX_CALLBACK_BYTES, 16 * MAX_PARTIAL_CONTROL_FRAME);
        assert_eq!(MAX_CALLBACK_BYTES / MAX_PARTIAL_CONTROL_FRAME, 16);
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
        for lane in [CONTROL_LANE, PEER_LANE_BASE, PEER_LANE_LAST, u64::MAX] {
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
        // The largest lane a peer can name on the wire is still ordinary.
        assert!(!is_reserved_lane(PEER_LANE_BASE - 1));
        adapter
            .send_reliable(StreamId(PEER_LANE_BASE - 1), b"record")
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
    fn the_two_control_bounds_move_independently() {
        // The peer's limit governs what goes out. What may arrive is what this
        // endpoint advertised. One field for both meant a peer advertising less
        // than this endpoint also narrowed what this endpoint would accept, so
        // a conforming inbound frame got the connection closed.
        let envelope = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let default = vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD;
        let mut adapter = MsQuicAdapter::default();
        assert_eq!(
            adapter.set_control_payload_limit(0),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            adapter.set_control_receive_limit(0),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(adapter.control_receive_limit(), Some(default));

        // A peer that allows less does not narrow what this endpoint accepts.
        adapter.set_control_payload_limit(64 * 1024).unwrap();
        assert_eq!(adapter.control_receive_limit(), Some(default));
        assert_eq!(
            adapter.send_control(&vec![0; 64 * 1024 + envelope + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            adapter.record_native_event(NativeEvent::Control(vec![0; default + envelope])),
            Ok(()),
            "still everything this endpoint advertised"
        );

        // And a peer that allows more does not widen it either.
        adapter.set_control_payload_limit(2 * 1024 * 1024).unwrap();
        adapter
            .send_control(&vec![0; 2 * 1024 * 1024 + envelope])
            .unwrap();
        assert_eq!(
            adapter.record_native_event(NativeEvent::Control(vec![0; default + envelope + 1])),
            Err(Error::RecordTooLarge)
        );

        // The receive bound moves on its own, which is what an endpoint
        // advertising less than the default is held to.
        let mut narrow = MsQuicAdapter::default();
        narrow.set_control_receive_limit(64 * 1024).unwrap();
        assert_eq!(narrow.control_receive_limit(), Some(64 * 1024));
        assert_eq!(
            narrow.record_native_event(NativeEvent::Control(vec![0; 64 * 1024 + envelope])),
            Ok(())
        );
        assert_eq!(
            narrow.record_native_event(NativeEvent::Control(vec![0; 64 * 1024 + envelope + 1])),
            Err(Error::RecordTooLarge)
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
