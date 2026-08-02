//! `MsQuic` event bridge for the backend-neutral VOT transport API.

#![deny(unsafe_code)]

use std::collections::VecDeque;

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

    fn preflight_reliable_batch(
        &self,
        _stream: StreamId,
        records: &[Payload],
    ) -> Result<(), Error> {
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
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use msquic::{
        BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Registration,
        RegistrationConfig, SendFlags, Stream, StreamEvent, StreamOpenFlags, StreamRef,
        StreamStartFlags,
    };

    use vot_transport_api::{ConnectionId, Error, Event, Payload, StreamId, TransportAdapter};

    use super::{Command, MsQuicAdapter, NativeEvent};
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
        streams: BTreeMap<u64, Stream>,
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
            let callback_inbound = Arc::clone(&inbound);
            let connection = Connection::open(
                &registration,
                move |_: ConnectionRef, event: ConnectionEvent| {
                    match event {
                        ConnectionEvent::Connected { .. } => {
                            push(&callback_inbound, NativeEvent::Connected(connection_id));
                        }
                        ConnectionEvent::ShutdownComplete { .. } => {
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
                streams: BTreeMap::new(),
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

        /// Opens a stream on first use and keeps it for the transport's life.
        fn stream(&mut self, id: u64) -> Result<&Stream, msquic::Status> {
            if !self.streams.contains_key(&id) {
                let connection = self.connection.as_ref().ok_or(msquic::Status::from(
                    msquic::StatusCode::QUIC_STATUS_INVALID_STATE,
                ))?;
                // The pool owns the handle and closes it at teardown. It is
                // never detached, so there is exactly one owner.
                let stream = Stream::open(connection, StreamOpenFlags::NONE, |_, event| {
                    if let StreamEvent::SendComplete { client_context, .. } = event {
                        // SAFETY: send_owned produced this context exactly once
                        // and MsQuic delivers SendComplete for it once.
                        unsafe { complete_send(client_context) };
                    }
                    Ok::<(), msquic::Status>(())
                })?;
                stream.start(StreamStartFlags::NONE)?;
                self.streams.insert(id, stream);
            }
            Ok(&self.streams[&id])
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

    fn push(queue: &Arc<Mutex<VecDeque<NativeEvent>>>, event: NativeEvent) {
        if let Ok(mut queue) = queue.lock() {
            queue.push_back(event);
        }
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

        fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
            self.adapter.send_datagram(context, payload)
        }

        fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
            self.adapter.set_receive_credit(bytes)
        }

        fn flush(&mut self) -> Result<(), Error> {
            // Commands are drained one at a time and a failed submission stays
            // at the head, so a backend error costs no data.
            let mut queued: Vec<Command> = Vec::new();
            self.adapter.drain_commands(|command| {
                queued.push(command);
                Ok::<(), Error>(())
            })?;
            for command in queued {
                match command {
                    Command::Reliable { stream, bytes } => {
                        let handle = self.stream(stream.0).map_err(|_| Error::Backend)?;
                        send_owned(handle, &bytes, SendFlags::NONE).map_err(|_| Error::Backend)?;
                    }
                    // Control frames, datagrams, and credit are not carried by
                    // this increment. Silently dropping them would be worse
                    // than saying so.
                    Command::Control(_) | Command::Datagram { .. } => {
                        return Err(Error::Unsupported);
                    }
                    Command::ReceiveCredit(_) => {}
                }
            }
            Ok(())
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

        use super::MsQuicTransport;

        use super::super::{Command as AdapterCommand, MsQuicAdapter, NativeEvent};
        use super::{close_peer_connection, close_peer_stream, complete_send, detach_stream};
        use vot_transport_api::{ConnectionId, Event, StreamId, TransportAdapter};

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
            done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(*received.lock().unwrap(), payload);

            drop(transport);
            listener.stop();
            drop(listener);
            registration.shutdown();
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
