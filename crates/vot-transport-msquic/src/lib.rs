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
    events: VecDeque<Event>,
    event_bytes: usize,
    event_count_limit: usize,
    event_byte_limit: usize,
}

impl Default for MsQuicAdapter {
    fn default() -> Self {
        Self {
            commands: VecDeque::new(),
            command_bytes: 0,
            command_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            command_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
            events: VecDeque::new(),
            event_bytes: 0,
            event_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            event_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
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

    /// Queues a native callback after enforcing protocol and memory bounds.
    ///
    /// # Errors
    /// Rejects oversized records, arithmetic overflow, or a full inbound queue.
    pub fn record_native_event(&mut self, event: NativeEvent) -> Result<(), Error> {
        let payload_len = match &event {
            NativeEvent::Control(bytes) => {
                if bytes.len() > vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD {
                    return Err(Error::RecordTooLarge);
                }
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
        Ok(())
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
        if frame.len() > vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD {
            return Err(Error::RecordTooLarge);
        }
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
        None
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

    use msquic::{
        BufferRef, Connection, ConnectionRef, Registration, RegistrationConfig, SendFlags, Stream,
        StreamRef,
    };

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
        use std::time::Duration;

        use msquic::{
            Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, Credential,
            CredentialConfig, CredentialFlags, Listener, ListenerEvent, SendFlags, Settings,
            Status, Stream, StreamEvent, StreamOpenFlags, StreamRef, StreamStartFlags,
        };

        use super::super::{Command as AdapterCommand, MsQuicAdapter};
        use super::{close_peer_connection, close_peer_stream, complete_send, detach_stream};
        use vot_transport_api::{StreamId, TransportAdapter};

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
    fn oversized_reliable_record_is_rejected_before_ffi() {
        let mut adapter = MsQuicAdapter::default();
        assert_eq!(
            adapter.send_reliable(
                StreamId(1),
                &vec![0; vot_transport_api::MAX_DATA_RECORD_BYTES + 1]
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
        adapter.send_control(&vec![0; vot_codec_limit()]).unwrap();
        assert_eq!(
            adapter.send_control(&vec![0; vot_codec_limit() + 1]),
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
            .record_native_event(NativeEvent::Control(vec![0; vot_codec_limit()]))
            .unwrap();
        assert!(matches!(oversized.poll(), Some(Event::Control(_))));
        assert_eq!(
            oversized.record_native_event(NativeEvent::Control(vec![0; vot_codec_limit() + 1])),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            oversized.record_native_event(NativeEvent::Reliable {
                stream: 1,
                sequence: 1,
                bytes: vec![0; vot_transport_api::MAX_DATA_RECORD_BYTES + 1],
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
