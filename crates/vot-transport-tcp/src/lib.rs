//! Authenticated TLS/TCP carrier, bounded adapter, and deterministic carrier race.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use vot_transport_api::{
    ConnectionId, Error, Event, PathStats, Payload, StreamId, TransportAck, TransportAdapter,
    shared_payload,
};
use vot_transport_queue::Queue;

#[cfg(test)]
const DEFAULT_COMMAND_COUNT_LIMIT: usize = vot_transport_queue::DEFAULT_COUNT_LIMIT;
#[cfg(test)]
const DEFAULT_COMMAND_BYTE_LIMIT: usize = vot_transport_queue::DEFAULT_BYTE_LIMIT;
#[cfg(test)]
const CONTROL_LIMIT: usize = vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD;

/// Max inbound queue bytes per event. `ReceiveLimits` is built against it.
pub const INBOUND_BYTE_CAPACITY: usize = vot_transport_queue::INBOUND_BYTE_CAPACITY;

pub use vot_transport_queue::Command;

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
}

/// Bounded TLS/TCP command and event adapter. VOT frame bytes are not rewritten.
/// One byte stream: lanes are logical identifiers, not separate streams.
#[derive(Debug, Default)]
pub struct TcpAdapter {
    queue: Queue,
    /// Lanes the peer has sent on. Only grows, for the reason above.
    inbound_lanes: BTreeSet<u64>,
}

impl TcpAdapter {
    /// Creates an adapter with explicit inbound and outbound queue limits.
    ///
    /// # Errors
    /// Rejects a zero command-count or byte limit.
    pub fn with_queue_limits(command_count: usize, command_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            queue: Queue::with_limits(command_count, command_bytes)?,
            inbound_lanes: BTreeSet::new(),
        })
    }

    /// Counts one peer lane against the advertised limit.
    ///
    /// # Errors
    /// Reports a peer using more lanes than it was told this endpoint carries.
    fn admit_lane(&mut self, stream: u64) -> Result<(), Error> {
        let Some(limits) = self.queue.receive_limits() else {
            return Ok(());
        };
        if self.inbound_lanes.contains(&stream) {
            return Ok(());
        }
        if self.inbound_lanes.len() >= limits.lanes() {
            return Err(Error::LaneLimitExceeded);
        }
        self.inbound_lanes.insert(stream);
        Ok(())
    }

    /// Applies what this endpoint advertised. Must be in force before the
    /// peer's first frame.
    pub const fn set_receive_limits(&mut self, limits: vot_transport_api::ReceiveLimits) {
        self.queue.set_receive_limits(limits);
    }

    /// Queues a native callback after enforcing protocol and memory bounds.
    ///
    /// # Errors
    /// Rejects oversized records, arithmetic overflow, or a full inbound queue.
    pub fn record_native_event(&mut self, event: NativeEvent) -> Result<(), Error> {
        let event = translate(event);
        self.queue.validate_event(&event)?;
        if let Event::Reliable { stream, .. } = &event {
            self.admit_lane(stream.0)?;
        }
        self.queue.admit_event(event)
    }

    pub fn next_command(&mut self) -> Option<Command> {
        self.queue.next_command()
    }

    /// Gives a carrier driver one queued command. Failed submissions stay queued.
    ///
    /// # Errors
    /// Returns the first carrier error reported by `submit`.
    pub fn drain_commands<F, E>(&mut self, submit: F) -> Result<(), E>
    where
        F: FnMut(Command) -> Result<(), E>,
    {
        self.queue.drain_commands(submit)
    }
}

/// Reads one carrier callback as the event the queue carries.
fn translate(event: NativeEvent) -> Event {
    match event {
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
    }
}

impl TransportAdapter for TcpAdapter {
    fn receive_limits(&self) -> Option<vot_transport_api::ReceiveLimits> {
        self.queue.receive_limits()
    }

    fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), Error> {
        self.queue.set_control_send_limit(limit)
    }

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

    fn preflight_reliable_batch(
        &self,
        _stream: StreamId,
        records: &[Payload],
    ) -> Result<(), Error> {
        self.queue.preflight_reliable_batch(records)
    }

    fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.queue.send_reliable(stream, record)
    }

    fn poll(&mut self) -> Option<Event> {
        self.queue.poll()
    }

    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
        self.queue.set_receive_credit(bytes)
    }

    /// Always absent on this backend. No socket to sample; fabricated metrics
    /// would be worse than none.
    fn path_stats(&self) -> Option<PathStats> {
        None
    }
}

#[derive(Debug)]
pub enum TlsError {
    Io(io::Error),
    Protocol(rustls::Error),
    NotAuthenticated,
}

impl From<io::Error> for TlsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustls::Error> for TlsError {
    fn from(error: rustls::Error) -> Self {
        Self::Protocol(error)
    }
}

/// Rustls record layer that exposes plaintext only after peer authentication.
pub struct TlsClientCarrier {
    connection: ClientConnection,
}

impl TlsClientCarrier {
    pub fn new(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, TlsError> {
        Ok(Self {
            connection: ClientConnection::new(config, server_name)?,
        })
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        !self.connection.is_handshaking()
            && self.connection.alpn_protocol() == Some(vot_transport_api::ALPN)
    }

    pub fn read_tls(&mut self, reader: &mut dyn Read) -> Result<usize, TlsError> {
        Ok(self.connection.read_tls(reader)?)
    }

    pub fn process_new_packets(&mut self) -> Result<(), TlsError> {
        self.connection.process_new_packets()?;
        Ok(())
    }

    pub fn write_tls(&mut self, writer: &mut dyn Write) -> Result<usize, TlsError> {
        Ok(self.connection.write_tls(writer)?)
    }

    pub fn queue_vot_bytes(&mut self, bytes: &[u8]) -> Result<(), TlsError> {
        if !self.is_authenticated() {
            return Err(TlsError::NotAuthenticated);
        }
        self.connection.writer().write_all(bytes)?;
        Ok(())
    }

    pub fn read_vot_bytes(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        if !self.is_authenticated() {
            return Err(TlsError::NotAuthenticated);
        }
        Ok(self.connection.reader().read(output)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Carrier {
    Quic,
    TlsTcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RaceAction {
    StartQuic,
    StartTlsTcp,
    Selected(Carrier),
    Switched(Carrier),
}

/// Detects UDP failure from bounded observation windows without ambient sleeps.
pub struct DegradedUdpDetector {
    threshold: u8,
    empty_windows: u8,
}

impl DegradedUdpDetector {
    pub const fn new(threshold: u8) -> Result<Self, Error> {
        if threshold == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            threshold,
            empty_windows: 0,
        })
    }

    pub fn observe(&mut self, acknowledged_bytes: u64, probe_acknowledged: bool) -> bool {
        if acknowledged_bytes > 0 || probe_acknowledged {
            self.empty_windows = 0;
            return false;
        }
        self.empty_windows = self.empty_windows.saturating_add(1);
        self.empty_windows >= self.threshold
    }
}

/// Happy-eyeballs-style carrier selection driven by caller-provided monotonic time.
pub struct CarrierRace {
    started_at: u64,
    tcp_delay: u64,
    tcp_started: bool,
    tcp_ready: bool,
    selected: Option<Carrier>,
    detector: DegradedUdpDetector,
}

impl CarrierRace {
    pub fn start(
        started_at: u64,
        tcp_delay: u64,
        degraded_windows: u8,
    ) -> Result<(Self, RaceAction), Error> {
        Ok((
            Self {
                started_at,
                tcp_delay,
                tcp_started: false,
                tcp_ready: false,
                selected: None,
                detector: DegradedUdpDetector::new(degraded_windows)?,
            },
            RaceAction::StartQuic,
        ))
    }

    pub fn poll(&mut self, now: u64) -> Option<RaceAction> {
        if self.tcp_started || now.saturating_sub(self.started_at) < self.tcp_delay {
            return None;
        }
        self.tcp_started = true;
        Some(RaceAction::StartTlsTcp)
    }

    pub fn ready(&mut self, carrier: Carrier) -> Option<RaceAction> {
        if carrier == Carrier::TlsTcp {
            self.tcp_ready = true;
        }
        if self.selected.is_some() {
            return None;
        }
        self.selected = Some(carrier);
        Some(RaceAction::Selected(carrier))
    }

    pub fn observe_quic(
        &mut self,
        acknowledged_bytes: u64,
        probe_acknowledged: bool,
    ) -> Option<RaceAction> {
        if self.selected != Some(Carrier::Quic)
            || !self.tcp_ready
            || !self
                .detector
                .observe(acknowledged_bytes, probe_acknowledged)
        {
            return None;
        }
        self.selected = Some(Carrier::TlsTcp);
        Some(RaceAction::Switched(Carrier::TlsTcp))
    }

    #[must_use]
    pub const fn selected(&self) -> Option<Carrier> {
        self.selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command as ProcessCommand, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use vot_transport_api::BatchFailure;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection};

    static IDENTITY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let sequence = IDENTITY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vot-tcp-identity-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let key_pem = directory.join("key.pem");
        let key_der = directory.join("key.der");
        let certificate_der = directory.join("cert.der");
        let status = ProcessCommand::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_pem.to_str().unwrap(),
                "-out",
                certificate_der.to_str().unwrap(),
                "-outform",
                "DER",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=vot.test",
                "-addext",
                "subjectAltName=DNS:vot.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let status = ProcessCommand::new("openssl")
            .args([
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                key_pem.to_str().unwrap(),
                "-out",
                key_der.to_str().unwrap(),
                "-outform",
                "DER",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let certificate = CertificateDer::from(std::fs::read(&certificate_der).unwrap());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(&key_der).unwrap()));
        let _ = std::fs::remove_dir_all(directory);
        (certificate, key)
    }

    fn transfer_client_to_server(client: &mut TlsClientCarrier, server: &mut ServerConnection) {
        let mut wire = Vec::new();
        for _ in 0..16 {
            if client.write_tls(&mut wire).unwrap() == 0 {
                break;
            }
        }
        assert_eq!(client.write_tls(&mut Vec::new()).unwrap(), 0);
        if !wire.is_empty() {
            server.read_tls(&mut wire.as_slice()).unwrap();
            server.process_new_packets().unwrap();
        }
    }

    fn transfer_server_to_client(server: &mut ServerConnection, client: &mut TlsClientCarrier) {
        let mut wire = Vec::new();
        for _ in 0..16 {
            if server.write_tls(&mut wire).unwrap() == 0 {
                break;
            }
        }
        if !wire.is_empty() {
            client.read_tls(&mut wire.as_slice()).unwrap();
            client.process_new_packets().unwrap();
        }
    }

    #[test]
    fn startup_does_not_wait_for_long_udp_timeout() {
        let (mut race, initial) = CarrierRace::start(1_000, 50, 3).unwrap();
        assert_eq!(initial, RaceAction::StartQuic);
        assert_eq!(race.poll(1_049), None);
        assert_eq!(race.poll(1_050), Some(RaceAction::StartTlsTcp));
        assert_eq!(race.poll(60_000), None);
        assert_eq!(
            race.ready(Carrier::TlsTcp),
            Some(RaceAction::Selected(Carrier::TlsTcp))
        );
    }

    #[test]
    fn degraded_udp_requires_bounded_consecutive_failures() {
        let mut detector = DegradedUdpDetector::new(3).unwrap();
        assert!(!detector.observe(0, false));
        assert!(!detector.observe(0, false));
        assert!(!detector.observe(1, false));
        assert!(!detector.observe(0, false));
        assert!(!detector.observe(0, false));
        assert!(detector.observe(0, false));
        assert_eq!(
            DegradedUdpDetector::new(0).err(),
            Some(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn ready_tcp_takes_over_after_udp_blackhole() {
        let (mut race, _) = CarrierRace::start(0, 10, 2).unwrap();
        assert_eq!(
            race.ready(Carrier::Quic),
            Some(RaceAction::Selected(Carrier::Quic))
        );
        assert_eq!(race.poll(10), Some(RaceAction::StartTlsTcp));
        assert_eq!(race.ready(Carrier::TlsTcp), None);
        assert_eq!(race.observe_quic(0, false), None);
        assert_eq!(
            race.observe_quic(0, false),
            Some(RaceAction::Switched(Carrier::TlsTcp))
        );
        assert_eq!(race.selected(), Some(Carrier::TlsTcp));
    }

    #[test]
    fn command_drain_preserves_order_and_removes_submitted_commands() {
        let mut adapter = TcpAdapter::default();
        adapter.send_control(b"control").unwrap();
        adapter.send_reliable(StreamId(4), b"payload").unwrap();

        let mut seen = Vec::new();
        adapter
            .drain_commands(|command| {
                seen.push(command);
                Ok::<(), Error>(())
            })
            .unwrap();
        assert_eq!(
            seen,
            vec![
                Command::Control(shared_payload(b"control")),
                Command::Reliable {
                    stream: StreamId(4),
                    bytes: shared_payload(b"payload"),
                },
            ]
        );
        assert_eq!(adapter.next_command(), None);
    }

    #[test]
    fn adapter_preserves_identical_vot_bytes_and_bounds_queues() {
        let mut adapter = TcpAdapter::with_queue_limits(2, 8).unwrap();
        adapter.send_control(b"abc").unwrap();
        adapter.send_reliable(StreamId(9), b"defg").unwrap();
        assert_eq!(adapter.send_control(b"x"), Err(Error::OutboundQueueFull));
        assert_eq!(
            adapter.next_command().unwrap().vot_bytes(),
            Some(b"abc".as_slice())
        );
        assert_eq!(
            adapter.next_command().unwrap().vot_bytes(),
            Some(b"defg".as_slice())
        );
        assert_eq!(
            adapter.send_reliable(
                StreamId(1),
                &vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1]
            ),
            Err(Error::RecordTooLarge)
        );
    }

    #[test]
    fn reliable_batch_preflight_keeps_queue_unchanged_on_count_failure() {
        let mut adapter = TcpAdapter::with_queue_limits(2, 100).unwrap();
        adapter.send_reliable(StreamId(1), b"first").unwrap();
        let records = [shared_payload(b"second"), shared_payload(b"third")];
        assert_eq!(
            adapter.send_reliable_batch(StreamId(1), &records),
            Err(BatchFailure::Rejected(Error::OutboundQueueFull))
        );
        assert_eq!(
            adapter.next_command(),
            Some(Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"first"),
            })
        );
        assert_eq!(adapter.next_command(), None);

        let mut exact_count = TcpAdapter::with_queue_limits(2, 100).unwrap();
        exact_count.send_reliable(StreamId(1), b"first").unwrap();
        assert_eq!(
            exact_count.send_reliable_batch(StreamId(1), &[shared_payload(b"second")]),
            Ok(())
        );

        let mut exact_bytes = TcpAdapter::with_queue_limits(3, 8).unwrap();
        exact_bytes.send_reliable(StreamId(1), b"one").unwrap();
        assert_eq!(
            exact_bytes.send_reliable_batch(StreamId(1), &[shared_payload(b"12345")]),
            Ok(())
        );
    }

    #[test]
    fn reliable_batch_preflight_keeps_queue_unchanged_on_byte_failure() {
        let mut adapter = TcpAdapter::with_queue_limits(3, 8).unwrap();
        adapter.send_reliable(StreamId(1), b"one").unwrap();
        let records = [shared_payload(b"two"), shared_payload(b"three")];
        assert_eq!(
            adapter.send_reliable_batch(StreamId(1), &records),
            Err(BatchFailure::Rejected(Error::OutboundQueueFull))
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
    fn path_stats_are_unavailable_without_a_native_path() {
        let adapter = TcpAdapter::default();
        assert_eq!(adapter.path_stats(), None);
    }

    #[test]
    fn a_peer_using_more_lanes_than_advertised_is_refused() {
        let mut adapter = TcpAdapter::default();
        let record = |lane: u64| NativeEvent::Reliable {
            stream: lane,
            sequence: lane,
            bytes: vec![0; 8],
        };
        assert_eq!(adapter.receive_limits(), None);
        for lane in 0..4 {
            adapter.record_native_event(record(lane)).unwrap();
        }

        let mut bounded = TcpAdapter::default();
        bounded.set_receive_limits(
            vot_transport_api::ReceiveLimits::advertised(
                &vot_codec::Settings {
                    reliable_lane_limit: 2,
                    ..vot_codec::Settings::default()
                },
                INBOUND_BYTE_CAPACITY,
            )
            .unwrap(),
        );
        bounded.record_native_event(record(1)).unwrap();
        bounded.record_native_event(record(2)).unwrap();
        bounded.record_native_event(record(1)).unwrap();
        assert_eq!(
            bounded.record_native_event(record(3)),
            Err(Error::LaneLimitExceeded),
            "one lane past what was advertised"
        );
    }

    #[test]
    fn the_two_control_bounds_move_independently() {
        assert_eq!(INBOUND_BYTE_CAPACITY, DEFAULT_COMMAND_BYTE_LIMIT);
        let too_large = vot_transport_api::ReceiveLimits::advertised(
            &vot_codec::Settings {
                max_control_frame_payload: (INBOUND_BYTE_CAPACITY
                    - vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
                    + 1) as u64,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        );
        assert_eq!(too_large, Err(Error::InvalidConfiguration));

        let envelope = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let mut adapter = TcpAdapter::default();
        assert_eq!(
            adapter.set_control_payload_limit(0),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            adapter.receive_limits(),
            None,
            "nothing is advertised until it is configured"
        );

        adapter.set_control_payload_limit(2 * 1024 * 1024).unwrap();
        assert_eq!(
            adapter.receive_limits(),
            None,
            "a peer's limit is not this endpoint's"
        );
        adapter
            .send_control(&vec![0; 2 * 1024 * 1024 + envelope])
            .unwrap();
        assert_eq!(
            adapter.send_control(&vec![0; 2 * 1024 * 1024 + envelope + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            adapter
                .record_native_event(NativeEvent::Control(vec![0; CONTROL_LIMIT + envelope + 1])),
            Err(Error::RecordTooLarge),
            "still only what this endpoint advertised"
        );

        let wide = vot_transport_api::ReceiveLimits::advertised(
            &vot_codec::Settings {
                max_control_frame_payload: 2 * 1024 * 1024,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        )
        .unwrap();
        adapter.set_receive_limits(wide);
        assert_eq!(adapter.receive_limits(), Some(wide));
        assert_eq!(
            adapter.record_native_event(NativeEvent::Control(vec![0; 2 * 1024 * 1024 + envelope])),
            Ok(())
        );

        let mut generous = TcpAdapter::default();
        generous
            .set_control_payload_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD)
            .unwrap();
        let largest = INBOUND_BYTE_CAPACITY - envelope;
        generous.send_control(&vec![0; largest + envelope]).unwrap();
        assert_eq!(
            generous.send_control(&vec![0; largest + envelope + 1]),
            Err(Error::RecordTooLarge),
            "refused at submission, not queued for ever"
        );

        let mut narrow = TcpAdapter::default();
        let narrow_limits = vot_transport_api::ReceiveLimits::advertised(
            &vot_codec::Settings {
                max_control_frame_payload: 64 * 1024,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        )
        .unwrap();
        narrow.set_receive_limits(narrow_limits);
        assert_eq!(
            narrow.receive_limits().unwrap().control_payload(),
            64 * 1024
        );
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
    fn tcp_datagrams_are_explicitly_unsupported() {
        let mut adapter = TcpAdapter::default();
        assert_eq!(
            adapter.send_datagram(7, b"datagram"),
            Err(Error::Unsupported)
        );
        assert_eq!(adapter.next_command(), None);
    }

    #[test]
    fn adapter_limits_events_and_credit_are_exact() {
        assert_eq!(DEFAULT_COMMAND_COUNT_LIMIT, 64);
        assert_eq!(DEFAULT_COMMAND_BYTE_LIMIT, 4_194_304);
        assert_eq!(CONTROL_LIMIT, 1_048_576);
        assert!(matches!(
            TcpAdapter::with_queue_limits(0, 1),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            TcpAdapter::with_queue_limits(1, 0),
            Err(Error::InvalidConfiguration)
        ));

        let mut exact = TcpAdapter::with_queue_limits(3, 7).unwrap();
        exact.send_control(b"abc").unwrap();
        exact.send_reliable(StreamId(2), b"defg").unwrap();
        exact.set_receive_credit(99).unwrap();
        assert_eq!(exact.next_command().unwrap().payload_len(), 3);
        assert_eq!(exact.next_command().unwrap().payload_len(), 4);
        assert_eq!(exact.next_command(), Some(Command::ReceiveCredit(99)));
        assert_eq!(Command::ReceiveCredit(1).payload_len(), 0);

        let mut bytes_over = TcpAdapter::with_queue_limits(2, 6).unwrap();
        bytes_over.send_control(b"abc").unwrap();
        assert_eq!(
            bytes_over.send_reliable(StreamId(2), b"defg"),
            Err(Error::OutboundQueueFull)
        );

        let mut control = TcpAdapter::default();
        control
            .send_control(&vec![
                0;
                CONTROL_LIMIT
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ])
            .unwrap();
        assert_eq!(
            control.send_control(&vec![
                0;
                CONTROL_LIMIT
                    + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
                    + 1
            ]),
            Err(Error::RecordTooLarge)
        );

        let events = [
            NativeEvent::Connected(1),
            NativeEvent::Control(b"control".to_vec()),
            NativeEvent::Reliable {
                stream: 2,
                sequence: 3,
                bytes: b"data".to_vec(),
            },
            NativeEvent::Acknowledged {
                stream: 2,
                sequence: 3,
            },
            NativeEvent::Disconnected(1),
        ];
        for event in events {
            control.record_native_event(event).unwrap();
        }
        assert_eq!(control.poll(), Some(Event::Connected(ConnectionId(1))));
        assert_eq!(
            control.poll(),
            Some(Event::Control(b"control".to_vec().into()))
        );
        assert!(matches!(control.poll(), Some(Event::Reliable { .. })));
        assert!(matches!(control.poll(), Some(Event::Acknowledged(_))));
        assert_eq!(control.poll(), Some(Event::Disconnected(ConnectionId(1))));
        assert_eq!(control.poll(), None);
    }

    #[test]
    fn inbound_events_apply_record_count_and_byte_backpressure() {
        let mut adapter = TcpAdapter::with_queue_limits(2, 5).unwrap();
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
            adapter.record_native_event(NativeEvent::Acknowledged {
                stream: 1,
                sequence: 2,
            }),
            Err(Error::InboundQueueFull)
        );
        assert!(matches!(adapter.poll(), Some(Event::Control(_))));
        adapter
            .record_native_event(NativeEvent::Control(b"678".to_vec()))
            .unwrap();
        assert!(matches!(adapter.poll(), Some(Event::Reliable { .. })));
        assert!(matches!(adapter.poll(), Some(Event::Control(_))));
        assert_eq!(adapter.poll(), None);

        let mut bytes = TcpAdapter::with_queue_limits(3, 5).unwrap();
        bytes
            .record_native_event(NativeEvent::Control(b"123".to_vec()))
            .unwrap();
        assert_eq!(
            bytes.record_native_event(NativeEvent::Control(b"456".to_vec())),
            Err(Error::InboundQueueFull)
        );

        let mut oversized = TcpAdapter::default();
        oversized
            .record_native_event(NativeEvent::Control(vec![
                0;
                CONTROL_LIMIT + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
            ]))
            .unwrap();
        assert!(matches!(oversized.poll(), Some(Event::Control(_))));
        assert_eq!(
            oversized.record_native_event(NativeEvent::Control(vec![
                0;
                CONTROL_LIMIT + vot_transport_api::MAX_FRAME_ENVELOPE_BYTES
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

    #[test]
    fn tls_plaintext_is_blocked_before_authentication() {
        let roots = rustls::RootCertStore::empty();
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![vot_transport_api::ALPN.to_vec()];
        let name = ServerName::try_from("vot.invalid").unwrap().to_owned();
        let mut carrier = TlsClientCarrier::new(Arc::new(config), name).unwrap();
        assert!(!carrier.is_authenticated());
        assert!(matches!(
            carrier.queue_vot_bytes(b"frame"),
            Err(TlsError::NotAuthenticated)
        ));
        assert!(matches!(
            carrier.read_vot_bytes(&mut [0; 1]),
            Err(TlsError::NotAuthenticated)
        ));
        assert!(carrier.write_tls(&mut Vec::new()).unwrap() > 0);
    }

    #[test]
    fn authenticated_tls_carries_identical_vot_bytes() {
        let (certificate, key) = test_identity();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![vot_transport_api::ALPN.to_vec()];
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        server_config.alpn_protocols = vec![vot_transport_api::ALPN.to_vec()];

        let name = ServerName::try_from("vot.test").unwrap().to_owned();
        let mut client = TlsClientCarrier::new(Arc::new(client_config), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..8 {
            transfer_client_to_server(&mut client, &mut server);
            transfer_server_to_client(&mut server, &mut client);
            if client.is_authenticated() && !server.is_handshaking() {
                break;
            }
        }
        assert!(client.is_authenticated());
        assert_eq!(server.alpn_protocol(), Some(vot_transport_api::ALPN));

        let frame = b"\x01\x03VOT";
        client.queue_vot_bytes(frame).unwrap();
        transfer_client_to_server(&mut client, &mut server);
        let mut received = [0; 5];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, frame);

        server.writer().write_all(b"reply").unwrap();
        transfer_server_to_client(&mut server, &mut client);
        let mut reply = [0; 5];
        assert_eq!(client.read_vot_bytes(&mut reply).unwrap(), 5);
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn completed_tls_without_vot_alpn_exposes_no_plaintext() {
        let (certificate, key) = test_identity();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![vot_transport_api::ALPN.to_vec()];
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();

        let name = ServerName::try_from("vot.test").unwrap().to_owned();
        let mut client = TlsClientCarrier::new(Arc::new(client_config), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..8 {
            transfer_client_to_server(&mut client, &mut server);
            transfer_server_to_client(&mut server, &mut client);
            if !client.connection.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.connection.is_handshaking());
        assert_eq!(client.connection.alpn_protocol(), None);
        assert!(!client.is_authenticated());
        assert!(matches!(
            client.queue_vot_bytes(b"frame"),
            Err(TlsError::NotAuthenticated)
        ));
        assert!(matches!(
            client.read_vot_bytes(&mut [0; 1]),
            Err(TlsError::NotAuthenticated)
        ));
    }

    #[test]
    fn quic_cannot_fallback_before_tcp_is_ready_or_after_tcp_selected() {
        let (mut quic, _) = CarrierRace::start(0, 10, 1).unwrap();
        quic.ready(Carrier::Quic).unwrap();
        assert_eq!(quic.observe_quic(0, false), None);
        assert_eq!(quic.selected(), Some(Carrier::Quic));

        let (mut tcp, _) = CarrierRace::start(0, 10, 1).unwrap();
        tcp.poll(10).unwrap();
        tcp.ready(Carrier::TlsTcp).unwrap();
        assert_eq!(tcp.observe_quic(0, false), None);
        assert_eq!(tcp.selected(), Some(Carrier::TlsTcp));
    }
}
