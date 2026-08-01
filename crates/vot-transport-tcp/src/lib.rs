//! Authenticated TLS/TCP carrier, bounded adapter, and deterministic carrier race.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use vot_transport_api::{ConnectionId, Error, Event, StreamId, TransportAck, TransportAdapter};

const DEFAULT_COMMAND_COUNT_LIMIT: usize = 64;
const DEFAULT_COMMAND_BYTE_LIMIT: usize = 4 * 1024 * 1024;
const CONTROL_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Control(Vec<u8>),
    Reliable { stream: StreamId, bytes: Vec<u8> },
    ReceiveCredit(u64),
}

impl Command {
    fn payload_len(&self) -> usize {
        match self {
            Self::Control(bytes) | Self::Reliable { bytes, .. } => bytes.len(),
            Self::ReceiveCredit(_) => 0,
        }
    }

    #[must_use]
    pub fn vot_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Control(bytes) | Self::Reliable { bytes, .. } => Some(bytes),
            Self::ReceiveCredit(_) => None,
        }
    }
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
}

/// Bounded TLS/TCP command and event adapter. VOT frame bytes are not rewritten.
pub struct TcpAdapter {
    commands: VecDeque<Command>,
    command_bytes: usize,
    command_count_limit: usize,
    command_byte_limit: usize,
    events: VecDeque<Event>,
}

impl Default for TcpAdapter {
    fn default() -> Self {
        Self {
            commands: VecDeque::new(),
            command_bytes: 0,
            command_count_limit: DEFAULT_COMMAND_COUNT_LIMIT,
            command_byte_limit: DEFAULT_COMMAND_BYTE_LIMIT,
            events: VecDeque::new(),
        }
    }
}

impl TcpAdapter {
    pub fn with_queue_limits(command_count: usize, command_bytes: usize) -> Result<Self, Error> {
        if command_count == 0 || command_bytes == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            command_count_limit: command_count,
            command_byte_limit: command_bytes,
            ..Self::default()
        })
    }

    pub fn record_native_event(&mut self, event: NativeEvent) {
        self.events.push_back(match event {
            NativeEvent::Connected(id) => Event::Connected(ConnectionId(id)),
            NativeEvent::Disconnected(id) => Event::Disconnected(ConnectionId(id)),
            NativeEvent::Control(bytes) => Event::Control(bytes),
            NativeEvent::Reliable {
                stream,
                sequence,
                bytes,
            } => Event::Reliable {
                stream: StreamId(stream),
                sequence,
                bytes,
            },
            NativeEvent::Acknowledged { stream, sequence } => {
                Event::Acknowledged(TransportAck::new(stream, sequence))
            }
        });
    }

    pub fn next_command(&mut self) -> Option<Command> {
        let command = self.commands.pop_front()?;
        self.command_bytes = self.command_bytes.saturating_sub(command.payload_len());
        Some(command)
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

impl TransportAdapter for TcpAdapter {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
        if frame.len() > CONTROL_LIMIT {
            return Err(Error::RecordTooLarge);
        }
        self.enqueue(Command::Control(frame.to_vec()))
    }

    fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        vot_transport_api::validate_data_record(record)?;
        self.enqueue(Command::Reliable {
            stream,
            bytes: record.to_vec(),
        })
    }

    fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
        self.enqueue(Command::ReceiveCredit(bytes))
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
        // A rustls client leaves the handshake only after certificate and
        // server-name validation succeeds under its ClientConfig.
        !self.connection.is_handshaking()
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
    use base64::Engine as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection};

    const TEST_CERT: &str = "MIIDQDCCAiigAwIBAgIUH2kAu8b2ouPR9XDkVFin4mBS82MwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIdm90LnRlc3QwHhcNMjYwODAxMDU1MjEyWhcNMzYwNzI5MDU1MjEyWjATMREwDwYDVQQDDAh2b3QudGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMG3NR4mquNRAy3vWYufkClhwqU6fL+esfVrBuMXUXLv4uomQR0ddtqN/6ciwTGLattqm6V0LfmLfPPFxB/cbgGCPJyyDe5TT81r+Af/eRQiWZohJZdkncCDZ2jhn8qAX81S1lilsBvHbgS+3ZSXkq3zP+HXA5A1QCXXbRpPG4dBO0TySb+dZusgIwUtJ+TciuNTFt3ndA5qkKspIMeHnmgx1p+fmgnZft8ZHRHBRqZ4wVxBJa3ZY9Rjkids1mku/bP2NDOmH0oSJQSXionkBXrBK9Fyr2/T9DitwOr+2t02JlNT1oLQ21r9OikCWXu/9o8VhEkYwAo2c5uwQhj5B+ECAwEAAaOBizCBiDAdBgNVHQ4EFgQUajW5JZNFtIhizFsXII9bCXfIvIIwHwYDVR0jBBgwFoAUajW5JZNFtIhizFsXII9bCXfIvIIwEwYDVR0RBAwwCoIIdm90LnRlc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAIRUsJDe9Pa8wIa/DShr9Wz4/HRrJFll37xVsdNi7IdwchWPQifN0vL3UowvcGGTr1RpL2UKyyQ+KMgouq3glV4nL65tXx5LSxklIsMiHQ2fJGJTk/JUFOouiVn7s764ICwRFSTPTxzrtqrv6+4DAUnA4zYxvs+dtc4CO7eQCeX2Zd4RT1j9mjH2Hi3oZ6h/fHZjLfoegTI5PeHjT24LVX0l9dW3q9fsf39zGVC8l2jyM+vYyYNGix15fAxgKHnW1AugjgaV9oeF66F5FQLWcO3BZFOWwOv3rOVst1lFvBkHJCHMnngl3XEZe3G2dWKUcwsNA45O4PwIa7M38PggUJ4=";
    const TEST_KEY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBtzUeJqrjUQMt71mLn5ApYcKlOny/nrH1awbjF1Fy7+LqJkEdHXbajf+nIsExi2rbapuldC35i3zzxcQf3G4Bgjycsg3uU0/Na/gH/3kUIlmaISWXZJ3Ag2do4Z/KgF/NUtZYpbAbx24Evt2Ul5Kt8z/h1wOQNUAl120aTxuHQTtE8km/nWbrICMFLSfk3IrjUxbd53QOapCrKSDHh55oMdafn5oJ2X7fGR0RwUameMFcQSWt2WPUY5InbNZpLv2z9jQzph9KEiUEl4qJ5AV6wSvRcq9v0/Q4rcDq/trdNiZTU9aC0Nta/TopAll7v/aPFYRJGMAKNnObsEIY+QfhAgMBAAECggEAHUaja/WbEPSu3tPT/CJ2xpJEOPVgYhNJQNZWeZ6ODClN6WYzpANOcZRRRUCe4u53jUaM1FH9GsAmd671R31oUKkOoP3V1iVYI6sEFq1Y7p6MXRtSU5F8t9oEGFk07YU+NUkmJMqRlXkr2uK/mRPZMpnXFzoIC1TI548pqXa4KdYCGTIiAg4c/lL0/KSRgPxiy54rXp8LqoapsO5Dsit3dMIs+0/O0N7BtWgcZ+wGbPRJoaRgJq7HaMglnbL+F1Q+8uXrahvNEzXV1r12mB1eed+KIdqsZ5n6CrRJI/gXPt3mWGEKX2ac3os0rvlXzRV4vUBv7+0Rk3R6794dcQxiowKBgQDlC5F9iKiJPjuRPhYJC/IhMhu/aTXyjnpHQIyvdzInuTxCSkjntcRVkaHdW+BbQXwtJiabyM4+97q3desvw9TIvJnB3z0Ss+g5PC1m0WdSE+Bf5layCq7KdxfGnZkrkNuwfVKokOYnX4ZLejqRumnoeY36GIu+wYscd/dxI4+mXwKBgQDYg0SrzEHz7l06NL585w6Gy7J57ZF8tAzeJk/eO+xuhd9RsAcZE/RsndC8R0ghPzS6nx6C8L20WV5+3RGIZZRa59s+PBU5HtF8HBKw6DA7BuHvBWncEkiEk8oqoRvwLMcWzYeg0qEsvBLBzte7zY39/RmBQ1quYShgk9tqy3d5vwKBgDDa7daj/qb/kj8hyht149i20npam7o4L9bg6uFGgHk+pp7RL4nVGKLT5H3N6iYs6qrKt3OFOpDt0HLvgRH4KHwE1psm3eUOYNtMfbavteUo/jQWcqmZY70l9/lShmhnhqS3ppj0B1OgqYmR8cpBw/NlciZFdBFlQSH6aNpGJo7rAoGBAIfql9BVUE3GJAYnGDGmhsr90pOSHFOxX6aRXHABJCIZriBEpaALk9QfmeqnwNMGL567xtaiNCSkOZrgQmJiiigrBsnhw9zwyMblhKJDkAtt/aUju9moLJf1guMR8kzqfyyEZ5EAyKchhZDevTUrC+kW2sz3sFRpr4Q5LXO0ONNXAoGAbqfqMdmCSv566ZePQmTq4T9JkZE3XHX+oP79A0bq8PcJebGbHcWqdPjgQNvG0xBLLk3zqPF2sYRlBuwoA59ARBKvLhsDG7nNoXQefnfl8IzkQLz2AfVAvDj5Bo8bHjepTs4wZZGwhTjdWQSu9oPMTuxFzu5GnGsrWcgCXXp+Gxk=";

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
                &vec![0; vot_transport_api::MAX_DATA_RECORD_BYTES + 1]
            ),
            Err(Error::RecordTooLarge)
        );
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
        control.send_control(&vec![0; CONTROL_LIMIT]).unwrap();
        assert_eq!(
            control.send_control(&vec![0; CONTROL_LIMIT + 1]),
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
            control.record_native_event(event);
        }
        assert_eq!(control.poll(), Some(Event::Connected(ConnectionId(1))));
        assert_eq!(control.poll(), Some(Event::Control(b"control".to_vec())));
        assert!(matches!(control.poll(), Some(Event::Reliable { .. })));
        assert!(matches!(control.poll(), Some(Event::Acknowledged(_))));
        assert_eq!(control.poll(), Some(Event::Disconnected(ConnectionId(1))));
        assert_eq!(control.poll(), None);
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
        let certificate = CertificateDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_CERT)
                .unwrap(),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_KEY)
                .unwrap(),
        ));
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
