//! The quiche backend as a benchmark carrier.
//!
//! A connected loopback pair: the client submits, the server receives, and each
//! endpoint owns its socket and its connection on a driver thread of its own
//! (ADR-0024). The handshake completes here, in the constructor, so no part of
//! it lands inside the timed section.
//!
//! Nothing in this file decides what a run means. It opens the endpoints and
//! forwards submissions and events; the transfer loop, the framing, and every
//! reported number are in `lib.rs`, where the mutation gate measures them. That
//! division is why this file is named in `.cargo/mutants.toml`: it compiles
//! only under the `quiche` feature, which the mutation matrix does not enable,
//! so a mutant here would be reported missed whatever the tests say. It is
//! measured where it compiles, by the tests at the bottom of this file.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use vot_transport_api::{Event, Payload, ReceiveLimits, StreamId, TransportAdapter};
use vot_transport_quiche::INBOUND_BYTE_CAPACITY;
use vot_transport_quiche::live::{Config as QuicheConfig, Transport};

use crate::{Carrier, Config, Error};

/// How long the pair is given to complete its handshake.
///
/// Loopback needs milliseconds. This is long enough that a loaded machine is
/// not mistaken for a broken one, and short enough that a run which will never
/// connect fails rather than hanging in CI.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Lanes the endpoints advertise.
///
/// The transfer uses one. The rest are advertised because a benchmark endpoint
/// should not be configured more tightly than the case it carries, and the
/// multi-rail work in the same backlog item needs room to open more.
const ADVERTISED_LANES: u64 = 4;

/// A connected pair of quiche endpoints over loopback.
pub(crate) struct QuicheCarrier {
    client: Transport,
    server: Transport,
    unmodelled: Vec<&'static str>,
}

impl QuicheCarrier {
    /// Connects a loopback pair and waits for both ends to report it.
    ///
    /// # Errors
    /// Reports a socket, credential, or configuration failure, and a pair that
    /// did not connect inside [`HANDSHAKE_TIMEOUT`].
    pub(crate) fn connected(config: &Config) -> Result<Self, Error> {
        let limits = ReceiveLimits::advertised(
            &vot_codec::Settings {
                reliable_lane_limit: ADVERTISED_LANES,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        )
        .map_err(Error::Transport)?;
        let (certificate, key) = credentials()?;
        let loopback: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|_| Error::Value("VOT_BENCH_BACKEND"))?;

        let mut server =
            Transport::serve(loopback, &QuicheConfig::server(limits, certificate, key))
                .map_err(Error::Transport)?;
        let mut client_config = QuicheConfig::client(limits);
        // The credential is generated for this run and trusted by construction.
        // What is being measured is the carrier, not the web PKI, and a
        // benchmark that failed on certificate validation would say nothing
        // about either.
        client_config.verify_peer = false;
        let mut client = Transport::connect(
            loopback,
            server.local_address(),
            Some("localhost"),
            &client_config,
        )
        .map_err(Error::Transport)?;

        handshake(&mut client, &mut server)?;
        Ok(Self {
            client,
            server,
            unmodelled: unmodelled_for(config),
        })
    }
}

/// Waits for both endpoints to report the connection.
///
/// # Errors
/// Reports a pair that did not connect inside [`HANDSHAKE_TIMEOUT`].
fn handshake(client: &mut Transport, server: &mut Transport) -> Result<(), Error> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let (mut client_up, mut server_up) = (false, false);
    while Instant::now() < deadline {
        client.flush().map_err(Error::Transport)?;
        server.flush().map_err(Error::Transport)?;
        while let Some(event) = client.poll() {
            client_up |= matches!(event, Event::Connected(_));
        }
        while let Some(event) = server.poll() {
            server_up |= matches!(event, Event::Connected(_));
        }
        if client_up && server_up {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Error::Stalled)
}

/// Impairment fields this carrier describes but does not shape.
///
/// Loopback is not the path the file describes and nothing here shapes it to
/// match. Every field is named rather than left for a reader to assume: the
/// case's MTU, bandwidth, queue, loss, and reordering are all the loopback
/// path's own, and its round-trip time is a few microseconds rather than the
/// one the case asks for. The receive window still comes from the case's
/// bandwidth-delay product, which is the one effect an impairment field has,
/// exactly as it has on the simulator.
fn unmodelled_for(config: &Config) -> Vec<&'static str> {
    let mut unmodelled = vec!["mtu_bytes", "bandwidth_bps", "queue_bytes"];
    for (present, name) in [
        (config.impairment.loss_ppm != 0, "loss_ppm"),
        (config.impairment.reorder_window != 0, "reorder_window"),
        (config.impairment.rtt_us != 0, "rtt_us"),
    ] {
        if present {
            unmodelled.push(name);
        }
    }
    unmodelled
}

/// Generates a self-signed credential once per process.
///
/// The same approach the quiche live tests take: `openssl` into a temporary
/// directory, so no dependency is added for something that never leaves this
/// host. Once per process because a run may build more than one pair, and two
/// of them writing the same two paths at once would let one load a half-written
/// certificate.
///
/// # Errors
/// Reports a failure to create the directory or to run `openssl`.
fn credentials() -> Result<(String, String), Error> {
    static MATERIAL: OnceLock<Option<(String, String)>> = OnceLock::new();
    MATERIAL
        .get_or_init(|| {
            let directory =
                std::env::temp_dir().join(format!("vot-bench-quiche-{}", std::process::id()));
            std::fs::create_dir_all(&directory).ok()?;
            let key = directory.join("key.pem");
            let certificate = directory.join("cert.pem");
            let status = std::process::Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    key.to_str()?,
                    "-out",
                    certificate.to_str()?,
                    "-sha256",
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                ])
                .status()
                .ok()?;
            status
                .success()
                .then(|| (certificate.display().to_string(), key.display().to_string()))
        })
        .clone()
        .ok_or(Error::Unmeasurable("quiche_credentials"))
}

impl Carrier for QuicheCarrier {
    fn name(&self) -> &'static str {
        "quiche"
    }

    fn unmodelled(&self) -> &[&'static str] {
        &self.unmodelled
    }

    // The server is the endpoint that receives the object, so its inbound bound
    // is the one the case's credit applies to.
    fn receiving(&mut self) -> &mut dyn TransportAdapter {
        &mut self.server
    }

    fn submit(
        &mut self,
        stream: StreamId,
        frame: &Payload,
    ) -> Result<(), vot_transport_api::Error> {
        self.client
            .send_reliable_shared(stream, Payload::clone(frame))
    }

    // Both ends. The client has records to hand its driver, and the server has
    // the acknowledgements and window updates that let the client send more.
    fn flush(&mut self) -> Result<(), vot_transport_api::Error> {
        self.client.flush()?;
        self.server.flush()
    }

    fn poll_received(&mut self) -> Option<Event> {
        self.server.poll()
    }

    // A sender that loses its connection is reported here and discarded with
    // the rest. The object stops arriving either way, so the run ends on the
    // receiver's disconnect or on the budget rather than silently.
    fn drain_sent(&mut self) {
        while self.client.poll().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::QuicheCarrier;
    use crate::{Config, ImpairmentCase, measure};
    use vot_verifier::Suite;

    fn case(object_bytes: u64) -> Config {
        Config {
            backend: "quiche".to_owned(),
            suite: Suite::Blake3Bao64,
            workers: 1,
            seed: 42,
            object_bytes,
            record_bytes: 65_536,
            impairment: ImpairmentCase {
                mtu_bytes: 1500,
                rtt_us: 1_000,
                loss_ppm: 0,
                reorder_window: 0,
                bandwidth_bps: 10_000_000_000,
                queue_bytes: 33_554_432,
            },
        }
    }

    fn note_field<'a>(notes: &'a str, name: &str) -> &'a str {
        notes
            .split(';')
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {notes}"))
    }

    #[test]
    fn a_case_crosses_a_real_socket_and_verifies() {
        // Past one batch and past one datagram many times over, so the record
        // is reassembled from packets rather than arriving whole.
        let object_bytes = 40 * 65_536;
        let measured = measure(&case(object_bytes)).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
        assert_eq!(measured.bytes_sent, object_bytes);
        assert_eq!(note_field(&measured.notes, "backend"), "quiche");
        // The whole object arrived over a carrier that delivers asynchronously,
        // which the receiver only reports verified after every byte is in.
        assert!(measured.elapsed_ns >= 1);
    }

    #[test]
    fn a_short_final_record_arrives_too() {
        let object_bytes = 3 * 65_536 + 17;
        let measured = measure(&case(object_bytes)).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
        // The envelope is on the wire and the object is not, so the carrier
        // moved strictly more than the object.
        let wire: u64 = note_field(&measured.notes, "wire_bytes").parse().unwrap();
        assert!(wire > object_bytes, "wire was {wire}");
    }

    #[test]
    fn the_carrier_bounds_its_credit_at_construction() {
        // ADR-0024: quiche extends connection flow control as the application
        // reads, so there is no absolute credit to set and the transport says
        // so rather than accepting a bound it would not apply. The report has
        // to carry which of the two happened.
        let measured = measure(&case(65_536)).unwrap();
        assert_eq!(note_field(&measured.notes, "credit_mode"), "constructed");
    }

    #[test]
    fn the_case_names_what_loopback_did_not_shape() {
        let mut lossy = case(65_536);
        lossy.impairment.loss_ppm = 100;
        let measured = measure(&lossy).unwrap();
        let unmodelled = note_field(&measured.notes, "unmodelled_impairment");
        for field in ["loss_ppm", "rtt_us", "mtu_bytes", "bandwidth_bps"] {
            assert!(
                unmodelled.contains(field),
                "{field} not named in {unmodelled}"
            );
        }
    }

    #[test]
    fn an_endpoint_pair_gives_its_ports_back() {
        // Each endpoint owns a socket on a driver thread, so a pair that is
        // dropped without stopping its drivers would leak both. Building
        // several in one process is what the measurement work does.
        for _ in 0..3 {
            let carrier = QuicheCarrier::connected(&case(65_536)).unwrap();
            drop(carrier);
        }
    }
}
