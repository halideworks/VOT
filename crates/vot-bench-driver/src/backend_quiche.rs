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

/// The datagram size the pair is configured with, when the case names one.
///
/// Not a `VOT_BENCH_*` variable, because it is not part of the benchmark
/// contract: it describes the path the run was taken on rather than the
/// workload. Named here so a comparison can hold packet size fixed across
/// backends, which it must, since one datagram is one syscall and one packet's
/// worth of crypto and the default is sized for a path whose MTU is unknown.
const DATAGRAM_BYTES: &str = "VOT_BENCH_QUICHE_DATAGRAM_BYTES";

/// Lanes the endpoints advertise.
///
/// The sequential transfer uses one, the ranged path uses one per worker
/// starting at lane 1, and the workload defines worker counts up to 8, so the
/// endpoint advertises room for that rather than being configured more
/// tightly than the cases it carries.
const ADVERTISED_LANES: u64 = 16;

/// A connected pair of quiche endpoints over loopback.
pub(crate) struct QuicheCarrier {
    client: Transport,
    server: Transport,
    unmodelled: Vec<&'static str>,
    /// What the pair was configured with, so a result says which path it
    /// describes rather than leaving a reader to assume the default.
    datagram_bytes: usize,
}

impl QuicheCarrier {
    /// Connects a loopback pair and waits for both ends to report it.
    ///
    /// # Errors
    /// Reports a socket, credential, or configuration failure, and a pair that
    /// did not connect inside [`HANDSHAKE_TIMEOUT`].
    pub(crate) fn connected(config: &Config) -> Result<Self, Error> {
        let limits = advertised_limits()?;
        let (certificate, key) = credentials()?;
        let loopback: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|_| Error::Value("VOT_BENCH_BACKEND"))?;

        let datagram_bytes = datagram_bytes_from_env()?;

        let mut server_config = QuicheConfig::server(limits, certificate, key);
        let mut client_config = QuicheConfig::client(limits);
        if let Some(bytes) = datagram_bytes {
            server_config.max_datagram_bytes = bytes;
            client_config.max_datagram_bytes = bytes;
        }
        let mut server = Transport::serve(loopback, &server_config).map_err(Error::Transport)?;
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
            // What was configured, rather than what was asked for, so an
            // unset case reports the default it actually ran at.
            datagram_bytes: client_config.max_datagram_bytes,
        })
    }
}

/// The limits both loopback endpoints and either role endpoint advertise.
fn advertised_limits() -> Result<ReceiveLimits, Error> {
    ReceiveLimits::advertised(
        &vot_codec::Settings {
            reliable_lane_limit: ADVERTISED_LANES,
            ..vot_codec::Settings::default()
        },
        INBOUND_BYTE_CAPACITY,
    )
    .map_err(Error::Transport)
}

/// Reads the datagram size the case names, when it names one.
fn datagram_bytes_from_env() -> Result<Option<usize>, Error> {
    std::env::var(DATAGRAM_BYTES)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| Error::Value(DATAGRAM_BYTES))
}

/// How long a role endpoint waits for its peer, against loopback's
/// [`HANDSHAKE_TIMEOUT`]: the two halves of a two-machine run are started by
/// hand on two machines, and a human is slower than a scheduler.
const ROLE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Listens on `address` and waits for the sending half to connect.
///
/// # Errors
/// Reports a socket, credential, or configuration failure, and a peer that did
/// not connect inside [`ROLE_HANDSHAKE_TIMEOUT`].
pub(crate) fn role_listen(
    config: &Config,
    address: SocketAddr,
) -> Result<crate::role::Endpoint, Error> {
    let (certificate, key) = credentials()?;
    let mut server_config = QuicheConfig::server(advertised_limits()?, certificate, key);
    if let Some(bytes) = datagram_bytes_from_env()? {
        server_config.max_datagram_bytes = bytes;
    }
    let mut server = Transport::serve(address, &server_config).map_err(Error::Transport)?;
    connected_within(&mut server, ROLE_HANDSHAKE_TIMEOUT)?;
    Ok(crate::role::Endpoint {
        adapter: Box::new(server),
        keepalive: None,
        backend: "quiche",
        detail: Some(format!(
            "datagram_bytes={}",
            server_config.max_datagram_bytes
        )),
        unmodelled: unmodelled_for(config),
    })
}

/// Connects to the receiving half at `peer`.
///
/// # Errors
/// Reports a socket or configuration failure, and a handshake that did not
/// complete inside [`ROLE_HANDSHAKE_TIMEOUT`].
pub(crate) fn role_connect(
    config: &Config,
    peer: SocketAddr,
) -> Result<crate::role::Endpoint, Error> {
    let mut client_config = QuicheConfig::client(advertised_limits()?);
    if let Some(bytes) = datagram_bytes_from_env()? {
        client_config.max_datagram_bytes = bytes;
    }
    // The receiving half's credential is generated for its run and trusted by
    // construction, exactly as the loopback pair trusts its own.
    client_config.verify_peer = false;
    let local: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .map_err(|_| Error::Value(crate::role::CONNECT))?;
    let mut client = Transport::connect(local, peer, Some("localhost"), &client_config)
        .map_err(Error::Transport)?;
    connected_within(&mut client, ROLE_HANDSHAKE_TIMEOUT)?;
    Ok(crate::role::Endpoint {
        adapter: Box::new(client),
        keepalive: None,
        backend: "quiche",
        detail: Some(format!(
            "datagram_bytes={}",
            client_config.max_datagram_bytes
        )),
        unmodelled: unmodelled_for(config),
    })
}

/// Waits for one endpoint to report its connection, where the peer is another
/// process pumping its own half.
///
/// # Errors
/// Reports [`Error::Handshake`] for an endpoint that did not connect in time.
fn connected_within(endpoint: &mut Transport, timeout: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        endpoint.flush().map_err(Error::Transport)?;
        while let Some(event) = endpoint.poll() {
            if matches!(event, Event::Connected(_)) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Error::Handshake)
}

/// Waits for both endpoints to report the connection.
///
/// # Errors
/// Reports [`Error::Handshake`] for a pair that did not connect inside
/// [`HANDSHAKE_TIMEOUT`].
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
    Err(Error::Handshake)
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

    fn detail(&self) -> Option<String> {
        Some(format!("datagram_bytes={}", self.datagram_bytes))
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

    // The receiving endpoint, because that is whose events an idle delivery
    // was short of. The pump's signal ends the wait as soon as one lands.
    fn wait(&mut self, bound: Duration) {
        self.server.wait_for_event(bound);
    }
}

#[cfg(test)]
mod tests {
    use super::QuicheCarrier;
    use crate::{Config, ImpairmentCase, Rails, measure};
    use vot_verifier::Suite;

    fn case(object_bytes: u64) -> Config {
        Config {
            backend: "quiche".to_owned(),
            suite: Suite::Blake3Bao64,
            workers: 1,
            seed: 42,
            object_bytes,
            record_bytes: 65_536,
            rails: Rails::Shared,
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
    fn a_ranged_case_crosses_a_real_socket_and_verifies() {
        // The multi-worker path over a real socket in both arrangements:
        // disjoint proof-bearing ranges on one lane per worker of a shared
        // connection, or on a connection per worker, a ragged tail included.
        for workers in [2_usize, 4] {
            for rails in [Rails::Shared, Rails::Provisioned] {
                let mut config = case(6 * 65_536 + 17);
                config.workers = workers;
                config.rails = rails;
                let measured = measure(&config).unwrap();
                assert_eq!(measured.verified_bytes, config.object_bytes);
                assert_eq!(note_field(&measured.notes, "path"), "ranged");
                assert_eq!(
                    measured.notes.contains(";rails=provisioned-multi-rail"),
                    rails == Rails::Provisioned
                );
            }
        }
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
