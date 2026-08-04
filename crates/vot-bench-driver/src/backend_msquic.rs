//! The `MsQuic` backend as a benchmark carrier.
//!
//! A connected loopback pair: the client submits, the accepted connection
//! receives, and `MsQuic` owns the sockets and the worker threads behind both.
//! The handshake completes here, in the constructor, so no part of it lands
//! inside the timed section.
//!
//! The same division as the quiche carrier. Nothing in this file decides what a
//! run means; it opens the endpoints and forwards submissions and events, while
//! the transfer loop, the framing, and every reported number stay in `lib.rs`
//! where the mutation gate measures them. That is why this file is named in
//! `.cargo/mutants.toml`: it compiles only under the `msquic` feature, which
//! the mutation matrix does not enable, so a mutant here would be reported
//! missed whatever the tests say.
//!
//! No `MsQuic` type appears below, which ADR-0012 requires of everything
//! outside `vot-transport-msquic`. The pair is built from that crate's `Config`
//! and its two boundary constructors.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use vot_transport_api::{Event, Payload, ReceiveLimits, StreamId, TransportAdapter};
use vot_transport_msquic::INBOUND_BYTE_CAPACITY;
use vot_transport_msquic::live::{
    AcceptedTransport, Config as MsQuicConfig, MsQuicServer, MsQuicTransport,
};

use crate::{Carrier, Config, Error};

/// How long the pair is given to connect and be accepted.
///
/// Loopback needs milliseconds. Long enough that a loaded machine is not
/// mistaken for a broken one, and short enough that a run which will never
/// connect fails rather than hanging in CI.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Lanes the endpoints advertise. The transfer uses one; the rest are room for
/// the multi-rail work in the same backlog item.
const ADVERTISED_LANES: u64 = 4;

/// The connection identifier the client reports its connection under. Arbitrary
/// and never compared against anything, because one pair carries one transfer.
const CONNECTION_ID: u64 = 1;

/// A connected pair of `MsQuic` endpoints over loopback.
pub(crate) struct MsQuicCarrier {
    client: MsQuicTransport,
    accepted: AcceptedTransport,
    /// Held so the listener outlives the connection it produced.
    _server: MsQuicServer,
    unmodelled: Vec<&'static str>,
}

impl MsQuicCarrier {
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
            MsQuicServer::bind(loopback, &MsQuicConfig::server(limits, certificate, key))
                .map_err(Error::Transport)?;
        let mut client_config = MsQuicConfig::client(limits);
        // The credential is generated for this run and trusted by
        // construction. What is measured is the carrier, not the web PKI.
        client_config.verify_peer = false;
        let mut client = MsQuicTransport::dial(
            server.local_address().map_err(Error::Transport)?,
            CONNECTION_ID,
            &client_config,
        )
        .map_err(Error::Transport)?;

        let accepted = handshake(&mut client, &mut server)?;
        Ok(Self {
            client,
            accepted,
            _server: server,
            unmodelled: unmodelled_for(config),
        })
    }
}

/// Waits for the client to connect and the listener to hand over the
/// connection it produced.
///
/// # Errors
/// Reports [`Error::Handshake`] for a pair that did not connect inside
/// [`HANDSHAKE_TIMEOUT`].
fn handshake(
    client: &mut MsQuicTransport,
    server: &mut MsQuicServer,
) -> Result<AcceptedTransport, Error> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut client_up = false;
    while Instant::now() < deadline {
        while let Some(event) = client.poll() {
            client_up |= matches!(event, Event::Connected(_));
        }
        if client_up {
            if let Some(accepted) = server.accept() {
                return Ok(accepted);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Error::Handshake)
}

/// Impairment fields this carrier describes but does not shape.
///
/// The same account the quiche carrier gives, and for the same reason: loopback
/// is not the path the file describes and nothing here shapes it to match. The
/// receive window still comes from the case's bandwidth-delay product, which is
/// the one effect an impairment field has.
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
/// The same approach both live test suites take: `openssl` into a temporary
/// directory, so nothing is added as a dependency for something that never
/// leaves this host.
///
/// # Errors
/// Reports a failure to create the directory or to run `openssl`.
fn credentials() -> Result<(String, String), Error> {
    static MATERIAL: OnceLock<Option<(String, String)>> = OnceLock::new();
    MATERIAL
        .get_or_init(|| {
            let directory =
                std::env::temp_dir().join(format!("vot-bench-msquic-{}", std::process::id()));
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
        .ok_or(Error::Unmeasurable("msquic_credentials"))
}

impl Carrier for MsQuicCarrier {
    fn name(&self) -> &'static str {
        "msquic"
    }

    fn unmodelled(&self) -> &[&'static str] {
        &self.unmodelled
    }

    // The accepted connection is the endpoint that receives the object, so its
    // inbound bound is the one the case's credit applies to.
    fn receiving(&mut self) -> &mut dyn TransportAdapter {
        &mut self.accepted
    }

    fn submit(
        &mut self,
        stream: StreamId,
        frame: &Payload,
    ) -> Result<(), vot_transport_api::Error> {
        self.client
            .send_reliable_shared(stream, Payload::clone(frame))
    }

    // Both ends, as on quiche: the client has records to hand over, and the
    // receiver has the acknowledgements that let the client send more.
    fn flush(&mut self) -> Result<(), vot_transport_api::Error> {
        self.client.flush()?;
        self.accepted.flush()
    }

    fn poll_received(&mut self) -> Option<Event> {
        self.accepted.poll()
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
    use super::MsQuicCarrier;
    use crate::{Config, ImpairmentCase, measure};
    use vot_verifier::Suite;

    fn case(object_bytes: u64) -> Config {
        Config {
            backend: "msquic".to_owned(),
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
        // Past one batch and past one datagram many times over, so records are
        // reassembled from packets rather than arriving whole.
        let object_bytes = 40 * 65_536;
        let measured = measure(&case(object_bytes)).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
        assert_eq!(measured.bytes_sent, object_bytes);
        assert_eq!(note_field(&measured.notes, "backend"), "msquic");
    }

    #[test]
    fn a_short_final_record_arrives_too() {
        let object_bytes = 3 * 65_536 + 17;
        let measured = measure(&case(object_bytes)).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
        // The envelope is on the wire and the object is not.
        let wire: u64 = note_field(&measured.notes, "wire_bytes").parse().unwrap();
        assert!(wire > object_bytes, "wire was {wire}");
    }

    #[test]
    fn the_carrier_bounds_its_credit_at_construction() {
        // The assembled MsQuic transport reports Unsupported for a per-call
        // credit, as the quiche one does, so the report has to say which bound
        // was in force rather than implying the receiver's was applied.
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
    fn a_pair_can_be_built_more_than_once_in_a_process() {
        // The measurement work builds one per case, and MsQuic keeps a
        // registration and worker threads behind each.
        for _ in 0..3 {
            let carrier = MsQuicCarrier::connected(&case(65_536)).unwrap();
            drop(carrier);
        }
    }
}
