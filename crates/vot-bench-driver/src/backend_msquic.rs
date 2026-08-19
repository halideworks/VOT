//! `MsQuic` backend as a benchmark carrier.
//!
//! A connected loopback pair: client submits, accepted connection receives.
//! Handshake completes in the constructor. Transfer loop and reported numbers
//! are in `lib.rs`. No `MsQuic` type appears directly (ADR-0012).

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use vot_transport_api::{Event, Payload, ReceiveLimits, StreamId, TransportAdapter};
use vot_transport_msquic::INBOUND_BYTE_CAPACITY;
use vot_transport_msquic::live::{
    AcceptedTransport, Config as MsQuicConfig, MsQuicServer, MsQuicTransport,
};

use crate::{Carrier, Config, Error};

/// Handshake timeout for the loopback pair.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Lanes the endpoints advertise. Workload uses up to 8 workers (one per lane).
const ADVERTISED_LANES: u64 = 16;

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
        let limits = advertised_limits()?;
        let (certificate, key) = credentials()?;
        let loopback: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|_| Error::Value("VOT_BENCH_BACKEND"))?;

        let mut server =
            MsQuicServer::bind(loopback, &MsQuicConfig::server(limits, certificate, key))
                .map_err(Error::Transport)?;
        let mut client_config = MsQuicConfig::client(limits);
        // Self-signed credential: benchmark measures the carrier, not the PKI.
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

/// Handshake timeout for two-machine runs. Longer than loopback because a
/// human starts each half.
const ROLE_HANDSHAKE_TIMEOUT: Duration = Duration::from_mins(1);

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
    let mut server = MsQuicServer::bind(
        address,
        &MsQuicConfig::server(advertised_limits()?, certificate, key),
    )
    .map_err(Error::Transport)?;
    let deadline = Instant::now() + ROLE_HANDSHAKE_TIMEOUT;
    let accepted = loop {
        if let Some(accepted) = server.accept() {
            break accepted;
        }
        if Instant::now() >= deadline {
            return Err(Error::Handshake);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    Ok(crate::role::Endpoint {
        adapter: Box::new(accepted),
        keepalive: Some(Box::new(server)),
        backend: "msquic",
        detail: None,
        unmodelled: unmodelled_for(config),
    })
}

/// Dial interval for two-machine connects. `MsQuic` reports a refused first
/// flight as dead rather than retrying, so dials repeat until the deadline.
const ROLE_DIAL_RETRY: Duration = Duration::from_secs(2);

/// Connects to the receiving half at `peer`, redialing while the deadline
/// allows.
///
/// # Errors
/// Reports a socket or configuration failure, and a handshake that did not
/// complete inside [`ROLE_HANDSHAKE_TIMEOUT`].
pub(crate) fn role_connect(
    config: &Config,
    peer: SocketAddr,
) -> Result<crate::role::Endpoint, Error> {
    let mut client_config = MsQuicConfig::client(advertised_limits()?);
    client_config.verify_peer = false;
    let deadline = Instant::now() + ROLE_HANDSHAKE_TIMEOUT;
    loop {
        let mut client =
            MsQuicTransport::dial(peer, CONNECTION_ID, &client_config).map_err(Error::Transport)?;
        let attempt = (Instant::now() + ROLE_DIAL_RETRY).min(deadline);
        let mut refused = false;
        while !refused && Instant::now() < attempt {
            while let Some(event) = client.poll() {
                match event {
                    Event::Connected(_) => {
                        return Ok(crate::role::Endpoint {
                            adapter: Box::new(client),
                            keepalive: None,
                            backend: "msquic",
                            detail: None,
                            unmodelled: unmodelled_for(config),
                        });
                    }
                    Event::Disconnected(_) => refused = true,
                    _ => {}
                }
            }
            if !refused {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::Handshake);
        }
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
        if client_up && let Some(accepted) = server.accept() {
            return Ok(accepted);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Error::Handshake)
}

/// Impairment fields this carrier describes but does not shape. Loopback has
/// its own characteristics; only the receive window (from the case's BDP) has
/// effect.
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

/// Generates a self-signed credential once per process via `openssl`.
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

    fn flush(&mut self) -> Result<(), vot_transport_api::Error> {
        self.client.flush()?;
        self.accepted.flush()
    }

    fn poll_received(&mut self) -> Option<Event> {
        self.accepted.poll()
    }

    fn drain_sent(&mut self) {
        while self.client.poll().is_some() {}
    }

    fn wait(&mut self, bound: Duration) {
        self.accepted.wait_for_event(bound);
    }
}

#[cfg(test)]
mod tests {
    use super::MsQuicCarrier;
    use crate::{Config, ImpairmentCase, Rails, measure};
    use vot_verifier::Suite;

    fn case(object_bytes: u64) -> Config {
        Config {
            backend: "msquic".to_owned(),
            suite: Suite::Blake3Bao64,
            workers: 1,
            seed: 42,
            object_bytes,
            record_bytes: 65_536,
            rails: Rails::Shared,
            sink: crate::SinkChoice::Discard,
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
        let object_bytes = 40 * 65_536;
        let measured = measure(&case(object_bytes)).unwrap();
        assert_eq!(measured.verified_bytes, object_bytes);
        assert_eq!(measured.bytes_sent, object_bytes);
        assert_eq!(note_field(&measured.notes, "backend"), "msquic");
    }

    #[test]
    fn a_ranged_case_crosses_a_real_socket_and_verifies() {
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
        let wire: u64 = note_field(&measured.notes, "wire_bytes").parse().unwrap();
        assert!(wire > object_bytes, "wire was {wire}");
    }

    #[test]
    fn the_carrier_bounds_its_credit_at_construction() {
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
        for _ in 0..3 {
            let carrier = MsQuicCarrier::connected(&case(65_536)).unwrap();
            drop(carrier);
        }
    }
}
