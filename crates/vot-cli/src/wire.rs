//! The commands' carrier: a QUIC endpoint under the two engines.
//!
//! ADR-0030 keeps the engines transport-agnostic and puts the
//! socket-owning backend behind a feature, so this module is the whole of
//! what `wire` adds: credentials, an endpoint at each end, and the two
//! calls the commands make.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use vot_transport_api::ReceiveLimits;
use vot_transport_quiche::live::{Config, CongestionControl, Listener, Transport};

use crate::{BundleFetcher, BundleServer, Credentials, Error, PackageSummary, ServeSession};

/// How a wire session authenticates, which is not at all.
///
/// ADR-0030: the channel is unauthenticated and the help text says so.
/// The nonce is the server's freshness for the handshake, not a secret.
fn authentication() -> vot_session::Authentication {
    vot_session::Authentication::NotRequired { nonce: [0; 32] }
}

/// What a session may hold inbound, matched to what the codec settings the
/// engines use will let a peer send.
fn limits() -> Result<ReceiveLimits, Error> {
    ReceiveLimits::advertised(
        &vot_codec::Settings::default(),
        vot_transport_quiche::INBOUND_BYTE_CAPACITY,
    )
    .map_err(|_| Error::InvalidArguments)
}

/// The environment variable that pins the datagram ceiling.
const DATAGRAM_BYTES: &str = "VOT_DATAGRAM_BYTES";

/// Opens the datagram ceiling to discovery, then applies
/// [`DATAGRAM_BYTES`] over it if set.
///
/// The carrier's own default ceiling is what a 1500-byte ethernet frame
/// carries, and path discovery only settles below a ceiling, never above
/// it, so no amount of discovery finds a jumbo path under that default.
/// The commands trust discovery instead: the ceiling opens to the most a
/// UDP payload can be, `discover_pmtu` probes with don't-fragment set and
/// fails closed, and the connection settles at what the path really
/// carries with nothing to configure. It matters on the serving process
/// most: packets are made where the bytes are served, and a fetch-side
/// ceiling alone moves nothing (docs/perf-engineering.md, 2026-08-06).
///
/// The variable remains as a pin for a path whose discovery misbehaves.
///
/// # Errors
/// Rejects a value that is not a number. The carrier rejects one outside
/// what it can carry.
fn apply_datagram_bytes(config: &mut Config) -> Result<(), Error> {
    config.max_datagram_bytes = vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE;
    let Ok(value) = std::env::var(DATAGRAM_BYTES) else {
        return Ok(());
    };
    apply_datagram_value(config, &value)
}

/// The parse half of the pin, apart from the environment that feeds it.
///
/// Validated against the carrier's own bounds here, where the refusal can
/// name the argument: left to the carrier it surfaces as an unavailable
/// endpoint, which reads as a network problem rather than a typo.
fn apply_datagram_value(config: &mut Config, value: &str) -> Result<(), Error> {
    let bytes: usize = value.trim().parse().map_err(|_| Error::InvalidArguments)?;
    let bounds = vot_transport_quiche::live::MIN_DATAGRAM_SIZE
        ..=vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE;
    if !bounds.contains(&bytes) {
        return Err(Error::InvalidArguments);
    }
    config.max_datagram_bytes = bytes;
    Ok(())
}

/// The environment variable that picks the congestion controller.
const CONGESTION: &str = "VOT_CONGESTION";

/// The environment variable that sets how many rails a fetch runs.
const FETCH_RAILS: &str = "VOT_FETCH_RAILS";

/// Rails a fetch may run at most.
///
/// The serve side drives this many sessions at once and backpressures the
/// rest by not accepting them, and a rail waiting at the accept is a rail
/// holding spans nobody answers, which stalls the whole fetch. So the cap
/// is the serve bound, stated once over both.
const MAX_FETCH_RAILS: usize = crate::drive::CONCURRENT_SESSIONS;

/// The width [`FETCH_RAILS`] names, or the machine's own when it is unset.
///
/// ADR-0031: default `min(4, available cores)`, 1 restoring the one-rail
/// shape exactly, bounded by [`MAX_FETCH_RAILS`].
///
/// # Errors
/// Rejects a value that is not a number, zero, or a width past the bound.
fn rails_from(pin: Option<&str>, cores: usize) -> Result<usize, Error> {
    let Some(value) = pin else {
        return Ok(4.min(cores.max(1)));
    };
    let rails: usize = value.trim().parse().map_err(|_| Error::InvalidArguments)?;
    if !(1..=MAX_FETCH_RAILS).contains(&rails) {
        return Err(Error::InvalidArguments);
    }
    Ok(rails)
}

/// The controller [`CONGESTION`] names, or bbr2 when it is unset.
///
/// Measured at width 4 with 4 GiB transfers: bbr2 is 13% faster than
/// cubic on the 10 gigabit LAN rig (5.1 s vs 5.8 s median), 33% faster at
/// 68 ms over the real WAN (50.3 s vs 75.5 s), 3-5x faster under
/// 0.5-1% emulated loss, and ties cubic on clean short paths. A
/// transfer is governed by the sender's controller, so the pin matters
/// most on the end serving the bytes, but both commands read it:
/// either end of a session sends. `cubic` remains the pin for a path
/// where bbr2 misbehaves.
///
/// # Errors
/// Rejects a value naming neither controller.
fn congestion_from(pin: Option<&str>) -> Result<CongestionControl, Error> {
    match pin.map(str::trim) {
        None | Some("bbr2") => Ok(CongestionControl::Bbr2),
        Some("cubic") => Ok(CongestionControl::Cubic),
        Some(_) => Err(Error::InvalidArguments),
    }
}

/// How many placed bytes between progress lines: 256 MiB is a line every
/// couple of seconds at a gigabit and one every few minutes on a slow
/// link, either of which reads as movement.
const PROGRESS_QUANTUM_BYTES: u64 = 268_435_456;

/// What a carrier's failure means to the command that asked for it.
///
/// A configuration the carrier refuses is an argument problem and says
/// so; everything else is the endpoint itself.
fn carrier_failure(error: vot_transport_api::Error) -> Error {
    match error {
        vot_transport_api::Error::InvalidConfiguration => Error::InvalidArguments,
        _ => Error::CarrierUnavailable,
    }
}

/// Tells one set of credentials from another in the same process.
///
/// Two servers in one process would otherwise write the same two paths:
/// the second fails to create them, and whichever is dropped first takes
/// the other's away.
static EPHEMERAL: AtomicU64 = AtomicU64::new(0);

/// Where an ephemeral certificate and key are written.
///
/// quiche loads both from files, so they cannot stay in memory. The
/// directory is this process's own and goes when the server does.
struct Ephemeral {
    directory: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        // Nothing to do about a failure here, and nothing to report it to:
        // the key was worth nothing to begin with.
        let _ = std::fs::remove_file(&self.certificate);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

impl Ephemeral {
    /// Generates a self-signed certificate for this process.
    ///
    /// ECDSA P-256, because `BoringSSL` as quiche configures it refuses an
    /// Ed25519 leaf, and because RSA would spend up to a second of every
    /// `serve` on key generation for a certificate nobody checks.
    fn generate() -> Result<Self, Error> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| Error::Randomness)?;
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .map_err(|_| Error::InvalidArguments)?;
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let certificate = parameters
            .self_signed(&key)
            .map_err(|_| Error::InvalidArguments)?;

        let directory = std::env::temp_dir().join(format!(
            "vot-serve-{}-{}",
            std::process::id(),
            EPHEMERAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory)?;
        let written = Self {
            certificate: directory.join("cert.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        crate::write_new_synced(&written.certificate, certificate.pem().as_bytes())?;
        crate::write_new_synced(&written.key, key.serialize_pem().as_bytes())?;
        Ok(written)
    }
}

/// The address this host would send from to reach `peer`, port unset.
///
/// quiche is told the address its socket is bound to and validates the
/// path against it, so a wildcard bind names a local address no packet
/// ever arrives at and the handshake never completes. Asking the routing
/// table costs one unconnected socket and puts nothing on the wire.
fn local_for(peer: SocketAddr) -> Result<SocketAddr, Error> {
    let wildcard = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let probe = std::net::UdpSocket::bind(wildcard)?;
    probe.connect(peer)?;
    let mut local = probe.local_addr()?;
    local.set_port(0);
    Ok(local)
}

/// Serves `bundle` on `address` until stopped or `sessions` are answered.
///
/// Each accepted carrier is driven to a settled state and then dropped;
/// the bundle is opened and proved once, ahead of any of them. One socket
/// carries every session (ADR-0031): the listener routes arrivals to
/// per-session pumps by connection ID, so a fetch's rails reach one fixed
/// address as concurrent sessions, and `listening` reports the bound
/// address once.
///
/// # Errors
/// Surfaces a bundle that will not open, a socket that will not bind, and
/// any failure of this end while a session is live.
pub fn serve_bundle(
    bundle: &Path,
    address: SocketAddr,
    credentials: &Credentials,
    sessions: Option<u32>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<PackageSummary, Error> {
    let server = BundleServer::open(bundle)?;
    let ephemeral = match credentials {
        Credentials::Ephemeral => Some(Ephemeral::generate()?),
        Credentials::Files { .. } => None,
    };
    let (certificate, key) = match (credentials, &ephemeral) {
        (Credentials::Files { certificate, key }, _) => (certificate.clone(), key.clone()),
        (Credentials::Ephemeral, Some(written)) => {
            (written.certificate.clone(), written.key.clone())
        }
        (Credentials::Ephemeral, None) => return Err(Error::InvalidArguments),
    };
    let mut config = Config::server(
        limits()?,
        certificate.to_str().ok_or(Error::InvalidPath)?.to_owned(),
        key.to_str().ok_or(Error::InvalidPath)?.to_owned(),
    );
    // A server told to answer every session it gets waits for each of them
    // for as long as it takes, and the default bound would read as a
    // carrier that died during the handshake. One told to answer a fixed
    // number means to stop, so it keeps a bound and stops if nobody comes.
    if sessions.is_none() {
        config.accept_timeout_ms = 0;
    }
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;

    // One socket for every session, and the address reported once: a
    // caller that asked for port zero cannot connect until it knows what
    // it got. A bounded count is what lets a test serve its sessions and
    // return; without one the command serves until it is stopped. The
    // loop and its failure policy live in `drive`, under the gate this
    // file is not.
    let listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    listening(listener.local_address());
    crate::drive::serve_sessions(sessions, || {
        // The accept parks this thread until a client's first packet
        // names a connection, so a session never spends its stall budget
        // waiting for one to exist.
        let carrier = listener.accept().map_err(carrier_failure)?;
        ServeSession::begin(&server, carrier, authentication())
    })?;
    Ok(server.package())
}

/// Runs the rendezvous service of ADR-0033 on `address` until stopped,
/// or until `datagrams` arrivals when bounded (which is what lets a test
/// serve an exchange and return).
///
/// One socket, the bounded pairing table, and nothing sent anywhere but
/// to an observed source or a registered mapping. Malformed arrivals
/// are shed; socket-level failures that are not timeouts end the
/// service, which is the endpoint itself failing.
///
/// # Errors
/// Surfaces a socket that will not bind, and the endpoint's own failure.
pub fn rendezvous_service(
    address: SocketAddr,
    datagrams: Option<u64>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    let socket = std::net::UdpSocket::bind(address).map_err(|_| Error::CarrierUnavailable)?;
    listening(socket.local_addr().map_err(|_| Error::CarrierUnavailable)?);
    let began = std::time::Instant::now();
    let mut pairings = crate::rendezvous::Pairings::default();
    let mut buffer = [0_u8; 128];
    // The bound is an iterator's, as the serve's is: a bounded service
    // takes exactly as many arrivals as the range yields.
    let mut turns: Box<dyn Iterator<Item = ()>> = match datagrams {
        Some(bound) => Box::new(std::iter::repeat_n((), usize::try_from(bound).unwrap_or(0))),
        None => Box::new(std::iter::repeat(())),
    };
    while turns.next().is_some() {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(arrival) => arrival,
            Err(error) => {
                if waited_out(&error) {
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) else {
            continue;
        };
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        let answer = pairings.take(datagram, source, now_ms);
        if let Some(reply) = answer.reply {
            let _ = socket.send_to(&crate::rendezvous::encode(&reply), source);
        }
        if let Some((mapping, notice)) = answer.notify {
            let _ = socket.send_to(&crate::rendezvous::encode(&notice), mapping);
        }
    }
    Ok(())
}

/// Whether a socket read failed only for want of a datagram, which is
/// the service waiting; anything else is the socket itself failing.
fn waited_out(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Fetches a bundle from `address` into `bundle`.
///
/// # Errors
/// Surfaces a destination that exists, a connection that will not open,
/// and any refusal the fetch made of what the server answered.
pub fn fetch_bundle(
    address: SocketAddr,
    bundle: &Path,
    pin: Option<[u8; 32]>,
) -> Result<PackageSummary, Error> {
    let rails = rails_from(
        std::env::var(FETCH_RAILS).ok().as_deref(),
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    )?;
    fetch_railed(address, bundle, pin, rails)
}

/// The fetch at an explicit width, apart from the environment that picks
/// one.
fn fetch_railed(
    address: SocketAddr,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error> {
    let mut config = Config::client(limits()?);
    // ADR-0030: the channel is unauthenticated and says so. A forged
    // server can only serve bytes that fail the proofs the fetch checks.
    config.verify_peer = false;
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;
    let connect = || {
        Transport::connect(local_for(address)?, address, Some("localhost"), &config)
            .map_err(carrier_failure)
    };
    let mut fetcher = BundleFetcher::begin(connect()?, bundle, pin)?;
    if let Ok(value) = std::env::var("VOT_FETCH_PROVERS") {
        fetcher.set_proving_threads(value.trim().parse().map_err(|_| Error::InvalidArguments)?)?;
    }
    // A wire transfer can run for minutes with nothing to look at, and a
    // line per placed quantum is what tells a slow path from a stall. On
    // stderr, so stdout stays the one summary line a script reads. A
    // fetch smaller than the quantum stays as quiet as today. The placed
    // count is the shared sink's, so one report covers every rail.
    fetcher.report_placed(
        PROGRESS_QUANTUM_BYTES,
        Box::new(|placed, total| match total {
            Some(total) => eprintln!("{} / {} MiB", placed >> 20, total.div_ceil(1 << 20)),
            None => eprintln!("{} MiB", placed >> 20),
        }),
    )?;
    crate::drive::fetch_striped(fetcher, rails, connect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn a_carrier_refusing_its_configuration_names_the_argument() {
        // The one refusal a user can fix in a command must not read as a
        // network problem, and everything else must: the map is the whole
        // difference between "fix the value" and "check the host".
        assert!(matches!(
            carrier_failure(vot_transport_api::Error::InvalidConfiguration),
            Error::InvalidArguments
        ));
        assert!(matches!(
            carrier_failure(vot_transport_api::Error::Backend),
            Error::CarrierUnavailable
        ));
    }

    #[test]
    fn the_datagram_ceiling_is_the_value_given_or_the_default() {
        // The parse half, apart from the process environment: a test that
        // set the real variable would race the socket test in this module.
        let mut config = Config::client(limits().unwrap());
        let unset = config.max_datagram_bytes;
        apply_datagram_value(&mut config, " 8972\n").unwrap();
        assert_eq!(config.max_datagram_bytes, 8972, "given, trimmed, taken");
        let mut config = Config::client(limits().unwrap());
        assert!(
            apply_datagram_value(&mut config, "jumbo").is_err(),
            "a value that is not a number is refused"
        );
        assert_eq!(
            config.max_datagram_bytes, unset,
            "a refused value changes nothing"
        );
        // Numeric and still wrong: outside what the carrier can carry is
        // refused here, where the error names the argument, not later as
        // an unavailable endpoint.
        assert!(apply_datagram_value(&mut config, "0").is_err());
        assert!(apply_datagram_value(&mut config, "70000").is_err());
        assert_eq!(config.max_datagram_bytes, unset);
        // And with nothing set, the ceiling opens all the way for
        // discovery to settle under, which is the seamless default.
        assert!(
            std::env::var(DATAGRAM_BYTES).is_err(),
            "the suite owns no env"
        );
        let mut config = Config::client(limits().unwrap());
        apply_datagram_bytes(&mut config).unwrap();
        assert_eq!(
            config.max_datagram_bytes,
            vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE
        );
    }

    #[test]
    fn the_service_pairs_a_register_with_a_resolve_across_real_sockets() {
        // The whole exchange over loopback: a serve-side socket
        // registers, a fetch-side socket resolves, the fetch learns the
        // serve's observed mapping, and the serve hears the fetch is
        // coming at its own observed mapping. Six datagrams bound the
        // service: register, resolve, and four strays it must shed
        // without answering.
        use crate::rendezvous::{Datagram, decode, encode};

        let (addressed, address) = mpsc::channel();
        let service = std::thread::spawn(move || {
            rendezvous_service("127.0.0.1:0".parse().unwrap(), Some(6), |at| {
                let _ = addressed.send(at);
            })
        });
        let at = address.recv().expect("the service reported its address");
        let key = [5; 32];

        let serve = UdpSocket::bind("127.0.0.1:0").expect("a serve socket");
        serve
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        serve
            .send_to(&encode(&Datagram::Register { key }), at)
            .expect("a register");
        let mut buffer = [0_u8; 128];
        let (length, _) = serve.recv_from(&mut buffer).expect("an acknowledgement");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Registered { key })
        );

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("a fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        // Strays first: garbage, another protocol's lead byte, and a
        // truncated request are shed without a reply, so the resolve
        // after them is answered first.
        fetch.send_to(&[], at).expect("an empty stray");
        fetch
            .send_to(&[0xC0, 1, 2, 3], at)
            .expect("a QUIC-shaped stray");
        fetch
            .send_to(&[0x1F, 1, 3, 9], at)
            .expect("a truncated stray");
        fetch
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a service-shaped stray");
        fetch
            .send_to(&encode(&Datagram::Resolve { key }), at)
            .expect("a resolve");
        let (length, _) = fetch.recv_from(&mut buffer).expect("an answer");
        let Some(Datagram::Resolved {
            serve: Some(mapping),
            ..
        }) = decode(&buffer[..length])
        else {
            panic!("the resolve was not answered with the serve's mapping");
        };
        assert_eq!(
            mapping.port(),
            serve.local_addr().expect("the socket").port(),
            "the mapping is the register's observed source"
        );

        // And the serve hears the fetch is coming, at the fetch's own
        // observed mapping.
        let (length, _) = serve.recv_from(&mut buffer).expect("the notification");
        let Some(Datagram::Coming { fetch: coming, .. }) = decode(&buffer[..length]) else {
            panic!("the serve was not told the fetch is coming");
        };
        assert_eq!(
            coming.port(),
            fetch.local_addr().expect("the socket").port()
        );
        service
            .join()
            .expect("the service thread")
            .expect("the service served its bound");
    }

    #[test]
    fn only_a_read_without_a_datagram_is_waited_out() {
        // The service rides out a read that found nothing and ends on
        // anything else; this table is the whole of that decision.
        use std::io::ErrorKind;
        assert!(waited_out(&std::io::Error::from(ErrorKind::WouldBlock)));
        assert!(waited_out(&std::io::Error::from(ErrorKind::TimedOut)));
        assert!(!waited_out(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(!waited_out(&std::io::Error::from(ErrorKind::Other)));
    }

    #[test]
    fn the_width_is_the_value_given_or_the_machines_own() {
        // The pin apart from the process environment, like the datagram
        // test above and for the same race. ADR-0031: default
        // min(4, available cores), 1 restoring today's shape, bounded by
        // what the serve drives at once.
        assert_eq!(rails_from(None, 1).unwrap(), 1);
        assert_eq!(rails_from(None, 3).unwrap(), 3);
        assert_eq!(rails_from(None, 4).unwrap(), 4);
        assert_eq!(rails_from(None, 64).unwrap(), 4, "the default caps at 4");
        assert_eq!(rails_from(None, 0).unwrap(), 1, "no cores is still one");
        assert_eq!(
            rails_from(Some(" 2\n"), 1).unwrap(),
            2,
            "given, trimmed, taken"
        );
        assert_eq!(
            rails_from(Some("8"), 1).unwrap(),
            MAX_FETCH_RAILS,
            "the bound itself is allowed"
        );
        // Zero rails is no fetch, and past the serve bound the excess
        // rails would hold spans nobody answers; both are refused where
        // the error names the argument.
        assert!(rails_from(Some("0"), 4).is_err());
        assert!(rails_from(Some("9"), 4).is_err());
        assert!(rails_from(Some("wide"), 4).is_err());
        assert!(std::env::var(FETCH_RAILS).is_err(), "the suite owns no env");
    }

    #[test]
    fn a_fetch_at_width_two_crosses_one_serve_socket() {
        // ADR-0031 on the wire: two whole sessions from one fetch, one
        // serve socket, the listener routing both. The serve is bounded at
        // exactly two sessions, so a fetch that quietly stayed at width
        // one would strand the bound and fail. Striping distribution is
        // the sim test's subject; the rig's W sweep is step 4.
        let source = crate::tests::temporary("railwire-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("big.bin"), crate::harness::patterned(2_000_000)).unwrap();
        let bundle = crate::tests::temporary("railwire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving_bundle = bundle.clone();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &serving_bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(2),
                |at| {
                    let _ = listening.send(at);
                },
            )
        });

        let at = address.recv().expect("the server reported its address");
        let fetched = crate::tests::temporary("railwire-fetched");
        let package = fetch_railed(at, &fetched, Some(built.root), 2).expect("a striped fetch");
        assert_eq!(package, built);
        let served = serving.join().expect("the serving thread").expect("served");
        assert_eq!(served, built);
        // The striped bytes are the built bytes, object for object.
        let objects = |root: &Path| -> Vec<(std::ffi::OsString, Vec<u8>)> {
            let mut all: Vec<_> = std::fs::read_dir(root.join("objects"))
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect();
            all.sort();
            all
        };
        assert_eq!(objects(&bundle), objects(&fetched));
        crate::harness::discard(&[&source, &bundle, &fetched]);
    }

    #[test]
    fn the_congestion_controller_is_the_value_given_or_bbr2() {
        // The pin apart from the process environment, like the datagram
        // test above and for the same race.
        assert_eq!(congestion_from(None).unwrap(), CongestionControl::Bbr2);
        assert_eq!(
            congestion_from(Some("cubic")).unwrap(),
            CongestionControl::Cubic
        );
        assert_eq!(
            congestion_from(Some(" bbr2\n")).unwrap(),
            CongestionControl::Bbr2,
            "given, trimmed, taken"
        );
        // A controller neither end has is refused here, where the error
        // names the argument, not as an unavailable endpoint.
        assert!(congestion_from(Some("reno")).is_err());
        assert!(std::env::var(CONGESTION).is_err(), "the suite owns no env");
    }

    #[test]
    fn an_ephemeral_certificate_goes_when_the_server_does() {
        // The key is worth nothing, but leaving it and its directory behind
        // on every serve is a temp directory that only grows.
        let (certificate, key, directory) = {
            let written = Ephemeral::generate().expect("credentials");
            assert!(written.certificate.is_file());
            assert!(written.key.is_file());
            (
                written.certificate.clone(),
                written.key.clone(),
                written.directory.clone(),
            )
        };
        assert!(!certificate.exists(), "the certificate was left behind");
        assert!(!key.exists(), "the key was left behind");
        assert!(!directory.exists(), "the directory was left behind");
    }

    /// The ADR's step-4 test: everything the CLI builds crosses a real
    /// socket and publishes unchanged, both engines driven by the one loop.
    #[test]
    fn a_bundle_crosses_a_quic_socket_and_publishes() {
        let source = crate::tests::temporary("wire-source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.txt"), vec![7_u8; 1000]).unwrap();
        std::fs::write(source.join("nested/b.bin"), vec![9_u8; 300_000]).unwrap();
        let bundle = crate::tests::temporary("wire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(1),
                |at| {
                    let _ = listening.send(at);
                },
            )
        });

        let at = address.recv().expect("the server reported its address");
        let fetched = crate::tests::temporary("wire-fetched");
        let package = fetch_bundle(at, &fetched, Some(built.root)).expect("a fetched bundle");
        assert_eq!(package, built);
        let served = serving.join().expect("the serving thread").expect("served");
        assert_eq!(served, built);

        // And the existing receive publishes what crossed the wire.
        let destination = crate::tests::temporary("wire-destination");
        let receipt = crate::tests::temporary("wire-receipt.cbor");
        let report = crate::receive_bundle(
            &fetched,
            &destination,
            &receipt,
            &crate::KeyMaterial::Shared(vec![7; 32]),
            "2026-08-06T00:00:00Z",
        )
        .unwrap();
        assert_eq!(report.package, built);
        assert_eq!(
            std::fs::read(destination.join("a.txt")).unwrap(),
            vec![7_u8; 1000]
        );
    }
}
