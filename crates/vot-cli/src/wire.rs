//! QUIC transport endpoint for the serve and fetch commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vot_transport_api::ReceiveLimits;
use vot_transport_quiche::live::{Config, CongestionControl, Listener, SideChannel, Transport};

use crate::{BundleFetcher, BundleServer, Credentials, Error, PackageSummary, ServeSession};

/// Returns unauthenticated session credentials. The nonce is handshake
/// freshness, not a secret.
fn authentication() -> vot_session::Authentication {
    vot_session::Authentication::NotRequired { nonce: [0; 32] }
}

/// Inbound receive limits matched to the codec's default settings.
fn limits() -> Result<ReceiveLimits, Error> {
    ReceiveLimits::advertised(
        &vot_codec::Settings::default(),
        vot_transport_quiche::INBOUND_BYTE_CAPACITY,
    )
    .map_err(|_| Error::InvalidArguments)
}

/// The environment variable that pins the datagram ceiling.
const DATAGRAM_BYTES: &str = "VOT_DATAGRAM_BYTES";

/// Opens the datagram ceiling to the maximum and lets PMTU discovery
/// settle it. [`DATAGRAM_BYTES`] overrides if set.
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

/// Parses and validates [`DATAGRAM_BYTES`] against the carrier's bounds.
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

/// Maximum fetch rails. Capped at the serve-side session limit because
/// excess rails stall waiting for accepts.
const MAX_FETCH_RAILS: usize = crate::drive::CONCURRENT_SESSIONS;

/// The width [`FETCH_RAILS`] names, or `min(4, available cores)` when unset.
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

/// The controller [`CONGESTION`] names, or bbr2 when unset.
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

/// Bytes between progress lines. 256 MiB: visible on both fast and slow links.
const PROGRESS_QUANTUM_BYTES: u64 = 268_435_456;

/// Maps carrier errors: configuration failures become argument errors,
/// everything else is the endpoint.
fn carrier_failure(error: vot_transport_api::Error) -> Error {
    match error {
        vot_transport_api::Error::InvalidConfiguration => Error::InvalidArguments,
        _ => Error::CarrierUnavailable,
    }
}

/// Counter for unique ephemeral credential paths within a process.
static EPHEMERAL: AtomicU64 = AtomicU64::new(0);

/// Temp files for an ephemeral certificate and key. quiche requires file paths.
struct Ephemeral {
    directory: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        // Best-effort cleanup; the key is ephemeral.
        let _ = std::fs::remove_file(&self.certificate);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

impl Ephemeral {
    /// Generates a self-signed ECDSA P-256 certificate. BoringSSL rejects
    /// Ed25519 leaves; RSA generation is too slow for an unchecked cert.
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

/// Finds the local source address for reaching `peer`. quiche rejects
/// wildcard binds, so a real address is needed before connect.
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
/// The bundle is opened and proved once upfront. All sessions share one
/// socket; `listening` reports the bound address once.
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
    // No session cap means serve indefinitely; disable the accept timeout
    // so the wait isn't mistaken for a dead carrier.
    if sessions.is_none() {
        config.accept_timeout_ms = 0;
    }
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;
    // Configure rendezvous routing before bind so the listener can
    // filter side-channel datagrams.
    let service = rendezvous_from(std::env::var(RENDEZVOUS).ok().as_deref())?;
    config.side_channel_lead = service.map(|_| crate::rendezvous::MAGIC);

    // The loop and its failure policy are in `drive`.
    let mut listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    listening(listener.local_address());
    let registration =
        start_registration(service, listener.take_side_channel(), server.package().root)?;
    let outcome = crate::drive::serve_sessions(sessions, || {
        // Accept blocks until a connection arrives.
        let carrier = listener.accept().map_err(carrier_failure)?;
        ServeSession::begin(&server, carrier, authentication())
    });
    // Drop before surfacing the error so the socket is released.
    drop(registration);
    outcome?;
    Ok(server.package())
}

/// Returns a registration only when both a service and side channel exist.
///
/// # Errors
/// Reports a registration thread that will not start.
fn start_registration(
    service: Option<SocketAddr>,
    side: Option<SideChannel>,
    root: [u8; 32],
) -> Result<Option<Registration>, Error> {
    match (service, side) {
        (Some(service), Some(side)) => Registration::begin(side, root, service).map(Some),
        _ => Ok(None),
    }
}

/// Registration thread for a serving process. Drop stops and joins it,
/// which releases the listener's socket.
struct Registration {
    stop: Arc<std::sync::atomic::AtomicBool>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Polls during drop to wait for the registration thread to stop. A
/// stuck thread is leaked rather than blocking the serve's return.
const STOP_TURNS: usize = 20;

impl Registration {
    /// Sends the first registration on the calling thread so an unreachable
    /// service fails immediately.
    ///
    /// # Errors
    /// Reports a service this socket cannot send to, and a thread that
    /// will not start.
    fn begin(side: SideChannel, root: [u8; 32], service: SocketAddr) -> Result<Self, Error> {
        let mut registrar = crate::rendezvous::Registrar::new(&root, service);
        post(&side, registrar.due(0))?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let ended = Arc::clone(&stopped);
        let thread = std::thread::Builder::new()
            .name("vot-rendezvous".to_owned())
            .spawn(move || {
                keep_registered(&side, &mut registrar, &flag);
                ended.store(true, Ordering::Relaxed);
            })
            .map_err(|_| Error::CarrierUnavailable)?;
        Ok(Self {
            stop,
            stopped,
            thread: Some(thread),
        })
    }

    /// Whether the registration thread has ended.
    #[cfg(test)]
    fn watch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.stopped)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return;
        };
        for _ in 0..STOP_TURNS {
            if self.stopped.load(Ordering::Relaxed) {
                let _ = thread.join();
                return;
            }
            std::thread::sleep(REGISTRAR_TICK);
        }
    }
}

/// Read timeout for the service loop. Also bounds idle wait time.
const SERVICE_TICK: Duration = Duration::from_millis(100);

/// Runs the rendezvous service on `address` until stopped, or `datagrams`
/// turns when bounded.
///
/// Malformed arrivals are shed; non-timeout socket errors end the service.
///
/// # Errors
/// Surfaces a socket that will not bind, and the endpoint's own failure.
pub fn rendezvous_service(
    address: SocketAddr,
    datagrams: Option<u64>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    let socket = std::net::UdpSocket::bind(address).map_err(|_| Error::CarrierUnavailable)?;
    socket
        .set_read_timeout(Some(SERVICE_TICK))
        .map_err(|_| Error::CarrierUnavailable)?;
    listening(socket.local_addr().map_err(|_| Error::CarrierUnavailable)?);
    let began = std::time::Instant::now();
    let mut pairings = crate::rendezvous::Pairings::default();
    let mut buffer = [0_u8; 128];
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

/// Rendezvous service address. Unset means no registration.
const RENDEZVOUS: &str = "VOT_RENDEZVOUS";

/// Parses [`RENDEZVOUS`] as an address. No DNS resolution.
///
/// # Errors
/// Rejects a value that is not an `ADDR:PORT`.
fn rendezvous_from(pin: Option<&str>) -> Result<Option<SocketAddr>, Error> {
    let Some(value) = pin else {
        return Ok(None);
    };
    value
        .trim()
        .parse()
        .map(Some)
        .map_err(|_| Error::InvalidArguments)
}

/// Side-channel read timeout for the registration thread.
const REGISTRAR_TICK: Duration = Duration::from_millis(200);

/// Sends registrar output on the listener's socket.
///
/// # Errors
/// Reports a send failure on the serve's own socket.
fn post(
    side: &SideChannel,
    sends: Vec<(SocketAddr, crate::rendezvous::Datagram)>,
) -> Result<(), Error> {
    for (to, datagram) in sends {
        side.send_to(&crate::rendezvous::encode(&datagram), to)
            .map_err(carrier_failure)?;
    }
    Ok(())
}

/// Runs the registration cadence until `stop`. Logs and exits on send
/// failure or router shutdown.
fn keep_registered(
    side: &SideChannel,
    registrar: &mut crate::rendezvous::Registrar,
    stop: &std::sync::atomic::AtomicBool,
) {
    let began = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Send pending registrations before blocking on the channel.
        if post(side, registrar.due(now_ms)).is_err() {
            eprintln!("rendezvous registration stopped: the socket would not send");
            return;
        }
        match side.next_within(REGISTRAR_TICK) {
            Ok(Some((bytes, from))) => {
                if let Some(datagram) = crate::rendezvous::decode(&bytes) {
                    registrar.take(datagram, from);
                }
            }
            Ok(None) => {}
            // Router closed; exit to avoid spinning.
            Err(_) => return,
        }
    }
}

/// Returns true for timeout/WouldBlock, false for real errors.
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

/// Fetches at an explicit rail width.
fn fetch_railed(
    address: SocketAddr,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error> {
    let mut config = Config::client(limits()?);
    // Channel is unauthenticated; proof verification catches forged servers.
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
    // Progress lines go to stderr so stdout stays clean for scripts.
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
        assert!(apply_datagram_value(&mut config, "0").is_err());
        assert!(apply_datagram_value(&mut config, "70000").is_err());
        assert_eq!(config.max_datagram_bytes, unset);
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
    fn a_registered_serve_is_resolved_and_warms_the_fetch_that_comes() {
        use crate::rendezvous::{Datagram, decode, encode, key_of};

        let (addressed, address) = mpsc::channel();
        let service_thread = std::thread::spawn(move || {
            rendezvous_service("127.0.0.1:0".parse().unwrap(), Some(120), |at| {
                let _ = addressed.send(at);
            })
        });
        let service = address.recv().expect("the service reported its address");

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let served = listener.local_address();
        let side = listener.take_side_channel().expect("a side channel");
        let root = [9; 32];
        let registration = Registration::begin(side, root, service).expect("a registration");

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("a fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        let mut buffer = [0_u8; 128];
        let mut mapping = None;
        for _ in 0..40 {
            fetch
                .send_to(&encode(&Datagram::Resolve { key: key_of(&root) }), service)
                .expect("a resolve");
            let Ok((length, _)) = fetch.recv_from(&mut buffer) else {
                continue;
            };
            if let Some(Datagram::Resolved {
                serve: Some(at), ..
            }) = decode(&buffer[..length])
            {
                mapping = Some(at);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mapping = mapping.expect("the serve registered and was resolved");
        assert_eq!(
            mapping.port(),
            served.port(),
            "the mapping is the socket sessions arrive at"
        );

        let mut warmed = false;
        for _ in 0..40 {
            let Ok((length, from)) = fetch.recv_from(&mut buffer) else {
                continue;
            };
            if decode(&buffer[..length]) == Some(Datagram::Warming) {
                assert_eq!(from.port(), served.port(), "the serve warmed the path");
                warmed = true;
                break;
            }
        }
        assert!(warmed, "the fetch's mapping was never warmed");
        drop(registration);
        drop(listener);
        let _ = service_thread.join().expect("the service thread");
    }

    #[test]
    fn a_registration_needs_both_a_service_and_a_socket_and_releases_it() {
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let service: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let root = [4; 32];

        assert!(
            start_registration(None, None, root)
                .expect("no service is no registration")
                .is_none()
        );
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        assert!(
            start_registration(None, Some(side), root)
                .expect("a socket without a service is no registration")
                .is_none()
        );

        let served = {
            let mut listener =
                Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
            let at = listener.local_address();
            let side = listener.take_side_channel().expect("a side channel");
            let registration = start_registration(Some(service), Some(side), root)
                .expect("a registration thread")
                .expect("a service and a socket register");
            let watch = registration.watch();
            drop(registration);
            assert!(
                watch.load(Ordering::Relaxed),
                "the drop stopped the registration thread and waited for it"
            );
            at
        };
        UdpSocket::bind(served).expect("the ended registration released the socket");

        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        assert!(
            matches!(
                start_registration(Some("[::1]:9".parse().unwrap()), Some(side), root),
                Err(Error::CarrierUnavailable)
            ),
            "an unreachable service is refused at the first registration"
        );
    }

    #[test]
    fn a_rendezvous_is_the_address_given_or_nowhere() {
        assert!(std::env::var(RENDEZVOUS).is_err(), "the suite owns no env");
        assert_eq!(rendezvous_from(None).expect("unset is nowhere"), None);
        assert_eq!(
            rendezvous_from(Some(" 198.51.100.7:9000 ")).expect("an address"),
            Some("198.51.100.7:9000".parse().unwrap()),
        );
        assert_eq!(
            rendezvous_from(Some("[2001:db8::1]:9000")).expect("an address"),
            Some("[2001:db8::1]:9000".parse().unwrap()),
        );
        assert!(
            matches!(
                rendezvous_from(Some("rendezvous.example.com")),
                Err(Error::InvalidArguments)
            ),
            "a name is not resolved here"
        );
        assert!(matches!(
            rendezvous_from(Some("198.51.100.7")),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            rendezvous_from(Some("")),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn only_a_read_without_a_datagram_is_waited_out() {
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
        assert!(rails_from(Some("0"), 4).is_err());
        assert!(rails_from(Some("9"), 4).is_err());
        assert!(rails_from(Some("wide"), 4).is_err());
        assert!(std::env::var(FETCH_RAILS).is_err(), "the suite owns no env");
    }

    #[test]
    fn a_fetch_at_width_two_crosses_one_serve_socket() {
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
        assert!(congestion_from(Some("reno")).is_err());
        assert!(std::env::var(CONGESTION).is_err(), "the suite owns no env");
    }

    #[test]
    fn an_ephemeral_certificate_goes_when_the_server_does() {
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
