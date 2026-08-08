//! The commands' carrier: a QUIC endpoint under the two engines.
//!
//! ADR-0030 keeps the engines transport-agnostic and puts the
//! socket-owning backend behind a feature, so this module is the whole of
//! what `wire` adds: credentials, an endpoint at each end, and the two
//! calls the commands make.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vot_transport_api::ReceiveLimits;
use vot_transport_quiche::live::{Config, CongestionControl, Listener, SideChannel, Transport};

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
    // The rendezvous shares this socket, so the router has to be told
    // which arrivals are not its own before it binds (ADR-0033).
    let service = rendezvous_from(std::env::var(RENDEZVOUS).ok().as_deref())?;
    config.side_channel_lead = service.map(|_| crate::rendezvous::MAGIC);

    // One socket for every session, and the address reported once: a
    // caller that asked for port zero cannot connect until it knows what
    // it got. A bounded count is what lets a test serve its sessions and
    // return; without one the command serves until it is stopped. The
    // loop and its failure policy live in `drive`, under the gate this
    // file is not.
    let mut listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    listening(listener.local_address());
    let registration =
        start_registration(service, listener.take_side_channel(), server.package().root)?;
    let outcome = crate::drive::serve_sessions(sessions, || {
        // The accept parks this thread until a client's first packet
        // names a connection, so a session never spends its stall budget
        // waiting for one to exist.
        let carrier = listener.accept().map_err(carrier_failure)?;
        ServeSession::begin(&server, carrier, authentication())
    });
    // Before the failure is surfaced, so a serve that ends badly still
    // stops registering and releases its socket.
    drop(registration);
    outcome?;
    Ok(server.package())
}

/// A registration when there is both a service to register with and a
/// socket to register on, and none otherwise.
///
/// Both halves come from the same decision: the configuration named a
/// service, so the bind was told to hand rendezvous datagrams aside. A
/// serve with one and not the other would send registrations nobody
/// answers, or hold a channel nothing reads.
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

/// A serve's registration for as long as it serves.
///
/// The thread lives beside the accept loop rather than inside it,
/// because the cadence has to keep running while an accept is parked
/// waiting for a client. Dropping it stops the thread and joins it,
/// which is also what releases the listener's socket: the thread holds
/// the same socket the router does, so one left running holds the port
/// after the serve has returned.
struct Registration {
    stop: Arc<std::sync::atomic::AtomicBool>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Turns the drop waits for the registration thread to notice the stop
/// flag, at [`REGISTRAR_TICK`] each.
///
/// The wait is counted rather than open: a thread that will not stop is
/// left behind, which costs a thread, where joining it would cost the
/// process. Its socket is the listener's and weakly held, so what it is
/// holding goes when the listener does either way.
const STOP_TURNS: usize = 20;

impl Registration {
    /// Starts registering `root` with `service` on the listener's socket.
    ///
    /// The first registration goes on this thread, so a service the
    /// socket cannot reach at all stops the serve here rather than
    /// leaving it running and unfindable: an address of the wrong family
    /// for the bound socket, or a route that does not exist, fails the
    /// send outright. A service that is merely not answering cannot be
    /// told from one that is, and the cadence keeps trying.
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

    /// Whether the registration thread has ended, which the drop waits
    /// for and a caller can watch across it.
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
        // Counted turns rather than a join outright: a thread that does
        // not answer the flag would otherwise hold the serve's return
        // forever, and a leaked thread on a weakly held socket is the
        // smaller failure.
        for _ in 0..STOP_TURNS {
            if self.stopped.load(Ordering::Relaxed) {
                let _ = thread.join();
                return;
            }
            std::thread::sleep(REGISTRAR_TICK);
        }
    }
}

/// How long the service waits on an empty socket before taking another
/// turn.
///
/// A bound counts turns rather than arrivals, so this is also what lets
/// a bounded service return when nobody is sending: without it a test
/// that asks for more turns than it produces waits on a read forever.
const SERVICE_TICK: Duration = Duration::from_millis(100);

/// Runs the rendezvous service of ADR-0033 on `address` until stopped,
/// or until `datagrams` turns when bounded (which is what lets a test
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
    socket
        .set_read_timeout(Some(SERVICE_TICK))
        .map_err(|_| Error::CarrierUnavailable)?;
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

/// The environment variable naming the rendezvous service a serve
/// registers with. Unset, a serve registers nowhere and behaves exactly
/// as it did before ADR-0033.
const RENDEZVOUS: &str = "VOT_RENDEZVOUS";

/// The service [`RENDEZVOUS`] names, apart from the environment that
/// feeds it, as [`congestion_from`] and [`rails_from`] are.
///
/// An address, not a name: nothing here resolves, so a serve's start
/// makes no DNS query. A value that is not one is refused where the
/// refusal can name the argument, rather than serving without the
/// reachability the caller asked for and never saying so.
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

/// How long a registered serve waits on its side channel before looking
/// at the clock and the stop flag again.
const REGISTRAR_TICK: Duration = Duration::from_millis(200);

/// Sends what the registrar handed back, on the listener's own socket,
/// which is the mapping the service observes and the one sessions arrive
/// at.
///
/// # Errors
/// Reports a socket that would not send, which is the socket this serve
/// answers on and not a peer's failure.
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

/// Keeps a serve registered and warms the fetches it is told about,
/// until `stop`.
///
/// Every decision is [`crate::rendezvous::Registrar`]'s. A send that
/// fails, or a router that has ended, ends the registration and says so
/// once: a serve that keeps a cadence nothing receives is a serve no
/// fetch can find, which is worth a line on stderr rather than silence.
fn keep_registered(
    side: &SideChannel,
    registrar: &mut crate::rendezvous::Registrar,
    stop: &std::sync::atomic::AtomicBool,
) {
    let began = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        // What is due goes before the wait, so a registration is never
        // held up by an arrival that has not come.
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
            // The router is gone, so nothing can arrive and the socket is
            // going with it. Returning is what keeps this from spinning
            // on a channel that answers instantly and forever.
            Err(_) => return,
        }
    }
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
    fn a_registered_serve_is_resolved_and_warms_the_fetch_that_comes() {
        // ADR-0033 step 2 end to end over loopback: the listener's own
        // socket registers under the bundle's key, so what a fetch
        // resolves is the address sessions arrive at, and the Coming the
        // service forwards makes this end send toward the fetch's
        // mapping, which is what opens its NAT.
        use crate::rendezvous::{Datagram, decode, encode, key_of};

        let (addressed, address) = mpsc::channel();
        // Bounded in turns, and joined at the end, so the service and
        // its socket go with the test rather than living on in the test
        // binary. A turn is an arrival or an empty tick, so the bound is
        // also what makes the join return.
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
        // Bounded by its own count: each turn asks once, and backs off a
        // little when the answer is that nobody has registered yet. The
        // count and the waits are what a regression costs the suite, so
        // they are the smallest that clear a loaded runner.
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

        // The service told the serve a fetch is coming, and the serve
        // warmed the path toward it.
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
        // Two properties of the same object. Which serves register: only
        // one told where to and given the socket to do it on, because
        // either half alone is a serve sending where nobody answers or
        // holding a channel nothing reads. And a registration that ends
        // releases the socket: its thread holds the same socket the
        // router does, so one left running keeps the port bound after
        // the serve has returned, and the next serve cannot have it.
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        // A loopback address nothing answers on: the first registration
        // has to leave the socket, and nothing has to reply for it to.
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

        // A service of the wrong family for the bound socket cannot be
        // sent to at all, and that is refused where it happens rather
        // than left as a serve nobody can resolve.
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
        // The pin apart from the process environment: unset is a serve
        // that registers nowhere, which is every serve before ADR-0033,
        // and a value that is not an address is refused at the argument
        // rather than at the socket.
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
