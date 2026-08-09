//! QUIC transport endpoint for the serve and fetch commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
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
    /// Generates a self-signed ECDSA P-256 certificate. `BoringSSL` rejects
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

        // The name is unguessable rather than merely unique. A private key
        // at a path another local user can work out is one they can wait
        // for, and a process ID is neither secret nor unique: inside a PID
        // namespace it repeats every run, and the second serve cannot start.
        let mut suffix = [0_u8; 16];
        getrandom::fill(&mut suffix).map_err(|_| Error::Randomness)?;
        let mut name = String::from("vot-serve-");
        for byte in suffix {
            use std::fmt::Write;
            let _ = write!(name, "{byte:02x}");
        }
        let directory = std::env::temp_dir().join(name);
        create_private_directory(&directory)?;
        let written = Self {
            certificate: directory.join("cert.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        write_private_synced(&written.certificate, certificate.pem().as_bytes())?;
        write_private_synced(&written.key, key.serialize_pem().as_bytes())?;
        Ok(written)
    }
}

/// Creates a directory only this user can enter. A directory that takes the
/// umask leaves the key inside it readable by anyone on the host. Windows has
/// no mode bits here, so there the per-user temp directory and the
/// unguessable name are the protection.
///
/// Any missing parents are created first, without the mode: they are the
/// temp root, shared by everything, and only the leaf holds a key. Creating
/// just the leaf was a regression, because a `TMPDIR` whose tree does not
/// exist yet then aborts a serve before it binds.
fn create_private_directory(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

/// Writes a new file only this user can read, and syncs it.
fn write_private_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    crate::write_new_synced_with_mode(path, bytes, Some(0o600))
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
    mut listening: impl FnMut(SocketAddr, [u8; 32]),
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
    let services = rendezvous_from(std::env::var(RENDEZVOUS).ok().as_deref())?;
    config.side_channel_lead = side_channel_lead(&services);

    // The loop and its failure policy are in `drive`.
    let mut listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    // The root goes with the address because a fetch needs both, and the
    // only place they are known together is here.
    listening(listener.local_address(), server.package().root);
    let registration = start_registration(
        &services,
        listener.take_side_channel(),
        server.package().root,
    )?;
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

/// The lead byte the listener sheds rendezvous datagrams by, which is
/// wanted exactly when there is a service to register with. Naming one
/// without a service would route datagrams aside that nothing reads.
const fn side_channel_lead(services: &[SocketAddr]) -> Option<u8> {
    if services.is_empty() {
        None
    } else {
        Some(crate::rendezvous::MAGIC)
    }
}

/// Returns a registration only when both a service and side channel exist.
///
/// # Errors
/// Reports a registration thread that will not start.
fn start_registration(
    services: &[SocketAddr],
    side: Option<SideChannel>,
    root: [u8; 32],
) -> Result<Option<Registration>, Error> {
    match (services.is_empty(), side) {
        (false, Some(side)) => Registration::begin(side, root, services).map(Some),
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
    /// Sends the first registration on the calling thread so a service this
    /// socket cannot reach at all fails immediately.
    ///
    /// One address of several may refuse: a host with no IPv6 route cannot
    /// send to the service's IPv6 address, and that is a route missing
    /// rather than a service missing. Only a service where none of its
    /// addresses took the registration is refused here.
    ///
    /// # Errors
    /// Reports a service none of whose addresses this socket can send to,
    /// and a thread that will not start.
    fn begin(side: SideChannel, root: [u8; 32], services: &[SocketAddr]) -> Result<Self, Error> {
        let mut registrar = crate::rendezvous::Registrar::new(&root, services);
        if !posted_any(&side, registrar.due(0)) {
            return Err(Error::CarrierUnavailable);
        }
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
    let listening_at = socket.local_addr().map_err(|_| Error::CarrierUnavailable)?;
    listening(listening_at);
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
        // A dual-stack socket sees an IPv4 peer as ::ffff:a.b.c.d. What it
        // records and hands out is the address that peer can be reached at
        // from its own family; what it sends to goes back through this
        // socket's family.
        let source = crate::rendezvous::canonical(source);
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        let answer = pairings.take(datagram, source, now_ms);
        if let Some(reply) = answer.reply {
            let _ = socket.send_to(
                &crate::rendezvous::encode(&reply),
                for_socket(source, listening_at),
            );
        }
        if let Some((mapping, notice)) = answer.notify {
            let _ = socket.send_to(
                &crate::rendezvous::encode(&notice),
                for_socket(mapping, listening_at),
            );
        }
    }
    Ok(())
}

/// Rendezvous service address. Unset means no registration.
const RENDEZVOUS: &str = "VOT_RENDEZVOUS";

/// Every address the service [`RENDEZVOUS`] names, or none when it is
/// unset.
///
/// # Errors
/// Rejects a value that is neither an address nor a name that resolves.
fn rendezvous_from(pin: Option<&str>) -> Result<Vec<SocketAddr>, Error> {
    pin.map_or_else(|| Ok(Vec::new()), crate::parse_rendezvous)
}

/// Side-channel read timeout for the registration thread.
const REGISTRAR_TICK: Duration = Duration::from_millis(200);

/// `target` as a socket bound in `local`'s family can address it. A
/// dual-stack socket takes an IPv4 destination only in its mapped form,
/// which is the inverse of what [`crate::rendezvous::canonical`] undoes.
fn for_socket(target: SocketAddr, local: SocketAddr) -> SocketAddr {
    match (local, target) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => target,
    }
}

/// Sends registrar output on the listener's socket, reporting whether any
/// of it went.
///
/// False means this socket reached none of what it was given, which for a
/// first registration is a service that is not there. One address of
/// several refusing is a route this host does not have, and a serve with
/// no IPv6 route is still findable over IPv4.
fn posted_any(side: &SideChannel, sends: Vec<(SocketAddr, crate::rendezvous::Datagram)>) -> bool {
    let Ok(local) = side.local_address() else {
        return false;
    };
    let mut went = false;
    for (to, datagram) in sends {
        went |= side
            .send_to(&crate::rendezvous::encode(&datagram), for_socket(to, local))
            .is_ok();
    }
    went
}

/// Sends what is due and keeps the cadence whatever one datagram does.
///
/// A warming to a fetch that has gone draws an ICMP unreachable, and with
/// path-MTU discovery on the socket the kernel reports that on the next
/// send, which is usually the registration. Ending the cadence there
/// stops the serve being findable at all, over one datagram nobody was
/// waiting for.
fn post_regardless(side: &SideChannel, sends: Vec<(SocketAddr, crate::rendezvous::Datagram)>) {
    let Ok(local) = side.local_address() else {
        return;
    };
    for (to, datagram) in sends {
        let _ = side.send_to(&crate::rendezvous::encode(&datagram), for_socket(to, local));
    }
}

/// Runs the registration cadence until `stop`, or until the router that
/// owns the socket has gone.
fn keep_registered(
    side: &SideChannel,
    registrar: &mut crate::rendezvous::Registrar,
    stop: &std::sync::atomic::AtomicBool,
) {
    let began = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Send pending registrations before blocking on the channel.
        post_regardless(side, registrar.due(now_ms));
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

/// What a failed read is worth reporting as: a wait that ran out is
/// nothing, and any other failure is the carrier's.
fn read_failure(error: &std::io::Error) -> Option<Error> {
    if waited_out(error) {
        None
    } else {
        Some(Error::CarrierUnavailable)
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
    let config = client_config()?;
    let connect = || {
        Transport::connect(local_for(address)?, address, Some("localhost"), &config)
            .map_err(carrier_failure)
    };
    fetch_with(connect, bundle, pin, rails)
}

/// The configuration every fetch rail is opened with.
fn client_config() -> Result<Config, Error> {
    let mut config = Config::client(limits()?);
    // Channel is unauthenticated; proof verification catches forged servers.
    config.verify_peer = false;
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;
    Ok(config)
}

/// Fetches `bundle` over `rails` carriers that `connect` opens.
fn fetch_with<F>(
    connect: F,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error>
where
    F: Fn() -> Result<Transport, Error> + Sync,
{
    fetch_over(connect()?, connect, bundle, pin, rails)
}

/// [`fetch_with`] with the first carrier already open, for a caller that
/// opened one to find out which route works.
fn fetch_over<F>(
    primary: Transport,
    connect: F,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error>
where
    F: Fn() -> Result<Transport, Error> + Sync,
{
    let mut fetcher = BundleFetcher::begin(primary, bundle, pin)?;
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

/// How long a resolve attempt waits for the service to answer.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a rail waits for the serve's warming before connecting anyway.
/// Long enough to cover a wide-area round trip to the service and the
/// serve's next registrar pass.
const WARMING_WAIT: Duration = Duration::from_millis(1_500);

/// Datagrams either rendezvous wait reads before giving up, so whatever
/// else arrives on the socket cannot extend a wait without bound.
const STRAY_READS: usize = 8;

/// Retries a resolve when no serve is registered yet.
const RESOLVE_RETRIES: u32 = 6;

/// How long a rail waits between resolves when the key is not registered.
const RESOLVE_RETRY_WAIT: Duration = Duration::from_millis(500);

/// How long a punched rail waits for its handshake before the path is
/// called unpunchable.
///
/// A punch lands in the first tenth of a second when both NATs keep the
/// mapping the service observed. When the serving end's NAT gives its
/// warming a different external port, the hole and the Initial do not
/// line up until the handshake has retried a few times, measured at
/// around ten seconds on two conntrack NATs. The bound is past that, so
/// what it names is a path that cannot open rather than one that is slow.
const PUNCH_WAIT: Duration = Duration::from_secs(15);

/// A rail's socket after the service has seen it: bound, announced under
/// the key, and given the serve time to open its side. `serve` is the
/// mapping the service holds for the key.
struct Punched {
    socket: std::net::UdpSocket,
    serve: SocketAddr,
}

/// Announces one rail's socket at the service and waits for the warming.
///
/// The `Resolve` leaves by the socket the session will use, so the mapping
/// the service forwards to the serve is the one the Initial arrives from.
/// Any other socket earns a hole in the serve's NAT that this rail's
/// packets do not fit through.
///
/// # Errors
/// Returns [`Error::RendezvousUnresolved`] when no serve is registered
/// under the key before the retry budget is spent, and
/// [`Error::CarrierUnavailable`] for a socket that will not bind or send.
fn punch(key: [u8; 32], service: SocketAddr) -> Result<Punched, Error> {
    punch_within(key, service, RESOLVE_RETRY_WAIT, WARMING_WAIT)
}

/// [`punch`] with its two waits as arguments, so a test spends neither.
fn punch_within(
    key: [u8; 32],
    service: SocketAddr,
    retry: Duration,
    warming: Duration,
) -> Result<Punched, Error> {
    // Bound toward the service, so the socket is in the service's family, and
    // so is every mapping the service ever observed to answer with.
    let socket =
        std::net::UdpSocket::bind(local_for(service)?).map_err(|_| Error::CarrierUnavailable)?;
    let mut buffer = [0_u8; 128];
    for _ in 0..RESOLVE_RETRIES {
        socket
            .send_to(
                &crate::rendezvous::encode(&crate::rendezvous::Datagram::Resolve { key }),
                service,
            )
            .map_err(|_| Error::CarrierUnavailable)?;
        if let Some(serve) = resolved(&socket, &mut buffer, key, service)? {
            open_toward(&socket, serve);
            wait_warm(&socket, &mut buffer, serve, warming)?;
            return Ok(Punched { socket, serve });
        }
        // A serve that has not registered yet is the case worth waiting on:
        // the answer came back at once, so the next attempt would too.
        std::thread::sleep(retry);
    }
    Err(Error::RendezvousUnresolved)
}

/// Sends this end's own warming toward the serve, before waiting for the
/// serve's.
///
/// Both ends have to send. A warming that arrives before this end has sent
/// anything to the serve is unsolicited, and a NAT that tracks it takes the
/// mapping this socket would have used: the session's packets then leave
/// under a different one than the service observed, and the serve's hole
/// does not fit them. Sending first is what keeps the mapping.
fn open_toward(socket: &std::net::UdpSocket, serve: SocketAddr) {
    let warming = crate::rendezvous::encode(&crate::rendezvous::Datagram::Warming);
    // A lost one costs the mapping, so it goes more than once. The serve
    // sheds them: they are not from its service, so they earn nothing.
    for _ in 0..crate::rendezvous::WARMING_DATAGRAMS {
        let _ = socket.send_to(&warming, serve);
    }
}

/// Reads datagrams until `accept` names a value, [`STRAY_READS`] have
/// arrived, or `budget` is spent.
///
/// The budget is the whole wait and not the wait per read. A stranger
/// sending to this port would otherwise buy back the full timeout with
/// every datagram, so the read count alone does not bound the wall clock.
fn read_until<T>(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    budget: Duration,
    mut accept: impl FnMut(crate::rendezvous::Datagram, SocketAddr) -> Option<T>,
) -> Result<Option<T>, Error> {
    let began = std::time::Instant::now();
    for _ in 0..STRAY_READS {
        let left = budget.saturating_sub(began.elapsed());
        // A zero read timeout is no timeout at all, so the spent budget
        // has to end the wait rather than arm a blocking read.
        if left.is_zero() {
            return Ok(None);
        }
        socket
            .set_read_timeout(Some(left))
            .map_err(|_| Error::CarrierUnavailable)?;
        let (length, source) = match socket.recv_from(buffer) {
            Ok(arrival) => arrival,
            Err(error) => return read_failure(&error).map_or(Ok(None), Err),
        };
        if let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) {
            if let Some(found) = accept(datagram, source) {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// Reads until `service` names a serve for `key` or the read runs out.
/// Nothing named is a retry, not a failure.
///
/// The answer decides where this rail sends its Initial, so it is taken
/// only from the service that was asked. The key alone is not enough: a
/// package root is not a secret, and anyone who can reach this port could
/// otherwise point the rail at an address of their choosing. This is the
/// check [`crate::rendezvous::Registrar::take`] makes on the serving end,
/// through the same [`crate::rendezvous::from_service`].
///
/// A service on a multi-homed host has to answer from the address it was
/// asked at. One that answers from another of its own addresses is heard
/// only if that address is among the ones the fetch was given.
fn resolved(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    key: [u8; 32],
    service: SocketAddr,
) -> Result<Option<SocketAddr>, Error> {
    let found = read_until(socket, buffer, RESOLVE_TIMEOUT, |datagram, source| {
        if !crate::rendezvous::from_service(source, service) {
            return None;
        }
        match datagram {
            crate::rendezvous::Datagram::Resolved {
                key: answered,
                serve,
            } if answered == key => Some(serve),
            _ => None,
        }
    })?;
    Ok(found.flatten())
}

/// Waits for the serve's warming, the one sign this end gets that the
/// serve has sent something toward this mapping.
///
/// A NAT that filters by port sheds the warming, so its absence proves
/// nothing and the wait is a floor on how long the serve has had to open
/// its side.
///
/// The port is not checked, unlike in [`resolved`]: a warming from a port
/// other than the one the service reported is the unpunchable case, and
/// ending the floor there costs nothing, because the warming decides no
/// address. The address is checked, because a warming from anywhere else
/// is not evidence about this serve at all and a stranger must not be
/// able to end the floor early.
///
/// `wait` is the whole floor. It is not restarted by what else arrives.
fn wait_warm(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8; 128],
    serve: SocketAddr,
    wait: Duration,
) -> Result<(), Error> {
    read_until(socket, buffer, wait, |datagram, source| {
        (datagram == crate::rendezvous::Datagram::Warming
            && crate::rendezvous::canonical(source).ip()
                == crate::rendezvous::canonical(serve).ip())
        .then_some(())
    })?;
    Ok(())
}

/// Fetches a bundle by resolving `root` through a rendezvous service.
///
/// Every rail punches for itself: one hole in the serve's NAT admits one
/// mapping, and each rail's socket is its own.
///
/// # Errors
/// Returns [`Error::RendezvousUnpunched`] when a serve is registered but
/// no session forms, which symmetric or carrier-grade NAT on either end
/// produces. Otherwise surfaces a resolution failure, or what
/// [`fetch_with`] does.
pub fn fetch_via_rendezvous(
    root: [u8; 32],
    bundle: &Path,
    services: &[SocketAddr],
) -> Result<PackageSummary, Error> {
    let rails = rails_from(
        std::env::var(FETCH_RAILS).ok().as_deref(),
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    )?;
    fetch_via_rendezvous_railed(root, bundle, services, rails)
}

/// Fetches through a rendezvous at an explicit rail width.
fn fetch_via_rendezvous_railed(
    root: [u8; 32],
    bundle: &Path,
    services: &[SocketAddr],
    rails: usize,
) -> Result<PackageSummary, Error> {
    let config = client_config()?;
    let key = crate::rendezvous::key_of(&root);
    let open = |service: SocketAddr| -> Result<(Transport, SocketAddr), Error> {
        let punched = punch(key, service)?;
        let serve = punched.serve;
        let carrier = Transport::connect_on(punched.socket, serve, Some("localhost"), &config)
            .map_err(carrier_failure)?;
        if carrier.connected_within(PUNCH_WAIT) {
            Ok((carrier, serve))
        } else {
            Err(Error::RendezvousUnpunched)
        }
    };
    let (primary, service) = first_route(services, &open)?;
    let connect = || open(service).map(|(carrier, _)| carrier);
    fetch_over(primary, connect, bundle, Some(root), rails)
}

/// Opens a carrier by the first service address that gives one, and
/// returns the address that did.
///
/// The candidates are ordered IPv6 first. Every rail after this one takes
/// the same route: a family that could not carry the first rail is not
/// going to carry the rest, and paying the punch bound per rail to find
/// that out again would be the whole ladder's cost times the width.
///
/// # Errors
/// Surfaces the last candidate's refusal, and
/// [`Error::InvalidArguments`] when there are no candidates at all.
fn first_route<F>(services: &[SocketAddr], open: &F) -> Result<(Transport, SocketAddr), Error>
where
    F: Fn(SocketAddr) -> Result<(Transport, SocketAddr), Error>,
{
    let mut refused = Error::InvalidArguments;
    for service in services {
        match open(*service) {
            Ok((carrier, serve)) => {
                // The route goes to stderr with the progress lines, because
                // which one carried a transfer is the first thing anyone
                // asks when one is slow or does not happen.
                eprintln!("route {serve}");
                return Ok((carrier, *service));
            }
            Err(error) => refused = error,
        }
    }
    Err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn ephemeral_credentials_are_unguessable_and_unreadable_by_others() {
        let first = Ephemeral::generate().expect("credentials");
        let second = Ephemeral::generate().expect("a second set");
        assert_ne!(
            first.directory, second.directory,
            "two serves in one process shared a directory"
        );
        let name = first
            .directory
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        // The shape, not the absence of the process ID as a substring: a
        // 32-character hex string contains a short decimal by chance most of
        // the time, and a one-digit PID is exactly what a PID namespace
        // gives, which is the case this change exists for. Hex throughout
        // says no decimal identifier is in there at all.
        let suffix = name
            .strip_prefix("vot-serve-")
            .expect("the credential prefix");
        assert_eq!(suffix.len(), 32, "{name}");
        assert!(
            suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the name carries something that is not the random suffix: {name}"
        );
        assert!(first.certificate.exists() && first.key.exists());

        // Unix-only because that is where mode bits decide it. Elsewhere the
        // per-user temp directory is what keeps the key private, and the
        // assertions above cover the part this change controls.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&first.directory), 0o700);
            assert_eq!(mode(&first.key), 0o600);
            assert_eq!(mode(&first.certificate), 0o600);
        }

        let directory = first.directory.clone();
        drop(first);
        assert!(!directory.exists(), "the key outlived its serve");

        // A temp root that does not exist yet is built rather than refused:
        // creating only the leaf aborted a serve before it bound, on any
        // TMPDIR whose tree the caller expects to be made on demand.
        let root = std::env::temp_dir().join(format!("vot-serve-root-{suffix}"));
        let leaf = root.join("deeper").join("credentials");
        create_private_directory(&leaf).expect("a tree that did not exist yet");
        assert!(leaf.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&leaf), 0o700, "only the leaf holds a key");
        }
        std::fs::remove_dir_all(&root).expect("the tree");
    }

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
        let registration = Registration::begin(side, root, &[service]).expect("a registration");

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
            start_registration(&[], None, root)
                .expect("no service is no registration")
                .is_none()
        );
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        assert!(
            start_registration(&[], Some(side), root)
                .expect("a socket without a service is no registration")
                .is_none()
        );

        let served = {
            let mut listener =
                Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
            let at = listener.local_address();
            let side = listener.take_side_channel().expect("a side channel");
            let registration = start_registration(&[service], Some(side), root)
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
        let unreachable: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(
            matches!(
                start_registration(&[unreachable], Some(side), root),
                Err(Error::CarrierUnavailable)
            ),
            "a service with no address this socket can reach is refused"
        );

        // One address of several refusing is a route this host does not
        // have, which is what a dual-stack name looks like from a host with
        // only one family.
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let registration = start_registration(&[unreachable, service], Some(side), root)
            .expect("one address that took it is a registration")
            .expect("a service and a socket register");
        drop(registration);
    }

    #[test]
    fn a_dual_stack_service_answers_an_ipv4_peer_with_an_ipv4_mapping() {
        // A service bound to [::] sees an IPv4 peer as ::ffff:a.b.c.d. Handing
        // that back as the mapping gives a fetch an IPv6 peer to connect its
        // IPv4 socket to, which fails before a packet leaves.
        use crate::rendezvous::{Datagram, decode, encode};

        let (addressed, address) = mpsc::channel();
        let service = std::thread::spawn(move || {
            rendezvous_service("[::]:0".parse().unwrap(), Some(40), |at| {
                let _ = addressed.send(at);
            })
        });
        let at = address.recv().expect("the service reported its address");
        let reachable = SocketAddr::new("127.0.0.1".parse().unwrap(), at.port());
        let key = [11; 32];

        let serve = UdpSocket::bind("127.0.0.1:0").expect("an IPv4 serve socket");
        serve
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        serve
            .send_to(&encode(&Datagram::Register { key }), reachable)
            .expect("a register");
        let mut buffer = [0_u8; 128];
        let (length, _) = serve.recv_from(&mut buffer).expect("an acknowledgement");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Registered { key }),
            "the answer came back to an IPv4 socket"
        );

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("an IPv4 fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        fetch
            .send_to(&encode(&Datagram::Resolve { key }), reachable)
            .expect("a resolve");
        let (length, _) = fetch.recv_from(&mut buffer).expect("an answer");
        let Some(Datagram::Resolved {
            serve: Some(mapping),
            ..
        }) = decode(&buffer[..length])
        else {
            panic!("the resolve was not answered with the serve's mapping");
        };
        assert!(
            mapping.is_ipv4(),
            "an IPv4 serve is named by an IPv4 mapping, not {mapping}"
        );
        assert_eq!(mapping, serve.local_addr().expect("the socket"));

        let (length, _) = serve.recv_from(&mut buffer).expect("the notification");
        let Some(Datagram::Coming { fetch: coming, .. }) = decode(&buffer[..length]) else {
            panic!("the serve was not told the fetch is coming");
        };
        assert_eq!(
            coming,
            fetch.local_addr().expect("the socket"),
            "and so is the fetch it is told about"
        );
        service
            .join()
            .expect("the service thread")
            .expect("the service served its bound");
    }

    #[test]
    fn an_address_is_the_family_that_is_really_its_own() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4433".parse().expect("an address");
        let plain: SocketAddr = "192.0.2.7:4433".parse().expect("an address");
        let six: SocketAddr = "[2001:db8::1]:4433".parse().expect("an address");
        assert_eq!(crate::rendezvous::canonical(mapped), plain);
        assert_eq!(crate::rendezvous::canonical(plain), plain);
        assert_eq!(crate::rendezvous::canonical(six), six);

        let v6_socket: SocketAddr = "[::]:9999".parse().expect("an address");
        let v4_socket: SocketAddr = "0.0.0.0:9999".parse().expect("an address");
        assert_eq!(
            for_socket(plain, v6_socket),
            mapped,
            "a dual-stack socket takes IPv4 only in its mapped form"
        );
        assert_eq!(for_socket(plain, v4_socket), plain);
        assert_eq!(for_socket(six, v6_socket), six);
        assert_eq!(for_socket(six, v4_socket), six, "nothing to do about it");
    }

    #[test]
    fn a_datagram_the_socket_refuses_does_not_end_the_cadence() {
        // What happens on a real serve: a warming goes to a fetch that has
        // gone, an ICMP unreachable comes back, and the kernel reports it on
        // the next send. If that ended the cadence, the serve would stop
        // being findable over one datagram nobody was waiting for.
        use crate::rendezvous::{Datagram, decode};

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");

        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        service
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = service.local_addr().expect("the service address");
        // An address this socket cannot send to at all: it is bound to IPv4.
        let refused: SocketAddr = "[::1]:9".parse().expect("an address");

        post_regardless(
            &side,
            vec![
                (refused, Datagram::Register { key: [1; 32] }),
                (at, Datagram::Register { key: [2; 32] }),
            ],
        );
        let mut buffer = [0_u8; 128];
        let (length, _) = service.recv_from(&mut buffer).expect("the second send");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Register { key: [2; 32] }),
            "the send after the refused one still went"
        );
    }

    #[test]
    fn a_rendezvous_is_the_address_or_name_given_or_nowhere() {
        assert!(std::env::var(RENDEZVOUS).is_err(), "the suite owns no env");
        assert_eq!(rendezvous_from(None).expect("unset is nowhere"), Vec::new());
        assert_eq!(
            rendezvous_from(Some(" 198.51.100.7:9000 ")).expect("an address"),
            vec!["198.51.100.7:9000".parse::<SocketAddr>().unwrap()],
        );
        assert_eq!(
            rendezvous_from(Some("[2001:db8::1]:9000")).expect("an address"),
            vec!["[2001:db8::1]:9000".parse::<SocketAddr>().unwrap()],
        );
        assert!(
            matches!(
                rendezvous_from(Some("rendezvous.example.com")),
                Err(Error::InvalidArguments)
            ),
            "a name without a port names no service"
        );
        let named = rendezvous_from(Some("localhost:9000")).expect("a name the resolver knows");
        assert!(!named.is_empty(), "localhost resolves to something");
        assert!(
            named.iter().all(|address| address.ip().is_loopback()),
            "localhost is this machine, {named:?}"
        );
        assert!(named.iter().all(|address| address.port() == 9000));
        assert!(
            named
                .windows(2)
                .all(|pair| !pair[0].is_ipv4() || !pair[1].is_ipv6()),
            "IPv6 comes first, {named:?}"
        );
        assert!(matches!(
            rendezvous_from(Some("198.51.100.7")),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(
            side_channel_lead(&[]),
            None,
            "no service is nothing to shed aside"
        );
        assert_eq!(
            side_channel_lead(&["198.51.100.7:9000".parse().unwrap()]),
            Some(crate::rendezvous::MAGIC)
        );
        assert!(matches!(
            rendezvous_from(Some("")),
            Err(Error::InvalidArguments)
        ));
    }

    /// A service that answers one resolve with `serve`, warms whoever asked,
    /// and reports the source it observed. Ahead of the answer it sends what
    /// a rail has to read past: a datagram that is no answer, and an answer
    /// under another key naming `elsewhere`.
    fn one_resolve(
        serve: SocketAddr,
        elsewhere: SocketAddr,
    ) -> (SocketAddr, std::thread::JoinHandle<SocketAddr>) {
        use crate::rendezvous::{Datagram, decode, encode};

        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = socket.local_addr().expect("the service address");
        let thread = std::thread::spawn(move || {
            let mut buffer = [0_u8; 128];
            loop {
                let (length, from) = socket.recv_from(&mut buffer).expect("a resolve");
                let Some(Datagram::Resolve { key }) = decode(&buffer[..length]) else {
                    continue;
                };
                let noise = [
                    Datagram::Registered { key },
                    Datagram::Resolved {
                        key: [0xAB; 32],
                        serve: Some(elsewhere),
                    },
                    Datagram::Resolved {
                        key,
                        serve: Some(serve),
                    },
                    Datagram::Warming,
                ];
                for datagram in noise {
                    socket.send_to(&encode(&datagram), from).expect("an answer");
                }
                return from;
            }
        });
        (at, thread)
    }

    #[test]
    fn a_rail_announces_the_socket_it_then_connects_on() {
        // The mapping the service observes is what the serve opens its NAT
        // for, so it has to be the session's own socket. Loopback cannot
        // filter by port, so the identity itself is the assertion.
        //
        // The rail also has to send toward the serve before it waits: a
        // warming that arrives before this end sent anything is unsolicited,
        // and a NAT that tracks it takes the mapping the session wanted.
        // Loopback cannot show that either, so what is asserted is that the
        // datagrams go, and go from the session's socket.
        use crate::rendezvous::{Datagram, decode};

        let at_serve = UdpSocket::bind("127.0.0.1:0").expect("a socket at the serve's mapping");
        // The warmings are queued before the punch returns, so this bound only
        // prices a mutant that sends none.
        at_serve
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bounded wait");
        let serve = at_serve.local_addr().expect("the serve's mapping");
        let elsewhere: SocketAddr = "198.51.100.9:4433".parse().expect("an address");
        let (service, observed) = one_resolve(serve, elsewhere);
        let punched = punch_within(
            [5; 32],
            service,
            Duration::from_millis(1),
            Duration::from_millis(50),
        )
        .expect("a punch");
        assert_eq!(
            punched.serve, serve,
            "the mapping the service holds under this key, not another"
        );
        let announced = punched.socket.local_addr().expect("the socket");
        assert_eq!(
            announced,
            observed.join().expect("the service thread"),
            "the announced mapping is the socket the session connects on"
        );

        let mut buffer = [0_u8; 128];
        for datagram in 0..crate::rendezvous::WARMING_DATAGRAMS {
            let (length, from) = at_serve
                .recv_from(&mut buffer)
                .unwrap_or_else(|_| panic!("warming {datagram} never reached the serve"));
            assert_eq!(decode(&buffer[..length]), Some(Datagram::Warming));
            assert_eq!(
                from, announced,
                "the rail opened its own side from the session's socket"
            );
        }
    }

    #[test]
    fn the_ladder_takes_the_first_candidate_that_opens() {
        // The candidates are the service's addresses, IPv6 first. One that
        // cannot open a carrier costs its own attempt and no more: the rest
        // of the rails take the route that worked, rather than paying the
        // punch bound again to learn the same thing.
        let refusing: SocketAddr = "[2001:db8::1]:9000".parse().expect("an address");
        let working: SocketAddr = "198.51.100.7:9000".parse().expect("an address");
        let tried = std::sync::Mutex::new(Vec::new());
        let open = |service: SocketAddr| -> Result<(Transport, SocketAddr), Error> {
            tried.lock().expect("a lock").push(service);
            Err(Error::RendezvousUnpunched)
        };
        assert!(
            matches!(
                first_route(&[refusing, working], &open),
                Err(Error::RendezvousUnpunched)
            ),
            "every candidate refusing is the last refusal"
        );
        assert_eq!(
            *tried.lock().expect("a lock"),
            vec![refusing, working],
            "in the order given, which is IPv6 first"
        );
        assert!(
            matches!(first_route(&[], &open), Err(Error::InvalidArguments)),
            "no candidates at all is an argument error, not a punch failure"
        );
        assert_eq!(
            tried.lock().expect("a lock").len(),
            2,
            "and nothing was opened for it"
        );
    }

    #[test]
    fn a_stray_before_the_answer_does_not_deny_it() {
        // The first arrival used to shorten every later read to 100ms, so a
        // single stray datagram denied any answer slower than that.
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        let service_at = service.local_addr().expect("the service address");
        let serve = "203.0.113.9:443".parse().expect("a serve address");

        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("something that is not an answer");
        let answering = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            service
                .send_to(
                    &encode(&Datagram::Resolved {
                        key: [5; 32],
                        serve: Some(serve),
                    }),
                    at,
                )
                .expect("the answer");
        });
        let mut buffer = [0_u8; 128];
        assert_eq!(
            resolved(&rail, &mut buffer, [5; 32], service_at).expect("a read"),
            Some(serve),
            "a stray spent the wait the answer needed"
        );
        answering.join().expect("the service");
    }

    #[test]
    fn a_wait_spends_one_budget_however_many_strays_arrive() {
        // Each read used to arm the whole wait again, so eight strays turned
        // a 250ms floor into a two second one.
        use crate::rendezvous::{Datagram, encode};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let budget = Duration::from_millis(250);
        let done = Arc::new(AtomicBool::new(false));
        let sending = Arc::clone(&done);
        // One stray just inside each read, so every read has something to
        // take and only the spent budget can end the wait.
        let straying = std::thread::spawn(move || {
            for _ in 0..STRAY_READS {
                if sending.load(Ordering::Relaxed) {
                    break;
                }
                let _ = stranger.send_to(&encode(&Datagram::Registered { key: [3; 32] }), at);
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let mut buffer = [0_u8; 128];
        let began = std::time::Instant::now();
        let found = read_until(&rail, &mut buffer, budget, |_, _| None::<()>).expect("a read");
        let spent = began.elapsed();
        done.store(true, Ordering::Relaxed);
        straying.join().expect("the stranger");
        assert_eq!(found, None, "nothing was accepted");
        assert!(
            spent < Duration::from_secs(1),
            "a {budget:?} budget under strays took {spent:?}"
        );
    }

    #[test]
    fn only_the_service_that_was_asked_can_name_the_serve() {
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        let service_at = service.local_addr().expect("the service address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let steered = "203.0.113.9:443".parse().expect("an address to be sent to");

        // The right key, the right shape, from the wrong host.
        let answer = encode(&Datagram::Resolved {
            key: [7; 32],
            serve: Some(steered),
        });
        stranger.send_to(&answer, at).expect("a forged answer");
        let mut buffer = [0_u8; 128];
        assert_eq!(
            resolved(&rail, &mut buffer, [7; 32], service_at).expect("a read"),
            None,
            "a stranger steered the rail"
        );

        // The same answer from the service is taken.
        service.send_to(&answer, at).expect("the real answer");
        assert_eq!(
            resolved(&rail, &mut buffer, [7; 32], service_at).expect("a read"),
            Some(steered)
        );
    }

    #[test]
    fn a_rail_reads_its_warming_and_gives_up_without_one() {
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let serve = UdpSocket::bind("127.0.0.1:0").expect("a serve socket");
        let serve_at = serve.local_addr().expect("the serve address");
        serve
            .send_to(&encode(&Datagram::Registered { key: [1; 32] }), at)
            .expect("something that is not a warming");
        serve
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a warming");
        let mut buffer = [0_u8; 128];
        wait_warm(&rail, &mut buffer, serve_at, Duration::from_secs(10)).expect("a wait");
        rail.set_nonblocking(true).expect("a peek");
        assert!(
            rail.recv_from(&mut buffer).is_err(),
            "the warming was read, not left for the session's socket"
        );
        rail.set_nonblocking(false).expect("a bounded wait");
        wait_warm(&rail, &mut buffer, serve_at, Duration::from_millis(50))
            .expect("a warming that never comes is not a failure");
    }

    #[test]
    fn only_the_serve_ends_the_warming_floor() {
        // The floor is what the serve gets to open its side. Anyone else
        // ending it early hands the session a hole that is not open yet.
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let stranger_at = stranger.local_addr().expect("the stranger's address");
        let elsewhere = "203.0.113.9:443".parse().expect("the serve's address");
        let floor = Duration::from_millis(250);

        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a forged warming");
        let mut buffer = [0_u8; 128];
        let began = std::time::Instant::now();
        wait_warm(&rail, &mut buffer, elsewhere, floor).expect("a wait");
        assert!(
            began.elapsed() >= Duration::from_millis(200),
            "a warming from {stranger_at} ended a floor owed to {elsewhere}"
        );

        // The same datagram from the serve's own address does end it. A
        // different port there is the unpunchable case, not a stranger.
        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("the serve's warming");
        let began = std::time::Instant::now();
        let reported = SocketAddr::new(stranger_at.ip(), stranger_at.port().wrapping_add(1));
        wait_warm(&rail, &mut buffer, reported, Duration::from_secs(10)).expect("a wait");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the serve's own warming did not end the floor"
        );
    }

    #[test]
    fn a_root_nobody_registered_is_unresolved_rather_than_punched() {
        use crate::rendezvous::{Datagram, decode, encode};

        // A service that is up and answers, but holds no mapping for the key.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = socket.local_addr().expect("the service address");
        let service = std::thread::spawn(move || {
            let mut buffer = [0_u8; 128];
            let mut answered = 0_u32;
            while answered < RESOLVE_RETRIES {
                let (length, from) = socket.recv_from(&mut buffer).expect("a resolve");
                let Some(Datagram::Resolve { key }) = decode(&buffer[..length]) else {
                    continue;
                };
                let answer = Datagram::Resolved { key, serve: None };
                socket.send_to(&encode(&answer), from).expect("an answer");
                answered += 1;
            }
            answered
        });
        assert!(
            matches!(
                punch_within(
                    [6; 32],
                    at,
                    Duration::from_millis(1),
                    Duration::from_millis(1)
                ),
                Err(Error::RendezvousUnresolved)
            ),
            "a service that names no serve is not a path to punch"
        );
        assert_eq!(
            service.join().expect("the service thread"),
            RESOLVE_RETRIES,
            "the whole retry budget was spent before the root was called unresolved"
        );
    }

    #[test]
    fn only_a_read_without_a_datagram_is_waited_out() {
        use std::io::ErrorKind;
        // What a failed read is reported as, which is the whole decision.
        assert!(read_failure(&std::io::Error::from(ErrorKind::WouldBlock)).is_none());
        assert!(read_failure(&std::io::Error::from(ErrorKind::TimedOut)).is_none());
        assert!(matches!(
            read_failure(&std::io::Error::from(ErrorKind::ConnectionRefused)),
            Some(Error::CarrierUnavailable)
        ));
        assert!(matches!(
            read_failure(&std::io::Error::from(ErrorKind::BrokenPipe)),
            Some(Error::CarrierUnavailable)
        ));
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
                |at, _| {
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
                |at, root| {
                    let _ = listening.send((at, root));
                },
            )
        });

        let (at, announced) = address.recv().expect("the server reported its address");
        // The address and the root together, because a fetch needs both and
        // a caller that has to go and find the second one fetches unpinned.
        assert_eq!(
            announced, built.root,
            "the serve announced a root that is not the bundle's"
        );
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

    #[test]
    fn a_rendezvous_fetch_punches_once_for_every_rail() {
        // One hole in a serve's NAT admits one mapping, so a rail that did not
        // announce its own socket has no path. Loopback cannot filter, so what
        // this asserts is that the service saw one distinct source per rail.
        const RAILS: usize = 2;
        /// Reads the service loop makes before giving up on the flag, so a
        /// fetch that never returns cannot leave the thread running.
        const SERVICE_READS: usize = 400;

        let source = crate::tests::temporary("rendezvous-wire-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), vec![0x5a; 200_000]).unwrap();
        let bundle = crate::tests::temporary("rendezvous-wire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        // The real pairing policy, in a loop that also records who resolved.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        let service = socket.local_addr().expect("the service address");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let service_thread = std::thread::spawn(move || {
            let mut pairings = crate::rendezvous::Pairings::default();
            let began = std::time::Instant::now();
            let mut resolvers = Vec::new();
            let mut buffer = [0_u8; 128];
            for _ in 0..SERVICE_READS {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) else {
                    continue;
                };
                if matches!(datagram, crate::rendezvous::Datagram::Resolve { .. }) {
                    resolvers.push(from);
                }
                let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
                let answer = pairings.take(datagram, from, now_ms);
                if let Some(reply) = answer.reply {
                    let _ = socket.send_to(&crate::rendezvous::encode(&reply), from);
                }
                if let Some((mapping, notice)) = answer.notify {
                    let _ = socket.send_to(&crate::rendezvous::encode(&notice), mapping);
                }
            }
            resolvers
        });

        // Start a serve with rendezvous registration.
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        config.accept_timeout_ms = 0;
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let registration =
            Registration::begin(side, built.root, &[service]).expect("a registration");

        let opened = BundleServer::open(&bundle).unwrap();
        let serving = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(u32::try_from(RAILS).unwrap()), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, authentication())
            })
            .unwrap();
            opened.package()
        });

        // Fetch via rendezvous: resolve root -> connect -> transfer.
        let fetched = crate::tests::temporary("rendezvous-wire-fetched");
        let package = fetch_via_rendezvous_railed(built.root, &fetched, &[service], RAILS)
            .expect("a fetch via rendezvous");
        assert_eq!(package, built);

        drop(registration);
        let served = serving.join().expect("the serving thread");
        assert_eq!(served, built);
        stop.store(true, Ordering::Relaxed);
        let mut resolvers = service_thread.join().expect("the service thread");
        resolvers.sort_unstable();
        resolvers.dedup();
        assert_eq!(
            resolvers.len(),
            RAILS,
            "every rail announced its own socket at the service"
        );
        crate::harness::discard(&[&source, &bundle, &fetched]);
    }
}
