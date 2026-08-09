//! QUIC transport endpoint for the serve and fetch commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use vot_transport_api::ReceiveLimits;
use vot_transport_quiche::live::{Config, CongestionControl, Listener, SideChannel, Transport};

use crate::{BundleFetcher, BundleServer, Credentials, Error, PackageSummary, ServeSession};

/// The serve's stance for one session: what it asks of the peer, with a fresh
/// nonce.
///
/// The nonce is drawn per session, which is what
/// `vot_session::no_capability` says it must be: a client that later binds to
/// it must not find a constant. With a requirement that is load bearing, and
/// not a caution: the binding is proof of possession, so the nonce is what
/// the holder signs and a constant would make one proof answer every session.
///
/// Only the serve's. `Session::client` builds its negotiation with a
/// constant and never looks at the nonce a client names, so drawing one
/// there would be work with no wire effect.
///
/// # Errors
/// Reports [`Error::Randomness`] when the system will not give 32 bytes.
fn serve_stance(
    requirement: Option<&crate::authz::Requirement>,
) -> Result<crate::authz::Stance<'_>, Error> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    Ok(match requirement {
        Some(requirement) => crate::authz::Stance::required(requirement, nonce),
        None => crate::authz::Stance::open(nonce),
    })
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

/// The issuer key a serve accepts capabilities from, as a `KEY_SOURCE`.
const SERVE_ISSUER: &str = "VOT_SERVE_ISSUER";

/// The issuer name that key signs under.
const SERVE_ISSUER_NAME: &str = "VOT_SERVE_ISSUER_NAME";

/// The deployment a capability must name.
const SERVE_AUDIENCE: &str = "VOT_SERVE_AUDIENCE";

/// What a serve requires of a fetch, or nothing.
///
/// Takes the values rather than reading them, like every other reader here,
/// so a test can hold both answers without an environment it cannot set.
///
/// All three or none. A serve given a key but no audience would accept a
/// token minted for another deployment, and one given an audience but no key
/// would accept nothing, which is a refusal that looks like a bug.
///
/// # Errors
/// Rejects a partial configuration and a key source that is not an Ed25519
/// public key.
fn requirement_from(
    issuer_source: Option<&str>,
    issuer: Option<&str>,
    audience: Option<&str>,
    root: [u8; 32],
) -> Result<Option<crate::authz::Requirement>, Error> {
    match (issuer_source, issuer, audience) {
        (None, None, None) => Ok(None),
        (Some(source), Some(issuer), Some(audience)) => {
            let crate::KeyMaterial::Verifying(key) = crate::load_key_spec(source)? else {
                // A signing key here would let the serve mint what it checks,
                // and a shared secret is not what a capability is signed with.
                return Err(Error::InvalidArguments);
            };
            Ok(Some(crate::authz::Requirement::new(
                issuer,
                crate::authz::key_id_of(&key),
                *key,
                audience,
                root,
            )))
        }
        _ => Err(Error::InvalidArguments),
    }
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
    // Read before the port is bound, so a misconfigured requirement is an
    // argument error rather than a serve that listens and refuses everyone.
    let requirement = requirement_from(
        std::env::var(SERVE_ISSUER).ok().as_deref(),
        std::env::var(SERVE_ISSUER_NAME).ok().as_deref(),
        std::env::var(SERVE_AUDIENCE).ok().as_deref(),
        server.package().root,
    )?;
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
        ServeSession::begin(&server, carrier, serve_stance(requirement.as_ref())?)
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

/// Slots this relay opens at once, its slot lifetime in milliseconds, and the
/// bytes one slot forwards. Each is a hard bound the operator sets.
const RELAY_SLOTS: &str = "VOT_RELAY_SLOTS";
const RELAY_TTL_MS: &str = "VOT_RELAY_TTL_MS";
const RELAY_BYTES: &str = "VOT_RELAY_BYTES";

/// The relay's bounds, from the environment or the defaults.
///
/// Every value is parsed and rejected here rather than clamped: an operator
/// who wrote a number this cannot read has said something, and guessing what
/// would be a donation they did not agree to.
///
/// # Errors
/// Rejects a value that is not a number, and a zero, which would be a relay
/// that opens no slots or closes them the instant they open.
fn relay_limits_from(
    slots: Option<&str>,
    ttl_ms: Option<&str>,
    bytes: Option<&str>,
) -> Result<crate::relay::Limits, Error> {
    let default = crate::relay::Limits::default();
    let read = |value: Option<&str>| -> Result<Option<u64>, Error> {
        value
            .map(|value| {
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::InvalidArguments)
            })
            .transpose()
            .and_then(|parsed| match parsed {
                Some(0) => Err(Error::InvalidArguments),
                other => Ok(other),
            })
    };
    let concurrent = match read(slots)? {
        Some(value) => usize::try_from(value).map_err(|_| Error::InvalidArguments)?,
        None => default.concurrent,
    };
    Ok(crate::relay::Limits {
        concurrent,
        ttl_ms: read(ttl_ms)?.unwrap_or(default.ttl_ms),
        bytes: read(bytes)?.unwrap_or(default.bytes),
    })
}

/// How long a slot thread waits on its socket before checking its deadline.
///
/// A slot that carries nothing still has to notice its own expiry, and this
/// is how often it looks. Short enough that a closed slot releases its port
/// promptly, long enough that an idle slot is not a spinning thread.
const SLOT_TICK: Duration = Duration::from_millis(200);

/// The widest datagram a slot forwards. A relayed datagram is exactly the
/// size of a direct one, so this is the carrier's own ceiling.
const SLOT_DATAGRAM_BYTES: usize = vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE;

/// Forwards one slot's datagrams until it spends its time or its bytes.
///
/// Owns its socket and its whole accounting, so no two slots share state and
/// the relay's bound is a count of threads rather than a lock.
fn run_slot(
    socket: &std::net::UdpSocket,
    mut meter: crate::relay::Meter,
    began: std::time::Instant,
    stopping: &std::sync::atomic::AtomicBool,
) {
    if socket.set_read_timeout(Some(SLOT_TICK)).is_err() {
        return;
    }
    let mut buffer = vec![0_u8; SLOT_DATAGRAM_BYTES];
    loop {
        // The relay stopping ends its slots. Without this a bounded run
        // returns and then waits out every slot's whole lifetime.
        if stopping.load(Ordering::Relaxed) {
            return close(&meter);
        }
        let now_ms = elapsed_ms(began);
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                match meter.take(source, length as u64, now_ms) {
                    crate::relay::Forward::To(peer) => {
                        // A refused send is the far end gone, which the other
                        // end learns from its own session rather than here.
                        let _ = socket.send_to(&buffer[..length], peer);
                    }
                    crate::relay::Forward::Nowhere => {}
                    crate::relay::Forward::Closed => return close(&meter),
                }
            }
            Err(error) => {
                if !waited_out(&error) {
                    return;
                }
                // Nothing arrived. The deadline still applies, and asking
                // about it must not look like an arrival: a slot waits for
                // its ends and the first one to speak has to be the first
                // end.
                if meter.expired(now_ms) {
                    return close(&meter);
                }
            }
        }
    }
}

/// Reports what a slot carried, which is the donation an operator is paying
/// for and the only thing the relay ever says about one.
fn close(meter: &crate::relay::Meter) {
    eprintln!("slot closed after {} bytes", meter.forwarded());
}

/// Milliseconds since `began`, saturating rather than wrapping.
fn elapsed_ms(began: std::time::Instant) -> u64 {
    u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Runs the relay on `address` until stopped, or until it has answered
/// `datagrams` requests for a slot when bounded.
///
/// The bound counts answers rather than loop passes, so a relay nobody asks
/// runs until it is stopped and a bounded one is not spent by its own read
/// timeouts.
///
/// The relay answers `Take` on this socket and opens one port per slot. It
/// never reads what a slot carries: ADR-0034.
///
/// # Errors
/// Surfaces a socket that will not bind, and a control socket that fails for
/// a reason other than its own read timeout.
pub fn relay_service(
    address: SocketAddr,
    datagrams: Option<u64>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    let limits = relay_limits_from(
        std::env::var(RELAY_SLOTS).ok().as_deref(),
        std::env::var(RELAY_TTL_MS).ok().as_deref(),
        std::env::var(RELAY_BYTES).ok().as_deref(),
    )?;
    let socket = std::net::UdpSocket::bind(address).map_err(|_| Error::CarrierUnavailable)?;
    socket
        .set_read_timeout(Some(SERVICE_TICK))
        .map_err(|_| Error::CarrierUnavailable)?;
    let listening_at = socket.local_addr().map_err(|_| Error::CarrierUnavailable)?;
    listening(listening_at);
    // The relay's own configuration, on stderr because it is what an
    // operator agreed to donate and the one thing they need to see is that
    // the numbers running are the numbers they set.
    eprintln!(
        "relay slots {} ttl {}ms bytes {}",
        limits.concurrent, limits.ttl_ms, limits.bytes
    );
    let began = std::time::Instant::now();
    let mut slots = crate::relay::Slots::default();
    let mut buffer = [0_u8; 128];
    // Counted in the loop's own body rather than by a clock, and only for a
    // request actually answered.
    let mut answered = 0_u64;
    // Slots run on their own threads and are joined when the relay stops, so
    // a bounded run leaves nothing behind.
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut running = Running {
        limits,
        began,
        stopping: &stopping,
        threads: Vec::new(),
    };
    while datagrams.is_none_or(|bound| answered < bound) {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(arrival) => arrival,
            Err(error) => {
                if waited_out(&error) {
                    slots.retire(elapsed_ms(began));
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        let Some(crate::relay::Datagram::Take { key }) = crate::relay::decode(&buffer[..length])
        else {
            continue;
        };
        let now_ms = elapsed_ms(began);
        let at = if let Some(held) = slots.held(key, now_ms) {
            // The same key asking again is answered with the slot it already
            // has, so a repeated Take costs one datagram rather than a port.
            Some(held)
        } else if slots.admit(key, now_ms, limits) {
            open_slot(&socket, &mut slots, key, now_ms, &mut running)
        } else {
            None
        };
        let _ = socket.send_to(
            &crate::relay::encode(&crate::relay::Datagram::Slot { key, at }),
            source,
        );
        answered = answered.saturating_add(1);
    }
    stopping.store(true, Ordering::Relaxed);
    for slot in running.threads {
        let _ = slot.join();
    }
    Ok(())
}

/// What every slot this relay opens shares: the bounds it runs under, the
/// clock it measures against, the flag that ends it, and the handles the
/// relay joins.
///
/// One value because they travel together and separately they are five
/// arguments to a function that opens a socket.
struct Running<'a> {
    limits: crate::relay::Limits,
    began: std::time::Instant,
    stopping: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

/// Opens one slot beside `control`, in the same family, and starts its
/// thread. Nothing is recorded if the socket will not bind.
fn open_slot(
    control: &std::net::UdpSocket,
    slots: &mut crate::relay::Slots,
    key: [u8; 32],
    now_ms: u64,
    running: &mut Running<'_>,
) -> Option<SocketAddr> {
    let local = control.local_addr().ok()?;
    let mut any = local;
    any.set_port(0);
    let socket = std::net::UdpSocket::bind(any).ok()?;
    let at = socket.local_addr().ok()?;
    let expires_at_ms = now_ms.saturating_add(running.limits.ttl_ms);
    let meter = crate::relay::Meter::new(expires_at_ms, running.limits.bytes);
    let began = running.began;
    let stopping = std::sync::Arc::clone(running.stopping);
    running.threads.push(std::thread::spawn(move || {
        run_slot(&socket, meter, began, &stopping);
    }));
    slots.opened(key, at, expires_at_ms);
    Some(crate::rendezvous::canonical(at))
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
    // The channel is unauthenticated. What catches a forged server is the
    // package root this fetch pinned, which every range proves to, and a
    // capability decides who may fetch rather than who is serving.
    config.verify_peer = false;
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;
    Ok(config)
}

/// The capability a fetch presents, as a path to what `vot capability issue`
/// wrote.
const FETCH_CAPABILITY: &str = "VOT_FETCH_CAPABILITY";

/// The holder key that capability names, as a `KEY_SOURCE`.
const FETCH_HOLDER_KEY: &str = "VOT_FETCH_HOLDER_KEY";

/// The capability a fetch will present, or nothing.
///
/// Takes the values, for the reason [`requirement_from`] does.
///
/// Both or neither, for the reason a serve needs all three: a token with no
/// key cannot be proved, and a key with no token proves nothing.
///
/// # Errors
/// Rejects a partial configuration, a key source that is not an Ed25519
/// secret, a token this build cannot read, and a key that is not the holder
/// the token names.
fn holder_from(
    capability: Option<&str>,
    key_source: Option<&str>,
) -> Result<Option<std::sync::Arc<crate::authz::Holder>>, Error> {
    match (capability, key_source) {
        (None, None) => Ok(None),
        (Some(path), Some(source)) => {
            let crate::KeyMaterial::Signing(key) = crate::load_key_spec(source)? else {
                // Proving possession needs the private half. A public key
                // here is the labelling mistake the key sources exist to
                // catch.
                return Err(Error::InvalidArguments);
            };
            let token = std::fs::read(Path::new(path))?;
            Ok(Some(std::sync::Arc::new(crate::authz::Holder::new(
                token, *key,
            )?)))
        }
        _ => Err(Error::InvalidArguments),
    }
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
    let mut fetcher = BundleFetcher::begin_with(
        primary,
        bundle,
        pin,
        holder_from(
            std::env::var(FETCH_CAPABILITY).ok().as_deref(),
            std::env::var(FETCH_HOLDER_KEY).ok().as_deref(),
        )?,
    )?;
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
    fn a_serve_draws_a_fresh_nonce_for_every_session() {
        let drawn = || {
            let vot_session::Authentication::NotRequired { nonce } =
                serve_stance(None).expect("a nonce").authentication
            else {
                panic!("a serve with no requirement asks for no capability");
            };
            nonce
        };
        let first = drawn();
        assert_ne!(first, drawn(), "two sessions advertised the same nonce");
        assert_ne!(first, [0; 32], "the nonce is the constant it used to be");
    }

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
        let serving_bundle = bundle.to_path_buf();
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
    fn a_rail_is_handed_the_token_the_primary_holds() {
        use ed25519_dalek::SigningKey;

        // Every rail opens its own session and answers its own challenge, so
        // a primary that kept its token to itself would leave every rail
        // after the first refused.
        let holder = SigningKey::from_bytes(&[24; 32]);
        let token = crate::authz::issue(
            "you.example",
            "them.example",
            &SigningKey::from_bytes(&[25; 32]),
            holder.verifying_key().to_bytes(),
            [6; 32],
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let held = std::sync::Arc::new(
            crate::authz::Holder::new(token, holder).expect("a holder for that token"),
        );
        let output = crate::tests::temporary("rail-token");
        let fetcher = BundleFetcher::begin_with(
            crate::harness::Loopback::default(),
            &output,
            None,
            Some(std::sync::Arc::clone(&held)),
        )
        .expect("a fetch holding a token");
        let handed = fetcher.holder().expect("the token, for a rail");
        assert!(
            std::sync::Arc::ptr_eq(&handed, &held),
            "a rail would have opened its session with no capability"
        );

        let without =
            BundleFetcher::begin_with(crate::harness::Loopback::default(), &output, None, None)
                .expect("a fetch holding none");
        assert!(without.holder().is_none(), "a token appeared from nowhere");
    }

    #[test]
    fn a_serve_requires_all_three_or_none_of_them() {
        use ed25519_dalek::SigningKey;

        let root = [4; 32];
        let key = SigningKey::from_bytes(&[21; 32]);
        let source = crate::tests::temporary("issuer-key");
        std::fs::write(
            &source,
            format!(
                "ed25519-public:{}",
                crate::hex_of(&key.verifying_key().to_bytes())
            ),
        )
        .expect("a key file");
        let named = source.to_string_lossy().into_owned();

        assert!(
            requirement_from(None, None, None, root)
                .expect("no requirement")
                .is_none(),
            "a serve given nothing required something"
        );
        assert!(
            requirement_from(
                Some(&named),
                Some("you.example"),
                Some("them.example"),
                root
            )
            .expect("a requirement")
            .is_some(),
            "a serve given all three required nothing"
        );
        // Any partial configuration. A key with no audience would take a
        // token minted for another deployment, and an audience with no key
        // would refuse everyone, which reads as a bug rather than a policy.
        for partial in [
            (Some(named.as_str()), None, None),
            (None, Some("you.example"), None),
            (None, None, Some("them.example")),
            (Some(named.as_str()), Some("you.example"), None),
            (Some(named.as_str()), None, Some("them.example")),
            (None, Some("you.example"), Some("them.example")),
        ] {
            assert!(
                matches!(
                    requirement_from(partial.0, partial.1, partial.2, root),
                    Err(Error::InvalidArguments)
                ),
                "{partial:?} was not refused"
            );
        }
        // A secret where the public half belongs would let a serve mint what
        // it checks.
        let secret = crate::tests::temporary("issuer-secret");
        std::fs::write(
            &secret,
            format!("ed25519-secret:{}", crate::hex_of(&key.to_bytes())),
        )
        .expect("a key file");
        assert!(matches!(
            requirement_from(
                Some(&secret.to_string_lossy()),
                Some("you.example"),
                Some("them.example"),
                root
            ),
            Err(Error::InvalidArguments)
        ));
        assert!(
            std::env::var(SERVE_ISSUER).is_err(),
            "the suite owns no env"
        );
    }

    #[test]
    fn a_fetch_presents_both_or_neither() {
        use ed25519_dalek::SigningKey;

        let issuer = SigningKey::from_bytes(&[22; 32]);
        let holder = SigningKey::from_bytes(&[23; 32]);
        let token = crate::authz::issue(
            "you.example",
            "them.example",
            &issuer,
            holder.verifying_key().to_bytes(),
            [4; 32],
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let token_path = crate::tests::temporary("holder-token");
        std::fs::write(&token_path, &token).expect("a token file");
        let named = token_path.to_string_lossy().into_owned();
        let key_path = crate::tests::temporary("holder-key");
        std::fs::write(
            &key_path,
            format!("ed25519-secret:{}", crate::hex_of(&holder.to_bytes())),
        )
        .expect("a key file");
        let key_named = key_path.to_string_lossy().into_owned();

        assert!(
            holder_from(None, None).expect("no holder").is_none(),
            "a fetch given nothing presented something"
        );
        assert!(
            holder_from(Some(&named), Some(&key_named))
                .expect("a holder")
                .is_some(),
            "a fetch given both presented nothing"
        );
        // A token with no key cannot be proved, and a key with no token
        // proves nothing.
        for partial in [
            (Some(named.as_str()), None),
            (None, Some(key_named.as_str())),
        ] {
            assert!(
                matches!(
                    holder_from(partial.0, partial.1),
                    Err(Error::InvalidArguments)
                ),
                "{partial:?} was not refused"
            );
        }
        // The public half cannot prove possession.
        let public_path = crate::tests::temporary("holder-public");
        std::fs::write(
            &public_path,
            format!(
                "ed25519-public:{}",
                crate::hex_of(&holder.verifying_key().to_bytes())
            ),
        )
        .expect("a key file");
        assert!(matches!(
            holder_from(Some(&named), Some(&public_path.to_string_lossy())),
            Err(Error::InvalidArguments)
        ));
        assert!(
            std::env::var(FETCH_CAPABILITY).is_err(),
            "the suite owns no env"
        );
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
        // receive_bundle writes a JSON summary beside the receipt, which the
        // receipt's own guard does not know about.
        let _summary = crate::tests::guarded(receipt.with_extension("json"));
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
                ServeSession::begin(&opened, carrier, serve_stance(None)?)
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

    #[test]
    fn a_serve_that_requires_a_capability_answers_only_a_holder() {
        // ADR-0036 end to end over a real QUIC socket: the same serve refuses
        // a fetch with no token and completes one with the right token.
        use ed25519_dalek::SigningKey;

        let source = crate::tests::temporary("capability-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), crate::harness::patterned(200_000)).unwrap();
        let bundle = crate::tests::temporary("capability-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let issuer_key = SigningKey::from_bytes(&[11; 32]);
        let holder_key = SigningKey::from_bytes(&[12; 32]);
        let requirement = crate::authz::Requirement::new(
            "issuer.example",
            crate::authz::key_id_of(&issuer_key.verifying_key()),
            issuer_key.verifying_key(),
            "receiver.example",
            built.root,
        );
        let token = crate::authz::issue(
            "issuer.example",
            "receiver.example",
            &issuer_key,
            holder_key.verifying_key().to_bytes(),
            built.root,
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let holder = Arc::new(
            crate::authz::Holder::new(token, holder_key).expect("a holder for that token"),
        );

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.accept_timeout_ms = 0;
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let at = listener.local_address();

        let opened = BundleServer::open(&bundle).unwrap();
        let refused_requirement = requirement.clone();
        let refusing = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(1), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(Some(&refused_requirement))?)
            })
        });

        // No token. `spec/wire.md` 1.1 says the format list lets a client
        // holding none of the accepted formats fail immediately rather than
        // after a rejected SESSION_OPEN, and this is that: the fetch stops on
        // the challenge instead of waiting out a session it cannot open.
        let refused_into = crate::tests::temporary("capability-refused");
        let client = client_config().expect("a client config");
        let carrier = Transport::connect(
            local_for(at).expect("a local address"),
            at,
            Some("localhost"),
            &client,
        )
        .expect("a carrier");
        let mut naked = BundleFetcher::begin(carrier, &refused_into, Some(built.root))
            .expect("a fetch with no token");
        let refusal = crate::drive::drive(&mut naked).expect("a driven fetch");
        assert_eq!(
            refusal,
            crate::FetchStatus::Closed(vot_codec::error_code::AUTHENTICATION_FAILED),
            "a fetch with no capability was served, or refused for another reason"
        );
        assert!(naked.package().is_none(), "a bundle was written anyway");
        drop(naked);
        // The peer left mid-negotiation, which a bounded serve surfaces. An
        // unbounded one outlives it, which is what a real serve is.
        assert!(
            refusing.join().expect("the refusing thread").is_err(),
            "a session whose peer never presented was reported as served"
        );

        // The same bundle and the same requirement, with the token it asked
        // for.
        let opened = BundleServer::open(&bundle).unwrap();
        let listener =
            Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a second bind");
        let at = listener.local_address();
        let granting = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(1), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(Some(&requirement))?)
            })
        });
        let fetched = crate::tests::temporary("capability-fetched");
        let carrier = Transport::connect(
            local_for(at).expect("a local address"),
            at,
            Some("localhost"),
            &client,
        )
        .expect("a carrier");
        let mut holding =
            BundleFetcher::begin_with(carrier, &fetched, Some(built.root), Some(holder))
                .expect("a fetch holding the token");
        let status = crate::drive::drive(&mut holding).expect("a driven fetch");
        assert_eq!(
            status,
            crate::FetchStatus::Complete,
            "the holder was refused"
        );
        assert_eq!(holding.package().expect("a package"), built);
        drop(holding);
        granting
            .join()
            .expect("the granting thread")
            .expect("served");

        crate::harness::discard(&[&source, &bundle, &refused_into, &fetched]);
    }

    #[test]
    fn a_relay_slot_carries_bytes_between_two_ends_and_nobody_else() {
        // ADR-0034 step 2 on loopback: take a slot, pair on it, and see the
        // bytes cross unchanged in both directions while a third address
        // gets nothing.
        use crate::relay::{Datagram, decode, encode};

        let (listening, address) = mpsc::channel();
        // Two answers: the take below, and one more at the end that releases
        // the relay once the assertions are done. A relay that stopped after
        // the first would close the slot before anything crossed it, which is
        // what stopping means.
        let relaying = std::thread::spawn(move || {
            relay_service("127.0.0.1:0".parse().unwrap(), Some(2), |at| {
                let _ = listening.send(at);
            })
        });
        let at = address.recv().expect("the relay reported its address");

        let taker = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        taker
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let key = [0x5a; 32];
        taker
            .send_to(&encode(&Datagram::Take { key }), at)
            .expect("a take");
        let mut buffer = [0_u8; 128];
        let (length, from) = taker.recv_from(&mut buffer).expect("an answer");
        assert_eq!(from, at, "the answer came from somewhere else");
        let Some(Datagram::Slot {
            key: answered,
            at: Some(slot),
        }) = decode(&buffer[..length])
        else {
            panic!("the relay gave no slot: {:?}", decode(&buffer[..length]));
        };
        assert_eq!(answered, key, "the answer named another key");
        assert_ne!(slot, at, "the slot is its own port, not the control one");

        // Two ends and a stranger, each with a bounded wait.
        let ends: Vec<UdpSocket> = (0..3)
            .map(|_| {
                let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
                socket
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("a bounded wait");
                socket
            })
            .collect();
        // The first arrival pairs nothing: there is nobody to send it to.
        ends[0].send_to(b"first", slot).expect("the first end");
        // The second pairs, and its bytes go to the first.
        ends[1].send_to(b"second", slot).expect("the second end");
        let mut carried = [0_u8; 64];
        let (length, from) = ends[0].recv_from(&mut carried).expect("the pairing");
        assert_eq!(&carried[..length], b"second", "the bytes changed");
        assert_eq!(from, slot, "not from the slot");

        // And back the other way, unchanged.
        ends[0]
            .send_to(b"reply", slot)
            .expect("the first end again");
        let (length, _) = ends[1].recv_from(&mut carried).expect("the reply");
        assert_eq!(&carried[..length], b"reply");

        // A third address is not part of this slot.
        ends[2].send_to(b"stranger", slot).expect("a stranger");
        assert!(
            ends[0].recv_from(&mut carried).is_err() && ends[1].recv_from(&mut carried).is_err(),
            "a third address was forwarded to an end of the slot"
        );

        // Release the relay, which stops its slots with it.
        taker
            .send_to(&encode(&Datagram::Take { key }), at)
            .expect("the releasing take");
        let _ = taker.recv_from(&mut buffer);
        relaying
            .join()
            .expect("the relay thread")
            .expect("a relay that answered its bound");
    }

    #[test]
    fn a_relay_refuses_past_its_bound_and_repeats_the_slot_it_gave() {
        use crate::relay::{Datagram, decode, encode};

        let (listening, address) = mpsc::channel();
        // Three control turns: two distinct keys and one repeat.
        let relaying = std::thread::spawn(move || {
            relay_service("127.0.0.1:0".parse().unwrap(), Some(3), |at| {
                let _ = listening.send(at);
            })
        });
        let at = address.recv().expect("the relay reported its address");
        let taker = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        taker
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let mut buffer = [0_u8; 128];
        let mut ask = |key: [u8; 32]| -> Option<SocketAddr> {
            taker
                .send_to(&encode(&Datagram::Take { key }), at)
                .expect("a take");
            let (length, _) = taker.recv_from(&mut buffer).expect("an answer");
            match decode(&buffer[..length]) {
                Some(Datagram::Slot { at, .. }) => at,
                other => panic!("not a slot answer: {other:?}"),
            }
        };
        let first = ask([1; 32]).expect("a slot");
        assert_eq!(ask([1; 32]), Some(first), "the same key got a second port");
        assert!(ask([2; 32]).is_some(), "a second key was refused early");
        relaying
            .join()
            .expect("the relay thread")
            .expect("a relay that answered its bound");
    }

    #[test]
    fn the_relay_bounds_are_the_numbers_given_or_the_defaults() {
        let default = crate::relay::Limits::default();
        assert_eq!(relay_limits_from(None, None, None).unwrap(), default);
        assert_eq!(
            relay_limits_from(Some(" 2\n"), Some("500"), Some("1024")).unwrap(),
            crate::relay::Limits {
                concurrent: 2,
                ttl_ms: 500,
                bytes: 1024
            },
            "given, trimmed, taken"
        );
        // Zero is not a bound anyone meant: a relay with no slots, or one
        // that closes them the instant they open.
        for zero in [
            relay_limits_from(Some("0"), None, None),
            relay_limits_from(None, Some("0"), None),
            relay_limits_from(None, None, Some("0")),
        ] {
            assert!(matches!(zero, Err(Error::InvalidArguments)));
        }
        assert!(relay_limits_from(Some("many"), None, None).is_err());
        assert!(std::env::var(RELAY_SLOTS).is_err(), "the suite owns no env");
    }
}
