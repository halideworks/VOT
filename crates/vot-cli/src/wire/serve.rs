//! The serve command over a live socket.

use super::push::{accept_sessions, bind_retry_listener};
use super::{
    BundleServer, CONGESTION, Config, Credentials, DATAGRAM_FEC, Ephemeral, Error, INITIAL_CWND,
    Listener, PREFIX_DUP, PackageSummary, Path, RENDEZVOUS, SERVE_AUDIENCE, SERVE_ISSUER,
    SERVE_ISSUER_NAME, ServeSession, SocketAddr, apply_datagram_bytes, automatic_fec,
    carrier_failure, congestion_from, extensions_from, initial_cwnd_from, limits, prefix_dup_from,
    rendezvous_from, requirement_from, start_registration,
};
use vot_transport_api::TransportAdapter as _;

/// How long a serve waits from session start for the peer's presentation
/// to be authorized; traffic does not refresh it. The receiver's deadline
/// (ADR-0045), applied to the serve.
const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// An untrusted presentation a host admits or refuses before a serve session
/// carries data: the peer, the challenge this end issued, what the peer
/// opened with, and the channel it bound to.
pub struct ServePresentation<'a> {
    pub peer: SocketAddr,
    pub challenge: &'a vot_codec::frames::AuthContext,
    pub open: &'a vot_codec::frames::SessionOpen,
    pub channel_binding: vot_transport_api::ChannelBinding,
    pub now: u64,
}

/// One admitted serve session: the bundle it is answered from, the exact
/// scope granted (encoded, as [`crate::authz::Requirement::decide`] returns
/// it), and where its end is reported.
pub struct ServeAdmission {
    pub server: std::sync::Arc<BundleServer>,
    pub scope: Vec<u8>,
    /// Runs on the session's own thread once it ends, holding that
    /// session's slot while it runs; a panic in it takes the accept loop
    /// down, as a panic in any session thread does.
    pub observer: Option<Box<dyn FnOnce(ServeReport) + Send>>,
}

/// How one admitted serve session ended.
#[derive(Debug)]
pub struct ServeReport {
    pub peer: SocketAddr,
    /// The receiver's last `GOAWAY` cursor, sent only when it stopped early.
    pub cursor: Option<u64>,
    /// Transfer objects the bundle holds, what `cursor` counts against.
    pub objects: u64,
    /// Bytes of answers the carrier took.
    pub served_bytes: u64,
    /// How the session ended: its final status, or the failure of this
    /// end. The failure lives here; the accept loop only learns that the
    /// session failed.
    pub status: Result<crate::ServeStatus, Error>,
}

/// What a serve admission may grant: a whole package under suite 1, and the
/// package the server answers from.
pub(crate) fn valid_serve_scope(scope: &vot_capability::Scope, served_root: [u8; 32]) -> bool {
    scope.suite == 1
        && scope.length.is_none()
        && scope.ranges.is_empty()
        && scope.root == served_root
}

/// Binds a Retry-protected listener suitable for [`serve_on`].
///
/// # Errors
/// Surfaces credentials that will not load and an address that will not
/// bind.
pub fn bind_serve_listener(
    address: SocketAddr,
    credentials: &Credentials,
) -> Result<(Listener, [u8; 32]), Error> {
    bind_retry_listener(address, credentials)
}

/// Accepts and concurrently serves sessions on an already-bound listener.
///
/// Every session is challenged for a capability with a fresh nonce; `policy`
/// receives the untrusted presentation and must authenticate and authorize
/// it before returning a [`ServeAdmission`] naming the bundle to answer
/// from. A presentation not authorized within ten seconds of the session's
/// start is closed. The listener must have stateless Retry enabled, as
/// [`bind_serve_listener`] leaves it.
///
/// # Errors
/// Refuses a listener without Retry with [`Error::InvalidArguments`], and
/// surfaces a listener that will not accept.
pub fn serve_on<P>(listener: &Listener, policy: P) -> Result<(), Error>
where
    P: Fn(ServePresentation<'_>) -> Option<ServeAdmission> + Sync,
{
    serve_on_bounded(listener, None, policy)
}

pub(super) fn serve_on_bounded<P>(
    listener: &Listener,
    sessions: Option<u32>,
    policy: P,
) -> Result<(), Error>
where
    P: Fn(ServePresentation<'_>) -> Option<ServeAdmission> + Sync,
{
    serve_on_bounded_with_timeout(listener, sessions, AUTHENTICATION_TIMEOUT, policy)
}

pub(super) fn serve_on_bounded_with_timeout<P>(
    listener: &Listener,
    sessions: Option<u32>,
    authentication_timeout: std::time::Duration,
    policy: P,
) -> Result<(), Error>
where
    P: Fn(ServePresentation<'_>) -> Option<ServeAdmission> + Sync,
{
    accept_sessions(listener, sessions, |carrier| {
        serve_one(carrier, &policy, authentication_timeout)
    })
}

/// Challenges one carrier, admits it through `policy`, and serves it to
/// its end, reporting to the admission's observer.
fn serve_one<P>(
    carrier: super::Transport,
    policy: &P,
    authentication_timeout: std::time::Duration,
) -> Result<(), Error>
where
    P: Fn(ServePresentation<'_>) -> Option<ServeAdmission>,
{
    let peer = carrier.peer_address().ok_or(Error::CarrierUnavailable)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let mut session = vot_session::Session::server(
        carrier,
        vot_codec::Settings::default(),
        crate::authz::default_extensions(),
        vot_session::Authentication::Capability {
            challenge: vot_codec::frames::AuthContext {
                nonce: nonce.to_vec(),
                binding: vot_codec::frames::Binding::ProofOfPossession,
                formats: vec![u64::from(vot_capability::FORMAT_ID)],
            },
        },
    );
    session.begin()?;
    let authentication_deadline = std::time::Instant::now() + authentication_timeout;
    let admission = loop {
        if std::time::Instant::now() >= authentication_deadline {
            let _ = session
                .driver()
                .close(vot_codec::error_code::AUTHENTICATION_FAILED);
            return Err(Error::PeerClosed(
                vot_codec::error_code::AUTHENTICATION_FAILED,
            ));
        }
        if let Some((challenge, open)) = session.pending_authorization() {
            let binding = session
                .channel_binding()
                .ok_or(Error::ChannelBindingUnavailable)?;
            let admitted = policy(ServePresentation {
                peer,
                challenge,
                open,
                channel_binding: binding,
                now: crate::authz::now_seconds()?,
            });
            // The policy decides the bundle and the seam holds it to that
            // bundle: a scope naming another root would serve one package
            // under a token for a different one.
            let admitted = admitted.filter(|admission| {
                vot_capability::decode_scope(&admission.scope)
                    .is_ok_and(|scope| valid_serve_scope(&scope, admission.server.package().root))
            });
            let Some(admission) = admitted else {
                session.refuse(
                    crate::authz::REFUSAL_REASON,
                    crate::authz::REFUSAL_DETAIL.to_owned(),
                )?;
                session.flush()?;
                continue;
            };
            if std::time::Instant::now() >= authentication_deadline {
                let _ = session
                    .driver()
                    .close(vot_codec::error_code::AUTHENTICATION_FAILED);
                return Err(Error::PeerClosed(
                    vot_codec::error_code::AUTHENTICATION_FAILED,
                ));
            }
            session.grant(admission.scope.clone())?;
            session.flush()?;
            break admission;
        }
        if let Some(vot_transport_api::Event::Disconnected(_)) = session.poll()? {
            return Err(Error::CarrierUnavailable);
        }
        session.flush()?;
        session
            .driver()
            .wait_for_event(std::time::Duration::from_millis(10));
    };
    let ServeAdmission {
        server, observer, ..
    } = admission;
    let mut serving = ServeSession::from_started_session(&server, session);
    let status = crate::drive::drive(&mut serving);
    let outcome = status
        .as_ref()
        .map_or(Err(Error::CarrierUnavailable), |_| Ok(()));
    let report = ServeReport {
        peer,
        cursor: serving.goaway_cursor(),
        objects: server.object_count(),
        served_bytes: serving.served_bytes(),
        status,
    };
    // Release the carrier before the observer runs: a receiver waiting on this
    // session's clean close should not wait through the observer's own work.
    drop(serving);
    if let Some(observer) = observer {
        observer(report);
    }
    outcome
}

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
pub(crate) fn serve_stance(
    requirement: Option<&crate::authz::Requirement>,
) -> Result<crate::authz::Stance<'_>, Error> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    Ok(match requirement {
        Some(requirement) => crate::authz::Stance::required(requirement, nonce),
        None => crate::authz::Stance::open(nonce),
    })
}

/// Serves `bundle` on `address` until stopped or `sessions` are answered.
///
/// The bundle is opened and proved once upfront. All sessions share one
/// socket; `listening` reports the bound address, the package root, and the
/// serve's identity once. The identity is the blake3 digest of the
/// certificate this serve presents, which a fetch pins with
/// `VOT_FETCH_SERVE_IDENTITY`.
///
/// # Errors
/// Surfaces a bundle that will not open, a socket that will not bind, and
/// any failure of this end while a session is live.
pub fn serve_bundle(
    bundle: &Path,
    address: SocketAddr,
    credentials: &Credentials,
    sessions: Option<u32>,
    listening: impl FnMut(SocketAddr, [u8; 32], [u8; 32]),
) -> Result<PackageSummary, Error> {
    let pin = std::env::var(DATAGRAM_FEC).ok();
    let extensions = extensions_from(pin.as_deref())?;
    serve_bundle_offering(
        bundle,
        address,
        credentials,
        sessions,
        &extensions,
        automatic_fec(pin.as_deref()),
        listening,
    )
}

/// [`serve_bundle`] offering `extensions` to every session.
pub(crate) fn serve_bundle_offering(
    bundle: &Path,
    address: SocketAddr,
    credentials: &Credentials,
    sessions: Option<u32>,
    extensions: &std::collections::BTreeSet<u64>,
    automatic_fec: bool,
    mut listening: impl FnMut(SocketAddr, [u8; 32], [u8; 32]),
) -> Result<PackageSummary, Error> {
    let mut server = BundleServer::open(bundle)?;
    server.set_automatic_fec(automatic_fec);
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
    config.initial_congestion_window_packets =
        initial_cwnd_from(std::env::var(INITIAL_CWND).ok().as_deref())?;
    if let Some(datagrams) = prefix_dup_from(std::env::var(PREFIX_DUP).ok().as_deref())? {
        config.prefix_duplication_datagrams = datagrams;
    }
    // Configure rendezvous routing before bind so the listener can
    // filter side-channel datagrams.
    let services = rendezvous_from(std::env::var(RENDEZVOUS).ok().as_deref())?;
    config.side_channel_lead = side_channel_lead(&services);

    let identity = identity_digest(&certificate)?;
    // The loop and its failure policy are in `drive`.
    let mut listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    // The root and identity go with the address because a fetch needs all
    // three, and the only place they are known together is here.
    listening(listener.local_address(), server.package().root, identity);
    let registration = start_registration(
        &services,
        listener.take_side_channel(),
        server.package().root,
    )?;
    let outcome = crate::drive::serve_sessions(sessions, || {
        // Accept blocks until a connection arrives.
        let carrier = listener.accept().map_err(carrier_failure)?;
        ServeSession::begin(
            &server,
            carrier,
            serve_stance(requirement.as_ref())?.offering(extensions.clone()),
        )
    });
    // Drop before surfacing the error so the socket is released.
    drop(registration);
    outcome?;
    Ok(server.package())
}

/// The lead byte the listener sheds rendezvous datagrams by, which is
/// wanted exactly when there is a service to register with. Naming one
/// without a service would route datagrams aside that nothing reads.
pub(crate) const fn side_channel_lead(services: &[SocketAddr]) -> Option<u8> {
    if services.is_empty() {
        None
    } else {
        Some(crate::rendezvous::MAGIC)
    }
}

/// The serve's identity: the blake3 digest of the leaf certificate in the
/// PEM at `certificate`, hashed over the DER the handshake presents, so it
/// equals what a fetch computes from the peer certificate it received.
pub(crate) fn identity_digest(certificate: &Path) -> Result<[u8; 32], Error> {
    let pem = std::fs::read(certificate)?;
    Ok(*blake3::hash(&der_from_pem(&pem)?).as_bytes())
}

/// The DER inside the first CERTIFICATE armor block of `pem`.
///
/// Only CERTIFICATE blocks count, because that is what the TLS stack loads:
/// `load_cert_chain_from_pem_file` skips keys, parameters, and bag
/// attributes to find the first certificate, and a combined PEM that leads
/// with any of those must still hash the certificate the handshake sends.
///
/// # Errors
/// Rejects bytes with no CERTIFICATE block or a body that is not base64,
/// which is a file the serve could not present a certificate from.
pub(crate) fn der_from_pem(pem: &[u8]) -> Result<Vec<u8>, Error> {
    use base64::Engine as _;
    let text = std::str::from_utf8(pem).map_err(|_| Error::InvalidArguments)?;
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
        } else if inside {
            if line == "-----END CERTIFICATE-----" {
                break;
            }
            body.push_str(line);
        }
    }
    if body.is_empty() {
        return Err(Error::InvalidArguments);
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| Error::InvalidArguments)
}
