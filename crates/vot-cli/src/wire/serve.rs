//! The serve command over a live socket.

use super::{
    BundleServer, CONGESTION, Config, Credentials, DATAGRAM_FEC, Ephemeral, Error, Listener,
    PackageSummary, Path, RENDEZVOUS, SERVE_AUDIENCE, SERVE_ISSUER, SERVE_ISSUER_NAME,
    ServeSession, SocketAddr, apply_datagram_bytes, automatic_fec, carrier_failure,
    congestion_from, extensions_from, limits, rendezvous_from, requirement_from,
    start_registration,
};

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
    listening: impl FnMut(SocketAddr, [u8; 32]),
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
    mut listening: impl FnMut(SocketAddr, [u8; 32]),
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
