//! The fetch command over a live socket.

use super::{
    BundleFetcher, CONGESTION, Config, Error, FETCH_CAPABILITY, FETCH_HOLDER_KEY, FETCH_RAILS,
    PROGRESS_QUANTUM_BYTES, PUNCH_WAIT, PackageSummary, Path, SocketAddr, Transport,
    apply_datagram_bytes, carrier_failure, congestion_from, holder_from, limits, local_for, punch,
    rails_from,
};

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
pub(crate) fn fetch_railed(
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
pub(crate) fn client_config() -> Result<Config, Error> {
    let mut config = Config::client(limits()?);
    // The channel is unauthenticated. What catches a forged server is the
    // package root this fetch pinned, which every range proves to, and a
    // capability decides who may fetch rather than who is serving.
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
pub(crate) fn fetch_via_rendezvous_railed(
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
pub(crate) fn first_route<F>(
    services: &[SocketAddr],
    open: &F,
) -> Result<(Transport, SocketAddr), Error>
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
