//! The fetch command over a live socket.

use super::{
    BundleFetcher, CONGESTION, Config, DATAGRAM_FEC, Error, FETCH_CAPABILITY, FETCH_HOLDER_KEY,
    FETCH_RAILS, FETCH_STATS, PROGRESS_QUANTUM_BYTES, PUNCH_WAIT, PackageSummary, Path, RELAY,
    SocketAddr, Transport, apply_datagram_bytes, carrier_failure, congestion_from, extensions_from,
    holder_from, limits, local_for, punch, rails_from, rendezvous_from, stats_wanted, take_slot,
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
pub(crate) fn fetch_over<F>(
    primary: Transport,
    connect: F,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error>
where
    F: Fn() -> Result<Transport, Error> + Sync,
{
    let extensions = extensions_from(std::env::var(DATAGRAM_FEC).ok().as_deref())?;
    fetch_over_offering(primary, connect, bundle, pin, rails, extensions)
        .map(|fetched| fetched.package)
}

/// [`fetch_over`] offering `extensions` on every rail, reporting what the
/// fetch measured as well as what it proved.
pub(crate) fn fetch_over_offering<F>(
    primary: Transport,
    connect: F,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
    extensions: std::collections::BTreeSet<u64>,
) -> Result<crate::drive::Fetched, Error>
where
    F: Fn() -> Result<Transport, Error> + Sync,
{
    // Read before the fetch runs, so a value this cannot read is refused now
    // rather than after the transfer it was meant to report on.
    let wanted = stats_wanted(std::env::var(FETCH_STATS).ok().as_deref())?;
    let mut fetcher = BundleFetcher::begin_with(
        primary,
        bundle,
        pin,
        holder_from(
            std::env::var(FETCH_CAPABILITY).ok().as_deref(),
            std::env::var(FETCH_HOLDER_KEY).ok().as_deref(),
        )?,
        extensions,
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
    let began = std::time::Instant::now();
    let outcome = crate::drive::fetch_striped(fetcher, rails, connect)?;
    let elapsed = began.elapsed();
    if wanted {
        let first = outcome
            .first_moved
            .map(|at| at.saturating_duration_since(began));
        eprintln!("{}", stats_line(outcome.moved, elapsed, first, outcome.fec));
    }
    Ok(outcome)
}

/// What one fetch measured, as one line an operator or a bench harness reads:
/// the bytes it placed itself and the wall time that divide into a
/// throughput, and the datagram-FEC counts that say how much of the object
/// the coded path carried and how much fell back to the reliable one.
///
/// `fec_coded` sits between offered and decoded because those two answer
/// different questions: a generation an epoch spanned but no symbol was ever
/// sent for was answered reliably and never coded at all, and reading
/// decoded against offered alone reports that as a decode failure.
///
/// The bytes are this fetch's own, not the package's length: a fetch that
/// resumed a bundle asks only for what is missing, and dividing the whole
/// package by the time it took to move the remainder is a throughput of
/// bytes nobody sent.
///
/// The line rather than the printing, so a test can read what the harness
/// would, the way [`super::relay::closing_line`] is written.
///
/// Elapsed time is truncated to whole milliseconds rather than rounded: a
/// transfer measured in microseconds is not a measurement, and reporting it
/// as one millisecond would hide that.
pub(crate) fn stats_line(
    bytes: u64,
    elapsed: std::time::Duration,
    first: Option<std::time::Duration>,
    fec: vot_scheduler::FecCounts,
) -> String {
    let first = first.map_or_else(|| "none".to_owned(), |time| time.as_millis().to_string());
    format!(
        "fetch stats bytes={bytes} ms={} first_ms={first} fec_offered={} fec_coded={} fec_decoded={} \
         fec_abandoned={} fec_refused={}",
        elapsed.as_millis(),
        fec.offered,
        fec.coded,
        fec.decoded,
        fec.abandoned,
        fec.refused
    )
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
    // Parsed like the rendezvous it mirrors: a name, resolved to every
    // address it has.
    let relays = rendezvous_from(std::env::var(RELAY).ok().as_deref())?;
    fetch_via_rendezvous_railed(root, bundle, services, &relays, rails)
}

/// Fetches through a rendezvous at an explicit rail width.
///
/// The relay is the ladder's last rung, taken only when every punchable
/// route refused and one is named. It runs at width one: a slot pairs
/// exactly two ends, and a wider fetch through a donated path would
/// multiply the donation.
pub(crate) fn fetch_via_rendezvous_railed(
    root: [u8; 32],
    bundle: &Path,
    services: &[SocketAddr],
    relays: &[SocketAddr],
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
    match first_route(services, &open) {
        Ok((primary, service)) => {
            let connect = || open(service).map(|(carrier, _)| carrier);
            fetch_over(primary, connect, bundle, Some(root), rails)
        }
        Err(refused) => {
            let Some(primary) = relay_route(key, relays, services, &config)? else {
                return Err(refused);
            };
            let connect = || Err(Error::RelayUnavailable);
            fetch_over(primary, connect, bundle, Some(root), 1)
        }
    }
}

/// Opens a carrier through the first relay that gives a slot and pairs.
///
/// Nothing found answers `None`, so the caller reports the punch's own
/// refusal rather than this rung's: the ladder failed where it failed.
pub(crate) fn relay_route(
    key: [u8; 32],
    relays: &[SocketAddr],
    services: &[SocketAddr],
    config: &Config,
) -> Result<Option<Transport>, Error> {
    for relay in relays {
        let Ok(taken) = take_slot(key, *relay, services) else {
            continue;
        };
        let slot = taken.serve;
        let carrier = Transport::connect_on(taken.socket, slot, Some("localhost"), config)
            .map_err(carrier_failure)?;
        if carrier.connected_within(PUNCH_WAIT) {
            eprintln!("route {slot} relayed");
            return Ok(Some(carrier));
        }
    }
    Ok(None)
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
