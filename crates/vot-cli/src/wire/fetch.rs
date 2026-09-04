//! The fetch command over a live socket.

use super::{
    BundleFetcher, CONGESTION, Config, DATAGRAM_FEC, Error, FETCH_CAPABILITY, FETCH_HOLDER_KEY,
    FETCH_RAILS, FETCH_SERVE_IDENTITY, FETCH_STATS, INITIAL_CWND, PREFIX_DUP,
    PROGRESS_QUANTUM_BYTES, PUNCH_WAIT, PackageSummary, Path, RELAY, SocketAddr, Transport,
    apply_datagram_bytes, carrier_failure, congestion_from, extensions_from, holder_from,
    identity_from, initial_cwnd_from, limits, local_for, prefix_dup_from, punch, rails_from,
    rendezvous_from, stats_wanted, take_slot,
};

/// How long a pinned fetch waits for the handshake to deliver the serve's
/// certificate before giving the carrier up.
const IDENTITY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Refuses a carrier whose serve is not the pinned identity.
///
/// The pump completes the handshake without the session driving, and the
/// session has sent nothing yet, so a wrong serve learns nothing but that a
/// connection came and went. `connected_within` peeks, so the lifecycle
/// event it reads is still there for the session to drain.
pub(crate) fn verify_serve_identity(
    carrier: &Transport,
    pin: Option<[u8; 32]>,
) -> Result<(), Error> {
    match pin {
        Some(pin) => certified_within(carrier, pin, IDENTITY_WAIT),
        None => Ok(()),
    }
}

fn certified_within(
    carrier: &Transport,
    pin: [u8; 32],
    wait: std::time::Duration,
) -> Result<(), Error> {
    if !carrier.connected_within(wait) {
        return Err(Error::CarrierUnavailable);
    }
    match carrier.peer_certificate() {
        Some(der) if *blake3::hash(&der).as_bytes() == pin => Ok(()),
        // A missing certificate on an established connection is refused the
        // way a wrong one is: the pin asked for proof this end cannot check.
        _ => Err(Error::ServeIdentityMismatch),
    }
}

/// Dials `address`, confirms the serve behind it presents `identity`, and
/// closes, all within `budget`.
///
/// A client asks this before it reserves anything on a receiver: a
/// preflight that mints a capability for a push the network will not carry
/// leaves state behind on both ends. The connection carries no session, so
/// the serve learns only that a connection came and went; a receiver whose
/// accept loop is bounded spends one of its sessions on the probe and
/// records the peer's close as a failure, so a probe belongs before a
/// preflight, not before a bounded receive.
///
/// # Errors
/// A handshake that does not complete within `budget` is
/// [`Error::CarrierUnavailable`]; a certificate other than `identity` is
/// [`Error::ServeIdentityMismatch`].
pub fn probe_serve(
    address: SocketAddr,
    identity: [u8; 32],
    budget: std::time::Duration,
) -> Result<(), Error> {
    let mut config = client_config()?;
    // The carrier's idle timeout is the budget, not the fetch default. A
    // handshake that has not completed by then is the probe's answer, and a
    // carrier dropped after the answer waits at most this to end its driver,
    // so the whole probe, the drop included, is bounded by the budget rather
    // than the 30-second fetch idle timeout.
    config.idle_timeout_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    let carrier = Transport::connect(local_for(address)?, address, Some("localhost"), &config)
        .map_err(carrier_failure)?;
    certified_within(&carrier, identity, budget)
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
pub(crate) fn fetch_railed(
    address: SocketAddr,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
) -> Result<PackageSummary, Error> {
    let config = client_config()?;
    let identity = identity_from(std::env::var(FETCH_SERVE_IDENTITY).ok().as_deref())?;
    let connect = || {
        let carrier = Transport::connect(local_for(address)?, address, Some("localhost"), &config)
            .map_err(carrier_failure)?;
        verify_serve_identity(&carrier, identity)?;
        Ok(carrier)
    };
    fetch_with(connect, bundle, pin, rails)
}

/// The configuration every fetch rail is opened with.
pub(crate) fn client_config() -> Result<Config, Error> {
    let mut config = Config::client(limits()?);
    // No certificate chain to verify against: what catches a forged server
    // is the package root this fetch pinned, which every range proves to,
    // plus the serve identity when `VOT_FETCH_SERVE_IDENTITY` pins one,
    // checked in `verify_serve_identity` before the session says anything.
    config.verify_peer = false;
    apply_datagram_bytes(&mut config)?;
    config.congestion = congestion_from(std::env::var(CONGESTION).ok().as_deref())?;
    config.initial_congestion_window_packets =
        initial_cwnd_from(std::env::var(INITIAL_CWND).ok().as_deref())?;
    if let Some(datagrams) = prefix_dup_from(std::env::var(PREFIX_DUP).ok().as_deref())? {
        config.prefix_duplication_datagrams = datagrams;
    }
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
/// fetch measured as well as what it proved. The capability, prover count,
/// and stats request come from the environment, and progress goes to
/// stderr every [`PROGRESS_QUANTUM_BYTES`] so stdout stays clean for scripts.
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
    let holder = holder_from(
        std::env::var(FETCH_CAPABILITY).ok().as_deref(),
        std::env::var(FETCH_HOLDER_KEY).ok().as_deref(),
    )?;
    let provers = std::env::var("VOT_FETCH_PROVERS")
        .ok()
        .map(|value| value.trim().parse().map_err(|_| Error::InvalidArguments))
        .transpose()?;
    let progress: crate::Progress = Box::new(|placed, total| match total {
        Some(total) => eprintln!("{} / {} MiB", placed >> 20, total.div_ceil(1 << 20)),
        None => eprintln!("{} MiB", placed >> 20),
    });
    let (outcome, began) = fetch_over_configured(
        primary,
        connect,
        bundle,
        pin,
        rails,
        extensions,
        holder,
        provers,
        Some((PROGRESS_QUANTUM_BYTES, progress)),
    )?;
    if wanted {
        let first = outcome
            .first_moved
            .map(|at| at.saturating_duration_since(began));
        eprintln!(
            "{}",
            stats_line(outcome.moved, began.elapsed(), first, outcome.fec)
        );
    }
    Ok(outcome)
}

/// The fetch every public entry point runs, with everything it needs handed
/// in and nothing read from the environment, and the instant the transfer
/// itself began, after the bundle and its resume store were opened.
#[expect(
    clippy::too_many_arguments,
    reason = "one fetch's settings, each already narrowed by its caller"
)]
fn fetch_over_configured<F>(
    primary: Transport,
    connect: F,
    bundle: &Path,
    pin: Option<[u8; 32]>,
    rails: usize,
    extensions: std::collections::BTreeSet<u64>,
    holder: Option<std::sync::Arc<crate::authz::Holder>>,
    provers: Option<usize>,
    progress: Option<(u64, crate::Progress)>,
) -> Result<(crate::drive::Fetched, std::time::Instant), Error>
where
    F: Fn() -> Result<Transport, Error> + Sync,
{
    let mut fetcher = BundleFetcher::begin_with(primary, bundle, pin, holder, extensions)?;
    let provers = provers.unwrap_or_else(|| fetcher.proving_threads());
    fetcher.set_proving_threads(provers_per_rail(provers, rails))?;
    if let Some((quantum, observer)) = progress {
        fetcher.report_placed(quantum, observer)?;
    }
    let began = std::time::Instant::now();
    let outcome = crate::drive::fetch_striped(fetcher, rails, connect)?;
    Ok((outcome, began))
}

/// Fetches into `bundle` with everything `options` names, so a long-lived
/// caller can run two fetches with two capabilities at once. Only the
/// process-wide carrier tuning stays with the environment
/// (`VOT_DATAGRAM_BYTES`, `VOT_CONGESTION`, `VOT_INITIAL_CWND`,
/// `VOT_PREFIX_DUP`), as it does for every command.
///
/// The fetcher reports placed bytes at quantum crossings only; the end of
/// the fetch is reported here, once, if the last crossing fell short of it.
///
/// # Errors
/// Refuses a rail count outside one to the fetch rail limit and a zero
/// progress quantum with [`Error::InvalidArguments`], before the bundle is
/// opened; otherwise as [`fetch_bundle`].
pub fn fetch_bundle_with(
    options: crate::FetchOptions,
    bundle: &Path,
) -> Result<PackageSummary, Error> {
    let crate::FetchOptions {
        address,
        holder,
        serve_identity,
        pin,
        rails,
        provers,
        extensions,
        progress,
    } = options;
    if !valid_fetch_rails(rails) || progress.as_ref().is_some_and(|(quantum, _)| *quantum == 0) {
        return Err(Error::InvalidArguments);
    }
    let config = client_config()?;
    let connect = || {
        let carrier = Transport::connect(local_for(address)?, address, Some("localhost"), &config)
            .map_err(carrier_failure)?;
        verify_serve_identity(&carrier, serve_identity)?;
        Ok(carrier)
    };
    let shared = progress.map(|(quantum, observer)| {
        (
            quantum,
            std::sync::Arc::new(std::sync::Mutex::new((0_u64, observer))),
        )
    });
    let forwarded = shared.as_ref().map(|(quantum, shared)| {
        let forward = std::sync::Arc::clone(shared);
        let forward: crate::Progress = Box::new(move |placed, total| {
            if let Ok(mut state) = forward.lock() {
                state.0 = placed;
                (state.1)(placed, total);
            }
        });
        (*quantum, forward)
    });
    let (outcome, _) = fetch_over_configured(
        connect()?,
        connect,
        bundle,
        pin,
        rails,
        extensions,
        holder,
        provers,
        forwarded,
    )?;
    if let Some((_, shared)) = &shared
        && let Ok(mut state) = shared.lock()
    {
        let length = outcome.package.logical_length;
        if state.0 < length {
            state.0 = length;
            (state.1)(length, Some(length));
        }
    }
    Ok(outcome.package)
}

/// Whether a caller's rail count is one the serve side can seat.
pub(super) const fn valid_fetch_rails(rails: usize) -> bool {
    rails != 0 && rails <= super::MAX_FETCH_RAILS
}

/// Splits one fetch's proof workers across its rails without leaving a rail
/// unable to place what it receives.
///
/// Never zero, whatever `VOT_FETCH_PROVERS` names: a fetch with no prover
/// books no coverage, so it would place nothing and stall. One is the
/// minimum, and `set_proving_threads` refuses anything less.
pub(super) fn provers_per_rail(provers: usize, rails: usize) -> usize {
    (provers / rails.max(1)).max(1)
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
         fec_abandoned={} fec_refused={} fec_symbols={} fec_symbol_drops={}",
        elapsed.as_millis(),
        fec.offered,
        fec.coded,
        fec.decoded,
        fec.abandoned,
        fec.refused,
        fec.symbols,
        fec.symbol_drops
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
    let identity = identity_from(std::env::var(FETCH_SERVE_IDENTITY).ok().as_deref())?;
    let key = crate::rendezvous::key_of(&root);
    let open = |service: SocketAddr| -> Result<(Transport, SocketAddr), Error> {
        let punched = punch(key, service)?;
        let serve = punched.serve;
        let carrier = Transport::connect_on(punched.socket, serve, Some("localhost"), &config)
            .map_err(carrier_failure)?;
        if carrier.connected_within(PUNCH_WAIT) {
            verify_serve_identity(&carrier, identity)?;
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
            // The relay forwards datagrams; the handshake, and so the
            // certificate this checks, is the serve's own.
            verify_serve_identity(
                &carrier,
                identity_from(std::env::var(FETCH_SERVE_IDENTITY).ok().as_deref())?,
            )?;
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
