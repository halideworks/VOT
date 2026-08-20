//! Bounded environment parsing and carrier configuration.

use super::{Config, CongestionControl, Error, Path, ReceiveLimits, SocketAddr};

/// Inbound receive limits matched to the codec's default settings.
pub(crate) fn limits() -> Result<ReceiveLimits, Error> {
    ReceiveLimits::advertised(
        &vot_codec::Settings::default(),
        vot_transport_quiche::INBOUND_BYTE_CAPACITY,
    )
    .map_err(|_| Error::InvalidArguments)
}

/// The environment variable that pins the datagram ceiling.
pub(crate) const DATAGRAM_BYTES: &str = "VOT_DATAGRAM_BYTES";

/// Opens the datagram ceiling to the maximum and lets PMTU discovery
/// settle it. [`DATAGRAM_BYTES`] overrides if set.
///
/// # Errors
/// Rejects a value that is not a number. The carrier rejects one outside
/// what it can carry.
pub(crate) fn apply_datagram_bytes(config: &mut Config) -> Result<(), Error> {
    config.max_datagram_bytes = vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE;
    let Ok(value) = std::env::var(DATAGRAM_BYTES) else {
        return Ok(());
    };
    apply_datagram_value(config, &value)
}

/// Parses and validates [`DATAGRAM_BYTES`] against the carrier's bounds.
pub(crate) fn apply_datagram_value(config: &mut Config, value: &str) -> Result<(), Error> {
    config.max_datagram_bytes = bounded(
        value,
        vot_transport_quiche::live::MIN_DATAGRAM_SIZE
            ..=vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE,
    )?;
    Ok(())
}

/// A number `bounds` admits, however it was spaced.
///
/// Every environment number here is rejected rather than clamped: an
/// operator who wrote a value this cannot read has said something, and
/// guessing is not reading it.
fn bounded(value: &str, bounds: std::ops::RangeInclusive<usize>) -> Result<usize, Error> {
    let parsed = value.trim().parse().map_err(|_| Error::InvalidArguments)?;
    if !bounds.contains(&parsed) {
        return Err(Error::InvalidArguments);
    }
    Ok(parsed)
}

/// A positive count, of anything zero would disable.
fn positive(value: &str) -> Result<u64, Error> {
    match value.trim().parse().map_err(|_| Error::InvalidArguments)? {
        0 => Err(Error::InvalidArguments),
        value => Ok(value),
    }
}

/// The environment variable that picks the congestion controller.
pub(crate) const CONGESTION: &str = "VOT_CONGESTION";

/// The environment variable that seeds the initial congestion window, in
/// packets. The sender's window governs a transfer, so it matters on the
/// serve; at any real round-trip time slow start from the default ten
/// packets is most of a small transfer's wall clock, and an operator who
/// knows the path skips it. The controller still collapses the window on
/// loss, so a wrong value costs one round of loss, not correctness.
pub(crate) const INITIAL_CWND: &str = "VOT_INITIAL_CWND";

/// The most packets [`INITIAL_CWND`] accepts: 64 MB of 1500-byte packets,
/// past any bandwidth-delay product this moves well on.
const MAX_INITIAL_CWND: usize = 44_739;

/// The window [`INITIAL_CWND`] names, or nothing when unset.
///
/// # Errors
/// Rejects a value that is not a number or is outside 10 to
/// [`MAX_INITIAL_CWND`] packets: below the default it is a lie about the
/// path, and unbounded it is a burst the first loss pays for.
pub(crate) fn initial_cwnd_from(pin: Option<&str>) -> Result<Option<usize>, Error> {
    pin.map(|value| bounded(value, 10..=MAX_INITIAL_CWND))
        .transpose()
}

/// The environment variable that pins the serve's identity: the 64 hex
/// characters of the blake3 digest of its certificate in DER, as the serve
/// prints at startup. Unset accepts any serve; the package root still holds
/// whoever answers to the right bytes.
pub(crate) const FETCH_SERVE_IDENTITY: &str = "VOT_FETCH_SERVE_IDENTITY";

/// The pin [`FETCH_SERVE_IDENTITY`] names, or nothing when unset.
///
/// # Errors
/// Rejects a value that is not 64 hex characters.
pub(crate) fn identity_from(pin: Option<&str>) -> Result<Option<[u8; 32]>, Error> {
    pin.map(str::trim)
        .map(crate::parse_package_root)
        .transpose()
}

/// The environment variable that controls the experimental datagram FEC
/// extension. Automatic unless explicitly disabled.
pub(crate) const DATAGRAM_FEC: &str = "VOT_DATAGRAM_FEC";

/// The extensions [`DATAGRAM_FEC`] names: unset or `auto` offer automatic FEC;
/// `1`, `on`, or `true` offer forced FEC; `0`, `off`, or `false` offer nothing.
///
/// # Errors
/// Rejects any other value.
pub(crate) fn extensions_from(pin: Option<&str>) -> Result<std::collections::BTreeSet<u64>, Error> {
    match pin
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("0" | "off" | "false") => Ok(std::collections::BTreeSet::new()),
        None | Some("1" | "on" | "true" | "auto") => Ok(std::collections::BTreeSet::from([
            vot_codec::extension_id::DATAGRAM_FEC,
        ])),
        Some(_) => Err(Error::InvalidArguments),
    }
}

/// Whether a validated [`DATAGRAM_FEC`] value asks the server to activate it
/// only after measured loss reaches its WAN crossover.
pub(crate) fn automatic_fec(pin: Option<&str>) -> bool {
    pin.is_none_or(|value| value.trim().eq_ignore_ascii_case("auto"))
}

/// The environment variable that asks a fetch to report what it measured.
pub(crate) const FETCH_STATS: &str = "VOT_FETCH_STATS";

/// Whether [`FETCH_STATS`] asks for the report, spelled as
/// [`extensions_from`] spells its switch.
///
/// # Errors
/// Rejects any other value.
pub(crate) fn stats_wanted(pin: Option<&str>) -> Result<bool, Error> {
    match pin
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("0" | "off" | "false") => Ok(false),
        Some("1" | "on" | "true") => Ok(true),
        Some(_) => Err(Error::InvalidArguments),
    }
}

/// The environment variable that sets how many rails a fetch runs.
pub(crate) const FETCH_RAILS: &str = "VOT_FETCH_RAILS";

/// Maximum fetch rails. Capped at the serve-side session limit because
/// excess rails stall waiting for accepts.
pub(crate) const MAX_FETCH_RAILS: usize = crate::drive::CONCURRENT_SESSIONS;

/// The width [`FETCH_RAILS`] names, or two rails per available core when unset.
///
/// # Errors
/// Rejects a value that is not a number, zero, or a width past the bound.
pub(crate) fn rails_from(pin: Option<&str>, cores: usize) -> Result<usize, Error> {
    let Some(value) = pin else {
        return Ok(cores.saturating_mul(2).clamp(1, MAX_FETCH_RAILS));
    };
    bounded(value, 1..=MAX_FETCH_RAILS)
}

/// The controller [`CONGESTION`] names, or bbr2 when unset.
///
/// # Errors
/// Rejects a value naming neither controller.
pub(crate) fn congestion_from(pin: Option<&str>) -> Result<CongestionControl, Error> {
    match pin.map(str::trim) {
        None | Some("bbr2") => Ok(CongestionControl::Bbr2),
        Some("cubic") => Ok(CongestionControl::Cubic),
        Some(_) => Err(Error::InvalidArguments),
    }
}

/// Bytes between progress lines. 256 MiB: visible on both fast and slow links.
pub(crate) const PROGRESS_QUANTUM_BYTES: u64 = 268_435_456;

/// The issuer key a serve accepts capabilities from, as a `KEY_SOURCE`.
pub(crate) const SERVE_ISSUER: &str = "VOT_SERVE_ISSUER";

/// The issuer name that key signs under.
pub(crate) const SERVE_ISSUER_NAME: &str = "VOT_SERVE_ISSUER_NAME";

/// The deployment a capability must name.
pub(crate) const SERVE_AUDIENCE: &str = "VOT_SERVE_AUDIENCE";

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
pub(crate) fn requirement_from(
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

/// Slots this relay opens at once, its slot lifetime in milliseconds, and the
/// bytes one slot forwards. Each is a hard bound the operator sets.
pub(crate) const RELAY_SLOTS: &str = "VOT_RELAY_SLOTS";

pub(crate) const RELAY_TTL_MS: &str = "VOT_RELAY_TTL_MS";

pub(crate) const RELAY_BYTES: &str = "VOT_RELAY_BYTES";

/// The relay's bounds, from the environment or the defaults.
///
/// Every value is parsed and rejected here rather than clamped: an operator
/// who wrote a number this cannot read has said something, and guessing what
/// would be a donation they did not agree to.
///
/// # Errors
/// Rejects a value that is not a number, and a zero, which would be a relay
/// that opens no slots or closes them the instant they open.
pub(crate) fn relay_limits_from(
    slots: Option<&str>,
    ttl_ms: Option<&str>,
    bytes: Option<&str>,
) -> Result<crate::relay::Limits, Error> {
    let default = crate::relay::Limits::default();
    let read = |value: Option<&str>| value.map(positive).transpose();
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

/// Rendezvous service address. Unset means no registration.
pub(crate) const RENDEZVOUS: &str = "VOT_RENDEZVOUS";

/// Relay address, named the way [`RENDEZVOUS`] names a service and parsed
/// by the same [`rendezvous_from`]. Unset means the ladder ends at the
/// punch, by name, as it did before relays existed.
pub(crate) const RELAY: &str = "VOT_RELAY";

/// Every address the service [`RENDEZVOUS`] names, or none when it is
/// unset.
///
/// # Errors
/// Rejects a value that is neither an address nor a name that resolves.
pub(crate) fn rendezvous_from(pin: Option<&str>) -> Result<Vec<SocketAddr>, Error> {
    pin.map_or_else(|| Ok(Vec::new()), crate::parse_rendezvous)
}

/// The capability a fetch presents, as a path to what `vot capability issue`
/// wrote.
pub(crate) const FETCH_CAPABILITY: &str = "VOT_FETCH_CAPABILITY";

/// The holder key that capability names, as a `KEY_SOURCE`.
pub(crate) const FETCH_HOLDER_KEY: &str = "VOT_FETCH_HOLDER_KEY";

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
pub(crate) fn holder_from(
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
