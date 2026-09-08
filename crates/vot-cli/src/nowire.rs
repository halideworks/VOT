//! Wire command stubs used when the transport feature is disabled.

use std::net::SocketAddr;
use std::path::Path;

use crate::{BundleServer, Credentials, Error, FetchOptions, PackageSummary, PushOptions};

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn serve_bundle(
    _bundle: &Path,
    _address: SocketAddr,
    _credentials: &Credentials,
    _sessions: Option<u32>,
    _listening: impl FnMut(SocketAddr, [u8; 32], [u8; 32]),
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn fetch_bundle(
    _address: SocketAddr,
    _bundle: &Path,
    _pin: Option<[u8; 32]>,
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn push_bundle(
    _bundle: &Path,
    _address: SocketAddr,
    _capability: &Path,
    _key_source: &str,
    _identity: [u8; 32],
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn receive_push(
    _address: SocketAddr,
    _directory: &Path,
    _credentials: &Credentials,
    _sessions: Option<u32>,
    _listening: impl FnMut(SocketAddr, [u8; 32]),
) -> Result<(), Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn rendezvous_service(
    _address: SocketAddr,
    _datagrams: Option<u64>,
    _listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn relay_service(
    _address: SocketAddr,
    _datagrams: Option<u64>,
    _listening: impl FnMut(SocketAddr),
) -> Result<(), Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn fetch_via_rendezvous(
    _root: [u8; 32],
    _bundle: &Path,
    _services: &[SocketAddr],
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn push_from(_server: &BundleServer, _options: PushOptions) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn probe_serve(
    _address: SocketAddr,
    _identity: [u8; 32],
    _budget: std::time::Duration,
) -> Result<(), Error> {
    Err(Error::WireUnsupported)
}

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn fetch_bundle_with(_options: FetchOptions, _bundle: &Path) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// Fetch with receive hooks requires the `wire` feature.
///
/// # Errors
/// Returns [`Error::WireUnsupported`] when built without `wire`.
pub fn fetch_bundle_with_seams(
    _options: FetchOptions,
    _bundle: &Path,
    _seams: crate::ReceiveSeams,
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}
