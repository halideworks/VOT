//! Wire command stubs used when the transport feature is disabled.

use std::net::SocketAddr;
use std::path::Path;

use crate::{Credentials, Error, PackageSummary};

/// Returns [`Error::WireUnsupported`] unconditionally.
pub fn serve_bundle(
    _bundle: &Path,
    _address: SocketAddr,
    _credentials: &Credentials,
    _sessions: Option<u32>,
    _listening: impl FnMut(SocketAddr, [u8; 32]),
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
