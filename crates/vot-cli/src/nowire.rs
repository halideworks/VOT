//! What the wire commands are without the carrier that answers them.
//!
//! A module rather than two functions beside their real versions, because
//! a mutation run resolves `mod` against the features it was given: a file
//! the configuration excludes is never read, where a function excluded
//! inside a file it does read is mutated into code that compiles, runs
//! nowhere, and is reported as a mutant nothing caught.

use std::net::SocketAddr;
use std::path::Path;

use crate::{Credentials, Error, PackageSummary};

/// Names the feature that carries the command, rather than failing as
/// though the caller got the arguments wrong.
///
/// # Errors
/// Always [`Error::WireUnsupported`].
pub fn serve_bundle(
    _bundle: &Path,
    _address: SocketAddr,
    _credentials: &Credentials,
    _sessions: Option<u32>,
    _listening: impl FnMut(SocketAddr),
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}

/// See [`serve_bundle`].
///
/// # Errors
/// Always [`Error::WireUnsupported`].
pub fn fetch_bundle(
    _address: SocketAddr,
    _bundle: &Path,
    _pin: Option<[u8; 32]>,
) -> Result<PackageSummary, Error> {
    Err(Error::WireUnsupported)
}
