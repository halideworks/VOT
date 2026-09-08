//! What a library caller hands a push or a fetch, in place of the
//! environment variables the CLI commands read.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::authz::Holder;

/// Where a transfer's progress goes: bytes so far and the total when it is
/// known. Called at most once per `quantum` bytes, and once at the end if
/// the last quantum fell short of it. A zero quantum is refused.
pub type Progress = Box<dyn FnMut(u64, Option<u64>) + Send>;

/// One push from a [`BundleServer`](crate::BundleServer) the caller holds.
pub struct PushOptions {
    /// The receiver's push listener.
    pub address: SocketAddr,
    /// The `PUBLISH` capability and the key that proves possession of it.
    pub holder: Arc<Holder>,
    /// The digest of the certificate the receiver must present.
    pub identity: [u8; 32],
    /// Sessions dialled at once, one to the receiver's session limit (eight).
    pub rails: usize,
    /// Extensions offered on every rail, as `VOT_DATAGRAM_FEC` names them.
    pub extensions: BTreeSet<u64>,
    /// Bytes the carriers have taken so far, framing included, reported
    /// every `quantum` bytes with no total: the sender does not know how
    /// much of what it offers the receiver will ask for.
    pub progress: Option<(u64, Progress)>,
}

/// One fetch into a bundle directory.
pub struct FetchOptions {
    /// The serve to dial.
    pub address: SocketAddr,
    /// The capability the serve requires, or none for an open serve.
    pub holder: Option<Arc<Holder>>,
    /// The digest the serve's certificate must have, or none to accept any.
    pub serve_identity: Option<[u8; 32]>,
    /// The package root the fetch must land on, or none to take what the
    /// serve announces.
    pub pin: Option<[u8; 32]>,
    /// Sessions dialled at once, one to the fetch rail limit.
    pub rails: usize,
    /// Proof workers for the whole fetch, split across its rails; none takes
    /// the fetcher's default.
    pub provers: Option<usize>,
    /// Extensions offered on every rail, as `VOT_DATAGRAM_FEC` names them.
    pub extensions: BTreeSet<u64>,
    /// Bytes placed so far and the package length once known, reported
    /// every `quantum` bytes.
    pub progress: Option<(u64, Progress)>,
}
