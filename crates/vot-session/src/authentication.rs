//! What this endpoint does about authentication.

use super::{AuthContext, Binding};

/// What this endpoint does about authentication.
///
/// `spec/wire.md` section 1.1 makes the exchange unconditional, so a caller
/// names its stance rather than opting in. Two of the three are for one role
/// only, and [`crate::Session::begin`] refuses a stance the role cannot act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authentication {
    /// No authentication required. The exchange concludes at `AUTH_CONTEXT`.
    ///
    /// The nonce is caller-supplied: this crate has no randomness. A client
    /// ignores it.
    NotRequired { nonce: [u8; 32] },
    /// A server that asks for a capability. The exchange concludes at
    /// `SESSION_ACCEPT`. The caller decides what a capability is worth through
    /// [`crate::Session::pending_authorization`], [`crate::Session::grant`], and
    /// [`crate::Session::refuse`].
    Capability { challenge: AuthContext },
    /// A client that answers a capability challenge. The caller builds the
    /// request and passes it to [`crate::Session::present`].
    Presenting,
}

/// Attempts a server accepts before closing, from `spec/wire.md` section 1.1.
///
/// Fixed rather than negotiated so both sides know it without a setting, and
/// it bounds the work an unauthenticated peer can ask for.
pub const MAX_AUTHENTICATION_ATTEMPTS: usize = 3;

/// The challenge a deployment requiring no authentication advertises.
///
/// No capability format, which `spec/wire.md` section 1.1 defines as requiring
/// none. The nonce is still fresh per session: a client that later binds to it
/// must not find a constant.
#[must_use]
pub fn no_capability(nonce: [u8; 32]) -> AuthContext {
    AuthContext {
        nonce: nonce.to_vec(),
        binding: Binding::None,
        formats: Vec::new(),
    }
}
