//! The context-bound rendezvous key.

/// The context string the rendezvous key is derived under, which is what
/// keeps that derivation from colliding with any other use of the root.
pub(crate) const KEY_CONTEXT: &str = "VOT 2026-08 rendezvous key v1";

/// Derives the rendezvous key from a package root. Must stay this exact
/// derivation forever (protocol identity).
pub(crate) fn key_of(root: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(KEY_CONTEXT, root)
}
