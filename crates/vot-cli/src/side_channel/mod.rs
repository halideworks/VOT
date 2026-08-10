//! Side-channel infrastructure the rendezvous and the relay share.
//!
//! One codec, so a fetch that can read one service's answer can read the
//! other's; neither protocol imports the other.

pub(crate) mod address;
pub(crate) mod padded;
