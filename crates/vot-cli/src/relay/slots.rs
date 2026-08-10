//! The bounded slot leases the relay's control side hands out.

use std::net::SocketAddr;

/// What an operator lets this relay give away.
///
/// Every field is a hard bound rather than a target: relaying is a donation
/// of somebody's bandwidth, and a relay that could be asked for more than its
/// operator agreed to is an open proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Limits {
    /// Slots open at once.
    pub concurrent: usize,
    /// How long a slot lives, whether or not it carries anything.
    pub ttl_ms: u64,
    /// Bytes one slot forwards before it closes.
    pub bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            concurrent: 8,
            // Long enough for a transfer to start and finish on a slow path,
            // short enough that an abandoned slot is not a standing donation.
            ttl_ms: 600_000,
            bytes: 8 << 30,
        }
    }
}

/// The relay's control side: which keys hold a slot, and whether there is
/// room for another.
#[derive(Debug, Default)]
pub(crate) struct Slots {
    open: Vec<SlotLease>,
}

/// One open slot: whose key holds it, where it answers, and until when.
#[derive(Debug)]
struct SlotLease {
    key: [u8; 32],
    at: SocketAddr,
    expires_at_ms: u64,
}

impl Slots {
    /// The answer to a `Take` for `key` at `now_ms`, given a slot the caller
    /// has just opened, or none when there is no room.
    ///
    /// The caller opens the socket only when this says there is room for it,
    /// which is what keeps the bound a count of sockets rather than a hope.
    pub(crate) fn admit(&mut self, key: [u8; 32], now_ms: u64, limits: Limits) -> bool {
        self.retire(now_ms);
        // A key that already holds a slot is answered with that slot rather
        // than a second one, so a repeated Take cannot spend the table.
        if self.held(key, now_ms).is_some() {
            return false;
        }
        self.open.len() < limits.concurrent
    }

    /// Records a slot this relay has opened for `key`.
    pub(crate) fn opened(&mut self, key: [u8; 32], at: SocketAddr, expires_at_ms: u64) {
        self.open.push(SlotLease {
            key,
            at,
            expires_at_ms,
        });
    }

    /// The live slot `key` already holds, if any.
    pub(crate) fn held(&self, key: [u8; 32], now_ms: u64) -> Option<SocketAddr> {
        self.open
            .iter()
            .find(|lease| lease.key == key && lease.expires_at_ms > now_ms)
            .map(|lease| lease.at)
    }

    /// Drops what has expired. Called before every admission, so a relay that
    /// is asked for slots keeps its table swept and one that is not costs
    /// nothing to hold.
    pub(crate) fn retire(&mut self, now_ms: u64) {
        self.open.retain(|lease| lease.expires_at_ms > now_ms);
    }

    /// Slots open at `now_ms`. Compiled with the tests, which is where the
    /// bound is checked; nothing on the serving path asks.
    #[cfg(test)]
    pub(crate) fn live(&self, now_ms: u64) -> usize {
        self.open
            .iter()
            .filter(|lease| lease.expires_at_ms > now_ms)
            .count()
    }
}
