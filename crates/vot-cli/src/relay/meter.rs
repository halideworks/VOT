//! One slot's pairing and accounting.

use std::net::SocketAddr;

use crate::side_channel::address::canonical;

/// The two ends of a slot, learned from who sends to it.
///
/// A slot pairs the first two distinct sources it hears and nothing after
/// them. That is the whole admission rule, and it is what keeps a slot from
/// becoming a general-purpose forwarder: there is no third end to address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Ends {
    /// Nobody has sent yet.
    #[default]
    None,
    /// One end is known and is waiting for the other.
    One(SocketAddr),
    /// Both are known, and each one's datagrams go to the other.
    Both(SocketAddr, SocketAddr),
}

impl Ends {
    /// Where a datagram from `source` goes, and what the ends are afterwards.
    ///
    /// Nothing to send is the answer for the first arrival, which has nobody
    /// to go to yet, and for a third party, which is not part of this slot.
    pub(crate) fn route(self, source: SocketAddr) -> (Self, Option<SocketAddr>) {
        let source = canonical(source);
        match self {
            Self::None => (Self::One(source), None),
            Self::One(first) if first == source => (Self::One(first), None),
            Self::One(first) => (Self::Both(first, source), Some(first)),
            Self::Both(first, second) if source == first => (self, Some(second)),
            Self::Both(first, second) if source == second => (self, Some(first)),
            // A third address. The slot has two ends and this is not one.
            Self::Both(..) => (self, None),
        }
    }
}

/// One slot's accounting, which the thread owning its socket keeps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Meter {
    ends: Ends,
    forwarded: u64,
    expires_at_ms: u64,
    bytes: u64,
}

/// What a slot does with one arrival.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Forward {
    /// Send these bytes to this address.
    To(SocketAddr),
    /// Take it and send nothing: the first arrival, or a third party.
    Nowhere,
    /// The slot is done. Whether it spent its time or its bytes, it closes.
    Closed,
}

impl Meter {
    /// A slot open until `expires_at_ms` that will forward `bytes`.
    pub(crate) const fn new(expires_at_ms: u64, bytes: u64) -> Self {
        Self {
            ends: Ends::None,
            forwarded: 0,
            expires_at_ms,
            bytes,
        }
    }

    /// Whether this slot's lifetime is over at `now_ms`.
    ///
    /// Separate from [`Meter::take`] because a slot with nothing to forward
    /// still has to notice its own expiry, and asking `take` would route a
    /// stand-in address through the pairing rule and claim an end with it.
    pub(crate) const fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// What to do with `length` bytes from `source` at `now_ms`.
    ///
    /// The ceiling is checked against the datagram that would cross it, not
    /// after it has: a slot forwards up to its ceiling and not one byte past.
    pub(crate) fn take(&mut self, source: SocketAddr, length: u64, now_ms: u64) -> Forward {
        if self.expired(now_ms) {
            return Forward::Closed;
        }
        let (ends, to) = self.ends.route(source);
        self.ends = ends;
        let Some(to) = to else {
            return Forward::Nowhere;
        };
        let Some(forwarded) = self.forwarded.checked_add(length) else {
            return Forward::Closed;
        };
        if forwarded > self.bytes {
            return Forward::Closed;
        }
        self.forwarded = forwarded;
        Forward::To(to)
    }

    /// Bytes this slot has forwarded, for the line the relay prints when it
    /// closes one.
    pub(crate) const fn forwarded(&self) -> u64 {
        self.forwarded
    }
}
