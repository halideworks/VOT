//! Relay protocol: a slot is a port that forwards datagrams between two ends
//! and reads none of them.
//!
//! ADR-0034 step 2. Both ends reach the relay outbound, which is why this
//! works where a punch does not: neither has to accept a packet it did not
//! ask for. Nothing is wrapped, so a relayed datagram is exactly the size of
//! a direct one and path-MTU discovery still measures the real path.
//!
//! Socket-independent, like the rendezvous beside it. Time is injected so
//! expiry is testable, and every bound is a count this code holds rather than
//! a policy a deployment is trusted to set.

use std::net::SocketAddr;

use crate::rendezvous::{AddressSlot, canonical, pull_address, push_address};

/// Lead byte for relay control datagrams. Below the QUIC range and distinct
/// from the rendezvous magic, so a datagram sent to the wrong service is shed
/// rather than half read.
pub(crate) const MAGIC: u8 = 0x1E;

/// The version after the magic, so the exchange can change shape later.
const VERSION: u8 = 1;

/// Every request is padded to the widest reply so the relay amplifies
/// nothing. A relay that answered a short request with a long reply would be
/// a reflector.
const REQUEST_BYTES: usize = 3 + 32 + 1 + 16 + 2;

/// What one relay control datagram says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Datagram {
    /// A fetch asking for a slot under a rendezvous key. The key is the same
    /// one the rendezvous service pairs on, so the relay never learns a root.
    Take { key: [u8; 32] },
    /// Where the slot is, or nothing when the relay has none to give.
    Slot {
        key: [u8; 32],
        at: Option<SocketAddr>,
    },
}

/// Encodes one control datagram.
pub(crate) fn encode(datagram: &Datagram) -> Vec<u8> {
    let mut wire = vec![MAGIC, VERSION];
    match datagram {
        Datagram::Take { key } => {
            wire.push(1);
            wire.extend_from_slice(key);
            wire.resize(REQUEST_BYTES, 0);
        }
        Datagram::Slot { key, at } => {
            wire.push(2);
            wire.extend_from_slice(key);
            push_address(&mut wire, *at);
        }
    }
    wire
}

/// Decodes one control datagram, or nothing for bytes that are not one.
///
/// Nothing here is a peer fault: a stray datagram on an open UDP port is
/// weather, and the caller sheds it.
#[must_use]
pub(crate) fn decode(bytes: &[u8]) -> Option<Datagram> {
    let [MAGIC, VERSION, kind, rest @ ..] = bytes else {
        return None;
    };
    match kind {
        1 => {
            if rest.len() != REQUEST_BYTES - 3 {
                return None;
            }
            let (key, padding) = rest.split_at_checked(32)?;
            // Padding that carried bytes would be a covert channel through
            // the relay's logs.
            if padding.iter().any(|byte| *byte != 0) {
                return None;
            }
            Some(Datagram::Take {
                key: key.try_into().ok()?,
            })
        }
        2 => {
            let (key, address) = rest.split_at_checked(32)?;
            let at = match pull_address(address) {
                AddressSlot::Invalid => return None,
                AddressSlot::Empty => None,
                AddressSlot::Held(address) => Some(address),
            };
            Some(Datagram::Slot {
                key: key.try_into().ok()?,
                at,
            })
        }
        _ => None,
    }
}

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

/// The relay's control side: which keys hold a slot, and whether there is
/// room for another.
#[derive(Debug, Default)]
pub(crate) struct Slots {
    open: Vec<([u8; 32], SocketAddr, u64)>,
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
        self.open.push((key, at, expires_at_ms));
    }

    /// The live slot `key` already holds, if any.
    pub(crate) fn held(&self, key: [u8; 32], now_ms: u64) -> Option<SocketAddr> {
        self.open
            .iter()
            .find(|(held, _, expires)| *held == key && *expires > now_ms)
            .map(|(_, at, _)| *at)
    }

    /// Drops what has expired. Called before every admission, so a relay that
    /// is asked for slots keeps its table swept and one that is not costs
    /// nothing to hold.
    pub(crate) fn retire(&mut self, now_ms: u64) {
        self.open.retain(|(_, _, expires)| *expires > now_ms);
    }

    /// Slots open at `now_ms`. Compiled with the tests, which is where the
    /// bound is checked; nothing on the serving path asks.
    #[cfg(test)]
    pub(crate) fn live(&self, now_ms: u64) -> usize {
        self.open
            .iter()
            .filter(|(_, _, expires)| *expires > now_ms)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_control_datagram_round_trips_and_a_stray_one_does_not() {
        let key = [3; 32];
        for datagram in [
            Datagram::Take { key },
            Datagram::Slot { key, at: None },
            Datagram::Slot {
                key,
                at: Some(at("198.51.100.7:9000")),
            },
            Datagram::Slot {
                key,
                at: Some(at("[2001:db8::7]:9000")),
            },
        ] {
            let wire = encode(&datagram);
            assert_eq!(wire[0], MAGIC);
            assert!(wire[0] < 0x40, "the magic can never open a QUIC packet");
            assert_ne!(
                wire[0],
                crate::rendezvous::MAGIC,
                "a relay datagram reads as a rendezvous one"
            );
            assert_eq!(decode(&wire), Some(datagram), "{datagram:?}");
        }

        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[MAGIC]), None);
        assert_eq!(decode(&[MAGIC, VERSION]), None);
        assert_eq!(decode(&[MAGIC, VERSION, 9, 0]), None, "an unknown kind");
        assert_eq!(
            decode(&[crate::rendezvous::MAGIC, VERSION, 1]),
            None,
            "a rendezvous datagram is not a relay one"
        );
        // Padding that carries bytes is a covert channel.
        let mut spoiled = encode(&Datagram::Take { key });
        *spoiled.last_mut().expect("padding") = 1;
        assert_eq!(decode(&spoiled), None);
        // And a truncated request is not a request.
        let short = encode(&Datagram::Take { key });
        assert_eq!(decode(&short[..short.len() - 1]), None);
    }

    #[test]
    fn a_reply_is_never_larger_than_the_request_that_earned_it() {
        let request = encode(&Datagram::Take { key: [0; 32] });
        let widest = encode(&Datagram::Slot {
            key: [0; 32],
            at: Some(at("[2001:db8::7]:65535")),
        });
        // Exactly, not at most. The padding exists to make these two equal,
        // so a padding size that merely happens to be large enough is a size
        // nothing holds: the next address family added would outgrow it
        // silently.
        assert_eq!(
            request.len(),
            REQUEST_BYTES,
            "a request is not the size the padding claims"
        );
        assert_eq!(
            widest.len(),
            REQUEST_BYTES,
            "the widest reply and the request are not the same size"
        );
        // And the narrowest reply is smaller, so the padding is padding
        // rather than the reply's own length.
        assert!(
            encode(&Datagram::Slot {
                key: [0; 32],
                at: None
            })
            .len()
                < REQUEST_BYTES
        );
    }

    #[test]
    fn a_slot_pairs_the_first_two_and_nobody_else() {
        let first = at("198.51.100.7:9000");
        let second = at("203.0.113.9:60123");
        let third = at("192.0.2.1:1234");

        let ends = Ends::None;
        // The first arrival has nowhere to go: the other end has not spoken.
        let (ends, to) = ends.route(first);
        assert_eq!((ends, to), (Ends::One(first), None));
        // The same end again is still one end.
        let (ends, to) = ends.route(first);
        assert_eq!((ends, to), (Ends::One(first), None));
        // The second pairs, and its datagram goes to the first.
        let (ends, to) = ends.route(second);
        assert_eq!((ends, to), (Ends::Both(first, second), Some(first)));
        // Then each goes to the other, in both directions.
        assert_eq!(ends.route(first), (ends, Some(second)));
        assert_eq!(ends.route(second), (ends, Some(first)));
        // And a third address is not part of this slot.
        assert_eq!(ends.route(third), (ends, None));
    }

    #[test]
    fn a_dual_stack_relay_reads_one_end_as_one_end() {
        // A relay bound to `[::]` sees an IPv4 peer as `::ffff:a.b.c.d`. The
        // same peer arriving in the mapped form is not a third address.
        let plain = at("198.51.100.7:9000");
        let mapped = at("[::ffff:198.51.100.7]:9000");
        let other = at("203.0.113.9:60123");
        let (ends, _) = Ends::None.route(mapped);
        assert_eq!(ends, Ends::One(plain), "the mapped form was kept as one");
        let (ends, to) = ends.route(other);
        assert_eq!(to, Some(plain));
        assert_eq!(ends.route(mapped), (ends, Some(other)));
    }

    #[test]
    fn a_slot_forwards_to_its_ceiling_and_not_one_byte_past() {
        let first = at("198.51.100.7:9000");
        let second = at("203.0.113.9:60123");
        let mut meter = Meter::new(1_000, 100);
        assert_eq!(meter.take(first, 40, 0), Forward::Nowhere, "nobody yet");
        assert_eq!(meter.take(second, 40, 0), Forward::To(first));
        assert_eq!(meter.forwarded(), 40);
        assert_eq!(
            meter.take(first, 60, 0),
            Forward::To(second),
            "exactly full"
        );
        assert_eq!(meter.forwarded(), 100);
        assert_eq!(meter.take(second, 1, 0), Forward::Closed, "one byte past");
        assert_eq!(meter.forwarded(), 100, "the refused byte was not counted");
    }

    #[test]
    fn waiting_for_the_ends_does_not_claim_one() {
        // A slot idles until its ends find it: the invitation has to reach
        // the serving end first. Asking whether it has expired must not look
        // like an arrival, or the first real end pairs with nothing and the
        // second is a third address.
        let first = at("198.51.100.7:9000");
        let second = at("203.0.113.9:60123");
        let mut meter = Meter::new(10_000, u64::MAX);
        for tick in 0..50 {
            assert!(!meter.expired(tick * 200), "closed early at {tick}");
        }
        assert_eq!(meter.take(first, 10, 0), Forward::Nowhere);
        assert_eq!(
            meter.take(second, 10, 0),
            Forward::To(first),
            "the ends did not pair after the slot waited for them"
        );
        assert_eq!(meter.take(first, 10, 0), Forward::To(second));
    }

    #[test]
    fn a_slot_closes_when_its_time_is_up() {
        let first = at("198.51.100.7:9000");
        let second = at("203.0.113.9:60123");
        let mut meter = Meter::new(1_000, u64::MAX);
        assert_eq!(meter.take(first, 10, 999), Forward::Nowhere);
        assert_eq!(meter.take(second, 10, 999), Forward::To(first));
        assert_eq!(meter.take(first, 10, 1_000), Forward::Closed, "the bound");
        assert_eq!(meter.take(first, 10, 5_000), Forward::Closed);
    }

    #[test]
    fn a_length_that_would_overflow_the_count_closes_the_slot() {
        let first = at("198.51.100.7:9000");
        let second = at("203.0.113.9:60123");
        let mut meter = Meter::new(1_000, u64::MAX);
        meter.take(first, 1, 0);
        assert_eq!(meter.take(second, 1, 0), Forward::To(first));
        assert_eq!(meter.take(first, u64::MAX, 0), Forward::Closed);
    }

    #[test]
    fn the_table_admits_to_its_bound_and_lets_expiry_make_room() {
        let limits = Limits {
            concurrent: 2,
            ttl_ms: 1_000,
            bytes: 1 << 20,
        };
        let mut slots = Slots::default();
        assert!(slots.admit([1; 32], 0, limits));
        slots.opened([1; 32], at("198.51.100.7:1"), 1_000);
        assert!(slots.admit([2; 32], 0, limits));
        slots.opened([2; 32], at("198.51.100.7:2"), 1_000);
        assert!(!slots.admit([3; 32], 0, limits), "past the bound");
        assert_eq!(slots.live(0), 2);

        // A key that already holds one is answered with it rather than given
        // a second, so a repeated Take cannot spend the table.
        assert!(!slots.admit([1; 32], 0, limits));
        assert_eq!(slots.held([1; 32], 0), Some(at("198.51.100.7:1")));
        assert_eq!(slots.held([3; 32], 0), None);

        // Expiry makes room, and an expired slot is not held.
        assert_eq!(slots.held([1; 32], 1_000), None, "expired at the bound");
        assert_eq!(slots.live(1_000), 0);
        assert!(slots.admit([3; 32], 1_000, limits));
    }

    #[test]
    fn the_default_bounds_are_a_donation_rather_than_a_proxy() {
        let limits = Limits::default();
        assert!(limits.concurrent > 0 && limits.concurrent <= 64);
        assert!(limits.ttl_ms > 0, "a slot that never expires is a proxy");
        assert!(limits.bytes > 0);
    }
}
