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

mod meter;
mod slots;
mod wire;

pub(crate) use meter::*;
pub(crate) use slots::*;
pub(crate) use wire::*;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

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
