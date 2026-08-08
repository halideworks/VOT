//! The rendezvous of ADR-0033: pairing a serve and a fetch by the root.
//!
//! This module is the protocol apart from any socket: the datagrams, the
//! key both ends derive from the root, and the pairing table the service
//! keeps. Time reaches the table as an argument, so every expiry branch
//! is a test's to hold. The socket halves live with the commands that
//! own the sockets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The lead byte of every rendezvous datagram.
///
/// QUIC packets carry the fixed bit: a long header leads 0xC0..=0xFF and
/// a short header 0x40..=0x7F, so 0x00..=0x3F can never open a QUIC
/// packet and the serve's router tells the two apart by one byte.
pub(crate) const MAGIC: u8 = 0x1F;

/// The version after the magic, so the exchange can change shape later
/// without a flag day at the service.
const VERSION: u8 = 1;

/// Every request is padded to the widest reply, so no reply outgrows
/// the request that earned it and the service cannot amplify: magic,
/// version, kind, key, and the widest address encoding.
const REQUEST_BYTES: usize = 3 + 32 + 1 + 16 + 2;

/// What one rendezvous datagram says.
///
/// The whole exchange: a serve registers under its key and keeps doing
/// so (which is also its NAT keepalive), a fetch resolves the key, the
/// service answers the fetch with the serve's mapping and notifies the
/// serve of the fetch's, and the serve warms the path. Replies are never
/// larger than the requests that earn them, so the service amplifies
/// nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Datagram {
    /// A serve's mapping claim: the source address the service observes
    /// is the mapping for exactly the socket sessions arrive at.
    Register { key: [u8; 32] },
    /// The service's answer to a register, so the serve knows it is
    /// findable and its cadence is landing.
    Registered { key: [u8; 32] },
    /// A fetch asking where the key's serve is.
    Resolve { key: [u8; 32] },
    /// The service's answer: the serve's mapping, or nothing yet.
    Resolved {
        key: [u8; 32],
        serve: Option<SocketAddr>,
    },
    /// The service telling the serve a fetch is coming, so the serve
    /// can open its own NAT toward the fetch before the Initial.
    Coming { key: [u8; 32], fetch: SocketAddr },
    /// The serve's warming datagram toward a fetch's mapping. Carries
    /// nothing; arriving is its whole job, and the fetch's router or
    /// socket sheds it.
    Warming,
}

/// Encodes one datagram.
pub(crate) fn encode(datagram: &Datagram) -> Vec<u8> {
    let mut wire = vec![MAGIC, VERSION];
    match datagram {
        Datagram::Register { key } => {
            wire.push(1);
            wire.extend_from_slice(key);
            wire.resize(REQUEST_BYTES, 0);
        }
        Datagram::Registered { key } => {
            wire.push(2);
            wire.extend_from_slice(key);
        }
        Datagram::Resolve { key } => {
            wire.push(3);
            wire.extend_from_slice(key);
            wire.resize(REQUEST_BYTES, 0);
        }
        Datagram::Resolved { key, serve } => {
            wire.push(4);
            wire.extend_from_slice(key);
            push_address(&mut wire, *serve);
        }
        Datagram::Coming { key, fetch } => {
            wire.push(5);
            wire.extend_from_slice(key);
            push_address(&mut wire, Some(*fetch));
        }
        Datagram::Warming => wire.push(6),
    }
    wire
}

/// Decodes one datagram, or nothing for bytes that are not one.
///
/// Nothing here is a peer fault: a stray or malformed datagram on an
/// open UDP port is weather, and the caller sheds it.
#[must_use]
pub(crate) fn decode(bytes: &[u8]) -> Option<Datagram> {
    let [MAGIC, VERSION, kind, rest @ ..] = bytes else {
        return None;
    };
    match (kind, rest.len()) {
        (1, _) => Some(Datagram::Register {
            key: padded_key(rest)?,
        }),
        (2, 32) => Some(Datagram::Registered {
            key: rest.try_into().ok()?,
        }),
        (3, _) => Some(Datagram::Resolve {
            key: padded_key(rest)?,
        }),
        (4, _) => {
            let (key, address) = rest.split_at_checked(32)?;
            let serve = match pull_address(address) {
                AddressSlot::Invalid => return None,
                AddressSlot::Empty => None,
                AddressSlot::Held(address) => Some(address),
            };
            Some(Datagram::Resolved {
                key: key.try_into().ok()?,
                serve,
            })
        }
        (5, _) => {
            let (key, address) = rest.split_at_checked(32)?;
            let AddressSlot::Held(fetch) = pull_address(address) else {
                return None;
            };
            Some(Datagram::Coming {
                key: key.try_into().ok()?,
                fetch,
            })
        }
        (6, 0) => Some(Datagram::Warming),
        _ => None,
    }
}

/// A request's key with its padding held to zero: padding that carries
/// bytes would be a covert channel through the service's logs.
fn padded_key(rest: &[u8]) -> Option<[u8; 32]> {
    if rest.len() != REQUEST_BYTES - 3 {
        return None;
    }
    let (key, padding) = rest.split_at_checked(32)?;
    if padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    key.try_into().ok()
}

/// Appends an optional address: a family byte, then the bytes it names.
fn push_address(wire: &mut Vec<u8>, address: Option<SocketAddr>) {
    match address {
        None => wire.push(0),
        Some(SocketAddr::V4(v4)) => {
            wire.push(4);
            wire.extend_from_slice(&v4.ip().octets());
            wire.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            wire.push(6);
            wire.extend_from_slice(&v6.ip().octets());
            wire.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

/// What an address slot held: bytes that encode no address at all, the
/// explicit no-address marker, or an address.
enum AddressSlot {
    Invalid,
    Empty,
    Held(SocketAddr),
}

/// The inverse of [`push_address`].
fn pull_address(bytes: &[u8]) -> AddressSlot {
    let held = |ip, port| AddressSlot::Held(SocketAddr::new(ip, port));
    match bytes {
        [0] => AddressSlot::Empty,
        [4, rest @ ..] if rest.len() == 6 => {
            let Ok(ip) = <[u8; 4]>::try_from(&rest[..4]) else {
                return AddressSlot::Invalid;
            };
            let Ok(port) = <[u8; 2]>::try_from(&rest[4..6]) else {
                return AddressSlot::Invalid;
            };
            held(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        [6, rest @ ..] if rest.len() == 18 => {
            let Ok(ip) = <[u8; 16]>::try_from(&rest[..16]) else {
                return AddressSlot::Invalid;
            };
            let Ok(port) = <[u8; 2]>::try_from(&rest[16..18]) else {
                return AddressSlot::Invalid;
            };
            held(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port))
        }
        _ => AddressSlot::Invalid,
    }
}

/// The context string the rendezvous key is derived under, which is what
/// keeps that derivation from colliding with any other use of the root.
const KEY_CONTEXT: &str = "VOT 2026-08 rendezvous key v1";

/// The rendezvous key for a package root.
///
/// A derived key rather than the root: the service pairs by it and never
/// learns what it names, and holding it is the same thing as holding the
/// root, which is already the capability to fetch (ADR-0033). Both ends
/// derive it from the string the humans exchanged, so it has to stay
/// exactly this derivation forever.
pub(crate) fn key_of(root: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(KEY_CONTEXT, root)
}

/// How long a registration stands without being refreshed.
///
/// The serve re-registers every [`REGISTER_CADENCE_MS`], so a live serve
/// refreshes several times inside its TTL and a dead one ages out in
/// about a minute, which is also as long as any pairing metadata exists
/// anywhere.
pub(crate) const REGISTRATION_TTL_MS: u64 = 90_000;

/// Registrations one service holds at most, which bounds its memory by
/// a constant however many keys are thrown at it.
pub(crate) const MAX_REGISTRATIONS: usize = 65_536;

/// How often a serve re-registers, which is also what keeps its NAT
/// mapping alive. Several refreshes fit inside [`REGISTRATION_TTL_MS`],
/// so a lost datagram costs findability for one cadence and no more.
pub(crate) const REGISTER_CADENCE_MS: u64 = 20_000;

/// Warming datagrams the serve sends toward a fetch it has been told is
/// coming. More than one because any of them may be the one a NAT drops,
/// and few because they are sent before anything has been verified.
///
/// They go one per pass rather than together: three that leave in the
/// same microsecond down the same path share the fate the redundancy
/// exists to cover.
pub(crate) const WARMING_DATAGRAMS: usize = 3;

/// Warming datagrams a serve will send between registrations, however
/// many fetches the service says are coming.
///
/// This is the whole amplification story of the serving end. One Coming
/// of 54 bytes earns at most [`WARMING_DATAGRAMS`] warmings of 3 bytes,
/// which shrinks bytes and multiplies packets by three, and this bound
/// caps the packets a cadence can be made to emit at 24 no matter how
/// many Comings arrive. The key is what an abuser needs to get one at
/// all, and holding the key is already holding the root.
pub(crate) const WARMINGS_PER_CADENCE: usize = 24;

/// Whether this end will send unprompted datagrams at `fetch`, having
/// been told about it by the service at `service`.
///
/// A Coming names where the serve sends with nothing yet verified, so
/// what cannot be an observed mapping is refused here: the wildcard, a
/// multicast group, a broadcast address, and port zero are nobody's
/// source address. Loopback is refused by the same test rather than
/// listed apart: a service out on the network cannot have observed one,
/// so the mapping is forged, while a service on loopback is this
/// machine's own and a loopback mapping from it is the only kind there
/// is.
fn warmable(fetch: SocketAddr, service: SocketAddr) -> bool {
    if fetch.port() == 0 {
        return false;
    }
    let near = service.ip().is_loopback();
    match fetch.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && (near || !ip.is_loopback())
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast() && (near || !ip.is_loopback()),
    }
}

/// The serve's side of the rendezvous: what it sends and when.
///
/// The whole policy with time as an argument, so every branch is a
/// test's. It owns no socket; the caller sends what this hands back on
/// the listener's own socket, which is the mapping being registered.
pub(crate) struct Registrar {
    key: [u8; 32],
    service: SocketAddr,
    /// When the next registration is due, which is immediately at first.
    due_at_ms: u64,
    /// Warmings earned and not yet sent, drained one per pass.
    warming: std::collections::VecDeque<SocketAddr>,
    /// Warmings this cadence has already earned, against the bound.
    warmed: usize,
}

impl Registrar {
    /// A serve registering `root` with the service at `service`.
    pub(crate) fn new(root: &[u8; 32], service: SocketAddr) -> Self {
        Self {
            key: key_of(root),
            service,
            due_at_ms: 0,
            warming: std::collections::VecDeque::new(),
            warmed: 0,
        }
    }

    /// What to send at `now_ms` with nothing having arrived: a
    /// registration when the cadence is due, and one warming a pass
    /// toward whatever fetches are still owed them.
    pub(crate) fn due(&mut self, now_ms: u64) -> Vec<(SocketAddr, Datagram)> {
        let mut sends = Vec::new();
        if let Some(fetch) = self.warming.pop_front() {
            sends.push((fetch, Datagram::Warming));
        }
        if now_ms >= self.due_at_ms {
            self.due_at_ms = now_ms.saturating_add(REGISTER_CADENCE_MS);
            self.warmed = 0;
            sends.push((self.service, Datagram::Register { key: self.key }));
        }
        sends
    }

    /// What a datagram that arrived from `source` earns.
    ///
    /// Only the service is heard, and only about this serve's own key: a
    /// Coming names an address this end will send to unprompted, so an
    /// arrival from anywhere else would make the serve a reflector. What
    /// it earns is queued rather than returned, because the warmings go
    /// one per pass.
    pub(crate) fn take(&mut self, datagram: Datagram, source: SocketAddr) {
        if source != self.service {
            return;
        }
        let Datagram::Coming { key, fetch } = datagram else {
            // The cadence is unconditional, so a Registered gates
            // nothing: a serve that never hears one registers exactly as
            // often as one that does, and the rest of the shapes are not
            // the service's to send.
            return;
        };
        if key != self.key || !warmable(fetch, self.service) {
            return;
        }
        let room = WARMINGS_PER_CADENCE.saturating_sub(self.warmed);
        let owed = WARMING_DATAGRAMS.min(room);
        self.warmed = self.warmed.saturating_add(owed);
        for _ in 0..owed {
            self.warming.push_back(fetch);
        }
    }
}

/// One registered serve: where it is, and until when it is believed.
struct Registration {
    mapping: SocketAddr,
    expires_at_ms: u64,
}

/// The service's pairing table, time injected in milliseconds so expiry
/// is arithmetic a test holds rather than a clock it waits on.
#[derive(Default)]
pub(crate) struct Pairings {
    registered: HashMap<[u8; 32], Registration>,
}

/// What the service answers one datagram with: replies to the observed
/// source only, plus at most one notification toward a registered serve.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Answer {
    /// Sent back to the datagram's own source.
    pub reply: Option<Datagram>,
    /// Sent to a registered serve's mapping: the fetch that is coming.
    pub notify: Option<(SocketAddr, Datagram)>,
}

impl Pairings {
    /// Takes one datagram as the service, from `source`, at `now_ms`.
    ///
    /// Everything the service does is here: register and refresh under
    /// the bound, resolve to whatever is live, pair the two ends, and
    /// shed what is expired, malformed, or not the service's to answer.
    pub(crate) fn take(&mut self, datagram: Datagram, source: SocketAddr, now_ms: u64) -> Answer {
        self.registered
            .retain(|_, registration| registration.expires_at_ms > now_ms);
        match datagram {
            Datagram::Register { key } => {
                if self.registered.len() >= MAX_REGISTRATIONS && !self.registered.contains_key(&key)
                {
                    // Full is shed, not an error: the serve retries on
                    // its cadence and room appears as others expire.
                    return Answer::default();
                }
                self.registered.insert(
                    key,
                    Registration {
                        mapping: source,
                        expires_at_ms: now_ms.saturating_add(REGISTRATION_TTL_MS),
                    },
                );
                Answer {
                    reply: Some(Datagram::Registered { key }),
                    notify: None,
                }
            }
            Datagram::Resolve { key } => {
                let serve = self.registered.get(&key).map(|entry| entry.mapping);
                Answer {
                    reply: Some(Datagram::Resolved { key, serve }),
                    // The serve hears the fetch is coming, so it can
                    // open its own NAT toward it before the Initial.
                    notify: serve.map(|mapping| (mapping, Datagram::Coming { key, fetch: source })),
                }
            }
            // The service sends these; receiving one is weather.
            Datagram::Registered { .. }
            | Datagram::Resolved { .. }
            | Datagram::Coming { .. }
            | Datagram::Warming => Answer::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn every_datagram_round_trips_and_no_reply_outgrows_its_request() {
        // The wire shapes exactly, and the amplification bound held by
        // construction: each reply the table can produce is no larger
        // than the request that earned it.
        let key = [7; 32];
        let cases = [
            Datagram::Register { key },
            Datagram::Registered { key },
            Datagram::Resolve { key },
            Datagram::Resolved { key, serve: None },
            Datagram::Resolved {
                key,
                serve: Some(v4("192.0.2.1:4433")),
            },
            Datagram::Resolved {
                key,
                serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
            },
            Datagram::Coming {
                key,
                fetch: v4("192.0.2.2:5000"),
            },
            Datagram::Warming,
        ];
        for datagram in cases {
            let wire = encode(&datagram);
            assert_eq!(wire[0], MAGIC);
            assert!(wire[0] < 0x40, "the magic can never open a QUIC packet");
            assert_eq!(decode(&wire), Some(datagram), "{datagram:?}");
        }
        let register = encode(&Datagram::Register { key }).len();
        let registered = encode(&Datagram::Registered { key }).len();
        assert_eq!(register, REQUEST_BYTES, "requests are padded to the bound");
        assert!(registered <= register);
        let resolve = encode(&Datagram::Resolve { key }).len();
        assert_eq!(resolve, REQUEST_BYTES);
        let resolved_widest = encode(&Datagram::Resolved {
            key,
            serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
        })
        .len();
        assert_eq!(
            resolved_widest, resolve,
            "the request is padded to the widest reply and no further"
        );
        let coming_widest = encode(&Datagram::Coming {
            key,
            fetch: "[2001:db8::2]:4433".parse().expect("an address"),
        })
        .len();
        assert_eq!(
            coming_widest, register,
            "the notification is exactly the registration that earned it"
        );
    }

    #[test]
    fn what_is_not_a_datagram_is_nothing() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[MAGIC]), None);
        assert_eq!(decode(&[MAGIC, VERSION]), None);
        assert_eq!(decode(&[MAGIC, VERSION + 1, 1]), None, "another version");
        assert_eq!(decode(&[0x40, VERSION, 6]), None, "another protocol");
        assert_eq!(decode(&[MAGIC, VERSION, 9]), None, "another kind");
        let mut short = encode(&Datagram::Register { key: [7; 32] });
        short.pop();
        assert_eq!(decode(&short), None, "a truncated request");
        let mut dirty = encode(&Datagram::Resolve { key: [7; 32] });
        *dirty.last_mut().expect("padding exists") = 1;
        assert_eq!(decode(&dirty), None, "padding that carries bytes");
        let mut long = encode(&Datagram::Warming);
        long.push(0);
        assert_eq!(decode(&long), None, "trailing bytes");
    }

    #[test]
    fn an_address_slot_is_the_length_its_family_names() {
        // A family byte is a claim about how many bytes follow, and a
        // slot that does not hold exactly that many is no address: the
        // width has to be read off the family rather than trusted from
        // whatever arrived behind it.
        let key = [7; 32];
        let widths = [
            Datagram::Resolved {
                key,
                serve: Some(v4("192.0.2.1:4433")),
            },
            Datagram::Resolved {
                key,
                serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
            },
            Datagram::Coming {
                key,
                fetch: v4("192.0.2.2:5000"),
            },
            Datagram::Coming {
                key,
                fetch: "[2001:db8::2]:5000".parse().expect("an address"),
            },
        ];
        for datagram in widths {
            let mut over = encode(&datagram);
            over.push(0);
            assert_eq!(decode(&over), None, "a slot wider than its family");
            let mut under = encode(&datagram);
            under.pop();
            assert_eq!(decode(&under), None, "a slot narrower than its family");
        }
    }

    #[test]
    fn a_register_pairs_a_resolve_until_the_ttl_ends() {
        let mut pairings = Pairings::default();
        let key = [3; 32];
        let serve = v4("198.51.100.1:4433");
        let fetch = v4("203.0.113.9:60123");

        // Unknown first: a resolve answers with nothing and tells nobody.
        let miss = pairings.take(Datagram::Resolve { key }, fetch, 1_000);
        assert_eq!(miss.reply, Some(Datagram::Resolved { key, serve: None }));
        assert_eq!(miss.notify, None);

        // Registered: the serve is acknowledged at its observed source.
        let ack = pairings.take(Datagram::Register { key }, serve, 1_000);
        assert_eq!(ack.reply, Some(Datagram::Registered { key }));
        assert_eq!(ack.notify, None);

        // Paired: the fetch learns the serve, the serve learns the fetch.
        let hit = pairings.take(Datagram::Resolve { key }, fetch, 2_000);
        assert_eq!(
            hit.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(serve)
            })
        );
        assert_eq!(hit.notify, Some((serve, Datagram::Coming { key, fetch })));

        // A refresh moves the mapping with the serve.
        let moved = v4("198.51.100.1:4500");
        pairings.take(Datagram::Register { key }, moved, 3_000);
        let refreshed = pairings.take(Datagram::Resolve { key }, fetch, 4_000);
        assert_eq!(
            refreshed.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(moved)
            })
        );

        // The TTL boundary exactly: alive one instant before, gone at it.
        let last = pairings.take(
            Datagram::Resolve { key },
            fetch,
            3_000 + REGISTRATION_TTL_MS - 1,
        );
        assert_eq!(
            last.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(moved)
            })
        );
        let expired = pairings.take(
            Datagram::Resolve { key },
            fetch,
            3_000 + REGISTRATION_TTL_MS,
        );
        assert_eq!(
            expired.reply,
            Some(Datagram::Resolved { key, serve: None }),
            "a registration is believed for its TTL and no longer"
        );

        // Service-sent shapes arriving at the service are weather.
        assert_eq!(
            pairings.take(Datagram::Warming, fetch, 5_000),
            Answer::default()
        );
    }

    #[test]
    fn the_key_is_this_derivation_of_the_root_and_no_other() {
        // Both ends derive the key from the root alone, so a derivation
        // that drifts pairs nobody and says nothing about why. The
        // committed vectors are the pin, and they are a file rather than
        // a literal here because a second implementation has to be able
        // to build against them: changing them is changing the protocol.
        let vectors = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../test-vectors/rendezvous/key.json"),
        )
        .expect("the committed key vectors");
        assert!(vectors.contains(KEY_CONTEXT), "the context is the vectors'");
        let mut cases = 0;
        for case in vectors.split("\"root_hex\": \"").skip(1) {
            let (root, rest) = case.split_once('"').expect("a root");
            let (_, key) = rest.split_once("\"key_hex\": \"").expect("a key");
            let (key, _) = key.split_once('"').expect("a key");
            let mut bytes = [0_u8; 32];
            for (byte, pair) in bytes.iter_mut().zip(root.as_bytes().chunks(2)) {
                *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16)
                    .expect("a byte");
            }
            assert_eq!(hex(&key_of(&bytes)), key, "the vector for root {root}");
            cases += 1;
        }
        assert_eq!(cases, 4, "every committed case was checked");
        assert_ne!(
            key_of(&[1; 32]),
            key_of(&[0; 32]),
            "another root, another key"
        );
        assert_ne!(key_of(&[0; 32]), [0; 32], "the key is not the root");
    }

    #[test]
    fn a_registrar_registers_on_its_cadence_and_warms_only_for_the_service() {
        let service = v4("198.51.100.7:9000");
        let fetch = v4("203.0.113.9:60123");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, service);
        let key = key_of(&root);

        // Due immediately, then not again until the cadence has run.
        assert_eq!(
            registrar.due(0),
            vec![(service, Datagram::Register { key })],
            "a serve is findable from the moment it is serving"
        );
        assert_eq!(registrar.due(REGISTER_CADENCE_MS - 1), Vec::new());
        assert_eq!(
            registrar.due(REGISTER_CADENCE_MS),
            vec![(service, Datagram::Register { key })]
        );

        // A Coming from the service warms the fetch's mapping, one
        // datagram a pass so the three do not share one path's fate.
        registrar.take(Datagram::Coming { key, fetch }, service);
        let now = REGISTER_CADENCE_MS;
        for pass in 0..WARMING_DATAGRAMS {
            assert_eq!(
                registrar.due(now),
                vec![(fetch, Datagram::Warming)],
                "pass {pass} owes exactly one warming"
            );
        }
        assert_eq!(registrar.due(now), Vec::new(), "and no more than it owes");

        // What earns nothing at all: an arrival from anywhere but the
        // service, since obeying it would make this end send unprompted
        // datagrams wherever a stranger named; another key's fetch; an
        // address that is nobody's mapping; and the shapes this end is
        // the one that sends.
        let refused = [
            (Datagram::Coming { key, fetch }, fetch),
            (
                Datagram::Coming {
                    key: [0xAB; 32],
                    fetch,
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("0.0.0.0:5000"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("203.0.113.9:0"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("239.0.0.1:5000"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("255.255.255.255:5000"),
                },
                service,
            ),
            (Datagram::Registered { key }, service),
            (Datagram::Resolve { key }, service),
            (Datagram::Warming, service),
        ];
        for (datagram, source) in refused {
            registrar.take(datagram, source);
            assert_eq!(
                registrar.due(now),
                Vec::new(),
                "{datagram:?} from {source} earned a warming"
            );
        }
    }

    #[test]
    fn only_what_could_be_an_observed_mapping_is_warmed() {
        // A Coming names where this end sends with nothing verified, so
        // this table is the whole of what it will aim at. Loopback turns
        // on where the service is: one out on the network cannot have
        // observed a loopback source, and one on loopback observes
        // nothing else.
        let far = v4("198.51.100.7:9000");
        let near = v4("127.0.0.1:9000");
        assert!(warmable(v4("203.0.113.9:60123"), far));
        assert!(warmable(
            "[2001:db8::2]:60123".parse().expect("an address"),
            far
        ));
        for refused in [
            "0.0.0.0:5000",
            "203.0.113.9:0",
            "239.0.0.1:5000",
            "255.255.255.255:5000",
        ] {
            assert!(!warmable(v4(refused), far), "{refused} is nobody's mapping");
        }
        assert!(!warmable("[::]:5000".parse().expect("an address"), far));
        assert!(!warmable(
            "[ff02::1]:5000".parse().expect("an address"),
            far
        ));
        assert!(
            !warmable(v4("127.0.0.1:5000"), far),
            "a service on the network never observed a loopback source"
        );
        assert!(!warmable("[::1]:5000".parse().expect("an address"), far));
        assert!(
            warmable(v4("127.0.0.1:5000"), near),
            "a service on loopback observes nothing else"
        );
        assert!(warmable("[::1]:5000".parse().expect("an address"), near));
    }

    #[test]
    fn a_cadence_of_warmings_is_bounded_however_many_fetches_come() {
        // The serving end's whole amplification story: a Coming is three
        // warmings, and a cadence emits no more than the bound however
        // many Comings arrive, so a key holder cannot turn the serve into
        // a packet multiplier at someone else's address.
        let service = v4("198.51.100.7:9000");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, service);
        let key = key_of(&root);
        registrar.due(0);
        for index in 0..100_u16 {
            let fetch = SocketAddr::new(v4("203.0.113.9:0").ip(), 1_000 + index);
            registrar.take(Datagram::Coming { key, fetch }, service);
        }
        let mut warmings = 0;
        // Bounded by its own count: the queue cannot outlive the bound.
        for _ in 0..WARMINGS_PER_CADENCE * 4 {
            warmings += registrar
                .due(1)
                .iter()
                .filter(|(_, datagram)| *datagram == Datagram::Warming)
                .count();
        }
        assert_eq!(warmings, WARMINGS_PER_CADENCE);

        // The next cadence opens the allowance again, and no sooner.
        registrar.take(
            Datagram::Coming {
                key,
                fetch: v4("203.0.113.9:6000"),
            },
            service,
        );
        assert_eq!(registrar.due(2), Vec::new(), "still inside the cadence");
        let opened = registrar.due(REGISTER_CADENCE_MS);
        assert_eq!(
            opened,
            vec![(service, Datagram::Register { key })],
            "the cadence turns over"
        );
        registrar.take(
            Datagram::Coming {
                key,
                fetch: v4("203.0.113.9:6000"),
            },
            service,
        );
        assert_eq!(
            registrar.due(REGISTER_CADENCE_MS),
            vec![(v4("203.0.113.9:6000"), Datagram::Warming)]
        );
    }

    #[test]
    fn the_table_is_bounded_and_full_is_shed_not_evicted() {
        let mut pairings = Pairings::default();
        for index in 0..MAX_REGISTRATIONS {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            pairings.take(Datagram::Register { key }, v4("192.0.2.1:1000"), 0);
        }
        assert_eq!(pairings.registered.len(), MAX_REGISTRATIONS);
        // One more is shed without evicting anyone: eviction would let
        // a flood of registrations push a live serve out of the table.
        let extra = pairings.take(
            Datagram::Register { key: [0xFF; 32] },
            v4("192.0.2.2:2000"),
            0,
        );
        assert_eq!(extra, Answer::default());
        assert_eq!(pairings.registered.len(), MAX_REGISTRATIONS);
        // A key already held refreshes even at the bound.
        let mut held = [0; 32];
        held[..8].copy_from_slice(&0_u64.to_be_bytes());
        let refreshed = pairings.take(Datagram::Register { key: held }, v4("192.0.2.3:3000"), 1);
        assert_eq!(refreshed.reply, Some(Datagram::Registered { key: held }));
    }
}
