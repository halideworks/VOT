//! Rendezvous protocol: pairing serve and fetch by the package root.
//! Socket-independent; time is injected so expiry is testable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Lead byte for rendezvous datagrams. Below QUIC range (0x00..=0x3F) so
/// the router distinguishes them by one byte.
pub(crate) const MAGIC: u8 = 0x1F;

/// The version after the magic, so the exchange can change shape later
/// without a flag day at the service.
const VERSION: u8 = 1;

/// Every request is padded to the widest reply so the service amplifies nothing.
const REQUEST_BYTES: usize = 3 + 32 + 1 + 16 + 2;

/// What one rendezvous datagram says. Replies are never larger than requests.
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

/// An address by the family that is really its own.
///
/// A socket bound to `[::]` observes an IPv4 peer as `::ffff:a.b.c.d` and
/// would hand that back as the peer's mapping, which the peer cannot then
/// connect to from the IPv4 socket it announced.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    let SocketAddr::V6(v6) = address else {
        return address;
    };
    match v6.ip().to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
        None => address,
    }
}

/// The inverse of [`push_address`].
fn pull_address(bytes: &[u8]) -> AddressSlot {
    let held = |ip, port| AddressSlot::Held(canonical(SocketAddr::new(ip, port)));
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

/// Derives the rendezvous key from a package root. Must stay this exact
/// derivation forever (protocol identity).
pub(crate) fn key_of(root: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(KEY_CONTEXT, root)
}

/// How long a registration stands without refresh. A dead serve ages out
/// in about a minute.
pub(crate) const REGISTRATION_TTL_MS: u64 = 90_000;

/// Registrations one service holds at most, which bounds its memory by
/// a constant however many keys are thrown at it.
pub(crate) const MAX_REGISTRATIONS: usize = 65_536;

/// How often a serve re-registers, which is also what keeps its NAT
/// mapping alive. Several refreshes fit inside [`REGISTRATION_TTL_MS`],
/// so a lost datagram costs findability for one cadence and no more.
pub(crate) const REGISTER_CADENCE_MS: u64 = 20_000;

/// Warming datagrams per Coming. Sent one per pass to avoid sharing a
/// single path's fate.
pub(crate) const WARMING_DATAGRAMS: usize = 3;

/// Total warming datagrams per cadence. One Coming earns at most
/// [`WARMING_DATAGRAMS`], and this bounds the total regardless of how many
/// Comings arrive, so a forged Coming cannot make a serve a reflector.
/// Sized for two fetches at the widest rail count inside one cadence,
/// since each of a fetch's rails punches for itself.
pub(crate) const WARMINGS_PER_CADENCE: usize = 48;

/// Whether to warm `fetch` based on a Coming from `service`. Rejects
/// addresses that cannot be an observed source mapping.
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

/// The serve-side rendezvous state: what to send and when. Owns no socket.
///
/// One registrar covers every address the service has, because a serve is
/// findable in each family it can reach the service over, and because the
/// warming bound is the serve's, not one service address's.
pub(crate) struct Registrar {
    key: [u8; 32],
    services: Vec<SocketAddr>,
    /// When the next registration is due, which is immediately at first.
    due_at_ms: u64,
    /// Mappings owed warmings, and how many each is still owed. Drained one
    /// mapping per pass and rotated, so a rail waiting on its first warming
    /// never waits behind another rail's second.
    warming: std::collections::VecDeque<(SocketAddr, usize)>,
    /// Warmings this cadence has already earned, against the bound.
    warmed: usize,
}

impl Registrar {
    /// A serve registering `root` with the service at every one of
    /// `services`, which are the addresses one service answers at.
    pub(crate) fn new(root: &[u8; 32], services: &[SocketAddr]) -> Self {
        Self {
            key: key_of(root),
            services: services.to_vec(),
            due_at_ms: 0,
            warming: std::collections::VecDeque::new(),
            warmed: 0,
        }
    }

    /// What to send at `now_ms` with nothing having arrived: a
    /// registration to every service address when the cadence is due, and
    /// one warming a pass toward whatever fetches are still owed them.
    pub(crate) fn due(&mut self, now_ms: u64) -> Vec<(SocketAddr, Datagram)> {
        let mut sends = Vec::new();
        if let Some((fetch, owed)) = self.warming.pop_front() {
            sends.push((fetch, Datagram::Warming));
            if owed > 1 {
                self.warming.push_back((fetch, owed - 1));
            }
        }
        if now_ms >= self.due_at_ms {
            self.due_at_ms = now_ms.saturating_add(REGISTER_CADENCE_MS);
            self.warmed = 0;
            for service in &self.services {
                sends.push((*service, Datagram::Register { key: self.key }));
            }
        }
        sends
    }

    /// Processes a datagram from `source`. Only the service is heard, and
    /// only about this serve's key. Earned warmings are queued.
    pub(crate) fn take(&mut self, datagram: Datagram, source: SocketAddr) {
        if !self.services.contains(&source) {
            return;
        }
        let Datagram::Coming { key, fetch } = datagram else {
            return;
        };
        if key != self.key || !warmable(fetch, source) {
            return;
        }
        let room = WARMINGS_PER_CADENCE.saturating_sub(self.warmed);
        let owed = WARMING_DATAGRAMS.min(room);
        self.warmed = self.warmed.saturating_add(owed);
        if owed > 0 {
            self.warming.push_back((fetch, owed));
        }
    }
}

/// One registered serve: where it is, and until when it is believed.
#[derive(Clone, Copy)]
struct Registration {
    mapping: SocketAddr,
    expires_at_ms: u64,
}

impl Registration {
    /// Whether this registration is still believed at `now_ms`.
    const fn live(&self, now_ms: u64) -> bool {
        self.expires_at_ms > now_ms
    }
}

/// What one key is registered at: at most one mapping per family, because
/// a serve reaches the service in each family it has and each of those
/// arrives under an address only that family can use.
#[derive(Default)]
struct Mappings {
    v4: Option<Registration>,
    v6: Option<Registration>,
}

impl Mappings {
    /// The slot an address belongs in. IPv4-mapped IPv6 is made canonical
    /// where addresses are read, so this is the family it will be used in.
    const fn slot(&mut self, address: SocketAddr) -> &mut Option<Registration> {
        match address {
            SocketAddr::V4(_) => &mut self.v4,
            SocketAddr::V6(_) => &mut self.v6,
        }
    }

    /// What is registered in `address`'s family and still believed.
    fn live_like(&self, address: SocketAddr, now_ms: u64) -> Option<SocketAddr> {
        let held = match address {
            SocketAddr::V4(_) => self.v4,
            SocketAddr::V6(_) => self.v6,
        };
        held.filter(|entry| entry.live(now_ms))
            .map(|entry| entry.mapping)
    }

    /// Whether any family still holds a believed registration.
    fn live(&self, now_ms: u64) -> bool {
        [self.v4, self.v6]
            .into_iter()
            .flatten()
            .any(|entry| entry.live(now_ms))
    }
}

/// Service-side pairing table. Time is injected so expiry is testable.
#[derive(Default)]
pub(crate) struct Pairings {
    registered: HashMap<[u8; 32], Mappings>,
}

/// Service reply: zero or one reply to the source, plus at most one
/// notification to a registered serve.
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
        match datagram {
            Datagram::Register { key } => {
                if self.registered.len() >= MAX_REGISTRATIONS && !self.registered.contains_key(&key)
                {
                    // The only sweep. Expiry is read at every lookup, so a
                    // table with room costs nothing to hold, and no datagram
                    // pays for the table's size. A key goes only when every
                    // family it holds has expired.
                    self.registered.retain(|_, mappings| mappings.live(now_ms));
                    if self.registered.len() >= MAX_REGISTRATIONS {
                        return Answer::default();
                    }
                }
                *self.registered.entry(key).or_default().slot(source) = Some(Registration {
                    mapping: source,
                    expires_at_ms: now_ms.saturating_add(REGISTRATION_TTL_MS),
                });
                Answer {
                    reply: Some(Datagram::Registered { key }),
                    notify: None,
                }
            }
            Datagram::Resolve { key } => {
                // Answered in the family it arrived over: that is the only
                // family the asker can reach a mapping in.
                let serve = self
                    .registered
                    .get(&key)
                    .and_then(|mappings| mappings.live_like(source, now_ms));
                Answer {
                    reply: Some(Datagram::Resolved { key, serve }),
                    notify: serve.map(|mapping| (mapping, Datagram::Coming { key, fetch: source })),
                }
            }
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

        let miss = pairings.take(Datagram::Resolve { key }, fetch, 1_000);
        assert_eq!(miss.reply, Some(Datagram::Resolved { key, serve: None }));
        assert_eq!(miss.notify, None);

        let ack = pairings.take(Datagram::Register { key }, serve, 1_000);
        assert_eq!(ack.reply, Some(Datagram::Registered { key }));
        assert_eq!(ack.notify, None);

        let hit = pairings.take(Datagram::Resolve { key }, fetch, 2_000);
        assert_eq!(
            hit.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(serve)
            })
        );
        assert_eq!(hit.notify, Some((serve, Datagram::Coming { key, fetch })));

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

        assert_eq!(
            pairings.take(Datagram::Warming, fetch, 5_000),
            Answer::default()
        );
    }

    #[test]
    fn the_key_is_this_derivation_of_the_root_and_no_other() {
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
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);

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
    fn every_mapping_is_warmed_before_any_is_warmed_twice() {
        // A fetch's rails each punch for themselves, and a rail connects when
        // its own warming lands. Draining one mapping to exhaustion before
        // starting the next would leave the last rail connecting into a NAT
        // that was never opened for it.
        let service = v4("198.51.100.7:9000");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);
        registrar.due(0);
        let rails: Vec<SocketAddr> = (0..4)
            .map(|index| v4(&format!("203.0.113.9:{}", 60_000 + index)))
            .collect();
        for rail in &rails {
            registrar.take(Datagram::Coming { key, fetch: *rail }, service);
        }
        let mut sent = Vec::new();
        for _ in 0..rails.len() * WARMING_DATAGRAMS {
            sent.extend(registrar.due(1).into_iter().map(|(to, _)| to));
        }
        assert_eq!(sent.len(), rails.len() * WARMING_DATAGRAMS);
        for round in sent.chunks(rails.len()) {
            let mut seen = round.to_vec();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), rails.len(), "a round warms each rail once");
        }
        assert_eq!(registrar.due(1), Vec::new(), "and no more than it owes");
    }

    #[test]
    fn a_cadence_of_warmings_is_bounded_however_many_fetches_come() {
        let service = v4("198.51.100.7:9000");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);
        registrar.due(0);
        for index in 0..100_u16 {
            let fetch = SocketAddr::new(v4("203.0.113.9:0").ip(), 1_000 + index);
            registrar.take(Datagram::Coming { key, fetch }, service);
        }
        let mut warmings = 0;
        for _ in 0..WARMINGS_PER_CADENCE * 4 {
            warmings += registrar
                .due(1)
                .iter()
                .filter(|(_, datagram)| *datagram == Datagram::Warming)
                .count();
        }
        assert_eq!(warmings, WARMINGS_PER_CADENCE);

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
    fn a_key_holds_one_mapping_per_family_and_each_expires_alone() {
        // A serve reaches the service in each family it has, and each of
        // those arrives under an address only that family can use. A resolve
        // is answered in the family it came over, because that is the only
        // one the asker can reach a mapping in.
        let mut pairings = Pairings::default();
        let key = [5; 32];
        let over_v4 = v4("198.51.100.1:4433");
        let over_v6: SocketAddr = "[2001:db8::1]:4433".parse().expect("an address");
        let asking_v4 = v4("203.0.113.9:60123");
        let asking_v6: SocketAddr = "[2001:db8::9]:60123".parse().expect("an address");

        pairings.take(Datagram::Register { key }, over_v4, 0);
        assert_eq!(
            pairings.take(Datagram::Resolve { key }, asking_v6, 1).reply,
            Some(Datagram::Resolved { key, serve: None }),
            "an IPv4 mapping is no answer to an asker that has only IPv6"
        );
        assert_eq!(
            pairings.take(Datagram::Resolve { key }, asking_v4, 1).reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v4)
            })
        );

        // The same serve registers over its other family, under one key.
        pairings.take(Datagram::Register { key }, over_v6, 2);
        let answered = pairings.take(Datagram::Resolve { key }, asking_v6, 3);
        assert_eq!(
            answered.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v6)
            })
        );
        assert_eq!(
            answered.notify,
            Some((
                over_v6,
                Datagram::Coming {
                    key,
                    fetch: asking_v6
                }
            )),
            "and the serve is told in the family the fetch can be reached in"
        );

        // One family ages out on its own clock and the other stands.
        let v4_gone = REGISTRATION_TTL_MS;
        assert_eq!(
            pairings
                .take(Datagram::Resolve { key }, asking_v4, v4_gone)
                .reply,
            Some(Datagram::Resolved { key, serve: None }),
            "the IPv4 registration is past its TTL"
        );
        assert_eq!(
            pairings
                .take(Datagram::Resolve { key }, asking_v6, v4_gone)
                .reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v6)
            }),
            "and the IPv6 one, registered later, is not"
        );
        assert_eq!(
            pairings.registered.len(),
            1,
            "one key, however many families it holds"
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
        let extra = pairings.take(
            Datagram::Register { key: [0xFF; 32] },
            v4("192.0.2.2:2000"),
            0,
        );
        assert_eq!(extra, Answer::default());
        assert_eq!(pairings.registered.len(), MAX_REGISTRATIONS);
        let mut held = [0; 32];
        held[..8].copy_from_slice(&0_u64.to_be_bytes());
        let refreshed = pairings.take(Datagram::Register { key: held }, v4("192.0.2.3:3000"), 1);
        assert_eq!(refreshed.reply, Some(Datagram::Registered { key: held }));

        // A full table sweeps what has expired rather than shedding forever,
        // at the instant those registrations expire and not a millisecond
        // later: everything here was registered at 0 except the refresh above.
        let at_expiry = REGISTRATION_TTL_MS;
        let room = pairings.take(
            Datagram::Register { key: [0xFF; 32] },
            v4("192.0.2.2:2000"),
            at_expiry,
        );
        assert_eq!(room.reply, Some(Datagram::Registered { key: [0xFF; 32] }));
        assert_eq!(
            pairings.registered.len(),
            2,
            "the refreshed registration and the one the sweep made room for"
        );
    }
}
