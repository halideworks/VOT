//! The service side: the pairing table and its bounds.

use std::collections::HashMap;
use std::net::SocketAddr;

use super::Datagram;

/// How long a registration stands without refresh. A dead serve ages out
/// in about a minute.
pub(crate) const REGISTRATION_TTL_MS: u64 = 90_000;

/// Registrations one service holds at most, which bounds its memory by
/// a constant however many keys are thrown at it.
pub(crate) const MAX_REGISTRATIONS: usize = 65_536;

/// One registered serve: where it is, and until when it is believed.
#[derive(Clone, Copy)]
pub(crate) struct Registration {
    pub(crate) mapping: SocketAddr,
    pub(crate) expires_at_ms: u64,
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
pub(crate) struct Mappings {
    pub(crate) v4: Option<Registration>,
    pub(crate) v6: Option<Registration>,
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

    /// A live mapping in `address`'s family, or the other family's:
    /// delivery is what matters, and any live mapping is a path the serve
    /// itself keeps open.
    fn live_preferring(&self, address: SocketAddr, now_ms: u64) -> Option<SocketAddr> {
        self.live_like(address, now_ms).or_else(|| {
            let other = match address {
                SocketAddr::V4(_) => "[::]:0",
                SocketAddr::V6(_) => "0.0.0.0:0",
            };
            other
                .parse()
                .ok()
                .and_then(|other| self.live_like(other, now_ms))
        })
    }
}

/// Service-side pairing table. Time is injected so expiry is testable.
#[derive(Default)]
pub(crate) struct Pairings {
    pub(crate) registered: HashMap<[u8; 32], Mappings>,
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
            Datagram::Invite { key, at } => {
                // Passed along for a registered key and dropped otherwise,
                // with no reply either way: the asker learns nothing, and
                // the one notify is never larger than the padded request.
                let serve = self
                    .registered
                    .get(&key)
                    .and_then(|mappings| mappings.live_preferring(source, now_ms));
                Answer {
                    reply: None,
                    notify: serve.map(|mapping| (mapping, Datagram::Invite { key, at })),
                }
            }
            Datagram::Registered { .. }
            | Datagram::Resolved { .. }
            | Datagram::Coming { .. }
            | Datagram::Warming => Answer::default(),
        }
    }
}
