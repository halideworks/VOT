//! The serve-side rendezvous state: cadence, registration, warming.

use std::net::{IpAddr, SocketAddr};

use super::{Datagram, key_of};
use crate::side_channel::address::{canonical, from_service};

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
pub(crate) fn warmable(fetch: SocketAddr, service: SocketAddr) -> bool {
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
        if !self.services.iter().any(|held| from_service(source, *held)) {
            return;
        }
        // A serve bound dual-stack reads a loopback service as
        // `::ffff:127.0.0.1`, which `warmable` would not know is near.
        let source = canonical(source);
        // An invitation is a Coming whose address is the relay slot: the
        // same warmings, from the same socket, claim the slot's first end.
        // One guard and one budget, so neither shape can make this serve
        // a reflector toward an address the service never observed.
        let fetch = match datagram {
            Datagram::Coming { key, fetch } if key == self.key => fetch,
            Datagram::Invite { key, at } if key == self.key => at,
            _ => return,
        };
        if !warmable(fetch, source) {
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
