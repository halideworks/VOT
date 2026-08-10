//! The rendezvous datagram and its exact codec.

use std::net::SocketAddr;

use crate::side_channel::address::{AddressSlot, pull_address, push_address};
use crate::side_channel::padded::padded_key;

/// Lead byte for rendezvous datagrams. Below QUIC range (0x00..=0x3F) so
/// the router distinguishes them by one byte.
pub(crate) const MAGIC: u8 = 0x1F;

/// The version after the magic, so the exchange can change shape later
/// without a flag day at the service.
pub(crate) const VERSION: u8 = 1;

/// Every request is padded to the widest reply so the service amplifies nothing.
pub(crate) const REQUEST_BYTES: usize = 3 + 32 + 1 + 16 + 2;

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
    /// A fetch that took a relay slot, asking the service to pass the
    /// slot's address to the serve. Travels both legs in this one shape:
    /// fetch to service as a padded request, service to serve as the
    /// notify, which is never larger than the request that earned it.
    Invite { key: [u8; 32], at: SocketAddr },
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
        Datagram::Invite { key, at } => {
            wire.push(7);
            wire.extend_from_slice(key);
            push_address(&mut wire, Some(*at));
            // Padded to the fixed request size, so the notify leg cannot
            // exceed the request leg and the service amplifies nothing.
            wire.resize(REQUEST_BYTES, 0);
        }
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
            key: padded_key(rest, REQUEST_BYTES)?,
        }),
        (2, 32) => Some(Datagram::Registered {
            key: rest.try_into().ok()?,
        }),
        (3, _) => Some(Datagram::Resolve {
            key: padded_key(rest, REQUEST_BYTES)?,
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
        (7, _) => {
            if rest.len() != REQUEST_BYTES - 3 {
                return None;
            }
            let (key, slot) = rest.split_at_checked(32)?;
            let at = pull_padded_address(slot)?;
            Some(Datagram::Invite {
                key: key.try_into().ok()?,
                at,
            })
        }
        _ => None,
    }
}

/// An address slot followed by padding held to zero, as [`Datagram::Invite`]
/// carries it: padding that carried bytes would be a covert channel through
/// the service.
fn pull_padded_address(bytes: &[u8]) -> Option<SocketAddr> {
    let held = match bytes.first()? {
        4 => 7,
        6 => 19,
        _ => return None,
    };
    let (address, padding) = bytes.split_at_checked(held)?;
    if padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    let AddressSlot::Held(at) = pull_address(address) else {
        return None;
    };
    Some(at)
}
