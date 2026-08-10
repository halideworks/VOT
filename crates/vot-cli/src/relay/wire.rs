//! The relay control datagram and its exact codec.

use std::net::SocketAddr;

use crate::side_channel::address::{AddressSlot, pull_address, push_address};
use crate::side_channel::padded::padded_key;

/// Lead byte for relay control datagrams. Below the QUIC range and distinct
/// from the rendezvous magic, so a datagram sent to the wrong service is shed
/// rather than half read.
pub(crate) const MAGIC: u8 = 0x1E;

/// The version after the magic, so the exchange can change shape later.
pub(crate) const VERSION: u8 = 1;

/// Every request is padded to the widest reply so the relay amplifies
/// nothing. A relay that answered a short request with a long reply would be
/// a reflector.
pub(crate) const REQUEST_BYTES: usize = 3 + 32 + 1 + 16 + 2;

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
        1 => Some(Datagram::Take {
            key: padded_key(rest, REQUEST_BYTES)?,
        }),
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
