//! An optional socket address on the wire: a family byte, then the bytes
//! it names, canonicalized so a dual-stack observation answers true.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Appends an optional address: a family byte, then the bytes it names.
pub(crate) fn push_address(wire: &mut Vec<u8>, address: Option<SocketAddr>) {
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
pub(crate) enum AddressSlot {
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

/// Whether `source` is `service`, whichever family each was observed in.
///
/// A dual-stack socket reports an IPv4 peer as `::ffff:a.b.c.d`, so the
/// two are compared as [`canonical`] forms rather than as they arrived.
pub(crate) fn from_service(source: SocketAddr, service: SocketAddr) -> bool {
    canonical(source) == canonical(service)
}

/// The inverse of [`push_address`].
pub(crate) fn pull_address(bytes: &[u8]) -> AddressSlot {
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
