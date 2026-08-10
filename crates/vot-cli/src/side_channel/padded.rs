//! The padded-key request both services read the same way.

/// A request's key with its padding held to zero: padding that carries
/// bytes would be a covert channel through the service's logs.
///
/// `request_bytes` is the whole datagram's size; the three lead bytes
/// (magic, version, kind) are already gone from `rest`.
pub(crate) fn padded_key(rest: &[u8], request_bytes: usize) -> Option<[u8; 32]> {
    if rest.len() != request_bytes - 3 {
        return None;
    }
    let (key, padding) = rest.split_at_checked(32)?;
    if padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    key.try_into().ok()
}
