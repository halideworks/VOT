//! Authentication and session-open frame family.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{Error, Reader, frame_type};

pub(super) const MAX_AUTH_NONCE: usize = 64;
pub(super) const MIN_AUTH_NONCE: usize = 16;
pub(super) const MAX_CAPABILITY_FORMATS: u64 = 16;
pub(super) const MAX_SCOPE_BYTES: usize = 4_096;
pub(super) const MAX_REJECT_DETAIL_BYTES: usize = 1_024;
pub(super) const MAX_CAPABILITY_FORMAT: u64 = 65_535;

/// Max capability bytes in a `SESSION_OPEN`, leaving room for both scopes and CBOR framing.
pub(super) const MAX_CAPABILITY_BYTES: usize = 49_152;
const _: () = assert!(
    match crate::registered_payload_limit(frame_type::SESSION_OPEN) {
        Some(limit) => MAX_CAPABILITY_BYTES + 2 * MAX_SCOPE_BYTES + 64 <= limit,
        None => false,
    },
    "a maximal SESSION_OPEN must fit the payload its registry entry allows"
);

/// How a capability is bound to the peer that presents it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    None,
    ProofOfPossession,
}

impl Binding {
    const fn from_wire(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::ProofOfPossession),
            _ => None,
        }
    }

    const fn to_wire(self) -> u64 {
        match self {
            Self::None => 0,
            Self::ProofOfPossession => 1,
        }
    }
}

/// Server authentication challenge. Empty `formats` means no auth required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthContext {
    pub nonce: Vec<u8>,
    pub binding: Binding,
    pub formats: Vec<u64>,
}

/// A client's request to open an authenticated session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOpen {
    pub session_id: [u8; 16],
    pub capability_format: u64,
    pub capability: Vec<u8>,
    pub requested_scope: Vec<u8>,
    pub binding_proof: Vec<u8>,
}

/// Granted scope, possibly narrower than requested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAccept {
    pub session_id: [u8; 16],
    pub granted_scope: Vec<u8>,
}

/// Why the server refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReject {
    pub session_id: [u8; 16],
    pub reason: u64,
    pub detail: String,
}

pub(super) fn encode_auth_context(value: &AuthContext, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_auth_context(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.nonce);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.binding.to_wire());
    vot_cbor::uint(output, 3);
    vot_cbor::array(output, value.formats.len() as u64);
    for format in &value.formats {
        vot_cbor::uint(output, *format);
    }
    Ok(())
}

pub(super) fn validate_auth_context(value: &AuthContext) -> Result<(), Error> {
    if value.nonce.len() < MIN_AUTH_NONCE || value.nonce.len() > MAX_AUTH_NONCE {
        return Err(Error::InvalidValue);
    }
    if value.formats.len() as u64 > MAX_CAPABILITY_FORMATS {
        return Err(Error::TooLarge);
    }
    // Ascending with no repeats: one policy, one encoding. 0x0000 is reserved.
    let ordered = value.formats.windows(2).all(|pair| pair[0] < pair[1]);
    if !ordered
        || value
            .formats
            .iter()
            .any(|format| *format == 0 || *format > MAX_CAPABILITY_FORMAT)
    {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

/// Decodes an `AUTH_CONTEXT` payload, envelope excluded.
///
/// # Errors
/// Rejects non-canonical CBOR under `spec/session.cddl`.
pub fn decode_auth_context_payload(payload: &[u8]) -> Result<AuthContext, Error> {
    decode_auth_context(payload)
}

/// Encodes an `AUTH_CONTEXT` payload, envelope excluded.
///
/// # Errors
/// Rejects a nonce or format list outside the bounds section 1.1 gives.
pub fn encode_auth_context_payload(value: &AuthContext, output: &mut Vec<u8>) -> Result<(), Error> {
    encode_auth_context(value, output)
}

pub(super) fn decode_auth_context(input: &[u8]) -> Result<AuthContext, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let nonce = reader.bytes(MAX_AUTH_NONCE)?.to_vec();
    reader.key(2)?;
    let binding = Binding::from_wire(reader.uint()?).ok_or(Error::InvalidValue)?;
    reader.key(3)?;
    let count = reader.array_len(MAX_CAPABILITY_FORMATS)?;
    let mut formats = Vec::with_capacity(usize::try_from(count).map_err(|_| Error::TooLarge)?);
    for _ in 0..count {
        formats.push(reader.uint()?);
    }
    reader.finish()?;
    let value = AuthContext {
        nonce,
        binding,
        formats,
    };
    validate_auth_context(&value)?;
    Ok(value)
}

pub(super) fn encode_session_open(value: &SessionOpen, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_session_open(value)?;
    vot_cbor::map(output, 6);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.session_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.capability_format);
    vot_cbor::uint(output, 3);
    vot_cbor::bytes(output, &value.capability);
    vot_cbor::uint(output, 4);
    vot_cbor::bytes(output, &value.requested_scope);
    vot_cbor::uint(output, 5);
    vot_cbor::bytes(output, &value.binding_proof);
    Ok(())
}

pub(super) fn validate_session_open(value: &SessionOpen) -> Result<(), Error> {
    if value.capability_format == 0 || value.capability_format > MAX_CAPABILITY_FORMAT {
        return Err(Error::InvalidValue);
    }
    if value.capability.len() > MAX_CAPABILITY_BYTES
        || value.requested_scope.len() > MAX_SCOPE_BYTES
        || value.binding_proof.len() > MAX_SCOPE_BYTES
    {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Decodes a `SESSION_OPEN` payload, envelope excluded.
///
/// # Errors
/// Rejects a payload that is not canonical CBOR under `spec/session.cddl`.
pub fn decode_session_open_payload(payload: &[u8]) -> Result<SessionOpen, Error> {
    decode_session_open(payload)
}

pub(super) fn decode_session_open(input: &[u8]) -> Result<SessionOpen, Error> {
    let mut reader = Reader::new(input);
    reader.map(6)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let session_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let capability_format = reader.uint()?;
    reader.key(3)?;
    let capability = reader.bytes(MAX_CAPABILITY_BYTES)?.to_vec();
    reader.key(4)?;
    let requested_scope = reader.bytes(MAX_SCOPE_BYTES)?.to_vec();
    reader.key(5)?;
    let binding_proof = reader.bytes(MAX_SCOPE_BYTES)?.to_vec();
    reader.finish()?;
    let value = SessionOpen {
        session_id,
        capability_format,
        capability,
        requested_scope,
        binding_proof,
    };
    validate_session_open(&value)?;
    Ok(value)
}

pub(super) fn encode_session_accept(
    value: &SessionAccept,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    validate_session_accept(value)?;
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.session_id);
    vot_cbor::uint(output, 2);
    vot_cbor::bytes(output, &value.granted_scope);
    Ok(())
}

pub(super) fn validate_session_accept(value: &SessionAccept) -> Result<(), Error> {
    if value.granted_scope.len() > MAX_SCOPE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Decodes a `SESSION_ACCEPT` payload, envelope excluded.
///
/// # Errors
/// Rejects non-canonical CBOR under `spec/session.cddl`.
pub fn decode_session_accept_payload(payload: &[u8]) -> Result<SessionAccept, Error> {
    decode_session_accept(payload)
}

/// Decodes a `SESSION_REJECT` payload, envelope excluded.
///
/// # Errors
/// Rejects a payload that is not canonical CBOR under `spec/session.cddl`, and
/// a reason `spec/wire.md` section 1.1 does not assign to a rejection.
pub fn decode_session_reject_payload(payload: &[u8]) -> Result<SessionReject, Error> {
    decode_session_reject(payload)
}

pub(super) fn decode_session_accept(input: &[u8]) -> Result<SessionAccept, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let session_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let granted_scope = reader.bytes(MAX_SCOPE_BYTES)?.to_vec();
    reader.finish()?;
    let value = SessionAccept {
        session_id,
        granted_scope,
    };
    // Validates on both sides so a new rule is never missed in one direction.
    validate_session_accept(&value)?;
    Ok(value)
}

pub(super) fn encode_session_reject(
    value: &SessionReject,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    validate_session_reject(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.session_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.reason);
    vot_cbor::uint(output, 3);
    vot_cbor::text(output, &value.detail);
    Ok(())
}

pub(super) fn validate_session_reject(value: &SessionReject) -> Result<(), Error> {
    // Only the three rejection codes from spec/wire.md section 1.1 are allowed.
    let registered = matches!(
        u16::try_from(value.reason),
        Ok(crate::error_code::AUTHENTICATION_FAILED
            | crate::error_code::AUTHORIZATION_FAILED
            | crate::error_code::REPLAY_REJECTED)
    );
    if !registered || value.detail.len() > MAX_REJECT_DETAIL_BYTES {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

pub(super) fn decode_session_reject(input: &[u8]) -> Result<SessionReject, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let session_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let reason = reader.uint()?;
    reader.key(3)?;
    let detail = reader.text(MAX_REJECT_DETAIL_BYTES)?.to_owned();
    reader.finish()?;
    let value = SessionReject {
        session_id,
        reason,
        detail,
    };
    validate_session_reject(&value)?;
    Ok(value)
}
