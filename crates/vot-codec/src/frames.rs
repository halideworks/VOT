//! Typed application payloads for the VOT v0.3 frame envelope.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{DecodeError, DecodeLimits, DecodedFrame, decode_one, encode_frame, frame_type};

const MAX_OBJECT_LENGTH: u64 = i64::MAX as u64;
const GROUP_BYTES: u64 = 65_536;

const MAX_REQUESTED_RANGE: u64 = 4_194_304;
const MAX_COVERED_RANGE: u64 = 4_259_840;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_DATA_BYTES: usize = 256 * 1024;
const MAX_MANIFEST_REQUEST_PAGES: u64 = 8_192;
const MAX_HAVE_RUNS: u64 = 2_097_152;

/// The most records one bundle can declare, from `spec/proof-bundle.cddl`.
pub const MAX_DATA_RECORDS_PER_BUNDLE: usize = 17;

const MAX_AUTH_NONCE: usize = 64;
const MIN_AUTH_NONCE: usize = 16;
const MAX_CAPABILITY_FORMATS: u64 = 16;
const MAX_SCOPE_BYTES: usize = 4_096;
const MAX_REJECT_DETAIL_BYTES: usize = 1_024;
const MAX_CAPABILITY_FORMAT: u64 = 65_535;

/// What is left of a `SESSION_OPEN` after the two scopes and the framing.
///
/// A capability sized without regard to what travels beside it would encode
/// alone and be refused in a real request, which is a bound admitting
/// something the wire never can. The 64 below is the CBOR around the fields:
/// the map head, six keys, the session identifier, the format, and three
/// byte-string heads come to 39 at these sizes, rounded up so a head that
/// widens does not take the bound with it.
const MAX_CAPABILITY_BYTES: usize = 49_152;
const _: () = assert!(
    match crate::registered_payload_limit(frame_type::SESSION_OPEN) {
        Some(limit) => MAX_CAPABILITY_BYTES + 2 * MAX_SCOPE_BYTES + 64 <= limit,
        None => false,
    },
    "a maximal SESSION_OPEN must fit the payload its registry entry allows"
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Envelope(DecodeError),
    WrongFrameType(u64),
    Malformed,
    InvalidValue,
    TooLarge,
    Manifest,
    Seal,
    Receipt,
}

impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        Self::Envelope(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

impl ObjectId {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.suite, 1 | 2) || self.length > MAX_OBJECT_LENGTH {
            Err(Error::InvalidValue)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDescriptor {
    pub package: ObjectId,
    pub manifest_id: [u8; 16],
    pub page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestRequest {
    pub request_id: [u8; 16],
    pub manifest_id: [u8; 16],
    pub first_page: u64,
    pub page_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeRequest {
    pub request_id: [u8; 16],
    pub object: ObjectId,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBundle {
    pub request_id: [u8; 16],
    pub bundle_id: [u8; 16],
    pub object: ObjectId,
    pub requested_offset: u64,
    pub requested_length: u64,
    pub covered_offset: u64,
    pub covered_length: u64,
    pub data_record_count: u64,
    pub total_plaintext_length: u64,
    pub proof: Vec<u8>,
}

impl ProofBundle {
    pub fn validate(&self) -> Result<(), Error> {
        validate_proof_bundle(self)
    }
}

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

/// What the server asks a client to present, and what it accepts.
///
/// An empty `formats` means this deployment requires no authentication, which
/// `spec/wire.md` section 1.1 gives as the way to say so.
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

/// What the server authorized, which may be narrower than what was asked.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRecord {
    pub bundle_id: [u8; 16],
    pub record_index: u64,
    pub plaintext_offset: u64,
    pub plaintext_length: u64,
    pub compression: u8,
    pub encoded: Vec<u8>,
}

impl DataRecord {
    pub fn validate(&self) -> Result<(), Error> {
        validate_data_record(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaveRun {
    pub start_group: u64,
    pub group_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Have {
    pub object: ObjectId,
    pub map_sequence: u64,
    pub runs: Vec<HaveRun>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    pub epoch: u64,
    pub available_bytes: u64,
    pub bdp_target_bytes: u64,
    pub max_inflight_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceFrame {
    pub object: ObjectId,
    pub sequence: u64,
    pub unit_start: u64,
    pub unit_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedFrame {
    AuthContext(AuthContext),
    SessionOpen(SessionOpen),
    SessionAccept(SessionAccept),
    SessionReject(SessionReject),
    PackageDescriptor(PackageDescriptor),
    ManifestRequest(ManifestRequest),
    ManifestPage(Vec<u8>),
    Seal(Vec<u8>),
    Have(Have),
    RangeRequest(RangeRequest),
    ProofBundle(ProofBundle),
    DataRecord(DataRecord),
    Capacity(Capacity),
    TransitVerified(AssuranceFrame),
    ChunkDurable(AssuranceFrame),
    ChunkAtRestVerified(AssuranceFrame),
    PublishReceipt(Vec<u8>),
}

impl TypedFrame {
    #[must_use]
    pub const fn frame_type(&self) -> u64 {
        match self {
            Self::AuthContext(_) => frame_type::AUTH_CONTEXT,
            Self::SessionOpen(_) => frame_type::SESSION_OPEN,
            Self::SessionAccept(_) => frame_type::SESSION_ACCEPT,
            Self::SessionReject(_) => frame_type::SESSION_REJECT,
            Self::PackageDescriptor(_) => frame_type::PACKAGE_DESCRIPTOR,
            Self::ManifestRequest(_) => frame_type::MANIFEST_REQUEST,
            Self::ManifestPage(_) => frame_type::MANIFEST_PAGE,
            Self::Seal(_) => frame_type::SEAL,
            Self::Have(_) => frame_type::HAVE,
            Self::RangeRequest(_) => frame_type::RANGE_REQUEST,
            Self::ProofBundle(_) => frame_type::PROOF_BUNDLE,
            Self::DataRecord(_) => frame_type::DATA_RECORD,
            Self::Capacity(_) => frame_type::CAPACITY,
            Self::TransitVerified(_) => frame_type::TRANSIT_VERIFIED,
            Self::ChunkDurable(_) => frame_type::CHUNK_DURABLE,
            Self::ChunkAtRestVerified(_) => frame_type::CHUNK_AT_REST_VERIFIED,
            Self::PublishReceipt(_) => frame_type::PUBLISH_RECEIPT,
        }
    }
}

/// Encodes one typed frame and its bounded envelope.
pub fn encode(frame: &TypedFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut payload = Vec::new();
    match frame {
        TypedFrame::AuthContext(value) => encode_auth_context(value, &mut payload)?,
        TypedFrame::SessionOpen(value) => encode_session_open(value, &mut payload)?,
        TypedFrame::SessionAccept(value) => encode_session_accept(value, &mut payload)?,
        TypedFrame::SessionReject(value) => encode_session_reject(value, &mut payload)?,
        TypedFrame::PackageDescriptor(value) => encode_package_descriptor(value, &mut payload)?,
        TypedFrame::ManifestRequest(value) => encode_manifest_request(value, &mut payload)?,
        TypedFrame::ManifestPage(bytes) => {
            validate_manifest_page(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Seal(bytes) => {
            validate_seal(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Have(value) => encode_have(value, &mut payload)?,
        TypedFrame::RangeRequest(value) => encode_range_request(value, &mut payload)?,
        TypedFrame::ProofBundle(value) => encode_proof_bundle(value, &mut payload)?,
        TypedFrame::DataRecord(value) => encode_data_record(value, &mut payload)?,
        TypedFrame::Capacity(value) => encode_capacity(value, &mut payload),
        TypedFrame::TransitVerified(value)
        | TypedFrame::ChunkDurable(value)
        | TypedFrame::ChunkAtRestVerified(value) => encode_assurance(value, &mut payload)?,
        TypedFrame::PublishReceipt(bytes) => {
            validate_receipt(bytes)?;
            payload.extend_from_slice(bytes);
        }
    }
    encode_frame(frame.frame_type(), &payload, output)?;
    Ok(())
}

/// Decodes one typed frame without accepting an unknown application payload.
pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<(TypedFrame, usize), Error> {
    let (decoded, consumed) = decode_one(input, limits)?;
    let frame_kind = decoded.frame_type();
    let payload = match decoded {
        DecodedFrame::Known { payload, .. } => payload,
        DecodedFrame::SkippedOptional { .. } => return Err(Error::WrongFrameType(frame_kind)),
    };
    let frame = match frame_kind {
        frame_type::AUTH_CONTEXT => TypedFrame::AuthContext(decode_auth_context(payload)?),
        frame_type::SESSION_OPEN => TypedFrame::SessionOpen(decode_session_open(payload)?),
        frame_type::SESSION_ACCEPT => TypedFrame::SessionAccept(decode_session_accept(payload)?),
        frame_type::SESSION_REJECT => TypedFrame::SessionReject(decode_session_reject(payload)?),
        frame_type::PACKAGE_DESCRIPTOR => {
            TypedFrame::PackageDescriptor(decode_package_descriptor(payload)?)
        }
        frame_type::MANIFEST_REQUEST => {
            TypedFrame::ManifestRequest(decode_manifest_request(payload)?)
        }
        frame_type::MANIFEST_PAGE => {
            validate_manifest_page(payload)?;
            TypedFrame::ManifestPage(payload.to_vec())
        }
        frame_type::SEAL => {
            validate_seal(payload)?;
            TypedFrame::Seal(payload.to_vec())
        }
        frame_type::HAVE => TypedFrame::Have(decode_have(payload)?),
        frame_type::RANGE_REQUEST => TypedFrame::RangeRequest(decode_range_request(payload)?),
        frame_type::PROOF_BUNDLE => TypedFrame::ProofBundle(decode_proof_bundle(payload)?),
        frame_type::DATA_RECORD => TypedFrame::DataRecord(decode_data_record(payload)?),
        frame_type::CAPACITY => TypedFrame::Capacity(decode_capacity(payload)?),
        frame_type::TRANSIT_VERIFIED => TypedFrame::TransitVerified(decode_assurance(payload)?),
        frame_type::CHUNK_DURABLE => TypedFrame::ChunkDurable(decode_assurance(payload)?),
        frame_type::CHUNK_AT_REST_VERIFIED => {
            TypedFrame::ChunkAtRestVerified(decode_assurance(payload)?)
        }
        frame_type::PUBLISH_RECEIPT => {
            validate_receipt(payload)?;
            TypedFrame::PublishReceipt(payload.to_vec())
        }
        other => return Err(Error::WrongFrameType(other)),
    };
    Ok((frame, consumed))
}

fn encode_auth_context(value: &AuthContext, output: &mut Vec<u8>) -> Result<(), Error> {
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

fn validate_auth_context(value: &AuthContext) -> Result<(), Error> {
    if value.nonce.len() < MIN_AUTH_NONCE || value.nonce.len() > MAX_AUTH_NONCE {
        return Err(Error::InvalidValue);
    }
    if value.formats.len() as u64 > MAX_CAPABILITY_FORMATS {
        return Err(Error::TooLarge);
    }
    // Ascending with no repeats, so one server policy has one encoding, and
    // `0x0000` is reserved by `spec/registries.md` section 11.
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
/// The negotiation state machine reads this one payload without going through
/// the typed frame dispatch, since it handles the frame itself.
///
/// # Errors
/// Rejects a payload that is not canonical CBOR under `spec/session.cddl`.
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

fn decode_auth_context(input: &[u8]) -> Result<AuthContext, Error> {
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

fn encode_session_open(value: &SessionOpen, output: &mut Vec<u8>) -> Result<(), Error> {
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

fn validate_session_open(value: &SessionOpen) -> Result<(), Error> {
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

fn decode_session_open(input: &[u8]) -> Result<SessionOpen, Error> {
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

fn encode_session_accept(value: &SessionAccept, output: &mut Vec<u8>) -> Result<(), Error> {
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

fn validate_session_accept(value: &SessionAccept) -> Result<(), Error> {
    if value.granted_scope.len() > MAX_SCOPE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Decodes a `SESSION_ACCEPT` payload, envelope excluded.
///
/// The negotiation state machine reads the four section 1.1 payloads without
/// going through the typed frame dispatch, since it handles the frames itself.
///
/// # Errors
/// Rejects a payload that is not canonical CBOR under `spec/session.cddl`.
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

fn decode_session_accept(input: &[u8]) -> Result<SessionAccept, Error> {
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
    // Every one of the four checks the same rules on both sides, so a rule
    // added to one direction cannot be missed in the other.
    validate_session_accept(&value)?;
    Ok(value)
}

fn encode_session_reject(value: &SessionReject, output: &mut Vec<u8>) -> Result<(), Error> {
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

fn validate_session_reject(value: &SessionReject) -> Result<(), Error> {
    // spec/wire.md section 1.1 names the three codes a rejection may carry, so
    // a rejection cannot report something that is not an authentication or
    // authorization outcome.
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

fn decode_session_reject(input: &[u8]) -> Result<SessionReject, Error> {
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

fn encode_package_descriptor(value: &PackageDescriptor, output: &mut Vec<u8>) -> Result<(), Error> {
    value.package.validate()?;
    if value.page_count == 0 {
        return Err(Error::InvalidValue);
    }
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    encode_object(&value.package, output);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.manifest_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.page_count);
    Ok(())
}

fn decode_package_descriptor(input: &[u8]) -> Result<PackageDescriptor, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let package = decode_object(&mut reader)?;
    reader.key(1)?;
    let manifest_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let page_count = reader.uint()?;
    reader.finish()?;
    let value = PackageDescriptor {
        package,
        manifest_id,
        page_count,
    };
    if value.page_count == 0 {
        Err(Error::InvalidValue)
    } else {
        Ok(value)
    }
}

fn encode_manifest_request(value: &ManifestRequest, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_manifest_request(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.manifest_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.first_page);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.page_count);
    Ok(())
}

fn decode_manifest_request(input: &[u8]) -> Result<ManifestRequest, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(1)?;
    let manifest_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let first_page = reader.uint()?;
    reader.key(3)?;
    let page_count = reader.uint()?;
    reader.finish()?;
    let value = ManifestRequest {
        request_id,
        manifest_id,
        first_page,
        page_count,
    };
    validate_manifest_request(&value)?;
    Ok(value)
}

fn validate_manifest_request(value: &ManifestRequest) -> Result<(), Error> {
    if value.page_count == 0
        || value.page_count > MAX_MANIFEST_REQUEST_PAGES
        || value.first_page > MAX_OBJECT_LENGTH
        || value.first_page.checked_add(value.page_count).is_none()
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn encode_range_request(value: &RangeRequest, output: &mut Vec<u8>) -> Result<(), Error> {
    value.object.validate()?;
    if value.length == 0
        || value.length > MAX_REQUESTED_RANGE
        || value.offset > MAX_OBJECT_LENGTH
        || value
            .offset
            .checked_add(value.length)
            .is_none_or(|end| end > value.object.length)
    {
        return Err(Error::InvalidValue);
    }
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 1);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.offset);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.length);
    Ok(())
}

fn decode_range_request(input: &[u8]) -> Result<RangeRequest, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(1)?;
    let object = decode_object(&mut reader)?;
    reader.key(2)?;
    let offset = reader.uint()?;
    reader.key(3)?;
    let length = reader.uint()?;
    reader.finish()?;
    let value = RangeRequest {
        request_id,
        object,
        offset,
        length,
    };
    encode_range_request(&value, &mut Vec::new())?;
    Ok(value)
}

fn encode_proof_bundle(value: &ProofBundle, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_proof_bundle(value)?;
    vot_cbor::map(output, 11);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.request_id);
    vot_cbor::uint(output, 2);
    vot_cbor::bytes(output, &value.bundle_id);
    vot_cbor::uint(output, 3);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.requested_offset);
    vot_cbor::uint(output, 5);
    vot_cbor::uint(output, value.requested_length);
    vot_cbor::uint(output, 6);
    vot_cbor::uint(output, value.covered_offset);
    vot_cbor::uint(output, 7);
    vot_cbor::uint(output, value.covered_length);
    vot_cbor::uint(output, 8);
    vot_cbor::uint(output, value.data_record_count);
    vot_cbor::uint(output, 9);
    vot_cbor::uint(output, value.total_plaintext_length);
    vot_cbor::uint(output, 10);
    vot_cbor::bytes(output, &value.proof);
    Ok(())
}

fn decode_proof_bundle(input: &[u8]) -> Result<ProofBundle, Error> {
    let mut reader = Reader::new(input);
    reader.map(11)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let request_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let bundle_id = reader.fixed::<16>()?;
    reader.key(3)?;
    let object = decode_object(&mut reader)?;
    reader.key(4)?;
    let requested_offset = reader.uint()?;
    reader.key(5)?;
    let requested_length = reader.uint()?;
    reader.key(6)?;
    let covered_offset = reader.uint()?;
    reader.key(7)?;
    let covered_length = reader.uint()?;
    reader.key(8)?;
    let data_record_count = reader.uint()?;
    reader.key(9)?;
    let total_plaintext_length = reader.uint()?;
    reader.key(10)?;
    let proof = reader.bytes(MAX_PROOF_BYTES)?;
    reader.finish()?;
    let mut value = ProofBundle {
        request_id,
        bundle_id,
        object,
        requested_offset,
        requested_length,
        covered_offset,
        covered_length,
        data_record_count,
        total_plaintext_length,
        proof: Vec::new(),
    };
    validate_proof_bundle_with_proof_len(&value, proof.len())?;
    value.proof = proof.to_vec();
    Ok(value)
}

fn validate_proof_bundle(value: &ProofBundle) -> Result<(), Error> {
    validate_proof_bundle_with_proof_len(value, value.proof.len())
}

fn validate_proof_bundle_with_proof_len(
    value: &ProofBundle,
    proof_len: usize,
) -> Result<(), Error> {
    value.object.validate()?;
    if value.object.length == 0
        || value.requested_length == 0
        || value.requested_length > MAX_REQUESTED_RANGE
        || value
            .requested_offset
            .checked_add(value.requested_length)
            .is_none_or(|end| end > value.object.length)
        || value.covered_offset != value.requested_offset / GROUP_BYTES * GROUP_BYTES
        || value.covered_offset % GROUP_BYTES != 0
        || value.covered_offset > value.requested_offset
        || value.covered_length == 0
        || value.covered_length > MAX_COVERED_RANGE
        || value
            .covered_offset
            .checked_add(value.covered_length)
            .is_none_or(|end| end > value.object.length)
        || value.data_record_count == 0
        || value.data_record_count > MAX_DATA_RECORDS_PER_BUNDLE as u64
        || value.total_plaintext_length != value.covered_length
        || proof_len > MAX_PROOF_BYTES
        || crate::registered_payload_limit(frame_type::PROOF_BUNDLE)
            .is_some_and(|limit| proof_bundle_payload_len_with(value, proof_len) > limit)
    {
        return Err(Error::InvalidValue);
    }
    let request_end = value
        .requested_offset
        .checked_add(value.requested_length)
        .ok_or(Error::InvalidValue)?;
    let expected_end = request_end
        .div_ceil(GROUP_BYTES)
        .checked_mul(GROUP_BYTES)
        .ok_or(Error::InvalidValue)?
        .min(value.object.length);
    if value.covered_offset.checked_add(value.covered_length) != Some(expected_end)
        || (expected_end < value.object.length && value.covered_length % GROUP_BYTES != 0)
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn proof_bundle_payload_len(value: &ProofBundle) -> usize {
    proof_bundle_payload_len_with(value, value.proof.len())
}

fn proof_bundle_payload_len_with(value: &ProofBundle, proof_len: usize) -> usize {
    let object_length = cbor_head_len(4)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(u64::from(value.object.suite)))
        .saturating_add(cbor_byte_string_len(32))
        .saturating_add(cbor_head_len(value.object.length));
    cbor_head_len(11)
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(3))
        .saturating_add(object_length)
        .saturating_add(cbor_head_len(4))
        .saturating_add(cbor_head_len(value.requested_offset))
        .saturating_add(cbor_head_len(5))
        .saturating_add(cbor_head_len(value.requested_length))
        .saturating_add(cbor_head_len(6))
        .saturating_add(cbor_head_len(value.covered_offset))
        .saturating_add(cbor_head_len(7))
        .saturating_add(cbor_head_len(value.covered_length))
        .saturating_add(cbor_head_len(8))
        .saturating_add(cbor_head_len(value.data_record_count))
        .saturating_add(cbor_head_len(9))
        .saturating_add(cbor_head_len(value.total_plaintext_length))
        .saturating_add(cbor_head_len(10))
        .saturating_add(cbor_byte_string_len(proof_len))
}

fn encode_data_record(value: &DataRecord, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_data_record(value)?;
    vot_cbor::map(output, 8);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, 1);
    vot_cbor::bytes(output, &value.bundle_id);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.record_index);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.plaintext_offset);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.plaintext_length);
    vot_cbor::uint(output, 5);
    vot_cbor::uint(output, u64::from(value.compression));
    vot_cbor::uint(output, 6);
    vot_cbor::uint(output, value.encoded.len() as u64);
    vot_cbor::uint(output, 7);
    vot_cbor::bytes(output, &value.encoded);
    Ok(())
}

fn decode_data_record(input: &[u8]) -> Result<DataRecord, Error> {
    let mut reader = Reader::new(input);
    reader.map(8)?;
    reader.key(0)?;
    if reader.uint()? != 0 {
        return Err(Error::InvalidValue);
    }
    reader.key(1)?;
    let bundle_id = reader.fixed::<16>()?;
    reader.key(2)?;
    let record_index = reader.uint()?;
    reader.key(3)?;
    let plaintext_offset = reader.uint()?;
    reader.key(4)?;
    let plaintext_length = reader.uint()?;
    reader.key(5)?;
    let compression = u8::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)?;
    reader.key(6)?;
    let encoded_length = reader.uint()?;
    reader.key(7)?;
    let encoded = reader.bytes(MAX_DATA_BYTES)?.to_vec();
    reader.finish()?;
    if encoded_length != encoded.len() as u64 {
        return Err(Error::InvalidValue);
    }
    let value = DataRecord {
        bundle_id,
        record_index,
        plaintext_offset,
        plaintext_length,
        compression,
        encoded,
    };
    validate_data_record(&value)?;
    Ok(value)
}

fn validate_data_record(value: &DataRecord) -> Result<(), Error> {
    let encoded_length = value.encoded.len() as u64;
    if value.record_index > 16
        || value.plaintext_offset > MAX_OBJECT_LENGTH
        || value.plaintext_length == 0
        || value.plaintext_length > MAX_DATA_BYTES as u64
        || encoded_length == 0
        || data_record_payload_len(value) > MAX_DATA_BYTES
        || !matches!(value.compression, 0 | 1)
        || (value.compression == 0 && value.plaintext_length != encoded_length)
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn data_record_payload_len(value: &DataRecord) -> usize {
    cbor_head_len(8)
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(0))
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_byte_string_len(16))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_head_len(value.record_index))
        .saturating_add(cbor_head_len(3))
        .saturating_add(cbor_head_len(value.plaintext_offset))
        .saturating_add(cbor_head_len(4))
        .saturating_add(cbor_head_len(value.plaintext_length))
        .saturating_add(cbor_head_len(5))
        .saturating_add(cbor_head_len(u64::from(value.compression)))
        .saturating_add(cbor_head_len(6))
        .saturating_add(cbor_head_len(value.encoded.len() as u64))
        .saturating_add(cbor_head_len(7))
        .saturating_add(cbor_byte_string_len(value.encoded.len()))
}

fn cbor_byte_string_len(length: usize) -> usize {
    cbor_head_len(length as u64).saturating_add(length)
}

fn cbor_head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn encode_have(value: &Have, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_have(value)?;
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.map_sequence);
    vot_cbor::uint(output, 2);
    vot_cbor::array(output, value.runs.len() as u64);
    for run in &value.runs {
        vot_cbor::array(output, 2);
        vot_cbor::uint(output, run.start_group);
        vot_cbor::uint(output, run.group_count);
    }
    Ok(())
}

fn decode_have(input: &[u8]) -> Result<Have, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let object = decode_object(&mut reader)?;
    reader.key(1)?;
    let map_sequence = reader.uint()?;
    reader.key(2)?;
    let count = reader.array_len(MAX_HAVE_RUNS)?;
    if count > (reader.remaining_len() / 2) as u64 {
        return Err(Error::Malformed);
    }
    let mut runs = Vec::with_capacity(count.min(8_192) as usize);
    for _ in 0..count {
        if reader.array(2)? != 2 {
            return Err(Error::Malformed);
        }
        runs.push(HaveRun {
            start_group: reader.uint()?,
            group_count: reader.uint()?,
        });
    }
    reader.finish()?;
    let value = Have {
        object,
        map_sequence,
        runs,
    };
    validate_have(&value)?;
    Ok(value)
}

fn validate_have(value: &Have) -> Result<(), Error> {
    value.object.validate()?;
    let payload_limit = crate::registered_payload_limit(frame_type::HAVE);
    if payload_limit.is_some_and(|limit| have_payload_len(value) > limit) {
        return Err(Error::TooLarge);
    }
    let group_count = value.object.length.div_ceil(GROUP_BYTES);
    let mut previous_end = 0_u64;
    for (index, run) in value.runs.iter().enumerate() {
        if run.group_count == 0
            || run.start_group < previous_end
            || (index > 0 && run.start_group == previous_end)
            || run
                .start_group
                .checked_add(run.group_count)
                .is_none_or(|end| end > group_count)
        {
            return Err(Error::InvalidValue);
        }
        previous_end = run.start_group + run.group_count;
    }
    Ok(())
}

fn have_payload_len(value: &Have) -> usize {
    let object_length = cbor_head_len(4)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(u64::from(value.object.suite)))
        .saturating_add(cbor_byte_string_len(32))
        .saturating_add(cbor_head_len(value.object.length));
    let mut length = cbor_head_len(3)
        .saturating_add(cbor_head_len(0))
        .saturating_add(object_length)
        .saturating_add(cbor_head_len(1))
        .saturating_add(cbor_head_len(value.map_sequence))
        .saturating_add(cbor_head_len(2))
        .saturating_add(cbor_head_len(value.runs.len() as u64));
    for run in &value.runs {
        length = length
            .saturating_add(cbor_head_len(2))
            .saturating_add(cbor_head_len(run.start_group))
            .saturating_add(cbor_head_len(run.group_count));
    }
    length
}

fn encode_capacity(value: &Capacity, output: &mut Vec<u8>) {
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, value.epoch);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.available_bytes);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.bdp_target_bytes);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.max_inflight_bytes);
}

fn decode_capacity(input: &[u8]) -> Result<Capacity, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let epoch = reader.uint()?;
    reader.key(1)?;
    let available_bytes = reader.uint()?;
    reader.key(2)?;
    let bdp_target_bytes = reader.uint()?;
    reader.key(3)?;
    let max_inflight_bytes = reader.uint()?;
    reader.finish()?;
    Ok(Capacity {
        epoch,
        available_bytes,
        bdp_target_bytes,
        max_inflight_bytes,
    })
}

fn encode_assurance(value: &AssuranceFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    validate_assurance(value)?;
    vot_cbor::map(output, 4);
    vot_cbor::uint(output, 0);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.sequence);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.unit_start);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.unit_count);
    Ok(())
}

fn decode_assurance(input: &[u8]) -> Result<AssuranceFrame, Error> {
    let mut reader = Reader::new(input);
    reader.map(4)?;
    reader.key(0)?;
    let object = decode_object(&mut reader)?;
    reader.key(1)?;
    let sequence = reader.uint()?;
    reader.key(2)?;
    let unit_start = reader.uint()?;
    reader.key(3)?;
    let unit_count = reader.uint()?;
    reader.finish()?;
    let value = AssuranceFrame {
        object,
        sequence,
        unit_start,
        unit_count,
    };
    validate_assurance(&value)?;
    Ok(value)
}

fn validate_assurance(value: &AssuranceFrame) -> Result<(), Error> {
    value.object.validate()?;
    if value.sequence == 0
        || value.unit_count == 0
        || value
            .unit_start
            .checked_add(value.unit_count)
            .is_none_or(|end| end > value.object.length.div_ceil(GROUP_BYTES))
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}

fn validate_manifest_page(bytes: &[u8]) -> Result<(), Error> {
    vot_manifest::decode_page(bytes)
        .map(|_| ())
        .map_err(|_| Error::Manifest)
}

fn validate_seal(bytes: &[u8]) -> Result<(), Error> {
    if crate::registered_payload_limit(frame_type::SEAL).is_some_and(|limit| bytes.len() > limit) {
        return Err(Error::TooLarge);
    }
    vot_manifest::decode_seal(bytes)
        .map(|_| ())
        .map_err(|_| Error::Seal)
}

fn validate_receipt(bytes: &[u8]) -> Result<(), Error> {
    vot_receipt::decode_authenticated(bytes)
        .map(|_| ())
        .map_err(|_| Error::Receipt)
}

fn encode_object(value: &ObjectId, output: &mut Vec<u8>) {
    vot_cbor::array(output, 4);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, u64::from(value.suite));
    vot_cbor::bytes(output, &value.root);
    vot_cbor::uint(output, value.length);
}

fn decode_object(reader: &mut Reader<'_>) -> Result<ObjectId, Error> {
    if reader.array(4)? != 4 {
        return Err(Error::Malformed);
    }
    if reader.uint()? != 1 {
        return Err(Error::InvalidValue);
    }
    let suite = u16::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)?;
    let root = reader.fixed::<32>()?;
    let length = reader.uint()?;
    let object = ObjectId {
        suite,
        root,
        length,
    };
    object.validate()?;
    Ok(object)
}

/// The frame codec's view of a deterministic CBOR reader.
///
/// `vot-cbor` decides what a well-formed canonical item is. This decides what a
/// frame payload calls each failure, which is two things: a bound the registry
/// set is `TooLarge`, and everything else is `Malformed`. A peer that sent an
/// item of the wrong type and a peer that sent a wider head than its value needs
/// have both sent a frame this endpoint refuses the same way.
struct Reader<'a> {
    reader: vot_cbor::Reader<'a>,
}

fn structural(error: vot_cbor::Error) -> Error {
    match error {
        vot_cbor::Error::TooLarge => Error::TooLarge,
        vot_cbor::Error::Truncated
        | vot_cbor::Error::Malformed
        | vot_cbor::Error::NonCanonical
        | vot_cbor::Error::WrongType
        | vot_cbor::Error::NotUtf8
        | vot_cbor::Error::Trailing => Error::Malformed,
    }
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            reader: vot_cbor::Reader::new(input),
        }
    }

    fn uint(&mut self) -> Result<u64, Error> {
        self.reader.uint().map_err(structural)
    }

    /// A map key, which has to be the one the schema puts there.
    ///
    /// A key that is not the expected value is the same refusal as one that is
    /// not an integer: this payload is not the shape the schema fixes.
    fn key(&mut self, expected: u64) -> Result<(), Error> {
        self.reader.key(expected).map_err(|_| Error::Malformed)
    }

    fn map(&mut self, expected: u64) -> Result<(), Error> {
        self.reader.map(expected).map_err(|_| Error::Malformed)
    }

    fn array(&mut self, expected: u64) -> Result<u64, Error> {
        self.reader
            .array(expected)
            .map(|()| expected)
            .map_err(|_| Error::Malformed)
    }

    /// An array head bounded by a registered maximum.
    ///
    /// Both halves are `TooLarge`, which is what the caller acts on: a count
    /// past the bound and a head that is not an array both mean this payload
    /// cannot be admitted.
    fn array_len(&mut self, maximum: u64) -> Result<u64, Error> {
        self.reader.array_len(maximum).map_err(|_| Error::TooLarge)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        self.reader.bytes(maximum).map_err(structural)
    }

    fn text(&mut self, maximum: usize) -> Result<&'a str, Error> {
        self.reader.text(maximum).map_err(structural)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.reader.fixed_bytes::<N>().map_err(|error| match error {
            // A byte string of another length where a fixed one was expected is
            // the wrong shape rather than an oversized one.
            vot_cbor::Error::TooLarge => Error::Malformed,
            other => structural(other),
        })
    }

    fn finish(&self) -> Result<(), Error> {
        self.reader.finish().map_err(|_| Error::Malformed)
    }

    fn remaining_len(&self) -> usize {
        self.reader.remaining().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> ObjectId {
        ObjectId {
            suite: 1,
            root: [7; 32],
            length: GROUP_BYTES * 2,
        }
    }

    fn round_trip(frame: &TypedFrame) {
        let mut out = Vec::new();
        encode(frame, &mut out).unwrap();
        let limits = DecodeLimits {
            max_unknown_payload: 1 << 20,
            max_frames: 1,
        };
        let (decoded, consumed) = decode(&out, limits).unwrap();
        assert_eq!(&decoded, frame);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn session_authentication_frames_round_trip() {
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![7; 16],
            binding: Binding::ProofOfPossession,
            formats: vec![1, 2, 9],
        }));
        // No capability format means no authentication is required, which
        // spec/wire.md section 1.1 gives as the way a server says so.
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![3; 64],
            binding: Binding::None,
            formats: Vec::new(),
        }));
        round_trip(&TypedFrame::SessionOpen(SessionOpen {
            session_id: [4; 16],
            capability_format: 1,
            capability: vec![9; 128],
            requested_scope: Vec::new(),
            binding_proof: vec![1; 64],
        }));
        round_trip(&TypedFrame::SessionAccept(SessionAccept {
            session_id: [4; 16],
            granted_scope: vec![2; 32],
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [4; 16],
            reason: u64::from(crate::error_code::AUTHORIZATION_FAILED),
            detail: String::new(),
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [4; 16],
            reason: u64::from(crate::error_code::REPLAY_REJECTED),
            detail: "scope".to_owned(),
        }));
    }

    #[test]
    fn the_payload_api_reads_what_the_typed_frame_api_writes() {
        // The negotiation state machine handles the section 1.1 frames itself,
        // so it decodes payloads rather than typed frames and never goes through
        // the dispatch the tests above use. Only these four have that door, and
        // it has to lead to the same place.
        let frames = [
            TypedFrame::AuthContext(AuthContext {
                nonce: vec![1; MIN_AUTH_NONCE],
                binding: Binding::ProofOfPossession,
                formats: vec![1, 7],
            }),
            TypedFrame::SessionOpen(SessionOpen {
                session_id: [2; 16],
                capability_format: 7,
                capability: vec![3; 8],
                requested_scope: vec![4; 8],
                binding_proof: vec![5; 8],
            }),
            TypedFrame::SessionAccept(SessionAccept {
                session_id: [2; 16],
                granted_scope: vec![6; 8],
            }),
            TypedFrame::SessionReject(SessionReject {
                session_id: [2; 16],
                reason: u64::from(crate::error_code::REPLAY_REJECTED),
                detail: "why".to_owned(),
            }),
        ];
        let limits = DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 1,
        };
        for frame in frames {
            let mut encoded = Vec::new();
            encode(&frame, &mut encoded).unwrap();
            let (envelope, _) = crate::decode_one(&encoded, limits).unwrap();
            let crate::DecodedFrame::Known { payload, .. } = envelope else {
                panic!("every section 1.1 frame is a known type");
            };
            let read = match &frame {
                TypedFrame::AuthContext(_) => {
                    TypedFrame::AuthContext(decode_auth_context_payload(payload).unwrap())
                }
                TypedFrame::SessionOpen(_) => {
                    TypedFrame::SessionOpen(decode_session_open_payload(payload).unwrap())
                }
                TypedFrame::SessionAccept(_) => {
                    TypedFrame::SessionAccept(decode_session_accept_payload(payload).unwrap())
                }
                _ => TypedFrame::SessionReject(decode_session_reject_payload(payload).unwrap()),
            };
            assert_eq!(read, frame);
        }

        // And the same refusals, since a payload decoder that skipped the
        // validation the dispatch applies would be a way around it.
        assert!(decode_session_accept_payload(&[]).is_err());

        // Canonical CBOR under the schema, carrying a code section 1.1 does not
        // assign to a rejection. Built field by field rather than by editing an
        // encoded one, so the payload is refused for its reason and not for a
        // key the edit moved.
        let mut unregistered = Vec::new();
        vot_cbor::map(&mut unregistered, 4);
        vot_cbor::uint(&mut unregistered, 0);
        vot_cbor::uint(&mut unregistered, 0);
        vot_cbor::uint(&mut unregistered, 1);
        vot_cbor::bytes(&mut unregistered, &[2; 16]);
        vot_cbor::uint(&mut unregistered, 2);
        vot_cbor::uint(
            &mut unregistered,
            u64::from(crate::error_code::MALFORMED_FRAME),
        );
        vot_cbor::uint(&mut unregistered, 3);
        vot_cbor::text(&mut unregistered, "");
        assert_eq!(
            decode_session_reject_payload(&unregistered),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn every_authentication_bound_admits_its_own_maximum() {
        // A bound that refuses its own maximum refuses a peer that sent
        // nothing oversized, and nothing else here would notice.
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![1; MIN_AUTH_NONCE],
            binding: Binding::None,
            formats: (1..=MAX_CAPABILITY_FORMATS).collect(),
        }));
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![1; MAX_AUTH_NONCE],
            binding: Binding::ProofOfPossession,
            formats: vec![MAX_CAPABILITY_FORMAT],
        }));
        round_trip(&TypedFrame::SessionOpen(SessionOpen {
            session_id: [1; 16],
            capability_format: MAX_CAPABILITY_FORMAT,
            capability: vec![2; MAX_CAPABILITY_BYTES],
            requested_scope: vec![3; MAX_SCOPE_BYTES],
            binding_proof: vec![4; MAX_SCOPE_BYTES],
        }));
        round_trip(&TypedFrame::SessionAccept(SessionAccept {
            session_id: [1; 16],
            granted_scope: vec![5; MAX_SCOPE_BYTES],
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [1; 16],
            reason: u64::from(crate::error_code::AUTHENTICATION_FAILED),
            detail: "d".repeat(MAX_REJECT_DETAIL_BYTES),
        }));

        let mut out = Vec::new();
        let mut wide = SessionAccept {
            session_id: [1; 16],
            granted_scope: vec![5; MAX_SCOPE_BYTES + 1],
        };
        assert!(encode_session_accept(&wide, &mut out).is_err());
        wide.granted_scope.pop();
        out.clear();
        assert!(encode_session_accept(&wide, &mut out).is_ok());

        let mut long = SessionReject {
            session_id: [1; 16],
            reason: u64::from(crate::error_code::AUTHENTICATION_FAILED),
            detail: "d".repeat(MAX_REJECT_DETAIL_BYTES + 1),
        };
        out.clear();
        assert!(encode_session_reject(&long, &mut out).is_err());
        long.detail.pop();
        out.clear();
        assert!(encode_session_reject(&long, &mut out).is_ok());
    }

    #[test]
    fn an_auth_context_states_one_server_policy_one_way() {
        let context = |formats: Vec<u64>| AuthContext {
            nonce: vec![7; 16],
            binding: Binding::None,
            formats,
        };
        let mut out = Vec::new();
        // Descending or repeated formats would give one policy two encodings.
        assert!(encode_auth_context(&context(vec![2, 1]), &mut out).is_err());
        assert!(encode_auth_context(&context(vec![1, 1]), &mut out).is_err());
        // 0x0000 is reserved by spec/registries.md section 11.
        assert!(encode_auth_context(&context(vec![0]), &mut out).is_err());
        assert!(encode_auth_context(&context(vec![65_536]), &mut out).is_err());
        assert!(
            encode_auth_context(&context((1..=17).collect()), &mut out).is_err(),
            "at most 16 formats"
        );

        let short = AuthContext {
            nonce: vec![7; 15],
            binding: Binding::None,
            formats: Vec::new(),
        };
        assert!(encode_auth_context(&short, &mut out).is_err());
        let long = AuthContext {
            nonce: vec![7; 65],
            binding: Binding::None,
            formats: Vec::new(),
        };
        assert!(encode_auth_context(&long, &mut out).is_err());
    }

    #[test]
    fn a_rejection_carries_a_registered_reason() {
        // A rejection that could report anything would let a server describe
        // an outcome the error registry never assigned.
        let mut out = Vec::new();
        for reason in [
            crate::error_code::AUTHENTICATION_FAILED,
            crate::error_code::AUTHORIZATION_FAILED,
            crate::error_code::REPLAY_REJECTED,
        ] {
            let reject = SessionReject {
                session_id: [1; 16],
                reason: u64::from(reason),
                detail: String::new(),
            };
            out.clear();
            assert!(encode_session_reject(&reject, &mut out).is_ok());
        }
        for reason in [0, u64::from(crate::error_code::MALFORMED_FRAME), 1 << 40] {
            let reject = SessionReject {
                session_id: [1; 16],
                reason,
                detail: String::new(),
            };
            out.clear();
            assert!(
                encode_session_reject(&reject, &mut out).is_err(),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_session_open_names_a_registered_capability_format() {
        let mut out = Vec::new();
        let open = |capability_format| SessionOpen {
            session_id: [1; 16],
            capability_format,
            capability: Vec::new(),
            requested_scope: Vec::new(),
            binding_proof: Vec::new(),
        };
        assert!(encode_session_open(&open(1), &mut out).is_ok());
        assert!(encode_session_open(&open(0), &mut out).is_err());
        assert!(encode_session_open(&open(65_536), &mut out).is_err());

        let mut oversized = open(1);
        oversized.capability = vec![0; MAX_CAPABILITY_BYTES + 1];
        assert!(encode_session_open(&oversized, &mut out).is_err());
        let mut wide_scope = open(1);
        wide_scope.requested_scope = vec![0; MAX_SCOPE_BYTES + 1];
        assert!(encode_session_open(&wide_scope, &mut out).is_err());
    }

    #[test]
    fn proof_and_data_frames_round_trip() {
        let bundle = TypedFrame::ProofBundle(ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        });
        let data = TypedFrame::DataRecord(DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: GROUP_BYTES,
            compression: 0,
            encoded: vec![0xaa; GROUP_BYTES as usize],
        });
        let mut encoded = Vec::new();
        encode(&bundle, &mut encoded).unwrap();
        encode(&data, &mut encoded).unwrap();
        let (decoded_bundle, used) = decode(&encoded, DecodeLimits::default()).unwrap();
        let (decoded_data, _) = decode(&encoded[used..], DecodeLimits::default()).unwrap();
        assert_eq!(decoded_bundle, bundle);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn proof_bundle_metadata_is_checked_before_proof_size() {
        let proof = vec![0xaa; 1024];
        let mut payload = Vec::new();
        vot_cbor::map(&mut payload, 11);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 1);
        vot_cbor::bytes(&mut payload, &[1; 16]);
        vot_cbor::uint(&mut payload, 2);
        vot_cbor::bytes(&mut payload, &[2; 16]);
        vot_cbor::uint(&mut payload, 3);
        encode_object(&object(), &mut payload);
        vot_cbor::uint(&mut payload, 4);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 5);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 6);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 7);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 8);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 9);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 10);
        vot_cbor::bytes(&mut payload, &proof);
        let mut encoded = Vec::new();
        encode_frame(frame_type::PROOF_BUNDLE, &payload, &mut encoded).unwrap();
        assert_eq!(
            decode(&encoded, DecodeLimits::default()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn proof_bundle_limit_includes_typed_payload_overhead() {
        let limit = crate::registered_payload_limit(frame_type::PROOF_BUNDLE).unwrap();
        let empty = ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        };
        let metadata = proof_bundle_payload_len(&empty) - cbor_byte_string_len(0);
        let mut maximum_proof_length = MAX_PROOF_BYTES.min(limit.saturating_sub(metadata));
        while metadata.saturating_add(cbor_byte_string_len(maximum_proof_length)) > limit {
            maximum_proof_length -= 1;
        }
        let mut valid = empty.clone();
        valid.proof = vec![0xaa; maximum_proof_length];
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::ProofBundle(valid), &mut Vec::new()).is_ok());

        let mut invalid = empty;
        invalid.proof = vec![0xaa; maximum_proof_length + 1];
        assert!(proof_bundle_payload_len(&invalid) > limit);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::ProofBundle(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_limit_includes_typed_payload_overhead() {
        let make_data = |encoded_length: usize| DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: encoded_length as u64,
            compression: 0,
            encoded: vec![0xaa; encoded_length],
        };
        let mut maximum_encoded_length = MAX_DATA_BYTES;
        while data_record_payload_len(&make_data(maximum_encoded_length)) > MAX_DATA_BYTES {
            maximum_encoded_length -= 1;
        }
        let valid = make_data(maximum_encoded_length);
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::DataRecord(valid), &mut Vec::new()).is_ok());

        let invalid = make_data(maximum_encoded_length + 1);
        assert!(data_record_payload_len(&invalid) > MAX_DATA_BYTES);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::DataRecord(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_validation_boundaries_are_explicit() {
        let mut data = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: 1,
            compression: 0,
            encoded: vec![0xaa],
        };
        data.record_index = 16;
        assert!(data.validate().is_ok());
        data.record_index = 17;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.record_index = 0;
        data.plaintext_offset = MAX_OBJECT_LENGTH;
        assert!(data.validate().is_ok());
        data.plaintext_offset += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_offset = 0;
        data.plaintext_length = MAX_DATA_BYTES as u64;
        data.compression = 1;
        assert!(data.validate().is_ok());
        data.plaintext_length += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_length = 1;
        data.compression = 0;
        data.encoded.clear();
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.encoded.push(0xaa);
        data.compression = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.compression = 0;
        data.plaintext_length = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));
        data.compression = 1;
        assert!(data.validate().is_ok());
    }

    #[test]
    fn cbor_head_width_boundaries_are_canonical() {
        assert_eq!(
            [
                cbor_head_len(0),
                cbor_head_len(23),
                cbor_head_len(24),
                cbor_head_len(255),
                cbor_head_len(256),
                cbor_head_len(65_535),
                cbor_head_len(65_536),
                cbor_head_len(u64::from(u32::MAX)),
                cbor_head_len(u64::from(u32::MAX) + 1),
            ],
            [1, 1, 2, 2, 3, 3, 5, 5, 9]
        );
    }

    #[test]
    fn adjacent_have_runs_are_rejected() {
        let error = encode(
            &TypedFrame::Have(Have {
                object: object(),
                map_sequence: 1,
                runs: vec![
                    HaveRun {
                        start_group: 0,
                        group_count: 1,
                    },
                    HaveRun {
                        start_group: 1,
                        group_count: 1,
                    },
                ],
            }),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::InvalidValue);
    }

    #[test]
    fn have_limit_includes_typed_run_overhead() {
        let run_count = 900_000_u64;
        let value = Have {
            object: ObjectId {
                suite: 1,
                root: [7; 32],
                length: GROUP_BYTES * (run_count * 2 + 1),
            },
            map_sequence: 1,
            runs: (0..run_count)
                .map(|index| HaveRun {
                    start_group: index * 2,
                    group_count: 1,
                })
                .collect(),
        };
        assert!(
            have_payload_len(&value) > crate::registered_payload_limit(frame_type::HAVE).unwrap()
        );
        assert_eq!(validate_have(&value), Err(Error::TooLarge));
        assert_eq!(
            encode(&TypedFrame::Have(value), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn valid_manifest_seals_are_bounded_by_the_wire_limit() {
        let pages = (0..vot_manifest::MAX_PAGE_COMMITMENTS)
            .map(|index| vot_manifest::PageCommitment {
                index: index as u64,
                digest: [8; 32],
            })
            .collect::<Vec<_>>();
        let seal = vot_manifest::Seal {
            manifest_id: [4; 16],
            final_page_count: pages.len() as u64,
            final_page_digest: [8; 32],
            package: vot_manifest::ObjectId {
                suite: 1,
                root: [9; 32],
                length: 123,
            },
            pages,
        };
        let encoded = vot_manifest::encode_seal(&seal).unwrap();
        assert!(encoded.len() > crate::registered_payload_limit(frame_type::SEAL).unwrap());
        assert_eq!(
            encode(&TypedFrame::Seal(encoded), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn owner_payloads_are_validated_before_framing() {
        assert_eq!(
            encode(&TypedFrame::ManifestPage(vec![0]), &mut Vec::new()),
            Err(Error::Manifest)
        );
        assert_eq!(
            encode(&TypedFrame::PublishReceipt(vec![0]), &mut Vec::new()),
            Err(Error::Receipt)
        );
    }
}
