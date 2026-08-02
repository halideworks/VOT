//! Typed payload schemas and bounded framing for the VOT v0.3 wire protocol.
//!
//! This crate validates the common envelope, criticality convention, grease
//! handling, registered per-frame limits, and typed application payloads before
//! a parser can allocate or mutate state.

#![forbid(unsafe_code)]

use core::cmp::min;
use std::collections::BTreeSet;

pub mod frames;

pub const MAX_QUIC_VARINT: u64 = (1_u64 << 62) - 1;
pub const MIN_CONTROL_FRAME_PAYLOAD: usize = 1024;
pub const HARD_MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_UNKNOWN_PAYLOAD: usize = 1024 * 1024;
pub const DEFAULT_MAX_FRAMES_PER_BATCH: usize = 4096;
pub const MAX_SETTINGS_PER_FRAME: usize = 128;
pub const MAX_EXTENSIONS_PER_HELLO: usize = 256;
pub const DRAFT_REVISION: u64 = 4;

pub mod setting_id {
    pub const MAX_CONTROL_FRAME_PAYLOAD: u64 = 0x01;
    pub const MAX_DATA_RECORD_PAYLOAD: u64 = 0x03;
    pub const MAX_MANIFEST_PAGE_PAYLOAD: u64 = 0x05;
    pub const RELIABLE_LANE_LIMIT: u64 = 0x07;
    pub const IDLE_TIMEOUT_MS: u64 = 0x09;
    pub const ACTIVE_KEEPALIVE_MS: u64 = 0x0b;
    pub const COMPRESSION_MIN_GAIN_BPS: u64 = 0x20;
    pub const TELEMETRY_LEVEL: u64 = 0x22;
}

pub mod error_code {
    pub const UNKNOWN_CRITICAL_FRAME: u16 = 0x0101;
    pub const MALFORMED_FRAME: u16 = 0x0102;
    pub const FRAME_TOO_LARGE: u16 = 0x0103;
    pub const INVALID_SETTING: u16 = 0x0105;
    pub const DUPLICATE_SETTING: u16 = 0x0106;
    pub const UNSUPPORTED_VERSION: u16 = 0x0104;
    pub const RESOURCE_LIMIT: u16 = 0x0502;
    pub const CARRIER_UNAVAILABLE: u16 = 0x0601;
    pub const REPLAY_REJECTED: u16 = 0x0203;
    pub const EXPERIMENT_NOT_NEGOTIATED: u16 = 0x0701;
}

/// Extension identifiers from `spec/registries.md` section 4.
pub mod extension_id {
    pub const CORE_RELIABLE: u64 = 0x00;
    pub const DATAGRAM_FEC: u64 = 0x01;
    pub const ZSTD_RECORDS: u64 = 0x02;
    pub const VCRC: u64 = 0x03;
    pub const PUBLIC_MULTI_RAIL: u64 = 0x04;
    pub const CUSTOM_CONGESTION_CONTROL: u64 = 0x05;
    pub const MULTIPATH_QUIC: u64 = 0x06;
}

/// The extension a known frame needs before it may be used.
///
/// `spec/wire.md` section 5: an experimental frame is invalid unless its
/// extension is negotiated, and using one anyway is
/// `EXPERIMENT_NOT_NEGOTIATED`. A frame with no entry needs nothing.
#[must_use]
pub const fn required_extension(frame_type: u64) -> Option<u64> {
    use crate::frame_type as ty;

    match frame_type {
        ty::DATAGRAM_CREDIT
        | ty::CODING_EPOCH_OPEN
        | ty::GEN_STATE
        | ty::GEN_DONE
        | ty::CODING_EPOCH_CLOSE => Some(extension_id::DATAGRAM_FEC),
        _ => None,
    }
}

pub mod frame_type {
    pub const HELLO: u64 = 0x01;
    pub const SETTINGS: u64 = 0x03;
    pub const SETTINGS_ACK: u64 = 0x05;
    pub const AUTH_CONTEXT: u64 = 0x07;
    pub const SESSION_OPEN: u64 = 0x09;
    pub const SESSION_ACCEPT: u64 = 0x0b;
    pub const SESSION_REJECT: u64 = 0x0d;

    pub const PACKAGE_DESCRIPTOR: u64 = 0x21;
    pub const MANIFEST_REQUEST: u64 = 0x23;
    pub const MANIFEST_PAGE: u64 = 0x25;
    pub const PROGRESSIVE_PAGE: u64 = 0x27;
    pub const SEAL: u64 = 0x29;
    pub const HAVE: u64 = 0x2b;
    pub const RANGE_REQUEST: u64 = 0x2d;
    pub const PROOF_BUNDLE: u64 = 0x2f;
    pub const DATA_RECORD: u64 = 0x31;
    pub const RANGE_CANCEL: u64 = 0x33;

    pub const CAPACITY: u64 = 0x40;
    pub const TRANSIT_VERIFIED: u64 = 0x43;
    pub const CHUNK_DURABLE: u64 = 0x45;
    pub const CHUNK_AT_REST_VERIFIED: u64 = 0x47;
    pub const PUBLISH_RECEIPT: u64 = 0x49;

    pub const DATAGRAM_CREDIT: u64 = 0x60;
    pub const CODING_EPOCH_OPEN: u64 = 0x62;
    pub const GEN_STATE: u64 = 0x64;
    pub const GEN_DONE: u64 = 0x66;
    pub const CODING_EPOCH_CLOSE: u64 = 0x68;

    pub const PING: u64 = 0x80;
    pub const GOAWAY: u64 = 0x83;
    pub const ERROR: u64 = 0x85;
    pub const SOURCE_SCORE_HINT: u64 = 0x86;
    pub const JOB_PRIORITY_UPDATE: u64 = 0x89;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    /// Limit used for an unknown optional frame, whose registered limit is not
    /// available to this implementation.
    pub max_unknown_payload: usize,
    /// Bounds result-vector growth when decoding a caller-provided batch.
    pub max_frames: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_unknown_payload: DEFAULT_MAX_UNKNOWN_PAYLOAD,
            max_frames: DEFAULT_MAX_FRAMES_PER_BATCH,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Incomplete {
        needed: usize,
        available: usize,
    },
    ValueOutOfRange(u64),
    InvalidLimits,
    LengthOverflow(u64),
    FrameTooLarge {
        frame_type: u64,
        length: u64,
        limit: usize,
    },
    UnknownCritical(u64),
    TooManyFrames {
        limit: usize,
    },
}

impl DecodeError {
    #[must_use]
    pub const fn protocol_code(&self) -> u16 {
        match self {
            Self::FrameTooLarge { .. } => error_code::FRAME_TOO_LARGE,
            Self::UnknownCritical(_) => error_code::UNKNOWN_CRITICAL_FRAME,
            Self::TooManyFrames { .. } => error_code::RESOURCE_LIMIT,
            Self::Incomplete { .. }
            | Self::ValueOutOfRange(_)
            | Self::InvalidLimits
            | Self::LengthOverflow(_) => error_code::MALFORMED_FRAME,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    pub max_control_frame_payload: u64,
    pub max_data_record_payload: u64,
    pub max_manifest_page_payload: u64,
    pub reliable_lane_limit: u64,
    pub idle_timeout_ms: u64,
    pub active_keepalive_ms: u64,
    pub compression_min_gain_bps: u64,
    pub telemetry_level: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_control_frame_payload: 1024 * 1024,
            max_data_record_payload: 256 * 1024,
            max_manifest_page_payload: 1024 * 1024,
            reliable_lane_limit: 16,
            idle_timeout_ms: 90_000,
            active_keepalive_ms: 20_000,
            compression_min_gain_bps: 500,
            telemetry_level: 1,
        }
    }
}

impl Settings {
    /// Every registered setting and the value advertised for it, in identifier
    /// order. Encoding walks this, so there is no lookup that cannot fail.
    #[must_use]
    pub const fn advertised(&self) -> [(u64, u64); 8] {
        use setting_id as id;

        [
            (
                id::MAX_CONTROL_FRAME_PAYLOAD,
                self.max_control_frame_payload,
            ),
            (id::MAX_DATA_RECORD_PAYLOAD, self.max_data_record_payload),
            (
                id::MAX_MANIFEST_PAGE_PAYLOAD,
                self.max_manifest_page_payload,
            ),
            (id::RELIABLE_LANE_LIMIT, self.reliable_lane_limit),
            (id::IDLE_TIMEOUT_MS, self.idle_timeout_ms),
            (id::ACTIVE_KEEPALIVE_MS, self.active_keepalive_ms),
            (id::COMPRESSION_MIN_GAIN_BPS, self.compression_min_gain_bps),
            (id::TELEMETRY_LEVEL, self.telemetry_level),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettingsError {
    Malformed(DecodeError),
    Duplicate(u64),
    UnknownCritical(u64),
    InvalidValue { setting: u64, value: u64 },
    TooMany { limit: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EndpointRole {
    Client = 0,
    Server = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub draft_revision: u64,
    pub endpoint_role: EndpointRole,
    pub extensions: BTreeSet<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelloError {
    Malformed(DecodeError),
    UnsupportedRevision(u64),
    RoleMismatch {
        expected: EndpointRole,
        actual: EndpointRole,
    },
    DuplicateExtension(u64),
    TooManyExtensions(u64),
    TrailingBytes,
}

impl HelloError {
    #[must_use]
    pub const fn protocol_code(&self) -> u16 {
        match self {
            Self::UnsupportedRevision(_) => error_code::UNSUPPORTED_VERSION,
            Self::TooManyExtensions(_) => error_code::RESOURCE_LIMIT,
            Self::Malformed(_)
            | Self::RoleMismatch { .. }
            | Self::DuplicateExtension(_)
            | Self::TrailingBytes => error_code::MALFORMED_FRAME,
        }
    }
}

/// Decodes the bounded HELLO payload before negotiation state is changed.
///
/// # Errors
/// Rejects the wrong revision or role, excessive or duplicate extensions,
/// truncation, and trailing bytes.
pub fn decode_hello(payload: &[u8], expected_role: EndpointRole) -> Result<Hello, HelloError> {
    let mut offset = 0;
    let draft_revision = hello_varint(payload, &mut offset)?;
    if draft_revision != DRAFT_REVISION {
        return Err(HelloError::UnsupportedRevision(draft_revision));
    }
    let endpoint_role = match hello_varint(payload, &mut offset)? {
        0 => EndpointRole::Client,
        1 => EndpointRole::Server,
        _ => {
            return Err(HelloError::Malformed(DecodeError::ValueOutOfRange(
                u64::MAX,
            )));
        }
    };
    if endpoint_role != expected_role {
        return Err(HelloError::RoleMismatch {
            expected: expected_role,
            actual: endpoint_role,
        });
    }
    let extension_count = hello_varint(payload, &mut offset)?;
    if extension_count > MAX_EXTENSIONS_PER_HELLO as u64 {
        return Err(HelloError::TooManyExtensions(extension_count));
    }
    let mut extensions = BTreeSet::new();
    for _ in 0..extension_count {
        let extension = hello_varint(payload, &mut offset)?;
        if !extensions.insert(extension) {
            return Err(HelloError::DuplicateExtension(extension));
        }
    }
    if offset != payload.len() {
        return Err(HelloError::TrailingBytes);
    }
    Ok(Hello {
        draft_revision,
        endpoint_role,
        extensions,
    })
}

fn hello_varint(payload: &[u8], offset: &mut usize) -> Result<u64, HelloError> {
    let (value, width) =
        decode_varint(payload.get(*offset..).unwrap_or_default()).map_err(HelloError::Malformed)?;
    *offset = offset
        .checked_add(width)
        .ok_or(HelloError::Malformed(DecodeError::LengthOverflow(u64::MAX)))?;
    Ok(value)
}

impl SettingsError {
    #[must_use]
    pub const fn protocol_code(&self) -> u16 {
        match self {
            Self::Duplicate(_) => error_code::DUPLICATE_SETTING,
            Self::InvalidValue { .. } | Self::UnknownCritical(_) => error_code::INVALID_SETTING,
            Self::TooMany { .. } => error_code::RESOURCE_LIMIT,
            Self::Malformed(error) => error.protocol_code(),
        }
    }
}

/// Decodes a bounded SETTINGS payload as identifier/value varint pairs.
///
/// Unknown optional settings are ignored. Unknown critical settings and
/// duplicates terminate negotiation.
///
/// # Errors
/// Returns a settings or bounded varint error.
pub fn decode_settings(payload: &[u8]) -> Result<Settings, SettingsError> {
    let mut settings = Settings::default();
    let mut seen = BTreeSet::new();
    let mut offset = 0;
    while offset < payload.len() {
        if seen.len() == MAX_SETTINGS_PER_FRAME {
            return Err(SettingsError::TooMany {
                limit: MAX_SETTINGS_PER_FRAME,
            });
        }
        let (identifier, identifier_width) =
            decode_varint(&payload[offset..]).map_err(SettingsError::Malformed)?;
        offset = offset
            .checked_add(identifier_width)
            .ok_or(SettingsError::Malformed(DecodeError::LengthOverflow(
                u64::MAX,
            )))?;
        let (value, value_width) =
            decode_varint(&payload[offset..]).map_err(SettingsError::Malformed)?;
        offset = offset
            .checked_add(value_width)
            .ok_or(SettingsError::Malformed(DecodeError::LengthOverflow(
                u64::MAX,
            )))?;
        if !seen.insert(identifier) {
            return Err(SettingsError::Duplicate(identifier));
        }
        apply_setting(&mut settings, identifier, value)?;
    }
    Ok(settings)
}

/// Every setting `spec/registries.md` defines, in identifier order.
pub const REGISTERED_SETTINGS: [u64; 8] = [
    setting_id::MAX_CONTROL_FRAME_PAYLOAD,
    setting_id::MAX_DATA_RECORD_PAYLOAD,
    setting_id::MAX_MANIFEST_PAGE_PAYLOAD,
    setting_id::RELIABLE_LANE_LIMIT,
    setting_id::IDLE_TIMEOUT_MS,
    setting_id::ACTIVE_KEEPALIVE_MS,
    setting_id::COMPRESSION_MIN_GAIN_BPS,
    setting_id::TELEMETRY_LEVEL,
];

/// The inclusive value range `spec/registries.md` gives a setting. One source
/// for both directions.
#[must_use]
pub const fn setting_range(identifier: u64) -> Option<(u64, u64)> {
    use setting_id as id;

    match identifier {
        id::MAX_CONTROL_FRAME_PAYLOAD => Some((
            MIN_CONTROL_FRAME_PAYLOAD as u64,
            HARD_MAX_FRAME_PAYLOAD as u64,
        )),
        id::MAX_DATA_RECORD_PAYLOAD => Some((64 * 1024, 256 * 1024)),
        id::MAX_MANIFEST_PAGE_PAYLOAD => Some((64 * 1024, 1024 * 1024)),
        id::RELIABLE_LANE_LIMIT => Some((1, 256)),
        id::IDLE_TIMEOUT_MS => Some((1000, 600_000)),
        id::ACTIVE_KEEPALIVE_MS => Some((10_000, 30_000)),
        id::COMPRESSION_MIN_GAIN_BPS => Some((0, 10_000)),
        id::TELEMETRY_LEVEL => Some((0, 2)),
        _ => None,
    }
}

/// The field a registered setting is carried in.
fn setting_field(settings: &mut Settings, identifier: u64) -> Option<&mut u64> {
    use setting_id as id;

    match identifier {
        id::MAX_CONTROL_FRAME_PAYLOAD => Some(&mut settings.max_control_frame_payload),
        id::MAX_DATA_RECORD_PAYLOAD => Some(&mut settings.max_data_record_payload),
        id::MAX_MANIFEST_PAGE_PAYLOAD => Some(&mut settings.max_manifest_page_payload),
        id::RELIABLE_LANE_LIMIT => Some(&mut settings.reliable_lane_limit),
        id::IDLE_TIMEOUT_MS => Some(&mut settings.idle_timeout_ms),
        id::ACTIVE_KEEPALIVE_MS => Some(&mut settings.active_keepalive_ms),
        id::COMPRESSION_MIN_GAIN_BPS => Some(&mut settings.compression_min_gain_bps),
        id::TELEMETRY_LEVEL => Some(&mut settings.telemetry_level),
        _ => None,
    }
}

/// Whether `value` is inside the range `spec/registries.md` gives `identifier`.
///
/// An unregistered identifier has no range, so nothing may be advertised under
/// it.
#[must_use]
pub fn setting_in_range(identifier: u64, value: u64) -> bool {
    setting_range(identifier).is_some_and(|(low, high)| (low..=high).contains(&value))
}

fn apply_setting(
    settings: &mut Settings,
    identifier: u64,
    value: u64,
) -> Result<(), SettingsError> {
    if !setting_in_range(identifier, value) {
        return if setting_range(identifier).is_some() {
            Err(SettingsError::InvalidValue {
                setting: identifier,
                value,
            })
        } else if is_critical(identifier) {
            Err(SettingsError::UnknownCritical(identifier))
        } else {
            // An unknown optional setting is ignored, which is what lets a
            // later revision add one without breaking this one.
            Ok(())
        };
    }
    // Registered and in range, so the field is there.
    if let Some(target) = setting_field(settings, identifier) {
        *target = value;
    }
    Ok(())
}

/// Encodes a `SETTINGS` payload as `spec/wire.md` section 1 defines it.
///
/// Every registered setting is advertised: the peer's defaults are its own.
///
/// # Errors
/// Returns [`SettingsError::InvalidValue`] for a value outside the registered
/// range, so a frame the peer would reject is never put on the wire.
pub fn encode_settings(settings: &Settings, output: &mut Vec<u8>) -> Result<(), SettingsError> {
    for (identifier, value) in settings.advertised() {
        if !setting_in_range(identifier, value) {
            return Err(SettingsError::InvalidValue {
                setting: identifier,
                value,
            });
        }
        encode_varint(identifier, output).map_err(SettingsError::Malformed)?;
        encode_varint(value, output).map_err(SettingsError::Malformed)?;
    }
    Ok(())
}

/// Encodes a `HELLO` payload as `spec/wire.md` section 1 defines it.
///
/// The revision is written as given, so a test can produce the frame a peer on
/// another draft would send.
///
/// # Errors
/// Returns [`HelloError::TooManyExtensions`] above the registered bound.
pub fn encode_hello(hello: &Hello, output: &mut Vec<u8>) -> Result<(), HelloError> {
    let count = hello.extensions.len();
    if count > MAX_EXTENSIONS_PER_HELLO {
        return Err(HelloError::TooManyExtensions(count as u64));
    }
    let write = |value: u64, output: &mut Vec<u8>| {
        encode_varint(value, output).map_err(HelloError::Malformed)
    };
    write(hello.draft_revision, output)?;
    write(hello.endpoint_role as u64, output)?;
    write(count as u64, output)?;
    // Ordered, so one HELLO has one encoding.
    for extension in &hello.extensions {
        write(*extension, output)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedFrame<'a> {
    Known {
        frame_type: u64,
        payload: &'a [u8],
    },
    SkippedOptional {
        frame_type: u64,
        payload_length: usize,
    },
}

impl DecodedFrame<'_> {
    #[must_use]
    pub const fn frame_type(&self) -> u64 {
        match self {
            Self::Known { frame_type, .. } | Self::SkippedOptional { frame_type, .. } => {
                *frame_type
            }
        }
    }
}

#[must_use]
pub const fn is_critical(frame_type: u64) -> bool {
    frame_type & 1 == 1
}

#[must_use]
pub const fn is_grease(frame_type: u64) -> bool {
    frame_type >= 0x1f00 && frame_type <= 0x1ffe && frame_type & 1 == 0
}

#[must_use]
pub const fn registered_payload_limit(frame_type: u64) -> Option<usize> {
    use crate::frame_type as ty;

    match frame_type {
        ty::HELLO | ty::CAPACITY | ty::DATAGRAM_CREDIT | ty::GOAWAY => Some(4 * 1024),
        ty::SETTINGS => Some(16 * 1024),
        ty::SETTINGS_ACK | ty::PING => Some(0),
        ty::AUTH_CONTEXT
        | ty::SESSION_OPEN
        | ty::SESSION_ACCEPT
        | ty::SESSION_REJECT
        | ty::MANIFEST_REQUEST
        | ty::RANGE_CANCEL
        | ty::TRANSIT_VERIFIED
        | ty::CHUNK_DURABLE
        | ty::CHUNK_AT_REST_VERIFIED
        | ty::PUBLISH_RECEIPT
        | ty::CODING_EPOCH_OPEN
        | ty::GEN_STATE
        | ty::GEN_DONE
        | ty::CODING_EPOCH_CLOSE
        | ty::ERROR
        | ty::SOURCE_SCORE_HINT
        | ty::JOB_PRIORITY_UPDATE => Some(64 * 1024),
        ty::SEAL | ty::DATA_RECORD => Some(256 * 1024),
        ty::PACKAGE_DESCRIPTOR | ty::MANIFEST_PAGE | ty::PROGRESSIVE_PAGE | ty::RANGE_REQUEST => {
            Some(1024 * 1024)
        }
        ty::HAVE => Some(4 * 1024 * 1024),
        ty::PROOF_BUNDLE => Some(HARD_MAX_FRAME_PAYLOAD),
        _ => None,
    }
}

#[must_use]
pub const fn is_known(frame_type: u64) -> bool {
    registered_payload_limit(frame_type).is_some()
}

/// Encodes one QUIC variable-length integer using its shortest representation.
///
/// # Errors
/// Returns [`DecodeError::ValueOutOfRange`] when `value` exceeds `2^62 - 1`.
pub fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<(), DecodeError> {
    if value > MAX_QUIC_VARINT {
        return Err(DecodeError::ValueOutOfRange(value));
    }

    if value < (1 << 6) {
        output.push(u8::try_from(value).map_err(|_| DecodeError::ValueOutOfRange(value))?);
    } else if value < (1 << 14) {
        let encoded =
            u16::try_from(value).map_err(|_| DecodeError::ValueOutOfRange(value))? | 0x4000;
        output.extend_from_slice(&encoded.to_be_bytes());
    } else if value < (1 << 30) {
        let encoded =
            u32::try_from(value).map_err(|_| DecodeError::ValueOutOfRange(value))? | 0x8000_0000;
        output.extend_from_slice(&encoded.to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }

    Ok(())
}

/// Decodes one legal QUIC variable-length integer from the start of `input`.
///
/// # Errors
/// Returns [`DecodeError::Incomplete`] when the encoded width is unavailable.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    let Some(first) = input.first().copied() else {
        return Err(DecodeError::Incomplete {
            needed: 1,
            available: 0,
        });
    };

    let width = 1_usize << (first >> 6);
    if input.len() < width {
        return Err(DecodeError::Incomplete {
            needed: width,
            available: input.len(),
        });
    }

    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, width))
}

/// Encodes a registered or optional frame after enforcing its payload bound.
///
/// # Errors
/// Returns an error for an invalid type, length overflow, or oversized payload.
pub fn encode_frame(
    frame_type: u64,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    let length = u64::try_from(payload.len()).map_err(|_| DecodeError::LengthOverflow(u64::MAX))?;
    let limit = registered_payload_limit(frame_type).unwrap_or(DEFAULT_MAX_UNKNOWN_PAYLOAD);
    let limit = min(limit, HARD_MAX_FRAME_PAYLOAD);
    if payload.len() > limit {
        return Err(DecodeError::FrameTooLarge {
            frame_type,
            length,
            limit,
        });
    }

    encode_varint(frame_type, output)?;
    encode_varint(length, output)?;
    output.extend_from_slice(payload);
    Ok(())
}

/// A frame's type and length, read without touching its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameEnvelope {
    pub frame_type: u64,
    pub payload_length: usize,
    /// Bytes the type and length varints occupy.
    pub header_length: usize,
    /// Header plus payload.
    pub total_length: usize,
    /// Whether the payload is to be discarded rather than parsed, which is the
    /// case for an unknown optional type and for grease.
    pub skipped: bool,
}

/// Reads the next frame's envelope without requiring its payload to be present.
///
/// `spec/wire.md` has a decoder determine the applicable limit and reject an
/// oversized or unknown critical frame before allocating anything, and
/// stream-discard an unknown optional payload rather than buffering it. A
/// stream transport cannot follow that with [`decode_one`] alone, because that
/// reports the frame incomplete until every byte has arrived, by which point a
/// caller has already held the payload it was supposed to throw away.
///
/// # Errors
/// Returns `Incomplete` until both varints have arrived, and otherwise the same
/// overflow, excessive-length, and unknown-critical errors as [`decode_one`].
pub fn peek_envelope(input: &[u8], limits: DecodeLimits) -> Result<FrameEnvelope, DecodeError> {
    validate_limits(limits)?;
    let (frame_type, type_width) = decode_varint(input)?;
    let (length, length_width) = decode_varint(&input[type_width..])?;
    let known_limit = registered_payload_limit(frame_type);
    let limit = min(
        known_limit.unwrap_or(limits.max_unknown_payload),
        HARD_MAX_FRAME_PAYLOAD,
    );
    let payload_length =
        usize::try_from(length).map_err(|_| DecodeError::LengthOverflow(length))?;
    if payload_length > limit {
        return Err(DecodeError::FrameTooLarge {
            frame_type,
            length,
            limit,
        });
    }
    if known_limit.is_none() && is_critical(frame_type) {
        return Err(DecodeError::UnknownCritical(frame_type));
    }
    let header_length = type_width
        .checked_add(length_width)
        .ok_or(DecodeError::LengthOverflow(length))?;
    let total_length = header_length
        .checked_add(payload_length)
        .ok_or(DecodeError::LengthOverflow(length))?;
    Ok(FrameEnvelope {
        frame_type,
        payload_length,
        header_length,
        total_length,
        skipped: known_limit.is_none() || is_grease(frame_type),
    })
}

/// Decodes one bounded frame without owning its payload.
///
/// # Errors
/// Returns an error for invalid limits, truncation, overflow, excessive length, or an unknown critical type.
pub fn decode_one(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<(DecodedFrame<'_>, usize), DecodeError> {
    validate_limits(limits)?;
    let (frame_type, type_width) = decode_varint(input)?;
    let (length, length_width) = decode_varint(&input[type_width..])?;
    let known_limit = registered_payload_limit(frame_type);
    let limit = min(
        known_limit.unwrap_or(limits.max_unknown_payload),
        HARD_MAX_FRAME_PAYLOAD,
    );
    let payload_length =
        usize::try_from(length).map_err(|_| DecodeError::LengthOverflow(length))?;

    if payload_length > limit {
        return Err(DecodeError::FrameTooLarge {
            frame_type,
            length,
            limit,
        });
    }
    if known_limit.is_none() && is_critical(frame_type) {
        return Err(DecodeError::UnknownCritical(frame_type));
    }

    let header_length = type_width
        .checked_add(length_width)
        .ok_or(DecodeError::LengthOverflow(length))?;
    let total_length = header_length
        .checked_add(payload_length)
        .ok_or(DecodeError::LengthOverflow(length))?;
    if input.len() < total_length {
        return Err(DecodeError::Incomplete {
            needed: total_length,
            available: input.len(),
        });
    }

    if known_limit.is_some() && !is_grease(frame_type) {
        Ok((
            DecodedFrame::Known {
                frame_type,
                payload: &input[header_length..total_length],
            },
            total_length,
        ))
    } else {
        Ok((
            DecodedFrame::SkippedOptional {
                frame_type,
                payload_length,
            },
            total_length,
        ))
    }
}

/// Decodes a bounded batch of frames from one complete input buffer.
///
/// # Errors
/// Returns any single-frame error or [`DecodeError::TooManyFrames`].
pub fn decode_all(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<Vec<DecodedFrame<'_>>, DecodeError> {
    validate_limits(limits)?;
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < input.len() {
        if frames.len() == limits.max_frames {
            return Err(DecodeError::TooManyFrames {
                limit: limits.max_frames,
            });
        }
        let (frame, consumed) = decode_one(&input[offset..], limits)?;
        frames.push(frame);
        offset = offset
            .checked_add(consumed)
            .ok_or(DecodeError::LengthOverflow(consumed as u64))?;
    }

    Ok(frames)
}

const fn validate_limits(limits: DecodeLimits) -> Result<(), DecodeError> {
    if limits.max_unknown_payload > HARD_MAX_FRAME_PAYLOAD || limits.max_frames == 0 {
        Err(DecodeError::InvalidLimits)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn an_envelope_is_read_before_its_payload_arrives() {
        // spec/wire.md has a decoder decide the limit, reject an oversized or
        // unknown critical frame, and stream-discard an unknown optional
        // payload, all before allocating. decode_one cannot serve that on a
        // stream transport: it reports incomplete until the last byte lands, by
        // which point the payload it was meant to throw away is already held.
        let mut frame = Vec::new();
        encode_frame(frame_type::DATA_RECORD, &[7; 4096], &mut frame).unwrap();
        let limits = DecodeLimits::default();

        // The header alone is enough, and it agrees with the full decode.
        let envelope = peek_envelope(&frame[..4], limits).unwrap();
        assert_eq!(envelope.frame_type, frame_type::DATA_RECORD);
        assert_eq!(envelope.payload_length, 4096);
        assert_eq!(envelope.total_length, frame.len());
        assert_eq!(
            envelope.header_length + envelope.payload_length,
            envelope.total_length
        );
        assert!(!envelope.skipped);
        assert_eq!(decode_one(&frame, limits).unwrap().1, envelope.total_length);
        assert!(matches!(
            decode_one(&frame[..4], limits),
            Err(DecodeError::Incomplete { .. })
        ));

        // An unknown optional type is skipped, and so is grease of a known one.
        // Each is read from its header alone, with none of the payload present.
        for (frame_type, payload) in [(0x7ffe_u64, &b"skip me"[..]), (0x1f00, &b"grease"[..])] {
            let mut encoded = Vec::new();
            encode_frame(frame_type, payload, &mut encoded).unwrap();
            let header = peek_envelope(&encoded, limits).unwrap().header_length;
            let envelope = peek_envelope(&encoded[..header], limits).unwrap();
            assert!(envelope.skipped, "type {frame_type:#x} must be skipped");
            assert_eq!(envelope.payload_length, payload.len());
            // One byte short of the header is not yet decidable.
            assert!(matches!(
                peek_envelope(&encoded[..header - 1], limits),
                Err(DecodeError::Incomplete { .. })
            ));
        }
        assert!(is_grease(0x1f00));

        // Too few bytes for both varints is incomplete, not malformed.
        assert!(matches!(
            peek_envelope(&[], limits),
            Err(DecodeError::Incomplete { .. })
        ));

        // The rejections happen on the envelope, with no payload in hand.
        let mut critical = Vec::new();
        encode_varint(0x7fff, &mut critical).unwrap();
        encode_varint(16, &mut critical).unwrap();
        assert_eq!(
            peek_envelope(&critical, limits),
            Err(DecodeError::UnknownCritical(0x7fff))
        );
        let mut huge = Vec::new();
        encode_varint(frame_type::DATA_RECORD, &mut huge).unwrap();
        encode_varint(MAX_DATA_RECORD_PAYLOAD_FOR_TEST + 1, &mut huge).unwrap();
        assert!(matches!(
            peek_envelope(&huge, limits),
            Err(DecodeError::FrameTooLarge { .. })
        ));

        // The limit is inclusive. A record of exactly the registered size is
        // legal, and rejecting it would refuse the largest frame the protocol
        // defines while every smaller one still worked.
        let mut exact = Vec::new();
        encode_varint(frame_type::DATA_RECORD, &mut exact).unwrap();
        encode_varint(MAX_DATA_RECORD_PAYLOAD_FOR_TEST, &mut exact).unwrap();
        let envelope = peek_envelope(&exact, limits).unwrap();
        assert_eq!(
            envelope.payload_length,
            registered_payload_limit(frame_type::DATA_RECORD).unwrap()
        );
        assert!(!envelope.skipped);
    }

    const MAX_DATA_RECORD_PAYLOAD_FOR_TEST: u64 =
        registered_payload_limit(frame_type::DATA_RECORD).unwrap() as u64;
    use super::*;

    #[test]
    fn varint_boundaries_round_trip_canonically() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            MAX_QUIC_VARINT,
        ] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            let (decoded, width) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(width, encoded.len());
        }
    }

    #[test]
    fn decoder_accepts_non_minimal_legal_varint() {
        let (value, width) = decode_varint(&[0x40, 0x01]).unwrap();
        assert_eq!((value, width), (1, 2));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn protocol_limits_and_error_codes_are_explicit() {
        assert_eq!(HARD_MAX_FRAME_PAYLOAD, 16 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_UNKNOWN_PAYLOAD, 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FRAMES_PER_BATCH, 4096);

        assert_eq!(
            DecodeError::Incomplete {
                needed: 2,
                available: 1
            }
            .protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            DecodeError::ValueOutOfRange(1).protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            DecodeError::InvalidLimits.protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            DecodeError::LengthOverflow(1).protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            DecodeError::FrameTooLarge {
                frame_type: 1,
                length: 2,
                limit: 1
            }
            .protocol_code(),
            error_code::FRAME_TOO_LARGE
        );
        assert_eq!(
            DecodeError::UnknownCritical(1).protocol_code(),
            error_code::UNKNOWN_CRITICAL_FRAME
        );
        assert_eq!(
            DecodeError::TooManyFrames { limit: 1 }.protocol_code(),
            error_code::RESOURCE_LIMIT
        );

        assert_eq!(
            HelloError::UnsupportedRevision(4).protocol_code(),
            error_code::UNSUPPORTED_VERSION
        );
        assert_eq!(
            HelloError::TooManyExtensions(1).protocol_code(),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            HelloError::Malformed(DecodeError::Incomplete {
                needed: 2,
                available: 1
            })
            .protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            HelloError::RoleMismatch {
                expected: EndpointRole::Client,
                actual: EndpointRole::Server
            }
            .protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            HelloError::DuplicateExtension(1).protocol_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(
            HelloError::TrailingBytes.protocol_code(),
            error_code::MALFORMED_FRAME
        );

        assert_eq!(
            SettingsError::Duplicate(1).protocol_code(),
            error_code::DUPLICATE_SETTING
        );
        assert_eq!(
            SettingsError::InvalidValue {
                setting: 1,
                value: 0
            }
            .protocol_code(),
            error_code::INVALID_SETTING
        );
        assert_eq!(
            SettingsError::UnknownCritical(1).protocol_code(),
            error_code::INVALID_SETTING
        );
        assert_eq!(
            SettingsError::TooMany { limit: 1 }.protocol_code(),
            error_code::RESOURCE_LIMIT
        );
        assert_eq!(
            SettingsError::Malformed(DecodeError::FrameTooLarge {
                frame_type: 1,
                length: 2,
                limit: 1
            })
            .protocol_code(),
            error_code::FRAME_TOO_LARGE
        );
    }

    #[test]
    fn optional_unknown_is_skipped() {
        let bytes = [0x1e, 0x03, 0xaa, 0xbb, 0xcc];
        let (frame, consumed) = decode_one(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            frame,
            DecodedFrame::SkippedOptional {
                frame_type: 0x1e,
                payload_length: 3,
            }
        );
    }

    #[test]
    fn critical_unknown_fails_without_payload() {
        let error = decode_one(&[0x1f, 0x00], DecodeLimits::default()).unwrap_err();
        assert_eq!(error, DecodeError::UnknownCritical(0x1f));
    }

    #[test]
    fn grease_is_tolerated() {
        assert!(is_grease(0x1f00));
        assert!(is_grease(0x1ffe));
        assert!(!is_grease(0x1eff));
        assert!(!is_grease(0x1f01));
        assert!(!is_grease(0x1fff));
        let bytes = [0x5f, 0x00, 0x03, 0xde, 0xc0, 0xde];
        let (frame, consumed) = decode_one(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            frame,
            DecodedFrame::SkippedOptional {
                frame_type: 0x1f00,
                payload_length: 3,
            }
        );
    }

    #[test]
    fn length_is_rejected_before_payload_is_required() {
        let bytes = [0x40, 0x90, 0x80, 0x10, 0x00, 0x01];
        let error = decode_one(&bytes, DecodeLimits::default()).unwrap_err();
        assert_eq!(
            error,
            DecodeError::FrameTooLarge {
                frame_type: 0x90,
                length: 1_048_577,
                limit: DEFAULT_MAX_UNKNOWN_PAYLOAD,
            }
        );
    }

    #[test]
    fn known_frame_limit_is_enforced() {
        let bytes = [0x31, 0x80, 0x04, 0x00, 0x01];
        let error = decode_one(&bytes, DecodeLimits::default()).unwrap_err();
        assert_eq!(
            error,
            DecodeError::FrameTooLarge {
                frame_type: frame_type::DATA_RECORD,
                length: 262_145,
                limit: 262_144,
            }
        );
    }

    #[test]
    fn mixed_sequence_preserves_known_frames() {
        let bytes = [
            0x01, 0x00, 0x1e, 0x01, 0xaa, 0x31, 0x04, 0xde, 0xad, 0xbe, 0xef,
        ];
        let frames = decode_all(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames[0],
            DecodedFrame::Known {
                frame_type: 1,
                payload: &[]
            }
        );
        assert_eq!(
            frames[1],
            DecodedFrame::SkippedOptional {
                frame_type: 0x1e,
                payload_length: 1,
            }
        );
        assert_eq!(
            frames[2],
            DecodedFrame::Known {
                frame_type: 0x31,
                payload: &[0xde, 0xad, 0xbe, 0xef],
            }
        );
    }

    #[test]
    fn settings_negotiation_skips_optional_and_applies_known_values() {
        let mut payload = Vec::new();
        for (identifier, value) in [(setting_id::RELIABLE_LANE_LIMIT, 32), (0x24, 9)] {
            encode_varint(identifier, &mut payload).unwrap();
            encode_varint(value, &mut payload).unwrap();
        }
        let settings = decode_settings(&payload).unwrap();
        assert_eq!(settings.reliable_lane_limit, 32);
        assert_eq!(
            settings.telemetry_level,
            Settings::default().telemetry_level
        );
    }

    #[test]
    fn settings_payload_limits_are_explicit() {
        assert_eq!(MIN_CONTROL_FRAME_PAYLOAD, 1024);
        let one_setting = |identifier: u64, value: u64| {
            let mut payload = Vec::new();
            encode_varint(identifier, &mut payload).unwrap();
            encode_varint(value, &mut payload).unwrap();
            payload
        };

        assert_eq!(
            decode_settings(&one_setting(setting_id::MAX_CONTROL_FRAME_PAYLOAD, 1024))
                .unwrap()
                .max_control_frame_payload,
            1024
        );
        assert_eq!(
            decode_settings(&one_setting(
                setting_id::MAX_CONTROL_FRAME_PAYLOAD,
                16 * 1024 * 1024
            ))
            .unwrap()
            .max_control_frame_payload,
            16 * 1024 * 1024
        );
        assert_eq!(
            decode_settings(&one_setting(setting_id::MAX_CONTROL_FRAME_PAYLOAD, 1023)),
            Err(SettingsError::InvalidValue {
                setting: setting_id::MAX_CONTROL_FRAME_PAYLOAD,
                value: 1023
            })
        );
        assert_eq!(
            decode_settings(&one_setting(
                setting_id::MAX_CONTROL_FRAME_PAYLOAD,
                16 * 1024 * 1024 + 1
            )),
            Err(SettingsError::InvalidValue {
                setting: setting_id::MAX_CONTROL_FRAME_PAYLOAD,
                value: 16 * 1024 * 1024 + 1
            })
        );

        assert_eq!(
            decode_settings(&one_setting(setting_id::MAX_DATA_RECORD_PAYLOAD, 64 * 1024))
                .unwrap()
                .max_data_record_payload,
            64 * 1024
        );
        assert_eq!(
            decode_settings(&one_setting(
                setting_id::MAX_DATA_RECORD_PAYLOAD,
                256 * 1024
            ))
            .unwrap()
            .max_data_record_payload,
            256 * 1024
        );
        assert_eq!(
            decode_settings(&one_setting(
                setting_id::MAX_DATA_RECORD_PAYLOAD,
                64 * 1024 - 1
            )),
            Err(SettingsError::InvalidValue {
                setting: setting_id::MAX_DATA_RECORD_PAYLOAD,
                value: 64 * 1024 - 1
            })
        );
        assert_eq!(
            decode_settings(&one_setting(
                setting_id::MAX_DATA_RECORD_PAYLOAD,
                256 * 1024 + 1
            )),
            Err(SettingsError::InvalidValue {
                setting: setting_id::MAX_DATA_RECORD_PAYLOAD,
                value: 256 * 1024 + 1
            })
        );
    }

    #[test]
    fn settings_negotiation_rejects_critical_duplicate_and_invalid() {
        let mut unknown = Vec::new();
        encode_varint(0x25, &mut unknown).unwrap();
        encode_varint(1, &mut unknown).unwrap();
        assert_eq!(
            decode_settings(&unknown),
            Err(SettingsError::UnknownCritical(0x25))
        );

        let mut duplicate = Vec::new();
        for _ in 0..2 {
            encode_varint(setting_id::TELEMETRY_LEVEL, &mut duplicate).unwrap();
            encode_varint(1, &mut duplicate).unwrap();
        }
        assert_eq!(
            decode_settings(&duplicate),
            Err(SettingsError::Duplicate(setting_id::TELEMETRY_LEVEL))
        );

        let mut invalid = Vec::new();
        encode_varint(setting_id::RELIABLE_LANE_LIMIT, &mut invalid).unwrap();
        encode_varint(0, &mut invalid).unwrap();
        assert_eq!(
            decode_settings(&invalid),
            Err(SettingsError::InvalidValue {
                setting: setting_id::RELIABLE_LANE_LIMIT,
                value: 0
            })
        );

        let mut excessive = Vec::new();
        for identifier in (0..=MAX_SETTINGS_PER_FRAME).map(|value| 0x100 + value as u64 * 2) {
            encode_varint(identifier, &mut excessive).unwrap();
            encode_varint(0, &mut excessive).unwrap();
        }
        assert_eq!(
            decode_settings(&excessive),
            Err(SettingsError::TooMany {
                limit: MAX_SETTINGS_PER_FRAME
            })
        );
    }

    #[test]
    fn hello_negotiation_is_bounded_and_role_checked() {
        let mut payload = Vec::new();
        for value in [DRAFT_REVISION, EndpointRole::Client as u64, 3, 0, 2, 6] {
            encode_varint(value, &mut payload).unwrap();
        }
        assert_eq!(
            decode_hello(&payload, EndpointRole::Client).unwrap(),
            Hello {
                draft_revision: DRAFT_REVISION,
                endpoint_role: EndpointRole::Client,
                extensions: BTreeSet::from([0, 2, 6]),
            }
        );
        assert!(matches!(
            decode_hello(&payload, EndpointRole::Server),
            Err(HelloError::RoleMismatch { .. })
        ));

        // The leading value is the draft revision, so this literal moves with
        // it rather than being a constant that happens to have matched.
        let server = [u8::try_from(DRAFT_REVISION).unwrap(), 1, 0];
        assert_eq!(
            decode_hello(&server, EndpointRole::Server)
                .unwrap()
                .endpoint_role,
            EndpointRole::Server
        );

        let mut duplicate = Vec::new();
        for value in [DRAFT_REVISION, 0, 2, 3, 3] {
            encode_varint(value, &mut duplicate).unwrap();
        }
        assert_eq!(
            decode_hello(&duplicate, EndpointRole::Client),
            Err(HelloError::DuplicateExtension(3))
        );

        let mut excessive = Vec::new();
        for value in [
            DRAFT_REVISION,
            EndpointRole::Client as u64,
            MAX_EXTENSIONS_PER_HELLO as u64 + 1,
        ] {
            encode_varint(value, &mut excessive).unwrap();
        }
        assert_eq!(
            decode_hello(&excessive, EndpointRole::Client),
            Err(HelloError::TooManyExtensions(
                MAX_EXTENSIONS_PER_HELLO as u64 + 1
            ))
        );

        let mut maximum = Vec::new();
        for value in [
            DRAFT_REVISION,
            EndpointRole::Client as u64,
            MAX_EXTENSIONS_PER_HELLO as u64,
        ] {
            encode_varint(value, &mut maximum).unwrap();
        }
        for extension in 0..MAX_EXTENSIONS_PER_HELLO as u64 {
            encode_varint(extension, &mut maximum).unwrap();
        }
        assert_eq!(
            decode_hello(&maximum, EndpointRole::Client)
                .unwrap()
                .extensions
                .len(),
            MAX_EXTENSIONS_PER_HELLO
        );
    }

    #[test]
    fn encoded_negotiation_payloads_decode_back_to_what_was_sent() {
        // Until these existed no endpoint could send HELLO or SETTINGS, so the
        // decoders had nothing to read but hand-built bytes.
        let hello = Hello {
            draft_revision: DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: BTreeSet::from([6, 2, 0]),
        };
        let mut payload = Vec::new();
        encode_hello(&hello, &mut payload).unwrap();
        // spec/wire.md section 1: revision, role, count, then the extensions in
        // ascending order because the set is ordered.
        assert_eq!(
            payload,
            vec![u8::try_from(DRAFT_REVISION).unwrap(), 0, 3, 0, 2, 6]
        );
        assert_eq!(decode_hello(&payload, EndpointRole::Client).unwrap(), hello);

        let settings = Settings::default();
        let mut payload = Vec::new();
        encode_settings(&settings, &mut payload).unwrap();
        assert_eq!(decode_settings(&payload).unwrap(), settings);
        // Every registered setting is advertised, not only those that differ
        // from a default the peer does not share.
        let mut identifiers = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let (identifier, width) = decode_varint(&payload[offset..]).unwrap();
            offset += width;
            let (_, width) = decode_varint(&payload[offset..]).unwrap();
            offset += width;
            identifiers.push(identifier);
        }
        assert_eq!(identifiers, REGISTERED_SETTINGS.to_vec());
        assert!(payload.len() <= registered_payload_limit(frame_type::SETTINGS).unwrap());
    }

    #[test]
    fn a_payload_the_peer_would_reject_is_never_encoded() {
        use setting_id as id;

        // The encoder and the decoder read one range table, so a value this
        // side would refuse is refused before it reaches the wire rather than
        // costing a round trip and a closed session.
        let out_of_range = Settings {
            telemetry_level: 3,
            ..Settings::default()
        };
        assert_eq!(
            encode_settings(&out_of_range, &mut Vec::new()),
            Err(SettingsError::InvalidValue {
                setting: setting_id::TELEMETRY_LEVEL,
                value: 3,
            })
        );
        // Every range pinned to the value spec/registries.md gives it, rather
        // than only checked for internal consistency. A range that quietly
        // widened would let this endpoint advertise a limit the registry does
        // not allow, and a peer would be right to refuse the session.
        assert_eq!(
            setting_range(id::MAX_CONTROL_FRAME_PAYLOAD),
            Some((1024, 16 * 1024 * 1024))
        );
        assert_eq!(
            setting_range(id::MAX_DATA_RECORD_PAYLOAD),
            Some((64 * 1024, 256 * 1024))
        );
        assert_eq!(
            setting_range(id::MAX_MANIFEST_PAGE_PAYLOAD),
            Some((64 * 1024, 1024 * 1024))
        );
        assert_eq!(setting_range(id::RELIABLE_LANE_LIMIT), Some((1, 256)));
        assert_eq!(setting_range(id::IDLE_TIMEOUT_MS), Some((1000, 600_000)));
        assert_eq!(
            setting_range(id::ACTIVE_KEEPALIVE_MS),
            Some((10_000, 30_000))
        );
        assert_eq!(
            setting_range(id::COMPRESSION_MIN_GAIN_BPS),
            Some((0, 10_000))
        );
        assert_eq!(setting_range(id::TELEMETRY_LEVEL), Some((0, 2)));
        assert_eq!(setting_range(0x02), None);

        for identifier in REGISTERED_SETTINGS {
            let (low, high) = setting_range(identifier).expect("a registered setting has a range");
            assert!(low <= high);
            // The bound itself is inside the range, and one past it is not.
            assert!(setting_in_range(identifier, low));
            assert!(setting_in_range(identifier, high));
            assert!(!setting_in_range(identifier, high + 1));
            let mut settings = Settings::default();
            *setting_field(&mut settings, identifier).expect("a registered setting has a field") =
                high;
            let mut payload = Vec::new();
            encode_settings(&settings, &mut payload).unwrap();
            assert_eq!(decode_settings(&payload).unwrap(), settings);
        }

        // The bound itself encodes, and one past it does not. Without the
        // first half a bound off by one would go unnoticed and this endpoint
        // would refuse a HELLO the registry allows.
        let at_bound = Hello {
            draft_revision: DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: (0..MAX_EXTENSIONS_PER_HELLO as u64).collect(),
        };
        let mut payload = Vec::new();
        encode_hello(&at_bound, &mut payload).unwrap();
        assert_eq!(
            decode_hello(&payload, EndpointRole::Client).unwrap(),
            at_bound
        );

        let too_many = Hello {
            draft_revision: DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: (0..=MAX_EXTENSIONS_PER_HELLO as u64).collect(),
        };
        assert_eq!(
            encode_hello(&too_many, &mut Vec::new()),
            Err(HelloError::TooManyExtensions(
                MAX_EXTENSIONS_PER_HELLO as u64 + 1
            ))
        );

        // The revision is written as given, so the frame a peer on an older
        // draft would send can be produced and shown to be rejected.
        let older = Hello {
            draft_revision: DRAFT_REVISION - 1,
            endpoint_role: EndpointRole::Client,
            extensions: BTreeSet::new(),
        };
        let mut payload = Vec::new();
        encode_hello(&older, &mut payload).unwrap();
        assert_eq!(
            decode_hello(&payload, EndpointRole::Client),
            Err(HelloError::UnsupportedRevision(DRAFT_REVISION - 1))
        );
    }

    #[test]
    fn experimental_frames_name_the_extension_they_need() {
        // spec/wire.md section 5: an experimental frame is invalid unless its
        // extension is negotiated. Without this table nothing can tell one
        // from an ordinary frame.
        for frame_type in [
            frame_type::DATAGRAM_CREDIT,
            frame_type::CODING_EPOCH_OPEN,
            frame_type::GEN_STATE,
            frame_type::GEN_DONE,
            frame_type::CODING_EPOCH_CLOSE,
        ] {
            assert_eq!(
                required_extension(frame_type),
                Some(extension_id::DATAGRAM_FEC),
                "{frame_type:#x}"
            );
        }
        for frame_type in [
            frame_type::HELLO,
            frame_type::SETTINGS,
            frame_type::DATA_RECORD,
            frame_type::MANIFEST_PAGE,
            frame_type::PING,
        ] {
            assert_eq!(required_extension(frame_type), None, "{frame_type:#x}");
        }
        assert_eq!(error_code::EXPERIMENT_NOT_NEGOTIATED, 0x0701);
        assert_eq!(error_code::REPLAY_REJECTED, 0x0203);
        assert_eq!(extension_id::DATAGRAM_FEC, 0x01);
        assert_eq!(extension_id::MULTIPATH_QUIC, 0x06);
    }

    #[test]
    fn deterministic_mutation_corpus_never_panics() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for length in 0..4096 {
            let mut input = vec![0; length % 513];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            if let Ok(frames) = decode_all(
                &input,
                DecodeLimits {
                    max_unknown_payload: 4096,
                    max_frames: 128,
                },
            ) {
                for frame in frames {
                    if let DecodedFrame::Known {
                        frame_type: frame_type::SETTINGS,
                        payload,
                    } = frame
                    {
                        let _ = decode_settings(payload);
                    }
                }
            }
        }
    }
}
