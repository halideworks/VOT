//! Typed payload schemas and bounded framing for the VOT v0.3 wire protocol.

#![forbid(unsafe_code)]

use core::cmp::min;
use std::collections::BTreeSet;

pub mod frames;
mod generated;
pub use generated::{
    REGISTERED_ERROR_CODES, REGISTERED_LIMITS, REGISTERED_OPERATIONS, REGISTERED_SETTINGS,
    error_code, extension_id, operation, resource_limit, setting_bounds, setting_default,
    setting_id,
};

pub const MAX_QUIC_VARINT: u64 = (1_u64 << 62) - 1;
pub const MIN_CONTROL_FRAME_PAYLOAD: usize = 1024;
pub const HARD_MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_UNKNOWN_PAYLOAD: usize = 1024 * 1024;
pub const DEFAULT_MAX_FRAMES_PER_BATCH: usize = 4096;
pub const MAX_SETTINGS_PER_FRAME: usize = 128;
pub const MAX_EXTENSIONS_PER_HELLO: usize = 256;
pub const DRAFT_REVISION: u64 = 5;

/// The registered default for `IDLE_TIMEOUT_MS`, named so the carrier that
/// installs its own idle timeout can take this one rather than repeat it.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = setting_default::IDLE_TIMEOUT_MS;

// The control frame bounds are the registry's; the constants the codec
// enforces with are the same numbers or nothing agrees.
const _: () =
    assert!(setting_bounds::MAX_CONTROL_FRAME_PAYLOAD.0 == MIN_CONTROL_FRAME_PAYLOAD as u64);
const _: () = assert!(setting_bounds::MAX_CONTROL_FRAME_PAYLOAD.1 == HARD_MAX_FRAME_PAYLOAD as u64);

/// One row per registered frame: identifier, payload ceiling, whether an
/// authenticated session is required to send it, and the extension it needs.
/// The invocation is generated from `spec/registries.yaml`. The macro
/// generates only mechanical lookups; nothing semantic hides in it.
macro_rules! frame_registry {
    ($($name:ident = $value:literal, limit: $limit:expr, auth: $auth:ident, extension: $extension:ident;)*) => {
        pub mod frame_type {
            $(pub const $name: u64 = $value;)*
        }

        #[must_use]
        pub const fn registered_payload_limit(frame_type: u64) -> Option<usize> {
            match frame_type {
                $(frame_type::$name => Some($limit),)*
                _ => None,
            }
        }

        /// The extension a known frame needs before it may be used.
        #[must_use]
        pub const fn required_extension(frame_type: u64) -> Option<u64> {
            match frame_type {
                $(frame_type::$name => frame_registry!(@extension $extension),)*
                _ => None,
            }
        }

        /// Whether a frame type requires an authenticated session.
        ///
        /// Session-setup frames are exempt: requiring auth to send them would
        /// block reaching a session. `ERROR` is never refused so a peer can
        /// report a fault before authenticating. Unregistered types answer
        /// true (fail-closed).
        #[must_use]
        pub const fn requires_authentication(frame_type: u64) -> bool {
            match frame_type {
                $(frame_type::$name => frame_registry!(@auth $auth),)*
                _ => true,
            }
        }
    };
    (@extension none) => { None };
    (@extension $extension:ident) => { Some(extension_id::$extension) };
    (@auth exempt) => { false };
    (@auth required) => { true };
}

include!("generated_frames.rs");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    /// Limit for an unknown optional frame.
    pub max_unknown_payload: usize,
    /// Bounds result-vector growth when decoding a batch.
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
    /// Negotiated and validated, but not installed. QUIC fixes its own idle
    /// timeout during the handshake, before this is negotiated, and the
    /// session has no clock to enforce it with. ADR-0035 says so in full;
    /// what closes an idle connection is the carrier's timeout, taken from
    /// [`Settings::default`].
    pub idle_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_control_frame_payload: setting_default::MAX_CONTROL_FRAME_PAYLOAD,
            max_data_record_payload: setting_default::MAX_DATA_RECORD_PAYLOAD,
            max_manifest_page_payload: setting_default::MAX_MANIFEST_PAGE_PAYLOAD,
            reliable_lane_limit: setting_default::RELIABLE_LANE_LIMIT,
            idle_timeout_ms: setting_default::IDLE_TIMEOUT_MS,
        }
    }
}

impl Settings {
    /// Registered settings and their advertised values, in identifier order.
    #[must_use]
    pub const fn advertised(&self) -> [(u64, u64); 5] {
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

/// Decodes the bounded HELLO payload.
///
/// # Errors
/// Rejects wrong revision/role, duplicate/excessive extensions, truncation, and trailing bytes.
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
/// Unknown optional settings are ignored; unknown critical settings and duplicates terminate negotiation.
///
/// # Errors
/// Rejects a malformed varint, an unknown critical setting, a duplicate, or a value outside its range.
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

/// Whether this revision knows what an operation authorizes. Unknown
/// identifiers grant nothing but do not invalidate the capability.
#[must_use]
pub fn is_registered_operation(identifier: u64) -> bool {
    REGISTERED_OPERATIONS.contains(&identifier)
}

/// An operation this revision can name.
///
/// A capability keeps whatever identifiers it was issued with, unknown ones
/// included, because `spec/registries.md` section 12 says an unknown value
/// does not invalidate the token. It also says such a value grants nothing,
/// and that is only true if an unknown identifier cannot reach the place
/// where a grant is decided. This is the type that stops it: an authorization
/// takes one of these, and the only way to get one is from an identifier the
/// registry names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    Publish,
    ReadManifest,
    ReadRanges,
}

/// An identifier this revision cannot name, carried so a diagnostic can say
/// which one it was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownOperation(pub u64);

impl Operation {
    #[must_use]
    pub const fn identifier(self) -> u64 {
        match self {
            Self::Publish => operation::PUBLISH,
            Self::ReadManifest => operation::READ_MANIFEST,
            Self::ReadRanges => operation::READ_RANGES,
        }
    }
}

impl TryFrom<u64> for Operation {
    type Error = UnknownOperation;

    fn try_from(identifier: u64) -> Result<Self, Self::Error> {
        match identifier {
            operation::PUBLISH => Ok(Self::Publish),
            operation::READ_MANIFEST => Ok(Self::ReadManifest),
            operation::READ_RANGES => Ok(Self::ReadRanges),
            other => Err(UnknownOperation(other)),
        }
    }
}

/// Whether this revision knows what a resource limit bounds. Unknown
/// identifiers fail closed (opposite of operations): ignoring a restriction
/// lifts it.
#[must_use]
pub fn is_registered_limit(identifier: u64) -> bool {
    REGISTERED_LIMITS.contains(&identifier)
}

/// The inclusive value range a registered setting allows.
#[must_use]
pub const fn setting_range(identifier: u64) -> Option<(u64, u64)> {
    use setting_id as id;

    match identifier {
        id::MAX_CONTROL_FRAME_PAYLOAD => Some(setting_bounds::MAX_CONTROL_FRAME_PAYLOAD),
        id::MAX_DATA_RECORD_PAYLOAD => Some(setting_bounds::MAX_DATA_RECORD_PAYLOAD),
        id::MAX_MANIFEST_PAGE_PAYLOAD => Some(setting_bounds::MAX_MANIFEST_PAGE_PAYLOAD),
        id::RELIABLE_LANE_LIMIT => Some(setting_bounds::RELIABLE_LANE_LIMIT),
        id::IDLE_TIMEOUT_MS => Some(setting_bounds::IDLE_TIMEOUT_MS),
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
        _ => None,
    }
}

/// Whether `value` is inside the registered range for `identifier`.
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
            // Unknown optional settings are ignored for forward compatibility.
            Ok(())
        };
    }
    if let Some(target) = setting_field(settings, identifier) {
        *target = value;
    }
    Ok(())
}

/// Encodes a `SETTINGS` payload. Every registered setting is advertised.
///
/// # Errors
/// Returns [`SettingsError::InvalidValue`] for a value outside the registered range.
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

/// Encodes a `HELLO` payload. The revision is written as given.
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
            u16::try_from(value).map_err(|_| DecodeError::ValueOutOfRange(value))? + 0x4000;
        output.extend_from_slice(&encoded.to_be_bytes());
    } else if value < (1 << 30) {
        let encoded =
            u32::try_from(value).map_err(|_| DecodeError::ValueOutOfRange(value))? + 0x8000_0000;
        output.extend_from_slice(&encoded.to_be_bytes());
    } else {
        output.extend_from_slice(&(value + 0xc000_0000_0000_0000).to_be_bytes());
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
        value = (value << 8) + u64::from(*byte);
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
    /// Whether the payload is discarded (unknown optional or grease).
    pub skipped: bool,
}

/// The one envelope parser. Validates limits, reads both varints, applies the
/// registered or unknown-payload bound, and rejects an unknown critical type,
/// all without requiring the payload present. Both public entry points wrap
/// it, so their envelope semantics cannot drift apart.
///
/// The check order is contractual: the payload bound before the
/// unknown-critical check, so an oversized frame closes as `FRAME_TOO_LARGE`
/// whatever its type.
#[inline]
fn parse_envelope_prefix(input: &[u8], limits: DecodeLimits) -> Result<FrameEnvelope, DecodeError> {
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

/// Reads the next frame's envelope without requiring its payload present.
///
/// Unlike [`decode_one`], allows a stream transport to reject or discard a
/// frame before buffering its payload.
///
/// # Errors
/// Returns `Incomplete` until both varints arrive; otherwise the same overflow,
/// length, and unknown-critical errors as [`decode_one`].
pub fn peek_envelope(input: &[u8], limits: DecodeLimits) -> Result<FrameEnvelope, DecodeError> {
    parse_envelope_prefix(input, limits)
}

/// Decodes one bounded frame without owning its payload.
///
/// # Errors
/// Returns an error for invalid limits, truncation, overflow, excessive length, or an unknown critical type.
pub fn decode_one(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<(DecodedFrame<'_>, usize), DecodeError> {
    let envelope = parse_envelope_prefix(input, limits)?;
    if input.len() < envelope.total_length {
        return Err(DecodeError::Incomplete {
            needed: envelope.total_length,
            available: input.len(),
        });
    }

    if envelope.skipped {
        Ok((
            DecodedFrame::SkippedOptional {
                frame_type: envelope.frame_type,
                payload_length: envelope.payload_length,
            },
            envelope.total_length,
        ))
    } else {
        Ok((
            DecodedFrame::Known {
                frame_type: envelope.frame_type,
                payload: &input[envelope.header_length..envelope.total_length],
            },
            envelope.total_length,
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
        let mut frame = Vec::new();
        encode_frame(frame_type::DATA_RECORD, &[7; 4096], &mut frame).unwrap();
        let limits = DecodeLimits::default();

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

        for (frame_type, payload) in [(0x7ffe_u64, &b"skip me"[..]), (0x1f00, &b"grease"[..])] {
            let mut encoded = Vec::new();
            encode_frame(frame_type, payload, &mut encoded).unwrap();
            let header = peek_envelope(&encoded, limits).unwrap().header_length;
            let envelope = peek_envelope(&encoded[..header], limits).unwrap();
            assert!(envelope.skipped, "type {frame_type:#x} must be skipped");
            assert_eq!(envelope.payload_length, payload.len());
            assert!(matches!(
                peek_envelope(&encoded[..header - 1], limits),
                Err(DecodeError::Incomplete { .. })
            ));
        }
        assert!(is_grease(0x1f00));

        assert!(matches!(
            peek_envelope(&[], limits),
            Err(DecodeError::Incomplete { .. })
        ));

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
            settings.idle_timeout_ms,
            Settings::default().idle_timeout_ms
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
            encode_varint(setting_id::IDLE_TIMEOUT_MS, &mut duplicate).unwrap();
            encode_varint(60_000, &mut duplicate).unwrap();
        }
        assert_eq!(
            decode_settings(&duplicate),
            Err(SettingsError::Duplicate(setting_id::IDLE_TIMEOUT_MS))
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

        // Moves with DRAFT_REVISION rather than a coincidental constant.
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
        let hello = Hello {
            draft_revision: DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: BTreeSet::from([6, 2, 0]),
        };
        let mut payload = Vec::new();
        encode_hello(&hello, &mut payload).unwrap();
        // Wire order: revision, role, count, then extensions ascending.
        assert_eq!(
            payload,
            vec![u8::try_from(DRAFT_REVISION).unwrap(), 0, 3, 0, 2, 6]
        );
        assert_eq!(decode_hello(&payload, EndpointRole::Client).unwrap(), hello);

        let settings = Settings::default();
        let mut payload = Vec::new();
        encode_settings(&settings, &mut payload).unwrap();
        assert_eq!(decode_settings(&payload).unwrap(), settings);
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
    fn every_frame_type_carries_the_payload_limit_the_registry_gives_it() {
        use frame_type as ty;
        for (frame, limit) in [
            (ty::HELLO, 4 * 1024),
            (ty::CAPACITY, 4 * 1024),
            (ty::DATAGRAM_CREDIT, 4 * 1024),
            (ty::GOAWAY, 4 * 1024),
            (ty::SETTINGS, 16 * 1024),
            (ty::SETTINGS_ACK, 0),
            (ty::PING, 0),
            (ty::AUTH_CONTEXT, 64 * 1024),
            (ty::SESSION_OPEN, 64 * 1024),
            (ty::SESSION_ACCEPT, 64 * 1024),
            (ty::SESSION_REJECT, 64 * 1024),
            (ty::MANIFEST_REQUEST, 64 * 1024),
            (ty::RANGE_CANCEL, 64 * 1024),
            (ty::TRANSIT_VERIFIED, 64 * 1024),
            (ty::CHUNK_DURABLE, 64 * 1024),
            (ty::CHUNK_AT_REST_VERIFIED, 64 * 1024),
            (ty::PUBLISH_RECEIPT, 64 * 1024),
            (ty::CODING_EPOCH_OPEN, 64 * 1024),
            (ty::GEN_STATE, 64 * 1024),
            (ty::GEN_DONE, 64 * 1024),
            (ty::CODING_EPOCH_CLOSE, 64 * 1024),
            (ty::ERROR, 64 * 1024),
            (ty::SOURCE_SCORE_HINT, 64 * 1024),
            (ty::JOB_PRIORITY_UPDATE, 64 * 1024),
            (ty::SEAL, 256 * 1024),
            (ty::DATA_RECORD, 256 * 1024),
            (ty::PACKAGE_DESCRIPTOR, 1024 * 1024),
            (ty::MANIFEST_PAGE, 1024 * 1024),
            (ty::PROGRESSIVE_PAGE, 1024 * 1024),
            (ty::RANGE_REQUEST, 1024 * 1024),
            (ty::HAVE, 4 * 1024 * 1024),
            (ty::PROOF_BUNDLE, HARD_MAX_FRAME_PAYLOAD),
        ] {
            assert_eq!(
                registered_payload_limit(frame),
                Some(limit),
                "frame {frame:#04x}"
            );
            assert!(is_known(frame), "frame {frame:#04x}");
        }

        // A zero limit is not the same as having no limit.
        assert_eq!(registered_payload_limit(ty::PING), Some(0));
        assert!(is_known(ty::PING));

        for frame in [0x00, 0x02, 0x1f00, u64::MAX] {
            assert_eq!(registered_payload_limit(frame), None, "frame {frame:#04x}");
            assert!(!is_known(frame), "frame {frame:#04x}");
        }
    }

    #[test]
    fn only_registered_limits_are_enforceable() {
        for identifier in REGISTERED_LIMITS {
            assert!(is_registered_limit(identifier), "{identifier:#06x}");
        }
        for identifier in [0x0000, 0x0004, 0x4000, u64::MAX] {
            assert!(!is_registered_limit(identifier), "{identifier:#06x}");
        }
        assert!(
            REGISTERED_LIMITS.windows(2).all(|pair| pair[0] < pair[1]),
            "REGISTERED_LIMITS is not ascending"
        );
        assert_eq!(resource_limit::CONCURRENT_LANES, 0x0001);
        assert_eq!(resource_limit::WIRE_BYTES, 0x0002);
        assert_eq!(resource_limit::STORAGE_BYTES, 0x0003);
    }

    #[test]
    fn decode_limits_are_refused_before_anything_is_read() {
        let mut payload = Vec::new();
        encode_frame(frame_type::PING, &[], &mut payload).unwrap();
        assert_eq!(
            decode_all(
                &payload,
                DecodeLimits {
                    max_unknown_payload: HARD_MAX_FRAME_PAYLOAD,
                    max_frames: 1,
                },
            )
            .map(|frames| frames.len()),
            Ok(1),
            "the ceiling itself is allowed"
        );
        assert_eq!(
            decode_all(
                &payload,
                DecodeLimits {
                    max_unknown_payload: HARD_MAX_FRAME_PAYLOAD + 1,
                    max_frames: 1,
                },
            ),
            Err(DecodeError::InvalidLimits),
            "one byte past it is not"
        );
        assert_eq!(
            decode_all(
                &payload,
                DecodeLimits {
                    max_unknown_payload: 1024,
                    max_frames: 0,
                },
            ),
            Err(DecodeError::InvalidLimits),
            "and no frames at all is not a limit but a contradiction"
        );
    }

    #[test]
    fn a_payload_at_its_registered_limit_decodes_and_one_byte_more_does_not() {
        let mut exact = Vec::new();
        encode_frame(frame_type::SETTINGS_ACK, &[], &mut exact).unwrap();
        let limits = DecodeLimits::default();
        assert!(decode_all(&exact, limits).is_ok());

        let mut oversized = Vec::new();
        encode_varint(frame_type::SETTINGS_ACK, &mut oversized).unwrap();
        encode_varint(1, &mut oversized).unwrap();
        oversized.push(0);
        assert!(matches!(
            decode_all(&oversized, limits),
            Err(DecodeError::FrameTooLarge { limit: 0, .. })
        ));

        let limit = registered_payload_limit(frame_type::HELLO).unwrap();
        let mut at_limit = Vec::new();
        encode_varint(frame_type::HELLO, &mut at_limit).unwrap();
        encode_varint(limit as u64, &mut at_limit).unwrap();
        at_limit.extend(std::iter::repeat_n(0, limit));
        assert!(
            decode_all(&at_limit, limits).is_ok(),
            "a payload at its own limit"
        );
    }

    #[test]
    fn no_unregistered_identifier_becomes_an_operation() {
        // The registry's width. Every value in it either names an operation
        // or cannot be turned into one, with no third answer.
        for identifier in 0..=u64::from(u16::MAX) {
            let converted = Operation::try_from(identifier);
            assert_eq!(
                converted.is_ok(),
                is_registered_operation(identifier),
                "{identifier:#06x}"
            );
            match converted {
                Ok(operation) => assert_eq!(operation.identifier(), identifier),
                Err(UnknownOperation(reported)) => assert_eq!(reported, identifier),
            }
        }
        // And past it, where a capability's own validation would already have
        // refused the value.
        for identifier in [0x1_0000, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                Operation::try_from(identifier),
                Err(UnknownOperation(identifier))
            );
        }
        // The loop above already holds the closed set and the table in exact
        // agreement across the registry's width. What it does not check is
        // the order the table's own doc comment claims.
        assert!(
            REGISTERED_OPERATIONS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "the registered operations are not in identifier order"
        );
    }

    #[test]
    fn only_registered_operations_are_recognized() {
        for identifier in REGISTERED_OPERATIONS {
            assert!(is_registered_operation(identifier), "{identifier:#06x}");
        }
        for identifier in [0x0000, 0x0004, 0x0011, u64::MAX] {
            assert!(!is_registered_operation(identifier), "{identifier:#06x}");
        }
        assert_eq!(
            REGISTERED_OPERATIONS,
            [
                operation::PUBLISH,
                operation::READ_MANIFEST,
                operation::READ_RANGES
            ]
        );
        assert!(
            REGISTERED_OPERATIONS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "REGISTERED_OPERATIONS is not ascending"
        );
        assert_eq!(operation::PUBLISH, 0x0001);
        assert_eq!(operation::READ_MANIFEST, 0x0002);
        assert_eq!(operation::READ_RANGES, 0x0003);
    }

    #[test]
    fn a_payload_the_peer_would_reject_is_never_encoded() {
        use setting_id as id;

        let out_of_range = Settings {
            idle_timeout_ms: 999,
            ..Settings::default()
        };
        assert_eq!(
            encode_settings(&out_of_range, &mut Vec::new()),
            Err(SettingsError::InvalidValue {
                setting: setting_id::IDLE_TIMEOUT_MS,
                value: 999,
            })
        );
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
        assert_eq!(setting_range(0x02), None);
        // ADR-0035 retired these three. A range would mean something still
        // reads them.
        for retired in id::RETIRED {
            assert_eq!(setting_range(retired), None, "{retired:#04x}");
            assert!(!REGISTERED_SETTINGS.contains(&retired), "{retired:#04x}");
        }

        for identifier in REGISTERED_SETTINGS {
            let (low, high) = setting_range(identifier).expect("a registered setting has a range");
            assert!(low <= high);
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
    fn only_the_frames_that_reach_an_authenticated_session_are_exempt() {
        for frame_type in [
            frame_type::HELLO,
            frame_type::SETTINGS,
            frame_type::SETTINGS_ACK,
            frame_type::AUTH_CONTEXT,
            frame_type::SESSION_OPEN,
            frame_type::SESSION_ACCEPT,
            frame_type::SESSION_REJECT,
            frame_type::PING,
            frame_type::ERROR,
        ] {
            assert!(!requires_authentication(frame_type), "{frame_type:#x}");
        }
        for frame_type in [
            frame_type::PROOF_BUNDLE,
            frame_type::DATA_RECORD,
            frame_type::MANIFEST_REQUEST,
            frame_type::PACKAGE_DESCRIPTOR,
            frame_type::PUBLISH_RECEIPT,
            frame_type::GOAWAY,
        ] {
            assert!(requires_authentication(frame_type), "{frame_type:#x}");
        }
        assert!(requires_authentication(0x1f01));
        assert!(requires_authentication(u64::MAX));
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
