//! Bounded codec primitives for the `vot-draft-03` frame envelope.
//!
//! Payload schemas live in their owning protocol modules. This crate validates
//! the common envelope, criticality convention, grease handling, and registered
//! per-frame limits before a payload parser can allocate or mutate state.

#![forbid(unsafe_code)]

use core::cmp::min;

pub const MAX_QUIC_VARINT: u64 = (1_u64 << 62) - 1;
pub const HARD_MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_UNKNOWN_PAYLOAD: usize = 1024 * 1024;
pub const DEFAULT_MAX_FRAMES_PER_BATCH: usize = 4096;

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
}
