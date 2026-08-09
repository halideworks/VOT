//! Characterization: `peek_envelope` and `decode_one` share one envelope
//! semantics. This pins their agreement over a generated header corpus so a
//! later shared parser cannot drift either one.

use vot_codec::{
    DecodeError, DecodeLimits, DecodedFrame, HARD_MAX_FRAME_PAYLOAD, MAX_QUIC_VARINT, decode_one,
    encode_varint, is_grease, is_known, peek_envelope, registered_payload_limit,
};

/// A header of two varints, no payload.
fn header(frame_type: u64, declared_length: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_varint(frame_type, &mut bytes).expect("a legal type varint");
    encode_varint(declared_length, &mut bytes).expect("a legal length varint");
    bytes
}

/// The declared lengths worth probing for a type: zero, one, both sides of
/// the applicable limit, both sides of the hard cap, and the largest
/// encodable value.
fn probe_lengths(frame_type: u64, limits: DecodeLimits) -> Vec<u64> {
    let limit = registered_payload_limit(frame_type)
        .unwrap_or(limits.max_unknown_payload)
        .min(HARD_MAX_FRAME_PAYLOAD) as u64;
    let mut lengths = vec![
        0,
        1,
        limit.saturating_sub(1),
        limit,
        limit + 1,
        HARD_MAX_FRAME_PAYLOAD as u64,
        HARD_MAX_FRAME_PAYLOAD as u64 + 1,
        MAX_QUIC_VARINT,
    ];
    lengths.dedup();
    lengths
}

/// Every frame type the corpus visits: the whole low registry space, the
/// grease range boundaries, and types needing wider varints.
fn probe_types() -> Vec<u64> {
    let mut types: Vec<u64> = (0..0x120).collect();
    types.extend([
        0x1eff,
        0x1f00,
        0x1f01,
        0x1ffe,
        0x1fff,
        0x2000,
        0x3fff,
        0x4000,
        0x7fff,
        (1 << 30) - 1,
        1 << 30,
        MAX_QUIC_VARINT,
    ]);
    types
}

#[test]
fn peek_and_decode_agree_on_every_header() {
    let limits = DecodeLimits::default();
    let mut visited = 0_u64;
    for frame_type in probe_types() {
        for declared in probe_lengths(frame_type, limits) {
            visited += 1;
            let head = header(frame_type, declared);
            let peeked = peek_envelope(&head, limits);
            match peeked {
                Err(error) => {
                    // A header peek rejects, decode_one rejects identically:
                    // limit and unknown-critical checks precede availability.
                    assert_eq!(
                        decode_one(&head, limits).unwrap_err(),
                        error,
                        "type {frame_type:#x} length {declared}"
                    );
                }
                Ok(envelope) => {
                    assert_eq!(envelope.frame_type, frame_type);
                    assert_eq!(envelope.payload_length as u64, declared);
                    assert_eq!(
                        envelope.total_length,
                        envelope.header_length + envelope.payload_length
                    );
                    assert_eq!(envelope.header_length, head.len());
                    assert_eq!(
                        envelope.skipped,
                        !is_known(frame_type) || is_grease(frame_type),
                        "type {frame_type:#x}"
                    );
                    // Without the payload, decode_one reports exactly what is
                    // missing.
                    if envelope.payload_length > 0 {
                        assert_eq!(
                            decode_one(&head, limits).unwrap_err(),
                            DecodeError::Incomplete {
                                needed: envelope.total_length,
                                available: head.len(),
                            },
                            "type {frame_type:#x} length {declared}"
                        );
                    }
                    // With it, the two agree on identity and consumption.
                    if envelope.payload_length <= 4096 {
                        let mut whole = head.clone();
                        whole.resize(envelope.total_length, 0xa5);
                        let (frame, consumed) =
                            decode_one(&whole, limits).expect("a complete frame peek accepted");
                        assert_eq!(consumed, envelope.total_length);
                        assert_eq!(frame.frame_type(), frame_type);
                        match frame {
                            DecodedFrame::Known { payload, .. } => {
                                assert!(!envelope.skipped);
                                assert_eq!(payload.len(), envelope.payload_length);
                            }
                            DecodedFrame::SkippedOptional { payload_length, .. } => {
                                assert!(envelope.skipped);
                                assert_eq!(payload_length, envelope.payload_length);
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(visited > 2_000, "the corpus stayed populated: {visited}");
}

#[test]
fn peek_and_decode_agree_on_every_header_truncation() {
    let limits = DecodeLimits::default();
    // Types chosen so headers span one-, two-, and four-byte varints and both
    // outcomes (accepted, unknown-critical).
    for frame_type in [0x01_u64, 0x31, 0x1f00, 0x7fff, 1 << 30] {
        let head = header(frame_type, 32);
        for cut in 0..head.len() {
            let truncated = &head[..cut];
            let peeked = peek_envelope(truncated, limits);
            let decoded =
                decode_one(truncated, limits).map(|(frame, used)| (frame.frame_type(), used));
            match peeked {
                Err(error) => assert_eq!(
                    decoded.unwrap_err(),
                    error,
                    "type {frame_type:#x} cut {cut}"
                ),
                Ok(envelope) => {
                    // The full header fit inside the cut; only the payload is
                    // outstanding for decode_one.
                    assert_eq!(
                        decoded.unwrap_err(),
                        DecodeError::Incomplete {
                            needed: envelope.total_length,
                            available: cut,
                        },
                        "type {frame_type:#x} cut {cut}"
                    );
                }
            }
        }
    }
}

#[test]
fn an_unknown_critical_frame_over_its_limit_is_too_large_first() {
    // Both entry points refuse an oversized frame before asking whether its
    // type is known: FRAME_TOO_LARGE outranks UNKNOWN_CRITICAL. A shared
    // parser must keep this precedence.
    let limits = DecodeLimits::default();
    let oversized = header(0x7fff, limits.max_unknown_payload as u64 + 1);
    for result in [
        peek_envelope(&oversized, limits).map(|_| ()),
        decode_one(&oversized, limits).map(|_| ()),
    ] {
        assert!(
            matches!(
                result,
                Err(DecodeError::FrameTooLarge {
                    frame_type: 0x7fff,
                    ..
                })
            ),
            "{result:?}"
        );
    }

    let fitting = header(0x7fff, limits.max_unknown_payload as u64);
    for result in [
        peek_envelope(&fitting, limits).map(|_| ()),
        decode_one(&fitting, limits).map(|_| ()),
    ] {
        assert_eq!(result, Err(DecodeError::UnknownCritical(0x7fff)));
    }
}

#[test]
fn invalid_limits_are_refused_by_both_before_any_parsing() {
    let bad = DecodeLimits {
        max_unknown_payload: HARD_MAX_FRAME_PAYLOAD + 1,
        max_frames: 1,
    };
    let zero_frames = DecodeLimits {
        max_unknown_payload: 1024,
        max_frames: 0,
    };
    let head = header(0x01, 4);
    for limits in [bad, zero_frames] {
        assert_eq!(
            peek_envelope(&head, limits).unwrap_err(),
            DecodeError::InvalidLimits
        );
        assert_eq!(
            decode_one(&head, limits).unwrap_err(),
            DecodeError::InvalidLimits
        );
        // Even an empty input reports the limits, not the emptiness.
        assert_eq!(
            peek_envelope(&[], limits).unwrap_err(),
            DecodeError::InvalidLimits
        );
    }
}
