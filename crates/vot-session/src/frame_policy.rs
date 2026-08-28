//! Per-frame checks: lanes, sides, extensions, and negotiated limits.

use super::{
    BTreeSet, DecodeError, EndpointRole, Error, ErrorKind, Negotiation, Settings, StreamId,
    decode_error, error_code, frame_type,
};

/// Whether one more lane fits a negotiated limit. A lane already in use is
/// free; deciding is separate from recording.
pub(super) fn lane_allowed(
    lanes: &BTreeSet<StreamId>,
    stream: StreamId,
    limit: u64,
    side: Side,
) -> Result<(), Error> {
    if lanes.contains(&stream) || u64::try_from(lanes.len()).is_ok_and(|used| used < limit) {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::LaneLimitExceeded { limit, side },
        error_code::RESOURCE_LIMIT,
    ))
}

/// The payload limit `settings` puts on `frame_type`. Negotiation can only
/// lower a registry maximum; a frame the settings do not name is bounded by
/// the control ceiling.
pub(super) fn negotiated_payload_limit(frame_type: u64, settings: &Settings) -> u64 {
    let ceiling = settings.max_control_frame_payload;
    match frame_type {
        frame_type::DATA_RECORD => settings.max_data_record_payload,
        frame_type::MANIFEST_PAGE | frame_type::PROGRESSIVE_PAGE => {
            settings.max_manifest_page_payload.min(ceiling)
        }
        _ => ceiling,
    }
}

/// Which stream a frame is on. A control-only frame on a lane bypasses
/// negotiation, so lane checking exists to keep them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    /// The negotiation stream, which carries every control frame.
    Control,
    /// An application lane, which carries records and nothing else.
    Reliable,
}

impl Lane {
    /// Whether a frame of this type belongs on the lane. `DATA_RECORD` is the
    /// payload; everything else is control.
    pub(super) const fn carries(self, frame_type: u64) -> bool {
        let payload = matches!(frame_type, vot_codec::frame_type::DATA_RECORD);
        match self {
            Self::Control => !payload,
            Self::Reliable => payload,
        }
    }
}

/// Whether the exchange owns this frame type. An application sending one would
/// drive the peer's state machine by hand. Use `grant` and `refuse` to answer.
pub(super) const fn is_exchange_frame(frame_type: u64) -> bool {
    matches!(
        frame_type,
        frame_type::HELLO
            | frame_type::SETTINGS
            | frame_type::SETTINGS_ACK
            | frame_type::AUTH_CONTEXT
            | frame_type::SESSION_OPEN
            | frame_type::SESSION_ACCEPT
            | frame_type::SESSION_REJECT
    )
}

/// Whose limits a frame is measured against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// What this endpoint advertised, so exceeding it is the peer's doing.
    Local,
    /// What the peer advertised, so exceeding it would be this endpoint's.
    Peer,
}

/// Which extensions a frame check consults, answered without building the
/// intersection set. Both directions consult the negotiated set (ADR-0041).
#[derive(Clone, Copy)]
pub(super) enum ExtensionPolicy<'a> {
    Negotiated(&'a Negotiation),
}

impl ExtensionPolicy<'_> {
    fn contains(self, extension: u64) -> bool {
        match self {
            Self::Negotiated(negotiation) => negotiation.extension_is_negotiated(extension),
        }
    }
}

/// Checks one encoded frame against the limits `settings` gives its type.
/// The one place a negotiated payload limit is applied, in both directions.
pub(super) fn check_frame(
    frame: &[u8],
    settings: &Settings,
    extensions: ExtensionPolicy<'_>,
    lane: Lane,
    side: Side,
    local_role: EndpointRole,
    enforce_direction: bool,
) -> Result<(), Error> {
    let limits = vot_codec::DecodeLimits {
        max_unknown_payload: usize::try_from(settings.max_control_frame_payload)
            .unwrap_or(usize::MAX),
        max_frames: 1,
    };
    let envelope = vot_codec::peek_envelope(frame, limits).map_err(decode_error)?;

    // Exactly one whole frame. peek_envelope succeeds on a header alone, so a
    // partial frame would leave the peer waiting on an open stream.
    if envelope.total_length != frame.len() {
        return Err(Error::new(
            ErrorKind::NotExactlyOneFrame {
                frame_type: envelope.frame_type,
                declared: envelope.total_length,
                found: frame.len(),
                side,
            },
            error_code::MALFORMED_FRAME,
        ));
    }

    // The lane decides which types it may carry.
    if !lane.carries(envelope.frame_type) {
        return Err(Error::new(
            ErrorKind::FrameOnTheWrongLane {
                frame_type: envelope.frame_type,
                lane,
                side,
            },
            error_code::MALFORMED_FRAME,
        ));
    }

    // Outbound only: the exchange consumes these on the way in, and reaching
    // here on the way out means an application encoded one itself.
    if matches!(side, Side::Peer) && is_exchange_frame(envelope.frame_type) {
        return Err(Error::new(
            ErrorKind::NegotiationFrameFromApplication {
                frame_type: envelope.frame_type,
            },
            error_code::MALFORMED_FRAME,
        ));
    }

    // spec/wire.md section 5: an experimental frame is invalid unless its
    // extension was negotiated, whichever side it came from.
    if let Some(extension) = vot_codec::required_extension(envelope.frame_type)
        && !extensions.contains(extension)
    {
        return Err(Error::new(
            ErrorKind::ExperimentNotNegotiated {
                frame_type: envelope.frame_type,
                extension,
                side,
            },
            error_code::EXPERIMENT_NOT_NEGOTIATED,
        ));
    }

    let payload = u64::try_from(envelope.payload_length).map_err(|_| {
        Error::new(
            ErrorKind::Decode(DecodeError::LengthOverflow(u64::MAX)),
            error_code::FRAME_TOO_LARGE,
        )
    })?;
    let limit = negotiated_payload_limit(envelope.frame_type, settings);
    if payload > limit {
        return Err(Error::new(
            ErrorKind::FrameExceedsLimit {
                frame_type: envelope.frame_type,
                bytes: payload,
                limit,
                side,
            },
            error_code::FRAME_TOO_LARGE,
        ));
    }
    if enforce_direction {
        let ExtensionPolicy::Negotiated(negotiation) = extensions;
        check_direction(envelope.frame_type, negotiation, local_role, side)?;
    }
    Ok(())
}

pub(super) fn check_direction(
    frame_type: u64,
    negotiation: &Negotiation,
    local_role: EndpointRole,
    side: Side,
) -> Result<(), Error> {
    let push = negotiation.extension_is_negotiated(vot_codec::extension_id::PUSH);
    if direction_allowed(frame_type, local_role, push, side) {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::FrameFromWrongRole {
            frame_type,
            role: sender_role(local_role, side),
            side,
        },
        error_code::MALFORMED_FRAME,
    ))
}

const fn sender_role(local: EndpointRole, side: Side) -> EndpointRole {
    match (local, side) {
        (role, Side::Peer) => role,
        (EndpointRole::Client, Side::Local) => EndpointRole::Server,
        (EndpointRole::Server, Side::Local) => EndpointRole::Client,
    }
}

pub(super) fn direction_allowed(
    frame_type: u64,
    local_role: EndpointRole,
    push: bool,
    side: Side,
) -> bool {
    let sender = sender_role(local_role, side);
    let publisher = if push {
        EndpointRole::Client
    } else {
        EndpointRole::Server
    };
    let requester = if push {
        EndpointRole::Server
    } else {
        EndpointRole::Client
    };
    if matches!(
        frame_type,
        frame_type::PACKAGE_DESCRIPTOR
            | frame_type::MANIFEST_PAGE
            | frame_type::PROGRESSIVE_PAGE
            | frame_type::SEAL
            | frame_type::PROOF_BUNDLE
            | frame_type::DATA_RECORD
    ) {
        sender == publisher
    } else if matches!(
        frame_type,
        frame_type::MANIFEST_REQUEST
            | frame_type::HAVE
            | frame_type::RANGE_REQUEST
            | frame_type::RANGE_CANCEL
    ) {
        sender == requester
    } else {
        true
    }
}
