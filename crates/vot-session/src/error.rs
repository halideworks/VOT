//! Session errors, peer-fault classification, and error mapping.

use super::{
    Binding, DecodeError, EndpointRole, HelloError, Lane, SettingsError, Side, State,
    TransportError, error_code,
};

/// Why a session cannot continue, with the code `spec/registries.md` gives it.
///
/// A peer-caused failure closes the carrier under that code before the error
/// is returned. A local one does not: see [`ErrorKind::is_peer_fault`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    close: u16,
}

impl Error {
    /// The registered code this failure should close the session under.
    #[must_use]
    pub const fn close_code(&self) -> u16 {
        self.close
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub(super) const fn new(kind: ErrorKind, close: u16) -> Self {
        Self { kind, close }
    }
}

/// The distinguishable ways a session fails, which one registered close code
/// cannot express.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// The peer's `HELLO` was not acceptable.
    Hello(HelloError),
    /// The peer's `SETTINGS` were not acceptable.
    Settings(SettingsError),
    /// The control stream did not carry a decodable frame.
    Decode(DecodeError),
    /// A legal frame arrived at a point in the exchange it cannot appear at.
    OutOfSequence { frame_type: u64, state: State },
    /// A frame that needs a negotiated session arrived before there was one.
    NotNegotiated { frame_type: u64 },
    /// A frame the registry marks `auth: yes` arrived after negotiation and
    /// before the authentication exchange concluded.
    NotAuthenticated { frame_type: u64 },
    /// The server asked for a capability and this endpoint has none to present.
    CapabilityRequired { formats: usize },
    /// `AUTH_CONTEXT` did not carry a challenge.
    AuthContextInvalid,
    /// `SESSION_OPEN` did not carry a request.
    SessionOpenInvalid,
    /// `SESSION_ACCEPT` or `SESSION_REJECT` did not carry an answer.
    SessionAnswerInvalid { frame_type: u64 },
    /// An answer named an attempt this endpoint did not make.
    ///
    /// Neither identifier is carried: a `Debug` derive is one log line from
    /// leaking a session identifier.
    SessionIdentifierMismatch,
    /// The caller answered a request with something that cannot be encoded: a
    /// scope too wide for the frame, or a reason the registry does not assign
    /// to authentication or authorization.
    SessionAnswerUnencodable,
    /// The caller's request cannot be presented, with the section 1.1 rule it
    /// broke. Local, so it closes nothing: another request may follow.
    PresentationInvalid(PresentationError),
    /// A request whose binding proof does not match the binding the challenge
    /// named.
    BindingProofMismatch {
        binding: Binding,
        proof_bytes: usize,
    },
    /// A retry reused a session identifier.
    SessionIdentifierReused,
    /// A request named a capability format this endpoint never advertised.
    CapabilityFormatNotOffered { format: u64 },
    /// More attempts than section 1.1 allows.
    TooManyAuthenticationAttempts { attempts: usize },
    /// A stance that means nothing for this endpoint's role, which would leave
    /// it advertising a challenge it never built or ignoring one it did.
    AuthenticationRoleMismatch { role: EndpointRole },
    /// The carrier ended before the exchange finished.
    Interrupted { state: State },
    /// The application tried to use the data plane before `Ready`.
    NotReady { state: State },
    /// The peer sent more before readiness than this endpoint will hold.
    PendingRecordsExhausted { bytes: usize, count: usize },
    /// Negotiation frames have not all reached the backend yet.
    HandshakeUnsent { remaining: usize },
    /// A frame whose payload is past the negotiated limit for its type.
    FrameExceedsLimit {
        frame_type: u64,
        bytes: u64,
        limit: u64,
        side: Side,
    },
    /// More lanes than the advertised `RELIABLE_LANE_LIMIT` allows.
    LaneLimitExceeded { limit: u64, side: Side },
    /// A submission that is not exactly one whole frame.
    NotExactlyOneFrame {
        frame_type: u64,
        declared: usize,
        found: usize,
        side: Side,
    },
    /// A frame whose extension was not negotiated.
    ExperimentNotNegotiated {
        frame_type: u64,
        extension: u64,
        side: Side,
    },
    /// An application submitted a frame the exchange owns.
    NegotiationFrameFromApplication { frame_type: u64 },
    /// A frame on a stream that does not carry its type.
    FrameOnTheWrongLane {
        frame_type: u64,
        lane: Lane,
        side: Side,
    },
    /// The backend refused something the session needed.
    Transport(TransportError),
    /// The backend would hold a peer to different limits from the ones this
    /// endpoint is about to advertise.
    ReceiveLimitMismatch {
        advertised_control: u64,
        advertised_lanes: u64,
        backend: vot_transport_api::ReceiveLimits,
    },
}

/// Why a request the caller built cannot go out, from `spec/wire.md`
/// section 1.1 rules on `SESSION_OPEN`. All are the caller's mistake, not the peer's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationError {
    /// No challenge is waiting for one, or an attempt is already out.
    NothingToAnswer { state: State },
    /// The attempts section 1.1 allows are spent, so a further request would
    /// be closed on rather than answered.
    AttemptsSpent { attempts: usize },
    /// A session identifier an earlier attempt used, which the server rejects
    /// as a duplicate rather than reading as a retry.
    IdentifierReused,
    /// A capability format the server did not advertise.
    FormatNotOffered { format: u64 },
    /// A binding proof that does not match the binding the challenge named:
    /// empty under proof of possession, or present under none.
    BindingProof {
        binding: Binding,
        proof_bytes: usize,
    },
}

impl ErrorKind {
    /// Whether the peer caused this, and so whether it belongs on the wire.
    #[must_use]
    pub const fn is_peer_fault(&self) -> bool {
        match self {
            Self::Hello(_)
            | Self::Settings(_)
            | Self::Decode(_)
            | Self::OutOfSequence { .. }
            | Self::NotNegotiated { .. }
            | Self::NotAuthenticated { .. }
            | Self::AuthContextInvalid
            | Self::SessionOpenInvalid
            | Self::SessionAnswerInvalid { .. }
            | Self::SessionIdentifierMismatch { .. }
            | Self::BindingProofMismatch { .. }
            | Self::SessionIdentifierReused
            | Self::CapabilityFormatNotOffered { .. }
            | Self::TooManyAuthenticationAttempts { .. }
            // The server did nothing wrong here; this endpoint cannot answer
            // it. The carrier still has to close, and under the registered
            // code rather than a bare disconnect.
            | Self::CapabilityRequired { .. }
            | Self::PendingRecordsExhausted { .. } => true,
            // Only when the peer is the one that went past its limit.
            Self::FrameExceedsLimit { side, .. }
            | Self::LaneLimitExceeded { side, .. }
            | Self::NotExactlyOneFrame { side, .. }
            | Self::ExperimentNotNegotiated { side, .. }
            | Self::FrameOnTheWrongLane { side, .. } => matches!(side, Side::Local),
            // Local. Closing over these would blame the peer for something it
            // did not do, or turn backpressure into a teardown.
            Self::NotReady { .. }
            | Self::Transport(_)
            | Self::Interrupted { .. }
            | Self::ReceiveLimitMismatch { .. }
            | Self::NegotiationFrameFromApplication { .. }
            | Self::SessionAnswerUnencodable
            | Self::PresentationInvalid(_)
            | Self::AuthenticationRoleMismatch { .. }
            | Self::HandshakeUnsent { .. } => false,
        }
    }
}

/// A request the caller cannot present. Local, so it closes nothing.
pub(super) const fn presentation_error(reason: PresentationError) -> Error {
    Error::new(
        ErrorKind::PresentationInvalid(reason),
        error_code::AUTHENTICATION_FAILED,
    )
}

pub(super) fn decode_error(error: DecodeError) -> Error {
    let close = error.protocol_code();
    Error::new(ErrorKind::Decode(error), close)
}

pub(super) fn transport_error(error: TransportError) -> Error {
    let close = match error {
        TransportError::RecordTooLarge => error_code::FRAME_TOO_LARGE,
        TransportError::OutboundQueueFull
        | TransportError::InboundQueueFull
        | TransportError::StagingExhausted => error_code::RESOURCE_LIMIT,
        _ => error_code::MALFORMED_FRAME,
    };
    Error::new(ErrorKind::Transport(error), close)
}
