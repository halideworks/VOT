//! The `spec/wire.md` section 1 exchange, and the gate it puts in front of the
//! data plane. See `docs/session.md`.
//!
//! `Ready` means negotiated, not authenticated. `AUTH_CONTEXT`,
//! `SESSION_OPEN`, and `SESSION_ACCEPT` are unimplemented, so every frame the
//! registry marks `auth: yes` is not yet conforming.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use vot_codec::frames::{AuthContext, Binding, SessionAccept, SessionOpen, SessionReject};
use vot_codec::{
    DecodeError, DecodedFrame, EndpointRole, Hello, HelloError, Settings, SettingsError,
    error_code, frame_type,
};
use vot_transport_api::{Error as TransportError, Event, Payload, StreamId, TransportAdapter};

/// Peer records held while this endpoint finishes negotiating.
///
/// A conforming peer can have data in flight before it learns this side is
/// ready, so refusing them would close a session it did nothing wrong in.
pub const DEFAULT_PENDING_RECORD_BYTES: usize = 4 * vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// The same bound by count, since bytes alone do not limit per-record
/// overhead.
pub const DEFAULT_PENDING_RECORD_COUNT: usize = 64;

/// How far a session has got through `spec/wire.md` section 1.
///
/// Named from the client's side: on a server, `HelloSent` means the peer's
/// `HELLO` arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// No carrier yet.
    Connecting,
    /// The negotiation stream exists and nothing has been sent on it.
    ControlReserved,
    /// `HELLO` has been sent by the client, or seen by the server.
    HelloSent,
    /// Both `SETTINGS` frames have been accounted for.
    SettingsExchanged,
    /// `SETTINGS_ACK` has been sent by the server, or seen by the client.
    /// Negotiation is done and the authentication exchange is not.
    Negotiated,
    /// The concluding frame of `spec/wire.md` section 1.1 has been sent or
    /// read, so frames the registry marks `auth: yes` are valid.
    Authenticated,
    /// The carrier is gone.
    Closed,
}

impl State {
    /// Whether the application may use the data plane.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Authenticated)
    }

    /// Whether negotiation has finished, which is when the authentication
    /// exchange runs.
    #[must_use]
    pub const fn is_negotiated(self) -> bool {
        matches!(self, Self::Negotiated | Self::Authenticated)
    }
}

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

    const fn new(kind: ErrorKind, close: u16) -> Self {
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
    /// The server asked for a capability, which no policy boundary can present
    /// yet.
    CapabilityRequired { formats: usize },
    /// `AUTH_CONTEXT` did not carry a challenge.
    AuthContextInvalid,
    /// `SESSION_OPEN` did not carry a request.
    SessionOpenInvalid,
    /// A retry reused a session identifier.
    SessionIdentifierReused,
    /// A request named a capability format this endpoint never advertised.
    CapabilityFormatNotOffered { format: u64 },
    /// More attempts than section 1.1 allows.
    TooManyAuthenticationAttempts { attempts: usize },
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
            | Self::HandshakeUnsent { .. } => false,
        }
    }
}

/// What accepting a control frame did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Accepted {
    /// Negotiation consumed the frame. `reply` goes out before anything else.
    Consumed { reply: Vec<Vec<u8>> },
    /// The frame is not part of negotiation and belongs to the application.
    Application,
    /// A peer opened a session. The caller's policy decides, and answers with
    /// [`Negotiation::grant`] or [`Negotiation::refuse`].
    ///
    /// Nothing moves until it does: the exchange is not concluded and the data
    /// plane is still shut.
    AuthorizationRequired,
}

/// The exchange as a state machine, with no carrier and no buffers.
/// [`Session`] connects it to a transport.
#[derive(Clone, Debug)]
pub struct Negotiation {
    role: EndpointRole,
    state: State,
    local: Settings,
    extensions: BTreeSet<u64>,
    /// The challenge a server advertises, and what a client read. Supplied by
    /// the caller: this crate has no randomness, and a session whose freshness
    /// came from inside it could not be tested for the value it actually sent.
    challenge: AuthContext,
    /// What the peer opened, once one attempt is under way.
    open: Option<SessionOpen>,
    /// Session identifiers already attempted, so a retry cannot reuse one.
    attempted: Vec<[u8; 16]>,
    peer_hello: Option<Hello>,
    peer_settings: Option<Settings>,
}

impl Negotiation {
    /// A connecting endpoint, which opens the negotiation stream and speaks
    /// first.
    #[must_use]
    pub fn client(local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(
            EndpointRole::Client,
            local,
            extensions,
            no_capability([0; 32]),
        )
    }

    /// An accepting endpoint, which answers on the stream the client opened.
    #[must_use]
    pub fn server(local: Settings, extensions: BTreeSet<u64>, challenge: AuthContext) -> Self {
        Self::new(EndpointRole::Server, local, extensions, challenge)
    }

    fn new(
        role: EndpointRole,
        local: Settings,
        extensions: BTreeSet<u64>,
        challenge: AuthContext,
    ) -> Self {
        Self {
            role,
            state: State::Connecting,
            local,
            extensions,
            challenge,
            open: None,
            attempted: Vec::new(),
            peer_hello: None,
            peer_settings: None,
        }
    }

    /// How far the exchange has got.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Whether the application may use the data plane.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// The limits this endpoint advertised, which bound what it will accept.
    #[must_use]
    pub const fn local_settings(&self) -> Settings {
        self.local
    }

    /// The limits the peer advertised, which bound what this endpoint sends.
    /// Absent until its `SETTINGS` arrive; guessing a default would be the
    /// assumption negotiation exists to remove.
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.peer_settings
    }

    /// The extensions this endpoint may send under.
    ///
    /// Always empty, and that is the specification gap rather than a policy.
    /// Only the client sends `HELLO`, so a server can compute an intersection
    /// and a client cannot. Sending under the server's half would put a frame
    /// on the wire that the client is obliged to refuse, closing a session that
    /// had negotiated correctly.
    ///
    /// Strict about what is sent, and [`negotiated_extensions`] for what is
    /// accepted. This becomes the intersection once the exchange can confirm
    /// extensions in both directions.
    ///
    /// [`negotiated_extensions`]: Self::negotiated_extensions
    #[must_use]
    pub fn usable_extensions(&self) -> BTreeSet<u64> {
        BTreeSet::new()
    }

    /// The extensions both endpoints advertised, which bound what is accepted.
    ///
    /// Advertising one does not authorise it, so this is the intersection.
    /// Empty until the peer's `HELLO` arrives, which is what keeps an
    /// experimental frame out of an unnegotiated session.
    #[must_use]
    pub fn negotiated_extensions(&self) -> BTreeSet<u64> {
        let Some(hello) = &self.peer_hello else {
            return BTreeSet::new();
        };
        self.extensions
            .intersection(&hello.extensions)
            .copied()
            .collect()
    }

    /// What the peer said about itself.
    #[must_use]
    pub const fn peer_hello(&self) -> Option<&Hello> {
        self.peer_hello.as_ref()
    }

    /// Reports the negotiation stream reserved and returns what to send.
    ///
    /// The client sends `HELLO` then `SETTINGS`; the server answers, so it
    /// sends nothing yet.
    ///
    /// # Errors
    /// Rejects a second call, and a local `HELLO` or `SETTINGS` this endpoint
    /// could not encode.
    pub fn begin(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.state != State::Connecting {
            return Err(Error::new(
                ErrorKind::OutOfSequence {
                    frame_type: frame_type::HELLO,
                    state: self.state,
                },
                error_code::MALFORMED_FRAME,
            ));
        }
        self.state = State::ControlReserved;
        if self.role == EndpointRole::Server {
            return Ok(Vec::new());
        }
        let hello = Hello {
            draft_revision: vot_codec::DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: self.extensions.clone(),
        };
        let frames = vec![Self::hello_frame(&hello)?, self.settings_frame()?];
        self.state = State::HelloSent;
        Ok(frames)
    }

    /// Feeds one complete control frame to the exchange.
    ///
    /// # Errors
    /// Reports an undecodable frame, a frame out of sequence, a peer on another
    /// draft, unacceptable settings, or an application frame before `Ready`.
    pub fn accept_control(&mut self, frame: &[u8]) -> Result<Accepted, Error> {
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: usize::try_from(self.local.max_control_frame_payload)
                .unwrap_or(usize::MAX),
            max_frames: 1,
        };
        let (decoded, consumed) = vot_codec::decode_one(frame, limits).map_err(decode_error)?;
        if consumed != frame.len() {
            // Trailing bytes mean the carrier and this layer disagree about
            // where frames end.
            return Err(Error::new(
                ErrorKind::Decode(DecodeError::LengthOverflow(consumed as u64)),
                error_code::MALFORMED_FRAME,
            ));
        }
        let DecodedFrame::Known {
            frame_type,
            payload,
        } = decoded
        else {
            // Unknown optional and grease frames are skipped at any point, so
            // a peer can send them mid-handshake.
            return Ok(Accepted::Consumed { reply: Vec::new() });
        };
        match frame_type {
            frame_type::HELLO => self.accept_hello(payload),
            frame_type::SETTINGS => self.accept_settings(payload),
            frame_type::SETTINGS_ACK => self.accept_settings_ack(),
            frame_type::AUTH_CONTEXT => self.accept_auth_context(payload),
            frame_type::SESSION_OPEN => self.accept_session_open(payload),
            other => self.accept_application(other),
        }
    }

    /// Ends the exchange because the peer broke it, as opposed to
    /// [`carrier_closed`](Self::carrier_closed), which is the carrier going
    /// away on its own.
    pub const fn abandon(&mut self) {
        self.state = State::Closed;
    }

    /// Reports the carrier gone.
    ///
    /// # Errors
    /// Reports a carrier that ended before the exchange finished, which is not
    /// the same as one that ended after.
    pub fn carrier_closed(&mut self) -> Result<(), Error> {
        let previous = self.state;
        self.state = State::Closed;
        if previous.is_ready() || previous == State::Closed {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::Interrupted { state: previous },
            error_code::MALFORMED_FRAME,
        ))
    }

    fn accept_hello(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        // spec/wire.md section 5: once per session, and only the client sends
        // it, on the stream it opened.
        if self.role != EndpointRole::Server || self.state != State::ControlReserved {
            return Err(self.out_of_sequence(frame_type::HELLO));
        }
        let hello = vot_codec::decode_hello(payload, EndpointRole::Client).map_err(|error| {
            let close = error.protocol_code();
            Error::new(ErrorKind::Hello(error), close)
        })?;
        self.peer_hello = Some(hello);
        self.state = State::HelloSent;
        Ok(Accepted::Consumed { reply: Vec::new() })
    }

    fn accept_settings(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        // Once per direction: a second would move limits the peer was already
        // told.
        if self.peer_settings.is_some() {
            return Err(self.out_of_sequence(frame_type::SETTINGS));
        }
        // The same state on both sides: HELLO accounted for, SETTINGS not.
        if self.state != State::HelloSent {
            return Err(self.out_of_sequence(frame_type::SETTINGS));
        }
        let settings = vot_codec::decode_settings(payload).map_err(|error| {
            let close = error.protocol_code();
            Error::new(ErrorKind::Settings(error), close)
        })?;
        self.peer_settings = Some(settings);
        self.state = State::SettingsExchanged;
        match self.role {
            EndpointRole::Client => Ok(Accepted::Consumed { reply: Vec::new() }),
            EndpointRole::Server => {
                // Answer, acknowledgement, and challenge together: nothing
                // further to ask. spec/wire.md section 1.1 puts AUTH_CONTEXT
                // straight after SETTINGS_ACK, so a peer never has to be told
                // to expect it.
                let reply = vec![
                    self.settings_frame()?,
                    settings_ack_frame()?,
                    self.auth_context_frame()?,
                ];
                self.state = State::Negotiated;
                // This deployment advertises no capability format, so
                // AUTH_CONTEXT is the concluding frame and sending it is what
                // authenticates this endpoint.
                self.state = State::Authenticated;
                Ok(Accepted::Consumed { reply })
            }
        }
    }

    /// Accepts `SETTINGS_ACK`. No payload check: the registry gives it a
    /// maximum of zero bytes, so the codec has already refused a longer one.
    fn accept_settings_ack(&mut self) -> Result<Accepted, Error> {
        // spec/wire.md section 5: a duplicate acknowledgement is ignored, so a
        // second one after readiness is not an error.
        if self.role == EndpointRole::Client && self.state.is_negotiated() {
            return Ok(Accepted::Consumed { reply: Vec::new() });
        }
        if self.role != EndpointRole::Client || self.state != State::SettingsExchanged {
            return Err(self.out_of_sequence(frame_type::SETTINGS_ACK));
        }
        self.state = State::Negotiated;
        Ok(Accepted::Consumed { reply: Vec::new() })
    }

    /// Accepts the server's challenge.
    ///
    /// No capability format is advertised yet, so this is the concluding frame
    /// of the exchange and reading it is what authenticates the client.
    fn accept_auth_context(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        if self.role != EndpointRole::Client || self.state != State::Negotiated {
            return Err(self.out_of_sequence(frame_type::AUTH_CONTEXT));
        }
        let context = vot_codec::frames::decode_auth_context_payload(payload)
            .map_err(|_| Error::new(ErrorKind::AuthContextInvalid, error_code::MALFORMED_FRAME))?;
        if !context.formats.is_empty() {
            // A server asking for a capability this endpoint cannot present.
            // Refusing is what stops a client from looking authenticated to
            // itself while the server waits for a SESSION_OPEN.
            return Err(Error::new(
                ErrorKind::CapabilityRequired {
                    formats: context.formats.len(),
                },
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        self.state = State::Authenticated;
        Ok(Accepted::Consumed { reply: Vec::new() })
    }

    /// Decides whether a frame outside the exchange may be carried.
    ///
    /// Two gates, in the order `spec/wire.md` puts them: section 1 refuses
    /// everything until negotiation has finished, and section 1.1 refuses the
    /// subset the registry marks `auth: yes` until the authentication exchange
    /// concludes. A frame the registry does not mark passes in between.
    /// Accepts a client's request to open a session.
    ///
    /// Everything section 1.1 requires of the request is checked here; whether
    /// the capability itself is good is the caller's policy to decide, which is
    /// what [`Accepted::AuthorizationRequired`] asks for.
    fn accept_session_open(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        // A deployment advertising no capability format concluded the exchange
        // at AUTH_CONTEXT, so there is nothing here to open.
        if self.role != EndpointRole::Server
            || self.state != State::Negotiated
            || self.challenge.formats.is_empty()
            || self.open.is_some()
        {
            return Err(self.out_of_sequence(frame_type::SESSION_OPEN));
        }
        if self.attempted.len() >= MAX_AUTHENTICATION_ATTEMPTS {
            return Err(Error::new(
                ErrorKind::TooManyAuthenticationAttempts {
                    attempts: self.attempted.len(),
                },
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        let open = vot_codec::frames::decode_session_open_payload(payload)
            .map_err(|_| Error::new(ErrorKind::SessionOpenInvalid, error_code::MALFORMED_FRAME))?;
        // A retry reusing an identifier is the conflicting duplicate section 5
        // rejects, not a new attempt.
        if self.attempted.contains(&open.session_id) {
            return Err(Error::new(
                ErrorKind::SessionIdentifierReused,
                error_code::REPLAY_REJECTED,
            ));
        }
        // Only a format this endpoint advertised. Anything else asks the policy
        // to parse bytes whose shape it never agreed to.
        if !self.challenge.formats.contains(&open.capability_format) {
            return Err(Error::new(
                ErrorKind::CapabilityFormatNotOffered {
                    format: open.capability_format,
                },
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        self.attempted.push(open.session_id);
        self.open = Some(open);
        Ok(Accepted::AuthorizationRequired)
    }

    /// The request awaiting a decision, and the challenge it answered.
    #[must_use]
    pub const fn pending_authorization(&self) -> Option<(&AuthContext, &SessionOpen)> {
        match &self.open {
            Some(open) => Some((&self.challenge, open)),
            None => None,
        }
    }

    /// Authorizes the pending request with the scope the policy granted.
    ///
    /// # Errors
    /// Rejects a grant with nothing pending, or a scope too wide for the frame.
    pub fn grant(&mut self, granted_scope: Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
        let open = self
            .open
            .take()
            .ok_or_else(|| self.out_of_sequence(frame_type::SESSION_ACCEPT))?;
        let accept = SessionAccept {
            // The identity the request carried. A server choosing its own would
            // leave a client unable to tell which attempt was answered.
            session_id: open.session_id,
            granted_scope,
        };
        let frame = Self::session_frame(&vot_codec::frames::TypedFrame::SessionAccept(accept))?;
        self.state = State::Authenticated;
        Ok(vec![frame])
    }

    /// Refuses the pending request under a registered reason.
    ///
    /// The session stays open: section 1.1 lets a client try again with another
    /// capability, up to [`MAX_AUTHENTICATION_ATTEMPTS`].
    ///
    /// # Errors
    /// Rejects a refusal with nothing pending, or a reason the registry does
    /// not assign to authentication or authorization.
    pub fn refuse(&mut self, reason: u16, detail: String) -> Result<Vec<Vec<u8>>, Error> {
        let open = self
            .open
            .take()
            .ok_or_else(|| self.out_of_sequence(frame_type::SESSION_REJECT))?;
        let reject = SessionReject {
            session_id: open.session_id,
            reason: u64::from(reason),
            detail,
        };
        let frame = Self::session_frame(&vot_codec::frames::TypedFrame::SessionReject(reject))?;
        Ok(vec![frame])
    }

    fn session_frame(frame: &vot_codec::frames::TypedFrame) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        vot_codec::frames::encode(frame, &mut encoded)
            .map_err(|_| Error::new(ErrorKind::SessionOpenInvalid, error_code::MALFORMED_FRAME))?;
        Ok(encoded)
    }

    fn accept_application(&mut self, frame_type: u64) -> Result<Accepted, Error> {
        if !self.state.is_negotiated() {
            return Err(Error::new(
                ErrorKind::NotNegotiated { frame_type },
                error_code::MALFORMED_FRAME,
            ));
        }
        if !self.state.is_ready() && vot_codec::requires_authentication(frame_type) {
            return Err(Error::new(
                ErrorKind::NotAuthenticated { frame_type },
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        Ok(Accepted::Application)
    }

    fn out_of_sequence(&self, frame_type: u64) -> Error {
        Error::new(
            ErrorKind::OutOfSequence {
                frame_type,
                state: self.state,
            },
            error_code::MALFORMED_FRAME,
        )
    }

    fn hello_frame(hello: &Hello) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        vot_codec::encode_hello(hello, &mut payload).map_err(|error| {
            let close = error.protocol_code();
            Error::new(ErrorKind::Hello(error), close)
        })?;
        frame(frame_type::HELLO, &payload)
    }

    /// The challenge this endpoint advertises, whatever its caller's policy
    /// put there.
    fn auth_context_frame(&self) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        // A challenge outside the bounds section 1.1 gives never reaches the
        // wire. Reported rather than unwrapped: the caller supplied it.
        vot_codec::frames::encode_auth_context_payload(&self.challenge, &mut payload)
            .map_err(|_| Error::new(ErrorKind::AuthContextInvalid, error_code::MALFORMED_FRAME))?;
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::AUTH_CONTEXT, &payload, &mut frame)
            .map_err(|error| Error::new(ErrorKind::Decode(error), error_code::MALFORMED_FRAME))?;
        Ok(frame)
    }

    fn settings_frame(&self) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        vot_codec::encode_settings(&self.local, &mut payload).map_err(|error| {
            let close = error.protocol_code();
            Error::new(ErrorKind::Settings(error), close)
        })?;
        frame(frame_type::SETTINGS, &payload)
    }
}

fn settings_ack_frame() -> Result<Vec<u8>, Error> {
    frame(frame_type::SETTINGS_ACK, &[])
}

fn frame(frame_type: u64, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    vot_codec::encode_frame(frame_type, payload, &mut encoded).map_err(decode_error)?;
    Ok(encoded)
}

fn decode_error(error: DecodeError) -> Error {
    let close = error.protocol_code();
    Error::new(ErrorKind::Decode(error), close)
}

/// A negotiation running over a transport, gating the data plane behind it.
/// Owns the adapter so an application cannot reach past the gate.
pub struct Session<A> {
    adapter: A,
    negotiation: Negotiation,
    /// Named by the caller, because no policy exists to establish it.
    authentication: Authentication,
    /// Negotiation frames the backend has not accepted yet, at most two.
    ///
    /// The exchange advances in pairs, and the state machine will not produce
    /// a frame twice, so a full outbound queue has to be backpressure rather
    /// than a lost handshake.
    outbound: VecDeque<Vec<u8>>,
    /// Records the peer sent before this endpoint reached `Ready`. Held here
    /// rather than in the adapter, whose single queue would block the control
    /// frames readiness is waiting for.
    pending: VecDeque<Event>,
    /// Lanes this endpoint has sent on, bounded by the peer's advertised
    /// `RELIABLE_LANE_LIMIT`.
    lanes: BTreeSet<StreamId>,
    pending_bytes: usize,
    pending_byte_limit: usize,
    pending_count_limit: usize,
    /// Whether the peer's control-frame limit reached the backend.
    control_limit_applied: bool,
}

impl<A: TransportAdapter> Session<A> {
    /// A connecting session, which opens the negotiation stream.
    ///
    /// `authentication` has to be named because there is no implementation
    /// behind it: see [`Authentication`].
    pub fn client(
        adapter: A,
        local: Settings,
        extensions: BTreeSet<u64>,
        authentication: Authentication,
    ) -> Self {
        Self::new(
            adapter,
            Negotiation::client(local, extensions),
            authentication,
        )
    }

    /// An accepting session, which answers on the stream the client opened.
    ///
    /// `authentication` has to be named because the exchange is
    /// unconditional: see [`Authentication`].
    pub fn server(
        adapter: A,
        local: Settings,
        extensions: BTreeSet<u64>,
        authentication: Authentication,
    ) -> Self {
        let challenge = match &authentication {
            Authentication::NotRequired { nonce } => no_capability(*nonce),
            Authentication::Capability { challenge } => challenge.clone(),
        };
        Self::new(
            adapter,
            Negotiation::server(local, extensions, challenge),
            authentication,
        )
    }

    /// What this endpoint does about authentication.
    #[must_use]
    pub const fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    fn new(adapter: A, negotiation: Negotiation, authentication: Authentication) -> Self {
        Self {
            adapter,
            negotiation,
            authentication,
            outbound: VecDeque::new(),
            pending: VecDeque::new(),
            lanes: BTreeSet::new(),
            pending_bytes: 0,
            pending_byte_limit: DEFAULT_PENDING_RECORD_BYTES,
            pending_count_limit: DEFAULT_PENDING_RECORD_COUNT,
            control_limit_applied: false,
        }
    }

    /// Sets how much peer data this session will hold before `Ready`.
    ///
    /// # Errors
    /// Rejects a bound that cannot hold one maximum record, which would refuse
    /// a conforming peer rather than bound it.
    pub fn set_pending_limits(&mut self, bytes: usize, count: usize) -> Result<(), Error> {
        if bytes < vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES || count == 0 {
            return Err(Error::new(
                ErrorKind::Transport(TransportError::InvalidConfiguration),
                error_code::RESOURCE_LIMIT,
            ));
        }
        self.pending_byte_limit = bytes;
        self.pending_count_limit = count;
        Ok(())
    }

    /// How far the exchange has got.
    #[must_use]
    pub const fn state(&self) -> State {
        self.negotiation.state()
    }

    /// Whether the application may use the data plane.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.negotiation.is_ready()
    }

    /// The limits this endpoint advertised.
    #[must_use]
    pub const fn local_settings(&self) -> Settings {
        self.negotiation.local_settings()
    }

    /// The limits the peer advertised.
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.negotiation.peer_settings()
    }

    /// Whether the peer's control-frame limit reached the backend. False when
    /// the backend has no such bound.
    #[must_use]
    pub const fn control_limit_applied(&self) -> bool {
        self.control_limit_applied
    }

    /// Borrows the backend for measurements that do not move data.
    pub const fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Borrows the backend mutably, for the code that drives the carrier.
    ///
    /// Some backends do their work through methods the adapter contract does
    /// not cover: a `TcpAdapter` moves bytes through `drain_commands` and
    /// `record_native_event`, both of which need this, and without it a session
    /// over one could queue a handshake nothing would ever send.
    ///
    /// This is for a driver, not an application. Reaching the adapter reaches
    /// past the readiness gate, and an application that sends through here is
    /// doing what [`send_reliable`](Self::send_reliable) exists to refuse.
    pub const fn driver(&mut self) -> &mut A {
        &mut self.adapter
    }

    /// Returns the backend, ending the session's ownership of it.
    pub fn into_adapter(self) -> A {
        self.adapter
    }

    /// Starts the exchange, sending whatever this endpoint speaks first.
    ///
    /// # Errors
    /// Reports a second call, an unencodable local frame, or a backend that
    /// refused the submission.
    pub fn begin(&mut self) -> Result<(), Error> {
        self.check_receive_limit()?;
        let frames = self.negotiation.begin()?;
        self.submit(frames)
    }

    /// Refuses to advertise a control-frame limit the backend will not keep.
    ///
    /// Checked rather than set: the bound has to be in force before the peer's
    /// first byte, and a session is built after the carrier.
    ///
    /// # Errors
    /// Reports a backend whose reassembly bound is not the limit this endpoint
    /// is about to advertise.
    fn check_receive_limit(&self) -> Result<(), Error> {
        let Some(backend) = self.adapter.receive_limits() else {
            // A backend that enforces nothing has nothing to disagree with.
            return Ok(());
        };
        let advertised = self.negotiation.local_settings();
        if backend.match_settings(&advertised) {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::ReceiveLimitMismatch {
                advertised_control: advertised.max_control_frame_payload,
                advertised_lanes: advertised.reliable_lane_limit,
                backend,
            },
            error_code::INVALID_SETTING,
        ))
    }

    /// Returns the next event the application should see.
    ///
    /// Negotiation frames are consumed here and never surface. Records that
    /// arrive before this endpoint is ready are held and released in order once
    /// it is.
    ///
    /// # Errors
    /// Reports a peer that broke the exchange, a carrier that ended during it,
    /// or more pre-readiness data than this session will hold. A failure the
    /// peer caused also closes the carrier under its registered code.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        match self.poll_inner() {
            Err(error) => Err(self.fail(error)),
            polled => polled,
        }
    }

    /// Ends the session when the peer is the one that broke it, and only
    /// then.
    fn fail(&mut self, error: Error) -> Error {
        if error.kind().is_peer_fault() {
            let _ = self.adapter.close(error.close_code());
            self.negotiation.abandon();
        }
        error
    }

    /// Whether queued negotiation frames should still be pushed. A closed
    /// session has nothing left to negotiate.
    const fn may_negotiate(&self) -> bool {
        !matches!(self.negotiation.state(), State::Closed)
    }

    fn poll_inner(&mut self) -> Result<Option<Event>, Error> {
        if self.may_negotiate() && !self.outbound.is_empty() {
            // So a driver that only polls recovers from a stall.
            self.drain_outbound()?;
        }
        if self.negotiation.state() == State::Closed {
            // Interpreting more would report the second thing that went wrong
            // rather than the first.
            return Ok(self.drain_lifecycle());
        }
        if self.negotiation.is_ready()
            && let Some(event) = self.take_pending()
        {
            return Ok(Some(event));
        }
        while let Some(event) = self.adapter.poll() {
            match event {
                Event::Control(bytes) => {
                    self.check_inbound(&bytes, Lane::Control)?;
                    if let Some(event) = self.accept_control(&bytes)? {
                        return Ok(Some(event));
                    }
                }
                Event::Disconnected(connection) => {
                    self.negotiation.carrier_closed()?;
                    return Ok(Some(Event::Disconnected(connection)));
                }
                record @ Event::Reliable { .. } => {
                    // No lane count here. A session never sees a stream close,
                    // so it could only count lanes ever used and would refuse a
                    // peer that closed one and opened another. The transport
                    // counts them at adoption and releases them at shutdown,
                    // which is the only place that lifecycle is visible.
                    if let Event::Reliable { bytes, .. } = &record {
                        self.check_inbound(bytes, Lane::Reliable)?;
                    }
                    if self.negotiation.is_ready() {
                        return Ok(Some(record));
                    }
                    self.hold(record)?;
                }
                other => return Ok(Some(other)),
            }
            if self.negotiation.is_ready()
                && let Some(event) = self.take_pending()
            {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// Submits an application control frame.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_control(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.require_sendable()?;
        self.check_outbound(frame, Lane::Control)?;
        self.adapter.send_control(frame).map_err(transport_error)
    }

    /// Submits an application record on a reliable lane.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        self.require_sendable()?;
        self.check_outbound(record, Lane::Reliable)?;
        self.require_lane_allowed(stream)?;
        // Counted only once the backend has it. A refused send opens no carrier
        // stream, so counting it would spend a lane on nothing and, at a limit
        // of one, refuse every later lane for good.
        self.adapter
            .send_reliable(stream, record)
            .map_err(transport_error)?;
        self.lanes.insert(stream);
        Ok(())
    }

    /// Submits an already shared record without another copy.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.require_sendable()?;
        self.check_outbound(&record, Lane::Reliable)?;
        self.require_lane_allowed(stream)?;
        self.adapter
            .send_reliable_shared(stream, record)
            .map_err(transport_error)?;
        self.lanes.insert(stream);
        Ok(())
    }

    /// Pushes queued submissions into the backend.
    ///
    /// Allowed before `Ready`, because the negotiation frames themselves have
    /// to reach the peer.
    ///
    /// # Errors
    /// Propagates a backend failure.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.may_negotiate() {
            return self.drain_outbound();
        }
        // Closed: flush what the backend holds, but add nothing to it.
        self.adapter.flush().map_err(transport_error)
    }

    fn accept_control(&mut self, bytes: &[u8]) -> Result<Option<Event>, Error> {
        match self.negotiation.accept_control(bytes)? {
            Accepted::Application => Ok(Some(Event::Control(vot_transport_api::shared_payload(
                bytes,
            )))),
            Accepted::Consumed { reply } => {
                let became_ready = self.negotiation.is_ready();
                self.submit(reply)?;
                if became_ready {
                    self.apply_peer_limits();
                }
                Ok(None)
            }
            // The caller's policy decides. Nothing is sent and nothing moves
            // until it answers through grant or refuse.
            Accepted::AuthorizationRequired => Ok(None),
        }
    }

    /// The request awaiting the caller's policy, and the challenge it answered.
    #[must_use]
    pub const fn pending_authorization(&self) -> Option<(&AuthContext, &SessionOpen)> {
        self.negotiation.pending_authorization()
    }

    /// Authorizes the pending request and sends the acceptance.
    ///
    /// # Errors
    /// Reports nothing pending, an unencodable scope, or a backend refusal.
    pub fn grant(&mut self, granted_scope: Vec<u8>) -> Result<(), Error> {
        let reply = self.negotiation.grant(granted_scope)?;
        self.submit(reply)?;
        self.apply_peer_limits();
        Ok(())
    }

    /// Refuses the pending request and sends the refusal.
    ///
    /// # Errors
    /// Reports nothing pending, an unregistered reason, or a backend refusal.
    pub fn refuse(&mut self, reason: u16, detail: String) -> Result<(), Error> {
        let reply = self.negotiation.refuse(reason, detail)?;
        self.submit(reply)
    }

    /// Applies what the peer advertised to the backend. Its control-frame
    /// maximum is the bound on what this endpoint may send.
    fn apply_peer_limits(&mut self) {
        let Some(peer) = self.negotiation.peer_settings() else {
            return;
        };
        let Ok(limit) = usize::try_from(peer.max_control_frame_payload) else {
            return;
        };
        self.control_limit_applied = self.adapter.set_control_payload_limit(limit).is_ok();
    }

    /// Queues negotiation frames and pushes as many as the backend will take.
    ///
    /// # Errors
    /// Reports a refusal that is not capacity. A full queue is backpressure:
    /// the next `flush` or `poll` retries.
    fn submit(&mut self, frames: Vec<Vec<u8>>) -> Result<(), Error> {
        self.outbound.extend(frames);
        self.drain_outbound()
    }

    /// Hands queued negotiation frames to the backend in order.
    ///
    /// # Errors
    /// Reports the first refusal that is not capacity. The frame stays queued
    /// either way.
    fn drain_outbound(&mut self) -> Result<(), Error> {
        while let Some(frame) = self.outbound.front() {
            match self.adapter.send_control(frame) {
                Ok(()) => {
                    self.outbound.pop_front();
                }
                // Backpressure: resume when the backend has room.
                Err(TransportError::OutboundQueueFull) => break,
                Err(error) => return Err(transport_error(error)),
            }
        }
        self.adapter.flush().map_err(transport_error)
    }

    /// Negotiation frames still waiting for the backend.
    #[must_use]
    pub fn unsent_negotiation_frames(&self) -> usize {
        self.outbound.len()
    }

    fn hold(&mut self, record: Event) -> Result<(), Error> {
        let bytes = match &record {
            Event::Reliable { bytes, .. } => bytes.len(),
            _ => 0,
        };
        let next = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or_else(|| self.pending_exhausted())?;
        if next > self.pending_byte_limit || self.pending.len() >= self.pending_count_limit {
            return Err(self.pending_exhausted());
        }
        self.pending_bytes = next;
        self.pending.push_back(record);
        Ok(())
    }

    /// Lifecycle events only. The caller still has to learn the carrier
    /// ended; nothing else on a closed session means anything.
    fn drain_lifecycle(&mut self) -> Option<Event> {
        while let Some(event) = self.adapter.poll() {
            match event {
                Event::Control(_) | Event::Reliable { .. } => {}
                lifecycle => return Some(lifecycle),
            }
        }
        None
    }

    fn take_pending(&mut self) -> Option<Event> {
        let event = self.pending.pop_front()?;
        if let Event::Reliable { bytes, .. } = &event {
            self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
        }
        Some(event)
    }

    fn pending_exhausted(&self) -> Error {
        Error::new(
            ErrorKind::PendingRecordsExhausted {
                bytes: self.pending_bytes,
                count: self.pending.len(),
            },
            error_code::RESOURCE_LIMIT,
        )
    }

    /// Whether the application may put a frame on the carrier.
    ///
    /// Readiness is not enough. A server becomes ready when it produces
    /// `SETTINGS_ACK`, not when the backend takes it, so an application frame
    /// sent while the acknowledgement is still queued would overtake it and
    /// reach a peer that is still waiting to finish negotiating.
    fn require_sendable(&self) -> Result<(), Error> {
        if !self.negotiation.is_ready() {
            return Err(Error::new(
                ErrorKind::NotReady {
                    state: self.negotiation.state(),
                },
                error_code::MALFORMED_FRAME,
            ));
        }
        if !self.outbound.is_empty() {
            return Err(Error::new(
                ErrorKind::HandshakeUnsent {
                    remaining: self.outbound.len(),
                },
                error_code::RESOURCE_LIMIT,
            ));
        }
        Ok(())
    }

    /// Checks a frame this endpoint is about to send against the peer's limits.
    /// Nothing to check before the peer has advertised any.
    fn check_outbound(&self, frame: &[u8], lane: Lane) -> Result<(), Error> {
        let Some(peer) = self.negotiation.peer_settings() else {
            return Ok(());
        };
        check_frame(
            frame,
            &peer,
            &self.negotiation.usable_extensions(),
            lane,
            Side::Peer,
        )
    }

    /// Checks a frame the peer sent against the limits this endpoint
    /// advertised, which the adapters bound only by the protocol ceiling.
    fn check_inbound(&self, frame: &[u8], lane: Lane) -> Result<(), Error> {
        check_frame(
            frame,
            &self.negotiation.local_settings(),
            &self.negotiation.negotiated_extensions(),
            lane,
            Side::Local,
        )
    }

    /// Refuses a lane past the number the peer said it would carry.
    ///
    /// Counted over every lane this endpoint has used, because nothing here
    /// closes one and the backends open a stream per distinct identifier.
    fn require_lane_allowed(&self, stream: StreamId) -> Result<(), Error> {
        let Some(peer) = self.negotiation.peer_settings() else {
            return Ok(());
        };
        lane_allowed(&self.lanes, stream, peer.reliable_lane_limit, Side::Peer)
    }
}

/// Whether one more lane fits a negotiated limit.
///
/// A lane already in use is free: the limit is on how many exist, and nothing
/// here closes one. Deciding is separate from recording, so a caller counts a
/// lane only once whatever it was opening for has succeeded.
fn lane_allowed(
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

/// The payload limit `settings` puts on `frame_type`.
///
/// `spec/registries.md` gives every frame a fixed maximum and negotiation can
/// only lower it, so a setting below a registry limit takes effect here and
/// nowhere else. A frame the settings do not name is bounded by the control
/// ceiling alone.
///
/// One table rather than a check per setting: every frame, in either
/// direction, is measured the same way, and a setting the registry adds later
/// is a row here rather than another branch somewhere.
fn negotiated_payload_limit(frame_type: u64, settings: &Settings) -> u64 {
    let ceiling = settings.max_control_frame_payload;
    match frame_type {
        frame_type::DATA_RECORD => settings.max_data_record_payload,
        frame_type::MANIFEST_PAGE | frame_type::PROGRESSIVE_PAGE => {
            settings.max_manifest_page_payload.min(ceiling)
        }
        _ => ceiling,
    }
}

/// What this endpoint does about authentication.
///
/// `spec/wire.md` section 1.1 makes the exchange unconditional, so a caller
/// names its stance rather than opting in. The variant that presents or
/// verifies a capability appears when there is a policy boundary behind it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authentication {
    /// This deployment requires none. The server advertises no capability
    /// format, so section 1.1 concludes the exchange at `AUTH_CONTEXT` and
    /// both endpoints are authenticated once it has been sent or read.
    ///
    /// The nonce is what a server puts in that frame. It is supplied rather
    /// than generated because this crate has no randomness, and a session
    /// whose freshness came from inside it could not be tested for the value
    /// it actually sent. A client ignores it.
    NotRequired { nonce: [u8; 32] },
    /// A server that asks for a capability. The exchange concludes at
    /// `SESSION_ACCEPT`, and what a capability is worth is decided by the
    /// caller through [`Session::pending_authorization`], [`Session::grant`],
    /// and [`Session::refuse`].
    ///
    /// The boundary is the caller's rather than a trait this crate calls: a
    /// policy needs a deployment's own identity store and clock, neither of
    /// which a session has.
    Capability { challenge: AuthContext },
}

/// Which stream a frame is on.
///
/// `spec/wire.md` section 7 gives negotiation its own stream and application
/// records their lanes. A control-only frame on a lane bypasses negotiation
/// entirely, so a duplicate `HELLO` after readiness would reach the
/// application instead of producing the sequence error the exchange requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    /// The negotiation stream, which carries every control frame.
    Control,
    /// An application lane, which carries records and nothing else.
    Reliable,
}

impl Lane {
    /// Whether a frame of this type belongs on the lane.
    ///
    /// `spec/wire.md` section 7 gives a lane the payload and the control stream
    /// everything else. `DATA_RECORD` is the payload. A `PROOF_BUNDLE`
    /// describes the payload and is bounded by the negotiated control ceiling,
    /// not by the fixed record limit, so it travels on the control stream.
    const fn carries(self, frame_type: u64) -> bool {
        let payload = matches!(frame_type, vot_codec::frame_type::DATA_RECORD);
        match self {
            Self::Control => !payload,
            Self::Reliable => payload,
        }
    }
}

/// Frames the negotiation state machine owns.
///
/// An application sending one drives the peer's exchange by hand: a second
/// `HELLO` or `SETTINGS` is refused as out of sequence and closes a session
/// that was working.
const fn is_negotiation(frame_type: u64) -> bool {
    matches!(
        frame_type,
        frame_type::HELLO
            | frame_type::SETTINGS
            | frame_type::SETTINGS_ACK
            | frame_type::AUTH_CONTEXT
    )
}

/// Attempts a server accepts before closing, from `spec/wire.md` section 1.1.
///
/// Fixed rather than negotiated so both sides know it without a setting, and
/// it bounds the work an unauthenticated peer can ask for.
pub const MAX_AUTHENTICATION_ATTEMPTS: usize = 3;

/// The challenge a deployment requiring no authentication advertises.
///
/// No capability format, which `spec/wire.md` section 1.1 defines as requiring
/// none. The nonce is still fresh per session: a client that later binds to it
/// must not find a constant.
#[must_use]
pub fn no_capability(nonce: [u8; 32]) -> AuthContext {
    AuthContext {
        nonce: nonce.to_vec(),
        binding: Binding::None,
        formats: Vec::new(),
    }
}

/// Whose limits a frame is measured against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// What this endpoint advertised, so exceeding it is the peer's doing.
    Local,
    /// What the peer advertised, so exceeding it would be this endpoint's.
    Peer,
}

/// Checks one encoded frame against the limits `settings` gives its type.
///
/// The one place a negotiated payload limit is applied. Records and control
/// frames pass through it in both directions, so the payload length is read
/// from the envelope once and a wire length is never mistaken for it.
fn check_frame(
    frame: &[u8],
    settings: &Settings,
    extensions: &BTreeSet<u64>,
    lane: Lane,
    side: Side,
) -> Result<(), Error> {
    let limits = vot_codec::DecodeLimits {
        max_unknown_payload: usize::try_from(settings.max_control_frame_payload)
            .unwrap_or(usize::MAX),
        max_frames: 1,
    };
    let envelope = vot_codec::peek_envelope(frame, limits).map_err(decode_error)?;

    // Exactly one whole frame. peek_envelope succeeds on a header alone, so a
    // header declaring a payload that is not there would go out as it stands
    // and leave the peer waiting on a stream that stays open. Trailing bytes
    // are the same disagreement from the other end.
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

    // The stream a frame is on decides which types it may be. Without this a
    // control-only frame on a lane skips negotiation and reaches the
    // application, and a record on the negotiation stream is not a record.
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
    if matches!(side, Side::Peer) && is_negotiation(envelope.frame_type) {
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
        && !extensions.contains(&extension)
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
    if payload <= limit {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::FrameExceedsLimit {
            frame_type: envelope.frame_type,
            bytes: payload,
            limit,
            side,
        },
        error_code::FRAME_TOO_LARGE,
    ))
}

fn transport_error(error: TransportError) -> Error {
    let close = match error {
        TransportError::RecordTooLarge => error_code::FRAME_TOO_LARGE,
        TransportError::OutboundQueueFull
        | TransportError::InboundQueueFull
        | TransportError::StagingExhausted => error_code::RESOURCE_LIMIT,
        _ => error_code::MALFORMED_FRAME,
    };
    Error::new(ErrorKind::Transport(error), close)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A transport that hands each endpoint whatever the other submitted.
    #[derive(Default)]
    struct Loopback {
        sent: Vec<Vec<u8>>,
        records: Vec<(StreamId, Vec<u8>)>,
        events: VecDeque<Event>,
        control_limit: Option<usize>,
        refuse_control_limit: bool,
        flushes: usize,
        refuse_sends: Option<TransportError>,
        /// Control frames the backend will take before reporting a full queue.
        control_capacity: Option<usize>,
        refuse_control: Option<TransportError>,
        closed: Vec<u16>,
        receive_limits: Option<vot_transport_api::ReceiveLimits>,
    }

    impl TransportAdapter for Loopback {
        fn send_control(&mut self, frame: &[u8]) -> Result<(), TransportError> {
            if let Some(error) = self.refuse_control {
                return Err(error);
            }
            if self
                .control_capacity
                .is_some_and(|room| self.sent.len() >= room)
            {
                return Err(TransportError::OutboundQueueFull);
            }
            self.sent.push(frame.to_vec());
            Ok(())
        }

        fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), TransportError> {
            if let Some(error) = self.refuse_sends {
                return Err(error);
            }
            self.records.push((stream, record.to_vec()));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), TransportError> {
            self.flushes += 1;
            Ok(())
        }

        fn poll(&mut self) -> Option<Event> {
            self.events.pop_front()
        }

        fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), TransportError> {
            Ok(())
        }

        fn set_control_payload_limit(&mut self, limit: usize) -> Result<(), TransportError> {
            if self.refuse_control_limit {
                return Err(TransportError::Unsupported);
            }
            self.control_limit = Some(limit);
            Ok(())
        }

        fn receive_limits(&self) -> Option<vot_transport_api::ReceiveLimits> {
            self.receive_limits
        }

        fn close(&mut self, code: u16) -> Result<(), TransportError> {
            self.closed.push(code);
            Ok(())
        }
    }

    fn control(bytes: &[u8]) -> Event {
        Event::Control(vot_transport_api::shared_payload(bytes))
    }

    /// One encoded `DATA_RECORD` frame, which is what a lane actually carries.
    fn data_record(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::DATA_RECORD, payload, &mut frame).unwrap();
        frame
    }

    /// The wire length of a `DATA_RECORD` carrying `payload` bytes.
    fn record_wire_len(payload: usize) -> usize {
        data_record(&vec![0; payload]).len()
    }

    fn record(lane: u64, payload: &[u8]) -> Event {
        Event::Reliable {
            stream: StreamId(lane),
            sequence: lane,
            bytes: vot_transport_api::shared_payload(&data_record(payload)),
        }
    }

    /// Runs the exchange to completion with the given local settings.
    fn negotiated_with(
        client_settings: Settings,
        server_settings: Settings,
    ) -> (Session<Loopback>, Session<Loopback>) {
        let mut client = Session::client(
            Loopback::default(),
            client_settings,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            server_settings,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        client.poll().unwrap();
        assert!(client.is_ready() && server.is_ready());
        (client, server)
    }

    /// Runs the exchange to completion, returning both endpoints.
    fn negotiated() -> (Session<Loopback>, Session<Loopback>) {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();

        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready(), "the server answers in one pass");

        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.is_ready());
        (client, server)
    }

    #[test]
    fn the_exchange_follows_the_order_the_specification_gives_it() {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::from([1, 2]),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        assert_eq!(client.state(), State::Connecting);
        client.begin().unwrap();
        assert_eq!(client.state(), State::HelloSent);

        // spec/wire.md section 1: the client sends HELLO then SETTINGS.
        let sent = client.adapter.sent.clone();
        assert_eq!(sent.len(), 2);
        let limits = vot_codec::DecodeLimits::default();
        let (first, _) = vot_codec::decode_one(&sent[0], limits).unwrap();
        let (second, _) = vot_codec::decode_one(&sent[1], limits).unwrap();
        assert_eq!(first.frame_type(), frame_type::HELLO);
        assert_eq!(second.frame_type(), frame_type::SETTINGS);

        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        // The server answers rather than speaking first, so nothing goes out
        // until the client's frames arrive.
        assert_eq!(server.state(), State::ControlReserved);
        assert!(server.adapter.sent.is_empty());

        server.adapter.events.push_back(control(&sent[0]));
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.state(), State::HelloSent);
        assert_eq!(
            server.negotiation.peer_hello().unwrap().extensions,
            BTreeSet::from([1, 2])
        );
        assert!(server.adapter.sent.is_empty(), "HELLO alone is not enough");

        server.adapter.events.push_back(control(&sent[1]));
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());

        // spec/wire.md section 1: the server sends its SETTINGS then
        // SETTINGS_ACK, and section 1.1 puts AUTH_CONTEXT straight after.
        let answer = server.adapter.sent.clone();
        assert_eq!(answer.len(), 3);
        let types: Vec<u64> = answer
            .iter()
            .map(|frame| vot_codec::decode_one(frame, limits).unwrap().0.frame_type())
            .collect();
        assert_eq!(
            types,
            vec![
                frame_type::SETTINGS,
                frame_type::SETTINGS_ACK,
                frame_type::AUTH_CONTEXT
            ]
        );

        for frame in answer {
            client.adapter.events.push_back(control(&frame));
        }
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.is_ready());
        assert_eq!(client.peer_settings(), Some(Settings::default()));
    }

    /// A client and a server driven to the end of the exchange, with what the
    /// server sent.
    fn negotiated_pair() -> (Session<Loopback>, Session<Loopback>, Vec<Vec<u8>>) {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        assert_eq!(server.poll().unwrap(), None);
        let answer = std::mem::take(&mut server.adapter.sent);
        for frame in &answer {
            client.adapter.events.push_back(control(frame));
        }
        assert_eq!(client.poll().unwrap(), None);
        (client, server, answer)
    }

    /// An `AUTH_CONTEXT` frame carrying the given challenge.
    fn auth_context(nonce: &[u8], formats: Vec<u64>) -> Vec<u8> {
        let context = vot_codec::frames::AuthContext {
            nonce: nonce.to_vec(),
            binding: vot_codec::frames::Binding::None,
            formats,
        };
        let mut payload = Vec::new();
        vot_codec::frames::encode_auth_context_payload(&context, &mut payload).unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::AUTH_CONTEXT, &payload, &mut frame).unwrap();
        frame
    }

    #[test]
    fn the_exchange_concludes_at_the_challenge_when_none_is_required() {
        // spec/wire.md section 1.1: a server advertising no capability format
        // requires no authentication, and AUTH_CONTEXT is the concluding
        // frame. Each endpoint reaches it by sending or reading that frame.
        let (client, server, answer) = negotiated_pair();
        assert_eq!(server.state(), State::Authenticated);
        assert_eq!(client.state(), State::Authenticated);
        assert!(server.is_ready() && client.is_ready());

        // The nonce is the caller's, not a constant this crate chose.
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 8,
        };
        let challenge = answer
            .iter()
            .find(|frame| {
                vot_codec::decode_one(frame, limits).unwrap().0.frame_type()
                    == frame_type::AUTH_CONTEXT
            })
            .expect("the server sent a challenge");
        let (decoded, _) = vot_codec::decode_one(challenge, limits).unwrap();
        let vot_codec::DecodedFrame::Known { payload, .. } = decoded else {
            panic!("AUTH_CONTEXT is a known frame");
        };
        let context = vot_codec::frames::decode_auth_context_payload(payload).unwrap();
        assert_eq!(context.nonce, vec![0x5a; 32]);
        assert!(context.formats.is_empty(), "no capability format");
        assert_eq!(context.binding, vot_codec::frames::Binding::None);
    }

    #[test]
    fn a_negotiated_session_is_not_yet_an_authenticated_one() {
        // The window between the two states is what the gate exists for. A
        // record arriving in it is well sequenced and not yet allowed.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.negotiation.state = State::Negotiated;
        assert!(!server.is_ready(), "negotiated is not ready");
        assert!(server.negotiation.state().is_negotiated());

        let error = server
            .send_reliable(StreamId(1), &data_record(b"early"))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);

        let mut inbound =
            Negotiation::server(Settings::default(), BTreeSet::new(), no_capability([1; 32]));
        inbound.state = State::Negotiated;
        let error = inbound.accept_control(&data_record(b"early")).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::NotAuthenticated {
                frame_type: frame_type::DATA_RECORD
            }
        );
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);
        assert!(error.kind().is_peer_fault(), "the peer sent it too early");

        // A frame the registry does not gate still passes in that window.
        inbound.state = State::Negotiated;
        assert_eq!(
            inbound
                .accept_control(&frame_of(frame_type::PING, 0))
                .unwrap(),
            Accepted::Application
        );
    }

    /// A challenge that does ask for a capability.
    fn demanding(nonce: [u8; 32]) -> AuthContext {
        AuthContext {
            nonce: nonce.to_vec(),
            binding: Binding::None,
            formats: vec![1, 2],
        }
    }

    /// A `SESSION_OPEN` frame.
    fn session_open(session_id: [u8; 16], capability_format: u64) -> Vec<u8> {
        let open = SessionOpen {
            session_id,
            capability_format,
            capability: vec![9; 32],
            requested_scope: Vec::new(),
            binding_proof: Vec::new(),
        };
        let mut frame = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::SessionOpen(open),
            &mut frame,
        )
        .unwrap();
        frame
    }

    /// A server that has negotiated and is asking for a capability.
    fn demanding_server() -> Negotiation {
        let mut server =
            Negotiation::server(Settings::default(), BTreeSet::new(), demanding([3; 32]));
        server.state = State::Negotiated;
        server
    }

    #[test]
    fn a_request_is_handed_to_the_policy_and_its_answer_carries_the_identity() {
        // The session frames are the mechanism; the decision is not this
        // crate's to make. spec/wire.md section 1.1 also ties the answer to the
        // request: a server choosing its own identifier would leave a client
        // unable to tell which attempt was answered.
        let mut server = demanding_server();
        assert_eq!(server.pending_authorization(), None);
        assert_eq!(
            server.accept_control(&session_open([7; 16], 2)).unwrap(),
            Accepted::AuthorizationRequired
        );
        let (challenge, open) = server
            .pending_authorization()
            .expect("a request is pending");
        assert_eq!(challenge.nonce, vec![3; 32], "the challenge it answered");
        assert_eq!(open.session_id, [7; 16]);
        assert_eq!(open.capability_format, 2);
        assert_eq!(server.state(), State::Negotiated, "not yet authenticated");

        let reply = server.grant(b"read:objects".to_vec()).unwrap();
        assert_eq!(server.state(), State::Authenticated);
        assert_eq!(server.pending_authorization(), None);
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 1,
        };
        let (frame, _) = vot_codec::frames::decode(&reply[0], limits).unwrap();
        let vot_codec::frames::TypedFrame::SessionAccept(accept) = frame else {
            panic!("a grant sends SESSION_ACCEPT");
        };
        assert_eq!(accept.session_id, [7; 16], "the identity of the request");
        assert_eq!(accept.granted_scope, b"read:objects");
    }

    #[test]
    fn a_refusal_leaves_the_session_open_until_the_attempts_run_out() {
        // Section 1.1: a client may try again with a different capability, and
        // a server accepts three attempts before closing. Unbounded retries are
        // the amplification spec/security.md section 7 exists to stop.
        let mut server = demanding_server();
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 1,
        };
        for attempt in 0..MAX_AUTHENTICATION_ATTEMPTS {
            let id = [u8::try_from(attempt).unwrap(); 16];
            assert_eq!(
                server.accept_control(&session_open(id, 1)).unwrap(),
                Accepted::AuthorizationRequired,
                "attempt {attempt}"
            );
            let reply = server
                .refuse(error_code::AUTHORIZATION_FAILED, String::new())
                .unwrap();
            let (frame, _) = vot_codec::frames::decode(&reply[0], limits).unwrap();
            let vot_codec::frames::TypedFrame::SessionReject(reject) = frame else {
                panic!("a refusal sends SESSION_REJECT");
            };
            assert_eq!(reject.session_id, id);
            assert_eq!(reject.reason, u64::from(error_code::AUTHORIZATION_FAILED));
            assert_eq!(
                server.state(),
                State::Negotiated,
                "a refusal does not close the session"
            );
        }

        let error = server
            .accept_control(&session_open([9; 16], 1))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::TooManyAuthenticationAttempts {
                attempts: MAX_AUTHENTICATION_ATTEMPTS
            }
        );
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);
    }

    #[test]
    fn a_session_hands_the_request_out_and_sends_what_the_caller_decides() {
        // The Negotiation tests cover the rules. This covers the path a real
        // caller takes: nothing reaches the carrier until the caller answers.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        );
        server.begin().unwrap();
        server.negotiation.state = State::Negotiated;
        std::mem::take(&mut server.adapter.sent);

        server
            .adapter
            .events
            .push_back(control(&session_open([7; 16], 1)));
        assert_eq!(server.poll().unwrap(), None);
        assert!(!server.is_ready(), "a request is not a grant");
        assert!(
            server.adapter().sent.is_empty(),
            "nothing goes out until the caller answers"
        );
        let (challenge, open) = server.pending_authorization().expect("pending");
        assert_eq!(challenge.formats, vec![1, 2]);
        assert_eq!(open.session_id, [7; 16]);

        server
            .refuse(error_code::AUTHENTICATION_FAILED, "no".to_owned())
            .unwrap();
        assert_eq!(server.adapter().sent.len(), 1);
        assert!(!server.is_ready(), "a refusal is not a grant");
        assert_eq!(server.pending_authorization(), None);

        server
            .adapter
            .events
            .push_back(control(&session_open([8; 16], 1)));
        assert_eq!(server.poll().unwrap(), None);
        server.grant(b"scope".to_vec()).unwrap();
        assert!(server.is_ready(), "the exchange concluded");
        assert_eq!(server.adapter().sent.len(), 2);

        // And with nothing pending, neither answer invents one.
        assert!(server.grant(Vec::new()).is_err());
        assert!(
            server
                .refuse(error_code::AUTHENTICATION_FAILED, String::new())
                .is_err()
        );
    }

    #[test]
    fn a_request_this_endpoint_never_invited_is_refused() {
        // Each of these would have the policy parse bytes whose shape it never
        // agreed to, or answer an attempt it cannot tell from another.
        let mut reused = demanding_server();
        reused.accept_control(&session_open([7; 16], 1)).unwrap();
        reused
            .refuse(error_code::AUTHENTICATION_FAILED, String::new())
            .unwrap();
        let error = reused
            .accept_control(&session_open([7; 16], 1))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::SessionIdentifierReused);
        assert_eq!(error.close_code(), error_code::REPLAY_REJECTED);

        let mut unoffered = demanding_server();
        let error = unoffered
            .accept_control(&session_open([7; 16], 9))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::CapabilityFormatNotOffered { format: 9 }
        );
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);

        let mut malformed = demanding_server();
        let error = malformed
            .accept_control(&frame_of(frame_type::SESSION_OPEN, 3))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::SessionOpenInvalid);

        // A deployment advertising no format concluded at AUTH_CONTEXT, so
        // there is nothing here to open.
        let mut open_to_nobody =
            Negotiation::server(Settings::default(), BTreeSet::new(), no_capability([1; 32]));
        open_to_nobody.state = State::Negotiated;
        assert!(
            open_to_nobody
                .accept_control(&session_open([7; 16], 1))
                .is_err()
        );

        // A second request while one is pending would let a peer replace the
        // subject of a decision the policy is already making.
        let mut busy = demanding_server();
        busy.accept_control(&session_open([7; 16], 1)).unwrap();
        assert!(busy.accept_control(&session_open([8; 16], 1)).is_err());

        // A client never reads one: it is the endpoint that sends it.
        let mut client = Negotiation::client(Settings::default(), BTreeSet::new());
        client.state = State::Negotiated;
        assert!(client.accept_control(&session_open([7; 16], 1)).is_err());

        // Nor does a server before negotiation finishes, or after the exchange
        // already concluded. Each of the four conditions refuses on its own.
        let mut early = demanding_server();
        early.state = State::HelloSent;
        assert!(early.accept_control(&session_open([7; 16], 1)).is_err());
        let mut done = demanding_server();
        done.state = State::Authenticated;
        assert!(done.accept_control(&session_open([7; 16], 1)).is_err());
    }

    #[test]
    fn an_answer_with_nothing_pending_is_refused() {
        // Granting out of nowhere would authenticate a session no peer asked
        // to open.
        let mut server = demanding_server();
        assert!(server.grant(Vec::new()).is_err());
        assert!(
            server
                .refuse(error_code::AUTHENTICATION_FAILED, String::new())
                .is_err()
        );
        assert_eq!(server.state(), State::Negotiated);

        // And a reason the registry does not assign to authentication or
        // authorization never reaches the wire.
        server.accept_control(&session_open([7; 16], 1)).unwrap();
        assert!(
            server
                .refuse(error_code::MALFORMED_FRAME, String::new())
                .is_err()
        );
    }

    #[test]
    fn a_challenge_asking_for_a_capability_is_refused() {
        // Nothing can present one yet. Accepting the frame would leave this
        // endpoint believing it is authenticated while the server waits for a
        // SESSION_OPEN that never comes.
        let mut client = Negotiation::client(Settings::default(), BTreeSet::new());
        client.state = State::Negotiated;
        let error = client
            .accept_control(&auth_context(&[7; 16], vec![1, 2]))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::CapabilityRequired { formats: 2 });
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);
        assert!(
            error.kind().is_peer_fault(),
            "the carrier still has to close"
        );
        assert_eq!(client.state(), State::Negotiated, "not authenticated");
    }

    #[test]
    fn a_challenge_out_of_sequence_or_out_of_shape_is_refused() {
        // A server never reads one: it is the endpoint that sends it.
        let mut server =
            Negotiation::server(Settings::default(), BTreeSet::new(), no_capability([1; 32]));
        server.state = State::Negotiated;
        assert_eq!(
            server
                .accept_control(&auth_context(&[7; 16], Vec::new()))
                .unwrap_err()
                .kind(),
            &ErrorKind::OutOfSequence {
                frame_type: frame_type::AUTH_CONTEXT,
                state: State::Negotiated
            }
        );

        // Nor does a client before negotiation finishes.
        let mut early = Negotiation::client(Settings::default(), BTreeSet::new());
        early.state = State::HelloSent;
        assert!(
            early
                .accept_control(&auth_context(&[7; 16], Vec::new()))
                .is_err()
        );

        // A second one after the exchange concluded is out of sequence too.
        let mut done = Negotiation::client(Settings::default(), BTreeSet::new());
        done.state = State::Negotiated;
        done.accept_control(&auth_context(&[7; 16], Vec::new()))
            .unwrap();
        assert_eq!(done.state(), State::Authenticated);
        assert!(
            done.accept_control(&auth_context(&[7; 16], Vec::new()))
                .is_err()
        );

        // A payload that is not a challenge closes under the decode code, not
        // the authentication one: nothing was decided about a capability.
        let mut malformed = Negotiation::client(Settings::default(), BTreeSet::new());
        malformed.state = State::Negotiated;
        let error = malformed
            .accept_control(&frame_of(frame_type::AUTH_CONTEXT, 3))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::AuthContextInvalid);
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
    }

    #[test]
    fn the_application_may_not_send_the_challenge_itself() {
        // The state machine owns it. An application-sent AUTH_CONTEXT would
        // let a caller claim an exchange the machine never ran.
        let (mut client, _server, _answer) = negotiated_pair();
        let error = client
            .send_control(&auth_context(&[7; 16], Vec::new()))
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::NegotiationFrameFromApplication { .. }
        ));
    }

    #[test]
    fn the_data_plane_is_refused_until_the_exchange_finishes() {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        for state in [State::Connecting, State::HelloSent] {
            assert_eq!(
                client
                    .send_reliable(StreamId(1), b"record")
                    .unwrap_err()
                    .kind(),
                &ErrorKind::NotReady { state }
            );
            assert_eq!(
                client.send_control(b"frame").unwrap_err().kind(),
                &ErrorKind::NotReady { state }
            );
            if state == State::Connecting {
                client.begin().unwrap();
            }
        }
        assert!(
            client.adapter.records.is_empty(),
            "nothing reached the backend"
        );

        let (mut client, _server) = negotiated();
        client
            .send_reliable(StreamId(1), &data_record(b"record"))
            .unwrap();
        assert_eq!(client.adapter.records.len(), 1);
    }

    #[test]
    fn records_that_arrive_early_are_held_rather_than_refused() {
        // The two endpoints reach readiness at different moments and QUIC
        // orders nothing between the negotiation stream and an application
        // lane, so a conforming peer can have records in flight already.
        // Closing the session over them would punish it for the protocol's own
        // shape.
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();

        let sent = std::mem::take(&mut client.adapter.sent);
        // A record between the two negotiation frames, which is the worst
        // ordering the carrier can produce.
        server.adapter.events.push_back(control(&sent[0]));
        server.adapter.events.push_back(record(7, b"early"));
        server.adapter.events.push_back(control(&sent[1]));
        server.adapter.events.push_back(record(8, b"also early"));

        // The record does not surface before readiness, and it does not block
        // the SETTINGS frame behind it either.
        let first = server
            .poll()
            .unwrap()
            .expect("the held records are released");
        assert!(server.is_ready());
        assert_eq!(first, record(7, b"early"));
        assert_eq!(server.poll().unwrap(), Some(record(8, b"also early")));
        assert_eq!(server.poll().unwrap(), None);
    }

    #[test]
    fn held_records_are_bounded() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        server
            .set_pending_limits(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES, 2)
            .unwrap();
        for lane in 0..2 {
            server.adapter.events.push_back(record(lane, b"held"));
        }
        server.adapter.events.push_back(record(2, b"one too many"));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::RESOURCE_LIMIT);
        assert!(matches!(
            error.kind(),
            ErrorKind::PendingRecordsExhausted { count: 2, .. }
        ));

        // A bound that cannot hold one maximum record would refuse a peer that
        // did nothing wrong.
        assert!(server.set_pending_limits(1, 1).is_err());
        assert!(server.set_pending_limits(usize::MAX, 0).is_err());
    }

    #[test]
    fn a_peer_on_another_draft_is_rejected_before_anything_else() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let older = Hello {
            draft_revision: vot_codec::DRAFT_REVISION - 1,
            endpoint_role: EndpointRole::Client,
            extensions: BTreeSet::new(),
        };
        let mut payload = Vec::new();
        vot_codec::encode_hello(&older, &mut payload).unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &payload, &mut frame).unwrap();
        server.adapter.events.push_back(control(&frame));

        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::UNSUPPORTED_VERSION);
        assert!(matches!(
            error.kind(),
            ErrorKind::Hello(HelloError::UnsupportedRevision(_))
        ));
        assert!(!server.is_ready());
    }

    #[test]
    fn the_wrong_role_and_the_wrong_order_are_both_refused() {
        // A HELLO claiming the server role on a client-initiated stream
        // contradicts the stream initiator.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let wrong_role = Hello {
            draft_revision: vot_codec::DRAFT_REVISION,
            endpoint_role: EndpointRole::Server,
            extensions: BTreeSet::new(),
        };
        let mut payload = Vec::new();
        vot_codec::encode_hello(&wrong_role, &mut payload).unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &payload, &mut frame).unwrap();
        server.adapter.events.push_back(control(&frame));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
        assert!(matches!(
            error.kind(),
            ErrorKind::Hello(HelloError::RoleMismatch { .. })
        ));

        // A client never receives HELLO, because it is the one that sends it.
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        client.adapter.events.push_back(control(&frame));
        assert!(matches!(
            client.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence { .. }
        ));

        // SETTINGS before HELLO leaves the server with limits from a peer it
        // has not identified.
        let mut early = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        early.begin().unwrap();
        let mut payload = Vec::new();
        vot_codec::encode_settings(&Settings::default(), &mut payload).unwrap();
        let mut settings = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS, &payload, &mut settings).unwrap();
        early.adapter.events.push_back(control(&settings));
        assert!(matches!(
            early.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence {
                frame_type: frame_type::SETTINGS,
                ..
            }
        ));
    }

    #[test]
    fn an_application_control_frame_before_readiness_ends_the_session() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::SEAL, b"payload", &mut frame).unwrap();
        server.adapter.events.push_back(control(&frame));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
        assert_eq!(
            error.kind(),
            &ErrorKind::NotNegotiated {
                frame_type: frame_type::SEAL
            }
        );

        // After readiness the same frame belongs to the application and passes
        // through untouched.
        let (mut client, _server) = negotiated();
        client.adapter.events.push_back(control(&frame));
        assert_eq!(client.poll().unwrap(), Some(control(&frame)));
    }

    #[test]
    fn an_unknown_optional_frame_does_not_end_the_exchange() {
        // spec/wire.md requires grease to be exercised, and a handshake is
        // where a peer is most likely to send it.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let mut grease = Vec::new();
        vot_codec::encode_frame(0x1f00, b"unspecified", &mut grease).unwrap();
        assert!(vot_codec::is_grease(0x1f00));
        server.adapter.events.push_back(control(&grease));
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.state(), State::ControlReserved);

        // And an unknown critical one still ends it.
        let mut critical = Vec::new();
        vot_codec::encode_frame(0x0f, b"", &mut critical).unwrap();
        server.adapter.events.push_back(control(&critical));
        assert_eq!(
            server.poll().unwrap_err().close_code(),
            error_code::UNKNOWN_CRITICAL_FRAME
        );
    }

    #[test]
    fn a_carrier_that_ends_mid_exchange_is_not_a_clean_close() {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        client
            .adapter
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(1)));
        assert_eq!(
            client.poll().unwrap_err().kind(),
            &ErrorKind::Interrupted {
                state: State::HelloSent
            }
        );

        // After readiness the same event is an ordinary end of session.
        let (mut client, _server) = negotiated();
        client
            .adapter
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(1)));
        assert_eq!(
            client.poll().unwrap(),
            Some(Event::Disconnected(vot_transport_api::ConnectionId(1)))
        );
    }

    #[test]
    fn the_peers_control_limit_reaches_the_backend() {
        // Without this the exchange is a state enum. The peer's advertised
        // maximum is the bound on what this endpoint may send.
        let peer = Settings {
            max_control_frame_payload: 64 * 1024,
            ..Settings::default()
        };

        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            peer,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        client.poll().unwrap();

        assert!(client.is_ready());
        assert!(client.control_limit_applied());
        assert_eq!(client.adapter().control_limit, Some(64 * 1024));

        // A backend with no such bound says so, and the session reports that
        // and the session reports the limit as not applied.
        let mut refusing = Session::client(
            Loopback {
                refuse_control_limit: true,
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut answering = Session::server(
            Loopback::default(),
            peer,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        refusing.begin().unwrap();
        answering.begin().unwrap();
        for frame in std::mem::take(&mut refusing.adapter.sent) {
            answering.adapter.events.push_back(control(&frame));
        }
        answering.poll().unwrap();
        for frame in std::mem::take(&mut answering.adapter.sent) {
            refusing.adapter.events.push_back(control(&frame));
        }
        refusing.poll().unwrap();
        assert!(refusing.is_ready());
        assert!(!refusing.control_limit_applied());
    }

    #[test]
    fn a_duplicate_settings_frame_is_refused_and_a_duplicate_ack_is_not() {
        let (mut client, mut server) = negotiated();
        let mut payload = Vec::new();
        vot_codec::encode_settings(&Settings::default(), &mut payload).unwrap();
        let mut settings = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS, &payload, &mut settings).unwrap();
        server.adapter.events.push_back(control(&settings));
        assert!(matches!(
            server.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence { .. }
        ));

        // spec/wire.md section 5: a duplicate acknowledgement is ignored.
        let mut ack = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS_ACK, &[], &mut ack).unwrap();
        client.adapter.events.push_back(control(&ack));
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.is_ready());

        // spec/wire.md section 5 gives SETTINGS_ACK a maximum of zero bytes, so
        // one carrying a payload is refused by its registered limit. Built by
        // hand because the encoder will not produce it either.
        let fat = [u8::try_from(frame_type::SETTINGS_ACK).unwrap(), 0x01, b'x'];
        client.adapter.events.push_back(control(&fat));
        assert_eq!(
            client.poll().unwrap_err().close_code(),
            error_code::FRAME_TOO_LARGE
        );
    }

    #[test]
    fn every_submission_path_reaches_the_backend() {
        // Shared payloads and flushes are the two paths an application uses
        // most and the two easiest to leave as accepted-and-dropped.
        let (mut client, _server) = negotiated();
        let flushes = client.adapter().flushes;
        client
            .send_reliable_shared(
                StreamId(3),
                vot_transport_api::shared_payload(&data_record(b"shared")),
            )
            .unwrap();
        assert_eq!(
            client.adapter().records,
            vec![(StreamId(3), data_record(b"shared"))]
        );
        client.flush().unwrap();
        assert_eq!(client.adapter().flushes, flushes + 1);

        // And a backend refusal is reported rather than swallowed, under the
        // code the refusal deserves rather than one generic code.
        let mut refusing = Session::client(
            Loopback {
                refuse_sends: Some(TransportError::RecordTooLarge),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        refusing.negotiation.state = State::Authenticated;
        let error = refusing
            .send_reliable(StreamId(1), &data_record(b"record"))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert_eq!(
            error.kind(),
            &ErrorKind::Transport(TransportError::RecordTooLarge)
        );

        for (backend, expected) in [
            (
                TransportError::OutboundQueueFull,
                error_code::RESOURCE_LIMIT,
            ),
            (TransportError::InboundQueueFull, error_code::RESOURCE_LIMIT),
            (TransportError::StagingExhausted, error_code::RESOURCE_LIMIT),
            (TransportError::Unsupported, error_code::MALFORMED_FRAME),
        ] {
            let mut session = Session::client(
                Loopback {
                    refuse_sends: Some(backend),
                    ..Loopback::default()
                },
                Settings::default(),
                BTreeSet::new(),
                Authentication::NotRequired { nonce: [0x5a; 32] },
            );
            session.negotiation.state = State::Authenticated;
            assert_eq!(
                session
                    .send_reliable(StreamId(1), &data_record(b"record"))
                    .unwrap_err()
                    .close_code(),
                expected
            );
        }
    }

    #[test]
    fn the_held_byte_bound_is_exact() {
        // The count bound and the byte bound fail differently, and only the
        // byte bound limits memory. One record short of the bound is held; the
        // byte that crosses it is not.
        let payload = vec![0_u8; 1024];
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        server
            .set_pending_limits(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES, 8)
            .unwrap();
        for lane in 0..4 {
            server.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.pending_bytes, 4 * record_wire_len(1024));

        let mut exact = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        exact.begin().unwrap();
        exact.pending_byte_limit = 2 * record_wire_len(1024);
        for lane in 0..2 {
            exact.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(exact.poll().unwrap(), None, "the bound itself is allowed");
        assert_eq!(exact.pending_bytes, 2 * record_wire_len(1024));

        exact.adapter.events.push_back(record(2, b"x"));
        let error = exact.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::RESOURCE_LIMIT);
        assert_eq!(
            error.kind(),
            &ErrorKind::PendingRecordsExhausted {
                bytes: 2 * record_wire_len(1024),
                count: 2,
            }
        );

        // The default holds several maximum records rather than one, so an
        // ordinary burst does not end a session.
        assert_eq!(
            DEFAULT_PENDING_RECORD_BYTES,
            4 * vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES
        );
        assert_eq!(DEFAULT_PENDING_RECORD_COUNT, 64);
    }

    #[test]
    fn a_repeated_negotiation_frame_is_refused_at_every_point() {
        // A second HELLO would replace the extensions and revision the rest of
        // the exchange was decided under.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let hello = Hello {
            draft_revision: vot_codec::DRAFT_REVISION,
            endpoint_role: EndpointRole::Client,
            extensions: BTreeSet::new(),
        };
        let mut payload = Vec::new();
        vot_codec::encode_hello(&hello, &mut payload).unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &payload, &mut frame).unwrap();

        server.adapter.events.push_back(control(&frame));
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.state(), State::HelloSent);
        server.adapter.events.push_back(control(&frame));
        assert!(matches!(
            server.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence {
                frame_type: frame_type::HELLO,
                state: State::HelloSent,
            }
        ));

        // And an acknowledgement before the settings it claims to acknowledge
        // would make the client ready without ever reading the peer's limits.
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        let mut ack = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS_ACK, &[], &mut ack).unwrap();
        client.adapter.events.push_back(control(&ack));
        assert!(matches!(
            client.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence {
                frame_type: frame_type::SETTINGS_ACK,
                state: State::HelloSent,
            }
        ));
        assert!(!client.is_ready());
        assert_eq!(client.peer_settings(), None);
    }

    #[test]
    fn only_the_peers_faults_reach_the_carrier() {
        // One registered code covers a peer that sent a frame out of sequence
        // and a local caller that asked too early. Closing on the second would
        // tear down a healthy connection over an API misuse and would tell the
        // peer it did something wrong when it did not.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::SEAL, b"payload", &mut frame).unwrap();
        server.adapter.events.push_back(control(&frame));
        assert_eq!(
            server.poll().unwrap_err().close_code(),
            error_code::MALFORMED_FRAME
        );
        assert_eq!(server.adapter().closed, vec![error_code::MALFORMED_FRAME]);
        assert_eq!(server.state(), State::Closed, "the session is over");

        // A local caller asking too early leaves the carrier alone.
        let mut early = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        early.begin().unwrap();
        assert!(early.send_reliable(StreamId(1), b"record").is_err());
        assert!(early.send_control(&frame_of(frame_type::PING, 0)).is_err());
        assert!(
            early.adapter().closed.is_empty(),
            "an API misuse is not the peer's fault"
        );

        // Nor does a backend refusing a submission: that is backpressure, and
        // closing over it would turn a full queue into a teardown.
        let mut refusing = Session::client(
            Loopback {
                refuse_sends: Some(TransportError::OutboundQueueFull),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        refusing.negotiation.state = State::Authenticated;
        assert!(
            refusing
                .send_reliable(StreamId(1), &data_record(b"record"))
                .is_err()
        );
        assert!(refusing.adapter().closed.is_empty());

        // Nor does a carrier that has already gone; there is nothing to close.
        let mut gone = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        gone.begin().unwrap();
        gone.adapter
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(1)));
        assert!(matches!(
            gone.poll().unwrap_err().kind(),
            ErrorKind::Interrupted { .. }
        ));
        assert!(gone.adapter().closed.is_empty());

        // Each peer fault closes under its own registered code.
        for (frame_type, payload, expected) in [
            (
                frame_type::SETTINGS_ACK,
                Vec::new(),
                error_code::MALFORMED_FRAME,
            ),
            (0x0f, Vec::new(), error_code::UNKNOWN_CRITICAL_FRAME),
        ] {
            let mut session = Session::server(
                Loopback::default(),
                Settings::default(),
                BTreeSet::new(),
                Authentication::NotRequired { nonce: [0x5a; 32] },
            );
            session.begin().unwrap();
            let mut frame = Vec::new();
            vot_codec::encode_frame(frame_type, &payload, &mut frame).unwrap();
            session.adapter.events.push_back(control(&frame));
            assert_eq!(session.poll().unwrap_err().close_code(), expected);
            assert_eq!(session.adapter().closed, vec![expected]);
        }
    }

    #[test]
    fn a_backend_that_would_accept_more_than_is_advertised_is_refused() {
        // Advertising one control-frame bound and reassembling up to another is
        // silent: the peer sends what it was told it could, and this endpoint
        // accepts more. The mismatch is caught before the limit goes out.
        let mut mismatched = Session::client(
            Loopback {
                receive_limits: Some(
                    vot_transport_api::ReceiveLimits::advertised(
                        &Settings {
                            max_control_frame_payload: 64 * 1024,
                            ..Settings::default()
                        },
                        4 * 1024 * 1024,
                    )
                    .unwrap(),
                ),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let error = mismatched.begin().unwrap_err();
        assert_eq!(error.close_code(), error_code::INVALID_SETTING);
        assert_eq!(
            error.kind(),
            &ErrorKind::ReceiveLimitMismatch {
                advertised_control: Settings::default().max_control_frame_payload,
                advertised_lanes: Settings::default().reliable_lane_limit,
                backend: vot_transport_api::ReceiveLimits::advertised(
                    &Settings {
                        max_control_frame_payload: 64 * 1024,
                        ..Settings::default()
                    },
                    4 * 1024 * 1024,
                )
                .unwrap(),
            }
        );
        assert!(
            mismatched.adapter().sent.is_empty(),
            "nothing was advertised"
        );
        // Local configuration, so the peer is not blamed for it.
        assert!(mismatched.adapter().closed.is_empty());

        // Agreeing is enough, whatever the value.
        let mut agreed = Session::client(
            Loopback {
                receive_limits: Some(
                    vot_transport_api::ReceiveLimits::advertised(
                        &Settings {
                            max_control_frame_payload: 64 * 1024,
                            ..Settings::default()
                        },
                        4 * 1024 * 1024,
                    )
                    .unwrap(),
                ),
                ..Loopback::default()
            },
            Settings {
                max_control_frame_payload: 64 * 1024,
                ..Settings::default()
            },
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        agreed.begin().unwrap();
        assert_eq!(agreed.adapter().sent.len(), 2);

        // A backend that reassembles nothing has nothing to disagree with.
        let mut silent = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        silent.begin().unwrap();
        assert_eq!(silent.adapter().sent.len(), 2);
    }

    #[test]
    fn a_closed_session_stops_interpreting_and_still_reports_the_carrier() {
        // Polling a failed session again used to report whatever the next frame
        // looked like against a closed state, which named the second thing that
        // went wrong rather than the first.
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        let mut older = Vec::new();
        vot_codec::encode_hello(
            &Hello {
                draft_revision: vot_codec::DRAFT_REVISION - 1,
                endpoint_role: EndpointRole::Client,
                extensions: BTreeSet::new(),
            },
            &mut older,
        )
        .unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &older, &mut frame).unwrap();
        server.adapter.events.push_back(control(&frame));
        assert_eq!(
            server.poll().unwrap_err().close_code(),
            error_code::UNSUPPORTED_VERSION
        );
        assert_eq!(server.state(), State::Closed);
        assert_eq!(
            server.adapter().closed,
            vec![error_code::UNSUPPORTED_VERSION],
            "closed once, under the first cause"
        );

        // Anything still on the carrier is dropped rather than reinterpreted.
        server.adapter.events.push_back(control(&frame));
        server.adapter.events.push_back(record(1, b"late"));
        server
            .adapter
            .events
            .push_back(Event::Disconnected(vot_transport_api::ConnectionId(1)));
        assert_eq!(
            server.poll().unwrap(),
            Some(Event::Disconnected(vot_transport_api::ConnectionId(1))),
            "the caller still has to learn the carrier ended"
        );
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(
            server.adapter().closed,
            vec![error_code::UNSUPPORTED_VERSION],
            "and the carrier is not closed a second time"
        );
    }

    #[test]
    fn a_full_outbound_queue_stalls_the_handshake_rather_than_losing_it() {
        // The exchange advances in pairs. A backend with room for HELLO and not
        // for SETTINGS used to leave the peer waiting for a frame nothing would
        // send again, because the state machine had already moved past
        // producing it and `begin` refuses a second call.
        let mut client = Session::client(
            Loopback {
                control_capacity: Some(1),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        assert_eq!(client.adapter().sent.len(), 1, "only HELLO fitted");
        assert_eq!(client.unsent_negotiation_frames(), 1);
        assert!(
            client.begin().is_err(),
            "the exchange has moved on, so it cannot be restarted"
        );

        // Room appears, and the frame that did not fit goes out on its own.
        client.adapter.control_capacity = Some(2);
        client.flush().unwrap();
        assert_eq!(client.unsent_negotiation_frames(), 0);
        let limits = vot_codec::DecodeLimits::default();
        let sent = client.adapter().sent.clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(
            vot_codec::decode_one(&sent[1], limits)
                .unwrap()
                .0
                .frame_type(),
            frame_type::SETTINGS,
            "and in the order the specification gives it"
        );

        // A driver that only polls gets there too, without knowing it stalled.
        let mut polling = Session::client(
            Loopback {
                control_capacity: Some(0),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        polling.begin().unwrap();
        assert_eq!(polling.unsent_negotiation_frames(), 2);
        polling.adapter.control_capacity = None;
        assert_eq!(polling.poll().unwrap(), None);
        assert_eq!(polling.unsent_negotiation_frames(), 0);
        assert_eq!(polling.adapter().sent.len(), 2);

        // The server's answer is three frames, and stalls the same way.
        let mut server = Session::server(
            Loopback {
                control_capacity: Some(1),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        for frame in polling.adapter().sent.clone() {
            server.adapter.events.push_back(control(&frame));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());
        assert_eq!(server.adapter().sent.len(), 1, "only SETTINGS fitted");
        assert_eq!(server.unsent_negotiation_frames(), 2);
        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.adapter().sent.len(), 3);
        let held: Vec<u64> = server.adapter().sent[1..]
            .iter()
            .map(|frame| vot_codec::decode_one(frame, limits).unwrap().0.frame_type())
            .collect();
        assert_eq!(
            held,
            vec![frame_type::SETTINGS_ACK, frame_type::AUTH_CONTEXT],
            "in the order the exchange gives them"
        );

        // A refusal that is not capacity is still a failure, and keeps the
        // frame rather than dropping it.
        let mut broken = Session::client(
            Loopback {
                refuse_control: Some(TransportError::Backend),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        assert!(broken.begin().is_err());
        assert_eq!(broken.unsent_negotiation_frames(), 2);
    }

    #[test]
    fn a_closed_session_stops_pushing_the_handshake() {
        // The retry queue and the closed state have to agree. A session that
        // kept draining after it failed would put a stale HELLO on a dying
        // connection, which the peer has to parse before it can tell the
        // session is over.
        let mut client = Session::client(
            Loopback {
                control_capacity: Some(0),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        assert_eq!(client.unsent_negotiation_frames(), 2);
        assert!(client.adapter().sent.is_empty());

        // A client never receives HELLO, so this ends the session while both
        // frames are still queued.
        let mut hello = Vec::new();
        vot_codec::encode_hello(
            &Hello {
                draft_revision: vot_codec::DRAFT_REVISION,
                endpoint_role: EndpointRole::Client,
                extensions: BTreeSet::new(),
            },
            &mut hello,
        )
        .unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &hello, &mut frame).unwrap();
        client.adapter.events.push_back(control(&frame));
        assert!(client.poll().is_err());
        assert_eq!(client.state(), State::Closed);

        // Room appears, and neither path takes it.
        client.adapter.control_capacity = None;
        assert_eq!(client.poll().unwrap(), None);
        client.flush().unwrap();
        assert_eq!(client.unsent_negotiation_frames(), 2, "still queued");
        assert!(
            client.adapter().sent.is_empty(),
            "a closed session sends no more of the handshake"
        );
        // The backend is still flushed, so anything it already holds can leave.
        assert!(client.adapter().flushes > 0);
    }

    #[test]
    fn an_application_frame_cannot_overtake_a_queued_acknowledgement() {
        // A server is ready when it produces SETTINGS_ACK, not when the backend
        // takes it. An application frame sent in between would reach a peer
        // still in SettingsExchanged, which closes for NotNegotiated.
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback {
                control_capacity: Some(1),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        assert!(server.is_ready());
        assert_eq!(
            server.unsent_negotiation_frames(),
            2,
            "the ACK and the challenge did not fit"
        );

        for send in [
            server.send_control(&frame_of(frame_type::PING, 0)),
            server.send_reliable(StreamId(1), &data_record(b"record")),
        ] {
            assert_eq!(
                send.unwrap_err().kind(),
                &ErrorKind::HandshakeUnsent { remaining: 2 }
            );
        }
        assert_eq!(
            server.adapter().sent.len(),
            1,
            "nothing overtook the acknowledgement"
        );
        assert!(server.adapter().records.is_empty());

        // Once it goes out, the application may send.
        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.unsent_negotiation_frames(), 0);
        server.send_control(&frame_of(frame_type::PING, 0)).unwrap();
        assert_eq!(server.adapter().sent.len(), 4);
    }

    #[test]
    fn a_record_larger_than_the_peer_accepts_is_refused() {
        // The adapter only knows the protocol ceiling. Sending past what the
        // peer advertised is a session the peer is entitled to end.
        let peer = Settings {
            max_data_record_payload: 64 * 1024,
            ..Settings::default()
        };
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            peer,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        client.poll().unwrap();
        assert!(client.is_ready());

        client
            .send_reliable(StreamId(1), &data_record(&vec![0; 64 * 1024]))
            .unwrap();
        let error = client
            .send_reliable(StreamId(1), &data_record(&vec![0; 64 * 1024 + 1]))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert_eq!(
            error.kind(),
            &ErrorKind::FrameExceedsLimit {
                frame_type: frame_type::DATA_RECORD,
                bytes: 64 * 1024 + 1,
                limit: 64 * 1024,
                side: Side::Peer,
            }
        );
        // The wire length of a conforming record is larger than the negotiated
        // payload maximum, so comparing it would refuse a legal frame.
        assert!(data_record(&vec![0; 64 * 1024]).len() > 64 * 1024);
        assert_eq!(
            client
                .send_reliable_shared(
                    StreamId(1),
                    vot_transport_api::shared_payload(&data_record(&vec![0; 64 * 1024 + 1]))
                )
                .unwrap_err()
                .kind(),
            error.kind()
        );
        assert_eq!(client.adapter().records.len(), 1, "only the one that fits");
    }

    #[test]
    fn a_record_past_the_limit_this_endpoint_advertised_is_refused() {
        // The adapters bound records by the protocol ceiling, so a session
        // advertising less than that would hand the application a record the
        // peer was told not to send.
        let local = Settings {
            max_data_record_payload: 64 * 1024,
            ..Settings::default()
        };
        let mut server = Session::server(
            Loopback::default(),
            local,
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(record(1, &vec![0; 64 * 1024]));
        assert_eq!(server.poll().unwrap(), None, "the bound itself is accepted");

        server
            .adapter
            .events
            .push_back(record(2, &vec![0; 64 * 1024 + 1]));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert_eq!(
            error.kind(),
            &ErrorKind::FrameExceedsLimit {
                frame_type: frame_type::DATA_RECORD,
                bytes: 64 * 1024 + 1,
                limit: 64 * 1024,
                side: Side::Local,
            }
        );
        // The peer sent past what it was given, so the carrier is closed.
        assert_eq!(server.adapter().closed, vec![error_code::FRAME_TOO_LARGE]);
    }

    /// One encoded frame of `frame_type` carrying `payload` bytes.
    fn frame_of(frame_type: u64, payload: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type, &vec![0; payload], &mut frame).unwrap();
        frame
    }

    #[test]
    fn every_negotiated_payload_limit_is_applied_in_both_directions() {
        // One table drives this, so a limit the registry adds later is a row
        // rather than another check. The cases below are the three the settings
        // name, plus a frame they do not, which falls back to the ceiling.
        let settings = Settings {
            max_control_frame_payload: 128 * 1024,
            max_data_record_payload: 64 * 1024,
            max_manifest_page_payload: 96 * 1024,
            ..Settings::default()
        };
        let cases = [
            (frame_type::DATA_RECORD, 64 * 1024, Lane::Reliable),
            (frame_type::MANIFEST_PAGE, 96 * 1024, Lane::Control),
            (frame_type::PROGRESSIVE_PAGE, 96 * 1024, Lane::Control),
            (frame_type::SEAL, 128 * 1024, Lane::Control),
        ];
        for (frame_type, limit, lane) in cases {
            assert_eq!(
                negotiated_payload_limit(frame_type, &settings),
                limit as u64,
                "{frame_type:#x}"
            );
            for side in [Side::Local, Side::Peer] {
                check_frame(
                    &frame_of(frame_type, limit),
                    &settings,
                    &BTreeSet::new(),
                    lane,
                    side,
                )
                .unwrap();
                let error = check_frame(
                    &frame_of(frame_type, limit + 1),
                    &settings,
                    &BTreeSet::new(),
                    lane,
                    side,
                )
                .unwrap_err();
                assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
                assert_eq!(
                    error.kind(),
                    &ErrorKind::FrameExceedsLimit {
                        frame_type,
                        bytes: limit as u64 + 1,
                        limit: limit as u64,
                        side,
                    }
                );
                // Only the peer exceeding what it was given is the peer's
                // fault.
                assert_eq!(error.kind().is_peer_fault(), side == Side::Local);
            }
        }

        // A manifest page is bounded by whichever of the two settings is lower,
        // so a generous page limit does not widen the control ceiling.
        let narrow_control = Settings {
            max_control_frame_payload: 64 * 1024,
            max_manifest_page_payload: 1024 * 1024,
            ..Settings::default()
        };
        assert_eq!(
            negotiated_payload_limit(frame_type::MANIFEST_PAGE, &narrow_control),
            64 * 1024
        );
    }

    #[test]
    fn a_frame_past_a_negotiated_limit_is_refused_on_the_way_out_and_in() {
        let peer = Settings {
            max_manifest_page_payload: 64 * 1024,
            ..Settings::default()
        };
        let (mut client, mut server) = negotiated_with(Settings::default(), peer);

        // Outbound: the peer said 64 KiB, so a larger page never leaves.
        client
            .send_control(&frame_of(frame_type::MANIFEST_PAGE, 64 * 1024))
            .unwrap();
        let error = client
            .send_control(&frame_of(frame_type::MANIFEST_PAGE, 64 * 1024 + 1))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert!(!error.kind().is_peer_fault());
        assert!(client.adapter().closed.is_empty());

        // Inbound: the server advertised 64 KiB, so a larger page closes the
        // session rather than being delivered. A known frame type is covered,
        // which the codec's own per-type limit would have let through.
        server
            .adapter
            .events
            .push_back(control(&frame_of(frame_type::MANIFEST_PAGE, 64 * 1024 + 1)));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert!(error.kind().is_peer_fault());
        assert_eq!(server.adapter().closed, vec![error_code::FRAME_TOO_LARGE]);
    }

    #[test]
    fn more_lanes_than_the_peer_carries_are_refused() {
        let peer = Settings {
            reliable_lane_limit: 1,
            ..Settings::default()
        };
        let (mut client, _server) = negotiated_with(Settings::default(), peer);
        let record = data_record(b"record");

        client.send_reliable(StreamId(1), &record).unwrap();
        // The same lane again is free; a second lane is not.
        client.send_reliable(StreamId(1), &record).unwrap();
        let error = client.send_reliable(StreamId(2), &record).unwrap_err();
        assert_eq!(error.close_code(), error_code::RESOURCE_LIMIT);
        assert_eq!(
            error.kind(),
            &ErrorKind::LaneLimitExceeded {
                limit: 1,
                side: Side::Peer,
            }
        );
        assert!(!error.kind().is_peer_fault());
        assert_eq!(client.adapter().records.len(), 2);
    }

    #[test]
    fn a_refused_send_does_not_spend_a_lane() {
        // The send opens no carrier stream when the backend refuses it, so
        // counting the lane would spend one on nothing and, at a limit of one,
        // refuse every later lane for good.
        let peer = Settings {
            reliable_lane_limit: 1,
            ..Settings::default()
        };
        let (mut client, _server) = negotiated_with(Settings::default(), peer);
        client.adapter.refuse_sends = Some(TransportError::OutboundQueueFull);
        let record = data_record(b"record");
        assert!(client.send_reliable(StreamId(1), &record).is_err());

        // The lane the failed send named is still free, and so is any other.
        client.adapter.refuse_sends = None;
        client.send_reliable(StreamId(2), &record).unwrap();
        assert_eq!(client.adapter().records.len(), 1);
        assert_eq!(
            client
                .send_reliable(StreamId(3), &record)
                .unwrap_err()
                .kind(),
            &ErrorKind::LaneLimitExceeded {
                limit: 1,
                side: Side::Peer,
            }
        );
    }

    #[test]
    fn a_submission_that_is_not_one_whole_frame_is_refused() {
        // peek_envelope succeeds on a header alone, so a header declaring a
        // payload that is not there would go out as it stands and leave the
        // peer waiting on a stream that stays open.
        let (mut client, mut server) = negotiated();
        let whole = frame_of(frame_type::PING, 0);
        client.send_control(&whole).unwrap();

        let record = data_record(b"payload");
        for truncated in [&record[..record.len() - 1], &record[..1]] {
            let error = client.send_reliable(StreamId(1), truncated).unwrap_err();
            assert!(matches!(
                error.kind(),
                ErrorKind::NotExactlyOneFrame { .. } | ErrorKind::Decode(_)
            ));
        }

        // Two frames in one submission is the same disagreement about where a
        // frame ends.
        let mut two = record.clone();
        two.extend_from_slice(&record);
        assert!(matches!(
            client.send_reliable(StreamId(1), &two).unwrap_err().kind(),
            ErrorKind::NotExactlyOneFrame {
                found,
                declared,
                ..
            } if *found == two.len() && *declared == record.len()
        ));

        // And the peer sending one closes the session rather than delivering it.
        server.adapter.events.push_back(control(&{
            let mut short = frame_of(frame_type::PING, 0);
            short.extend_from_slice(&frame_of(frame_type::PING, 0));
            short
        }));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
        assert!(error.kind().is_peer_fault());
    }

    #[test]
    fn an_experimental_frame_needs_its_extension_negotiated() {
        // spec/wire.md section 5: a known experimental frame is invalid unless
        // its extension was negotiated, and the default sets are empty.
        let credit = frame_of(frame_type::DATAGRAM_CREDIT, 8);
        let (mut client, mut server) = negotiated();
        let error = client.send_control(&credit).unwrap_err();
        assert_eq!(error.close_code(), error_code::EXPERIMENT_NOT_NEGOTIATED);
        assert_eq!(
            error.kind(),
            &ErrorKind::ExperimentNotNegotiated {
                frame_type: frame_type::DATAGRAM_CREDIT,
                extension: vot_codec::extension_id::DATAGRAM_FEC,
                side: Side::Peer,
            }
        );

        server.adapter.events.push_back(control(&credit));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::EXPERIMENT_NOT_NEGOTIATED);
        assert!(error.kind().is_peer_fault());

        // A client cannot reach the state where one is allowed, and that is a
        // specification gap rather than a policy choice. spec/wire.md section 1
        // has only the client send HELLO, so the server learns which extensions
        // the client offered and the client learns nothing about the server's.
        // The registry requires both endpoints to negotiate an extension, so
        // the side that cannot know has to refuse.
        let fec = BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]);
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            fec.clone(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            fec,
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        client.poll().unwrap();

        // The server saw the offer, so it can compute an intersection and
        // will accept an experimental frame from the client.
        assert_eq!(
            server.negotiation.negotiated_extensions(),
            BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC])
        );
        // The client saw no HELLO, so it has none and refuses either way.
        assert!(client.negotiation.negotiated_extensions().is_empty());
        assert!(client.send_control(&credit).is_err());

        // And neither may send one. Sending under the server's half would put
        // a frame on the wire the client is obliged to refuse, closing a
        // session that had negotiated correctly.
        assert!(server.negotiation.usable_extensions().is_empty());
        assert!(client.negotiation.usable_extensions().is_empty());
        let error = server.send_control(&credit).unwrap_err();
        assert_eq!(error.close_code(), error_code::EXPERIMENT_NOT_NEGOTIATED);
        assert!(!error.kind().is_peer_fault());
        assert!(
            server.adapter().closed.is_empty(),
            "a local refusal does not close the carrier"
        );
    }

    #[test]
    fn a_lane_carries_the_payload_and_the_control_stream_describes_it() {
        // A PROOF_BUNDLE is bounded by the negotiated control ceiling, which a
        // lane does not carry: every backend frames a lane at the fixed record
        // limit, so a proof above it could be routed and never sent.
        assert!(Lane::Reliable.carries(frame_type::DATA_RECORD));
        assert!(!Lane::Control.carries(frame_type::DATA_RECORD));
        for frame_type in [
            frame_type::PROOF_BUNDLE,
            frame_type::HELLO,
            frame_type::SETTINGS,
            frame_type::MANIFEST_PAGE,
            frame_type::PUBLISH_RECEIPT,
            frame_type::PING,
        ] {
            assert!(Lane::Control.carries(frame_type), "{frame_type:#x}");
            assert!(!Lane::Reliable.carries(frame_type), "{frame_type:#x}");
        }
    }

    #[test]
    fn a_frame_on_the_wrong_stream_is_refused() {
        // spec/wire.md section 7 gives negotiation its own stream. A
        // control-only frame on a lane would skip negotiation entirely, so a
        // duplicate HELLO after readiness would reach the application instead
        // of producing the sequence error the exchange requires.
        let (mut client, mut server) = negotiated();
        let mut hello = Vec::new();
        vot_codec::encode_hello(
            &Hello {
                draft_revision: vot_codec::DRAFT_REVISION,
                endpoint_role: EndpointRole::Client,
                extensions: BTreeSet::new(),
            },
            &mut hello,
        )
        .unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &hello, &mut frame).unwrap();

        // Inbound on a lane: refused rather than delivered.
        server.adapter.events.push_back(Event::Reliable {
            stream: StreamId(1),
            sequence: 1,
            bytes: vot_transport_api::shared_payload(&frame),
        });
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
        assert_eq!(
            error.kind(),
            &ErrorKind::FrameOnTheWrongLane {
                frame_type: frame_type::HELLO,
                lane: Lane::Reliable,
                side: Side::Local,
            }
        );
        assert!(error.kind().is_peer_fault());

        // Outbound the same way, and a record on the negotiation stream is
        // refused for the mirror reason.
        assert_eq!(
            client
                .send_reliable(StreamId(1), &frame)
                .unwrap_err()
                .kind(),
            &ErrorKind::FrameOnTheWrongLane {
                frame_type: frame_type::HELLO,
                lane: Lane::Reliable,
                side: Side::Peer,
            }
        );
        assert_eq!(
            client
                .send_control(&data_record(b"record"))
                .unwrap_err()
                .kind(),
            &ErrorKind::FrameOnTheWrongLane {
                frame_type: frame_type::DATA_RECORD,
                lane: Lane::Control,
                side: Side::Peer,
            }
        );
    }

    #[test]
    fn a_driver_can_reach_a_backend_the_adapter_contract_does_not_cover() {
        // A TcpAdapter moves bytes through methods the contract has no place
        // for, so without this a session over one would queue a handshake that
        // nothing could ever send.
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        assert_eq!(client.adapter().sent.len(), 2);

        // The same adapter, reachable for the work the session cannot do.
        client.driver().sent.clear();
        assert!(client.adapter().sent.is_empty());
        client
            .driver()
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(1)));
        assert_eq!(
            client.poll().unwrap(),
            Some(Event::Connected(vot_transport_api::ConnectionId(1)))
        );
    }

    #[test]
    fn an_application_cannot_send_the_frames_the_exchange_owns() {
        // A caller encoding its own HELLO or SETTINGS drives the peer's state
        // machine by hand: the peer refuses it as out of sequence and closes a
        // session that was working.
        let (mut client, _server) = negotiated();
        for frame_type in [
            frame_type::HELLO,
            frame_type::SETTINGS,
            frame_type::SETTINGS_ACK,
            frame_type::AUTH_CONTEXT,
        ] {
            let error = client.send_control(&frame_of(frame_type, 0)).unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::NegotiationFrameFromApplication { frame_type }
            );
            // The caller's mistake, so the carrier is left alone.
            assert!(!error.kind().is_peer_fault());
            assert!(client.adapter().closed.is_empty());
        }
        assert!(client.adapter().sent.is_empty(), "none reached the backend");

        // The exchange still sends its own, which do not go through this path.
        let mut fresh = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        fresh.begin().unwrap();
        assert_eq!(fresh.adapter().sent.len(), 2);

        // And an ordinary application frame is unaffected.
        let (mut ready, _peer) = negotiated();
        ready.send_control(&frame_of(frame_type::PING, 0)).unwrap();
        assert_eq!(ready.adapter().sent.len(), 1);
    }

    #[test]
    fn beginning_twice_is_refused() {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        assert!(matches!(
            client.begin().unwrap_err().kind(),
            ErrorKind::OutOfSequence { .. }
        ));
        assert_eq!(client.adapter.sent.len(), 2, "nothing was sent twice");
    }
}
