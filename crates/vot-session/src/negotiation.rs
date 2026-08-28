//! The `spec/wire.md` section 1 handshake and authentication state machine.

use super::{
    AuthContext, BTreeSet, Binding, DecodeError, DecodedFrame, EndpointRole, Error, ErrorKind,
    Hello, MAX_AUTHENTICATION_ATTEMPTS, PresentationError, SessionAccept, SessionOpen,
    SessionReject, Settings, Side, decode_error, error_code, frame_type, negotiated_payload_limit,
    no_capability, presentation_error,
};

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
    /// `HELLO` has been sent by the client (and, once the server answers,
    /// its answer read), or seen by the server.
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
    /// A server asked for a capability, or refused the last one. The caller
    /// answers with [`Negotiation::present`], reading the challenge from
    /// [`Negotiation::pending_presentation`] and the refusal from
    /// [`Negotiation::last_refusal`].
    PresentationRequired,
}

/// The exchange as a state machine, with no carrier and no buffers.
/// [`Session`] connects it to a transport.
#[derive(Clone, Debug)]
pub struct Negotiation {
    pub(super) role: EndpointRole,
    pub(super) state: State,
    local: Settings,
    extensions: BTreeSet<u64>,
    /// The challenge a server advertises, or what a client read. Caller-supplied:
    /// this crate has no randomness.
    challenge: AuthContext,
    /// Whether a client has read the server's challenge. A demanding challenge
    /// leaves the client `Negotiated`, so without this a second `AUTH_CONTEXT`
    /// would replace the one an attempt is already answering.
    challenge_read: bool,
    /// Whether this client will answer a challenge that asks for a capability.
    /// False on a server, and on a client whose caller presents nothing.
    presenting: bool,
    /// The attempt under way: what the peer opened on a server, and what this
    /// endpoint sent on a client.
    open: Option<SessionOpen>,
    /// Session identifiers already attempted, so a retry cannot reuse one.
    attempted: Vec<[u8; 16]>,
    /// What the server authorized, which may be narrower than what a client
    /// asked for. The caller has no other way to learn it.
    granted: Option<SessionAccept>,
    /// Why the last attempt was refused, for a caller deciding whether another
    /// is worth making. Cleared when one is.
    refusal: Option<SessionReject>,
    pub(super) peer_hello: Option<Hello>,
    pub(super) peer_settings: Option<Settings>,
}

impl Negotiation {
    /// A connecting endpoint, which opens the negotiation stream and speaks
    /// first, and presents no capability.
    #[must_use]
    pub fn client(local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(
            EndpointRole::Client,
            local,
            extensions,
            no_capability([0; 32]),
            false,
        )
    }

    /// A connecting endpoint whose caller answers a challenge that asks for a
    /// capability.
    ///
    /// Nothing is declared here: a request binds to the nonce in the challenge,
    /// which does not exist until the server sends one. The caller passes it to
    /// [`present`](Self::present).
    #[must_use]
    pub fn presenting_client(local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(
            EndpointRole::Client,
            local,
            extensions,
            no_capability([0; 32]),
            true,
        )
    }

    /// An accepting endpoint, which answers on the stream the client opened.
    #[must_use]
    pub fn server(local: Settings, extensions: BTreeSet<u64>, challenge: AuthContext) -> Self {
        Self::new(EndpointRole::Server, local, extensions, challenge, false)
    }

    fn new(
        role: EndpointRole,
        local: Settings,
        extensions: BTreeSet<u64>,
        challenge: AuthContext,
        presenting: bool,
    ) -> Self {
        Self {
            role,
            state: State::Connecting,
            local,
            extensions,
            challenge,
            challenge_read: false,
            presenting,
            open: None,
            attempted: Vec::new(),
            granted: None,
            refusal: None,
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

    /// The extensions this endpoint may send under: the negotiated set, the
    /// same one that bounds what it accepts (ADR-0041).
    #[must_use]
    pub fn usable_extensions(&self) -> BTreeSet<u64> {
        self.negotiated_extensions()
    }

    /// The intersection of both endpoints' extensions, which bound what is
    /// sent and accepted. Empty until the peer's `HELLO` arrives: the
    /// client's offer at a server, the server's answer at a client.
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

    /// Whether one extension is in the negotiated intersection, without
    /// building it. What the per-frame checks ask instead of
    /// [`negotiated_extensions`](Self::negotiated_extensions).
    pub(super) fn extension_is_negotiated(&self, extension: u64) -> bool {
        self.peer_hello.as_ref().is_some_and(|hello| {
            self.extensions.contains(&extension) && hello.extensions.contains(&extension)
        })
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
            // The exchange owns its answers inbound too. Refused rather than
            // handed to the application when no attempt is out: an answer to
            // nothing would let a peer look authenticated.
            frame_type::SESSION_ACCEPT => self.accept_session_accept(payload),
            frame_type::SESSION_REJECT => self.accept_session_reject(payload),
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
        // spec/wire.md section 1: once per direction. The client's offer
        // opens the exchange; the server's answer arrives while the client
        // waits for the server's SETTINGS.
        let (expected_state, peer_role) = match self.role {
            EndpointRole::Server => (State::ControlReserved, EndpointRole::Client),
            EndpointRole::Client => (State::HelloSent, EndpointRole::Server),
        };
        if self.state != expected_state || self.peer_hello.is_some() {
            return Err(self.out_of_sequence(frame_type::HELLO));
        }
        let hello = vot_codec::decode_hello(payload, peer_role).map_err(|error| {
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
        // At a client, accounted for means the server's answer has arrived.
        if self.state != State::HelloSent || self.peer_hello.is_none() {
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
                // Answer, acknowledgement, and challenge together.
                // spec/wire.md section 1.1 puts AUTH_CONTEXT straight after
                // SETTINGS_ACK.
                // The answer to HELLO leads: what this server accepts of the
                // client's offer, so both ends hold the same set (ADR-0041).
                let answer = Hello {
                    draft_revision: vot_codec::DRAFT_REVISION,
                    endpoint_role: EndpointRole::Server,
                    extensions: self.negotiated_extensions(),
                };
                let reply = vec![
                    Self::hello_frame(&answer)?,
                    self.settings_frame()?,
                    settings_ack_frame()?,
                    self.auth_context_frame()?,
                ];
                // spec/wire.md section 1.1: the concluding frame is
                // AUTH_CONTEXT when no capability format was advertised, and
                // SESSION_ACCEPT when one was. Only the first concludes here.
                self.state = if self.challenge.formats.is_empty() {
                    State::Authenticated
                } else {
                    State::Negotiated
                };
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

    /// Accepts the server's challenge. One with no capability format concludes
    /// the exchange; one with a format needs a caller-built answer.
    fn accept_auth_context(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        // Sent once. Without the flag a second would replace the challenge an
        // attempt is answering and change what it was signed over.
        if self.role != EndpointRole::Client
            || self.state != State::Negotiated
            || self.challenge_read
        {
            return Err(self.out_of_sequence(frame_type::AUTH_CONTEXT));
        }
        let context = vot_codec::frames::decode_auth_context_payload(payload)
            .map_err(|_| Error::new(ErrorKind::AuthContextInvalid, error_code::MALFORMED_FRAME))?;
        if context.formats.is_empty() {
            self.challenge_read = true;
            self.challenge = context;
            self.state = State::Authenticated;
            return Ok(Accepted::Consumed { reply: Vec::new() });
        }
        if !self.presenting {
            // A server asking for a capability this endpoint has none of.
            // Refusing immediately stops a client from looking authenticated
            // to itself.
            return Err(Error::new(
                ErrorKind::CapabilityRequired {
                    formats: context.formats.len(),
                },
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        self.challenge_read = true;
        self.challenge = context;
        Ok(Accepted::PresentationRequired)
    }

    /// Accepts the server's acceptance, which concludes the exchange.
    fn accept_session_accept(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        let sent = self.answered_attempt(frame_type::SESSION_ACCEPT)?;
        let accept = vot_codec::frames::decode_session_accept_payload(payload).map_err(|_| {
            Error::new(
                ErrorKind::SessionAnswerInvalid {
                    frame_type: frame_type::SESSION_ACCEPT,
                },
                error_code::MALFORMED_FRAME,
            )
        })?;
        Self::require_answers_attempt(accept.session_id, sent)?;
        self.open = None;
        self.refusal = None;
        self.granted = Some(accept);
        self.state = State::Authenticated;
        Ok(Accepted::Consumed { reply: Vec::new() })
    }

    /// Accepts the server's refusal, which leaves the session open for another
    /// attempt.
    fn accept_session_reject(&mut self, payload: &[u8]) -> Result<Accepted, Error> {
        let sent = self.answered_attempt(frame_type::SESSION_REJECT)?;
        // The codec refuses reasons section 1.1 does not assign to a rejection.
        let reject = vot_codec::frames::decode_session_reject_payload(payload).map_err(|_| {
            Error::new(
                ErrorKind::SessionAnswerInvalid {
                    frame_type: frame_type::SESSION_REJECT,
                },
                error_code::MALFORMED_FRAME,
            )
        })?;
        Self::require_answers_attempt(reject.session_id, sent)?;
        self.open = None;
        self.refusal = Some(reject);
        // Still Negotiated. Another attempt may follow.
        Ok(Accepted::PresentationRequired)
    }

    /// The identifier an inbound answer must belong to.
    /// A server holds a request in the same field and must not read an answer to it.
    fn answered_attempt(&self, frame_type: u64) -> Result<[u8; 16], Error> {
        match (self.role, self.state, &self.open) {
            (EndpointRole::Client, State::Negotiated, Some(open)) => Ok(open.session_id),
            _ => Err(self.out_of_sequence(frame_type)),
        }
    }

    /// Refuses an answer naming an attempt this endpoint did not make.
    /// Without this a server could authenticate a client by answering an attempt
    /// never sent, or a rejection could clear one in flight.
    fn require_answers_attempt(answered: [u8; 16], sent: [u8; 16]) -> Result<(), Error> {
        if answered == sent {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::SessionIdentifierMismatch,
            error_code::AUTHENTICATION_FAILED,
        ))
    }

    /// Accepts a client's request to open a session.
    ///
    /// All section 1.1 rules on the request are checked here; whether the
    /// capability itself is good is the caller's policy via
    /// [`Accepted::AuthorizationRequired`].
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
        // The same binding rule the client applies before sending.
        if !binding_proof_agrees(self.challenge.binding, &open.binding_proof) {
            return Err(Error::new(
                ErrorKind::BindingProofMismatch {
                    binding: self.challenge.binding,
                    proof_bytes: open.binding_proof.len(),
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

    /// The challenge awaiting a capability, on a presenting client.
    /// Absent while an attempt is out.
    #[must_use]
    pub const fn pending_presentation(&self) -> Option<&AuthContext> {
        match (
            self.role,
            self.state,
            self.presenting,
            self.challenge_read,
            &self.open,
        ) {
            (EndpointRole::Client, State::Negotiated, true, true, None) => Some(&self.challenge),
            _ => None,
        }
    }

    /// Attempts section 1.1 still allows this session. Zero means a further
    /// request would be closed on rather than answered.
    #[must_use]
    pub const fn attempts_remaining(&self) -> usize {
        MAX_AUTHENTICATION_ATTEMPTS.saturating_sub(self.attempted.len())
    }

    /// What the server authorized, once it has accepted an attempt. Empty is a
    /// grant of the capability's whole scope, not an absent one.
    #[must_use]
    pub const fn granted(&self) -> Option<&SessionAccept> {
        self.granted.as_ref()
    }

    /// Why the last attempt was refused, for a caller deciding whether to make
    /// another.
    #[must_use]
    pub const fn last_refusal(&self) -> Option<&SessionReject> {
        self.refusal.as_ref()
    }

    /// Presents the caller's capability. All section 1.1 rules are checked
    /// here; the server decides what the capability is worth.
    ///
    /// # Errors
    /// Reports a request section 1.1 does not allow (no challenge, spent
    /// attempts, reused identifier, unoffered format, mismatched binding proof,
    /// or one the peer's limit will not carry). None closes the session.
    pub fn present(&mut self, request: SessionOpen) -> Result<Vec<Vec<u8>>, Error> {
        if self.pending_presentation().is_none() {
            return Err(presentation_error(PresentationError::NothingToAnswer {
                state: self.state,
            }));
        }
        if self.attempts_remaining() == 0 {
            return Err(presentation_error(PresentationError::AttemptsSpent {
                attempts: self.attempted.len(),
            }));
        }
        // Checked here first: breaking one is a close, not a rejection, and
        // costs the session every attempt.
        if self.attempted.contains(&request.session_id) {
            return Err(presentation_error(PresentationError::IdentifierReused));
        }
        if !self.challenge.formats.contains(&request.capability_format) {
            return Err(presentation_error(PresentationError::FormatNotOffered {
                format: request.capability_format,
            }));
        }
        if !binding_proof_agrees(self.challenge.binding, &request.binding_proof) {
            return Err(presentation_error(PresentationError::BindingProof {
                binding: self.challenge.binding,
                proof_bytes: request.binding_proof.len(),
            }));
        }
        // Encoded and measured before the attempt is spent, so a request that
        // cannot go out leaves the caller able to make another.
        let frame =
            Self::session_frame(&vot_codec::frames::TypedFrame::SessionOpen(request.clone()))?;
        self.within_peer_control_limit(&frame)?;
        self.attempted.push(request.session_id);
        self.refusal = None;
        self.open = Some(request);
        Ok(vec![frame])
    }

    /// Refuses an exchange frame the peer's negotiated limit would not carry.
    /// The exchange does not go through [`Session::check_outbound`].
    ///
    /// [`Session::check_outbound`]: Session::check_outbound
    fn within_peer_control_limit(&self, frame: &[u8]) -> Result<(), Error> {
        let Some(peer) = self.peer_settings else {
            return Ok(());
        };
        let limits = vot_codec::DecodeLimits {
            // The protocol ceiling, not the negotiated one: this endpoint
            // encoded the frame, so only the peer's bound matters.
            max_unknown_payload: vot_codec::HARD_MAX_FRAME_PAYLOAD,
            max_frames: 1,
        };
        let envelope = vot_codec::peek_envelope(frame, limits).map_err(decode_error)?;
        let bytes = u64::try_from(envelope.payload_length).unwrap_or(u64::MAX);
        let limit = negotiated_payload_limit(envelope.frame_type, &peer);
        if bytes <= limit {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::FrameExceedsLimit {
                frame_type: envelope.frame_type,
                bytes,
                limit,
                // The peer's limit, so going past it would be this endpoint's
                // doing.
                side: Side::Peer,
            },
            error_code::FRAME_TOO_LARGE,
        ))
    }

    /// Authorizes the pending request with the scope the policy granted.
    ///
    /// # Errors
    /// Rejects a grant with nothing pending, or a scope too wide for the frame.
    pub fn grant(&mut self, granted_scope: Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
        let open = self
            .open
            .as_ref()
            .ok_or_else(|| self.out_of_sequence(frame_type::SESSION_ACCEPT))?;
        let accept = SessionAccept {
            // The identity the request carried. A server choosing its own would
            // leave a client unable to tell which attempt was answered.
            session_id: open.session_id,
            granted_scope,
        };
        // Encoded and measured before the request is spent. Dropping it first
        // would leave a peer waiting on a decision nothing holds.
        let frame = Self::session_frame(&vot_codec::frames::TypedFrame::SessionAccept(
            accept.clone(),
        ))?;
        self.within_peer_control_limit(&frame)?;
        self.granted = Some(accept);
        self.open = None;
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
            .as_ref()
            .ok_or_else(|| self.out_of_sequence(frame_type::SESSION_REJECT))?;
        let reject = SessionReject {
            session_id: open.session_id,
            reason: u64::from(reason),
            detail,
        };
        let frame = Self::session_frame(&vot_codec::frames::TypedFrame::SessionReject(reject))?;
        self.within_peer_control_limit(&frame)?;
        self.open = None;
        Ok(vec![frame])
    }

    fn session_frame(frame: &vot_codec::frames::TypedFrame) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        // The caller's own frame, not the peer's. Blaming the peer for it would
        // close the carrier over a local mistake.
        vot_codec::frames::encode(frame, &mut encoded).map_err(|_| {
            Error::new(
                ErrorKind::SessionAnswerUnencodable,
                error_code::MALFORMED_FRAME,
            )
        })?;
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
        // Measured like the other three, uniformly.
        self.within_peer_control_limit(&frame)?;
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

pub(super) fn settings_ack_frame() -> Result<Vec<u8>, Error> {
    frame(frame_type::SETTINGS_ACK, &[])
}

/// Whether a request's binding proof matches the binding the challenge named.
/// One function for both directions so the rule cannot diverge between sender and reader.
pub(super) const fn binding_proof_agrees(binding: Binding, proof: &[u8]) -> bool {
    match binding {
        Binding::None => proof.is_empty(),
        Binding::ProofOfPossession => !proof.is_empty(),
    }
}

pub(super) fn frame(frame_type: u64, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    vot_codec::encode_frame(frame_type, payload, &mut encoded).map_err(decode_error)?;
    Ok(encoded)
}
