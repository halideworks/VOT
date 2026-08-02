//! VOT session negotiation and the gate it puts in front of the data plane.
//!
//! `spec/wire.md` section 1 puts negotiation on the first client-initiated
//! bidirectional stream: the client sends `HELLO` then `SETTINGS`, the server
//! answers with its own `SETTINGS` then `SETTINGS_ACK`. Until that exchange
//! finishes neither side knows the other's limits, its draft revision, or the
//! extensions it understands.
//!
//! The transport backends can open streams and move bytes without any of that,
//! which is what makes this layer necessary rather than decorative: reserving
//! the negotiation stream is not the same as negotiating on it. Nothing here
//! adds protocol machinery. It enforces machinery `spec/wire.md` already
//! defines.
//!
//! ## What `Ready` means
//!
//! `Ready` means negotiated, not authenticated. `spec/wire.md` also defines
//! `AUTH_CONTEXT`, `SESSION_OPEN`, and `SESSION_ACCEPT`, and marks most
//! application frames as requiring an authenticated session. None of those are
//! implemented here, so a session that reaches `Ready` has completed the
//! version and limit exchange and nothing else. Every frame the registry marks
//! `auth: yes` is therefore not yet conforming.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use vot_codec::{
    DecodeError, DecodedFrame, EndpointRole, Hello, HelloError, Settings, SettingsError,
    error_code, frame_type,
};
use vot_transport_api::{Error as TransportError, Event, Payload, StreamId, TransportAdapter};

/// Largest number of peer records held while this endpoint finishes
/// negotiating.
///
/// A conforming peer can have data in flight before it learns this side is
/// ready: the two endpoints reach `Ready` at different moments, and QUIC orders
/// nothing between the negotiation stream and an application lane. Refusing
/// those records would close a session the peer did nothing wrong in, so they
/// are held. Held, not unbounded: this is the only place peer data accumulates
/// on behalf of a session that has not agreed to anything yet.
pub const DEFAULT_PENDING_RECORD_BYTES: usize = 4 * vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES;

/// Largest number of peer records held before readiness, by count.
///
/// A byte bound alone does not limit per-record overhead, and a peer that sends
/// many tiny records would otherwise queue an unbounded number of them.
pub const DEFAULT_PENDING_RECORD_COUNT: usize = 64;

/// How far a session has got through `spec/wire.md` section 1.
///
/// The names are written from the client's side of the exchange. On an
/// accepting endpoint `HelloSent` means the peer's `HELLO` arrived, and
/// `SettingsExchanged` means its `SETTINGS` arrived and this side's went out.
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
    Ready,
    /// The carrier is gone.
    Closed,
}

impl State {
    /// Whether the application may use the data plane.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Why a session cannot continue, with the code `spec/registries.md` gives it.
///
/// A failure the peer caused is applied to the carrier before the error is
/// returned, so the peer learns which rule it broke rather than seeing the
/// session end for no stated reason. A local failure is not: see
/// [`ErrorKind::is_peer_fault`].
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

/// The distinguishable ways a session fails.
///
/// Kept separate from the registered close code so a caller can tell a peer
/// that sent the wrong thing from one that sent nothing, and a local refusal
/// from a peer-induced one, which the single wire code cannot express.
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
    /// The carrier ended before the exchange finished.
    Interrupted { state: State },
    /// The application tried to use the data plane before `Ready`.
    NotReady { state: State },
    /// The peer sent more before readiness than this endpoint will hold.
    PendingRecordsExhausted { bytes: usize, count: usize },
    /// The backend refused something the session needed.
    Transport(TransportError),
    /// The backend would reassemble control frames larger than this endpoint
    /// is about to say it accepts.
    ReceiveLimitMismatch { advertised: u64, backend: usize },
}

impl ErrorKind {
    /// Whether the peer caused this, and so whether it belongs on the wire.
    ///
    /// The question `spec/wire.md` cannot answer from the close code alone: one
    /// registered code covers a peer that sent a frame out of sequence and a
    /// local caller that asked for something too early, and only the first is
    /// a reason to end a working connection.
    #[must_use]
    pub const fn is_peer_fault(&self) -> bool {
        match self {
            Self::Hello(_)
            | Self::Settings(_)
            | Self::Decode(_)
            | Self::OutOfSequence { .. }
            | Self::NotNegotiated { .. }
            | Self::PendingRecordsExhausted { .. } => true,
            // A local misuse of the API, a backend refusal the backend already
            // knows about, and a carrier that has already gone. Closing over
            // any of these would either blame the peer for something it did
            // not do or turn backpressure into a teardown.
            Self::NotReady { .. }
            | Self::Transport(_)
            | Self::Interrupted { .. }
            | Self::ReceiveLimitMismatch { .. } => false,
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
}

/// The `spec/wire.md` section 1 exchange, as a state machine.
///
/// Carries no carrier and no buffers, so the sequence can be exercised without
/// one. [`Session`] is what connects it to a transport.
#[derive(Clone, Debug)]
pub struct Negotiation {
    role: EndpointRole,
    state: State,
    local: Settings,
    extensions: BTreeSet<u64>,
    peer_hello: Option<Hello>,
    peer_settings: Option<Settings>,
}

impl Negotiation {
    /// A connecting endpoint, which opens the negotiation stream and speaks
    /// first.
    #[must_use]
    pub fn client(local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(EndpointRole::Client, local, extensions)
    }

    /// An accepting endpoint, which answers on the stream the client opened.
    #[must_use]
    pub fn server(local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(EndpointRole::Server, local, extensions)
    }

    fn new(role: EndpointRole, local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self {
            role,
            state: State::Connecting,
            local,
            extensions,
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
    ///
    /// Absent until the peer's `SETTINGS` arrive, because a default guessed on
    /// its behalf is exactly the kind of assumption negotiation exists to
    /// remove.
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.peer_settings
    }

    /// What the peer said about itself.
    #[must_use]
    pub const fn peer_hello(&self) -> Option<&Hello> {
        self.peer_hello.as_ref()
    }

    /// Reports the negotiation stream reserved and returns what to send.
    ///
    /// The client sends `HELLO` then `SETTINGS`. The server sends nothing yet:
    /// `spec/wire.md` has it answer, and answering before the question would
    /// mean acknowledging settings it has not seen.
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
            // The caller is expected to hand over exactly one framed frame.
            // More bytes mean the carrier and this layer disagree about where
            // frames end, which is not something to guess about.
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
            // An unknown optional or grease frame is skipped by its validated
            // length at any point in the exchange, which is what lets a peer
            // send them during a handshake without ending it.
            return Ok(Accepted::Consumed { reply: Vec::new() });
        };
        match frame_type {
            frame_type::HELLO => self.accept_hello(payload),
            frame_type::SETTINGS => self.accept_settings(payload),
            frame_type::SETTINGS_ACK => self.accept_settings_ack(),
            other => self.accept_application(other),
        }
    }

    /// Ends the exchange because the peer broke it.
    ///
    /// Separate from [`carrier_closed`](Self::carrier_closed), which reports a
    /// carrier that went away on its own. Nothing further is accepted either
    /// way, but only this one is the peer's doing.
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
        // spec/wire.md section 5: HELLO is sent once per session, and section 1
        // has only the client send it, on the stream it opened. A server that
        // sent one would be claiming a role the stream initiator contradicts.
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
        // Once per direction. A second one would change limits the peer has
        // already been told this endpoint is working under.
        if self.peer_settings.is_some() {
            return Err(self.out_of_sequence(frame_type::SETTINGS));
        }
        // The same state on both sides: the client has sent HELLO and SETTINGS
        // and is waiting for the answer, and the server has seen HELLO and is
        // waiting for the settings behind it.
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
                // The answer and the acknowledgement go out together: the
                // acknowledgement says the settings just parsed were accepted,
                // and this endpoint has nothing further to ask.
                let reply = vec![self.settings_frame()?, settings_ack_frame()?];
                self.state = State::Ready;
                Ok(Accepted::Consumed { reply })
            }
        }
    }

    /// Accepts `SETTINGS_ACK`.
    ///
    /// No payload check: `spec/wire.md` section 5 gives this frame a maximum of
    /// zero bytes, and the codec rejects a longer one as `FRAME_TOO_LARGE`
    /// before it reaches here. A second check would be a branch nothing could
    /// take.
    fn accept_settings_ack(&mut self) -> Result<Accepted, Error> {
        // spec/wire.md section 5: a duplicate acknowledgement is ignored, so a
        // second one after readiness is not an error.
        if self.role == EndpointRole::Client && self.state.is_ready() {
            return Ok(Accepted::Consumed { reply: Vec::new() });
        }
        if self.role != EndpointRole::Client || self.state != State::SettingsExchanged {
            return Err(self.out_of_sequence(frame_type::SETTINGS_ACK));
        }
        self.state = State::Ready;
        Ok(Accepted::Consumed { reply: Vec::new() })
    }

    fn accept_application(&mut self, frame_type: u64) -> Result<Accepted, Error> {
        if self.state.is_ready() {
            return Ok(Accepted::Application);
        }
        // spec/wire.md section 1: frames that require a session are invalid
        // until there is one. Reported as a state violation rather than an
        // authentication failure, because no authentication policy has run:
        // claiming one rejected this would describe a check that does not
        // exist yet.
        Err(Error::new(
            ErrorKind::NotNegotiated { frame_type },
            error_code::MALFORMED_FRAME,
        ))
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
///
/// Owns the adapter so an application cannot reach past the gate to the raw
/// backend. The backends stay able to open streams and move bytes on their own,
/// which is what makes them testable; this is what stops a deployment doing it
/// before there is anything to send it under.
pub struct Session<A> {
    adapter: A,
    negotiation: Negotiation,
    /// Negotiation frames the backend has not accepted yet.
    ///
    /// The exchange advances in pairs: a client sends `HELLO` and `SETTINGS`
    /// together, a server answers with `SETTINGS` and `SETTINGS_ACK`. A backend
    /// with room for the first and not the second would leave the peer waiting
    /// for a frame nothing would ever send again, because the state machine has
    /// already moved past producing it. Holding the remainder here makes a full
    /// outbound queue backpressure rather than a lost handshake.
    ///
    /// At most two frames, since that is the largest step the exchange takes.
    outbound: VecDeque<Vec<u8>>,
    /// Records the peer sent before this endpoint reached `Ready`.
    ///
    /// Held here rather than left in the adapter: an adapter queue is one
    /// ordered stream of events, so leaving a record in it would block the
    /// control frames behind it, and those are what readiness is waiting for.
    pending: VecDeque<Event>,
    pending_bytes: usize,
    pending_byte_limit: usize,
    pending_count_limit: usize,
    /// Whether the peer's control-frame limit reached the backend.
    control_limit_applied: bool,
}

impl<A: TransportAdapter> Session<A> {
    /// A connecting session, which opens the negotiation stream.
    pub fn client(adapter: A, local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(adapter, Negotiation::client(local, extensions))
    }

    /// An accepting session, which answers on the stream the client opened.
    pub fn server(adapter: A, local: Settings, extensions: BTreeSet<u64>) -> Self {
        Self::new(adapter, Negotiation::server(local, extensions))
    }

    fn new(adapter: A, negotiation: Negotiation) -> Self {
        Self {
            adapter,
            negotiation,
            outbound: VecDeque::new(),
            pending: VecDeque::new(),
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

    /// The limits the peer advertised.
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.negotiation.peer_settings()
    }

    /// Whether the peer's control-frame limit was applied to the backend.
    ///
    /// A backend with no such bound reports [`TransportError::Unsupported`] and
    /// this stays false, so a caller can tell an applied limit from one that
    /// was quietly dropped.
    #[must_use]
    pub const fn control_limit_applied(&self) -> bool {
        self.control_limit_applied
    }

    /// Borrows the backend for measurements that do not move data.
    pub const fn adapter(&self) -> &A {
        &self.adapter
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
    /// Advertising one bound and reassembling up to another is the asymmetry
    /// negotiation exists to remove, and it is silent: the peer sends what it
    /// was told it could, and this endpoint accepts more. Checked rather than
    /// set, because the bound has to be in force before the first byte and a
    /// session is constructed after the carrier is.
    ///
    /// # Errors
    /// Reports a backend whose reassembly bound is not the limit this endpoint
    /// is about to advertise.
    fn check_receive_limit(&self) -> Result<(), Error> {
        let Some(backend) = self.adapter.control_receive_limit() else {
            // A backend that reassembles nothing has nothing to disagree with.
            return Ok(());
        };
        let advertised = self.negotiation.local_settings().max_control_frame_payload;
        if usize::try_from(advertised) == Ok(backend) {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::ReceiveLimitMismatch {
                advertised,
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

    /// Ends the session when the peer is the one that broke it.
    ///
    /// Only then. A local caller using the API wrongly, or a backend refusing a
    /// submission, is not something to tear a healthy connection down over, and
    /// `NotReady` on the wire would tell the peer nothing it did was wrong. A
    /// carrier that has already gone has nothing left to close.
    fn fail(&mut self, error: Error) -> Error {
        if error.kind().is_peer_fault() {
            let _ = self.adapter.close(error.close_code());
            self.negotiation.abandon();
        }
        error
    }

    /// Whether queued negotiation frames should still be pushed.
    ///
    /// A closed session has nothing left to negotiate, and a stale `HELLO`
    /// arriving on a dying connection is noise the peer has to parse before it
    /// can work out the session is over.
    const fn may_negotiate(&self) -> bool {
        !matches!(self.negotiation.state(), State::Closed)
    }

    fn poll_inner(&mut self) -> Result<Option<Event>, Error> {
        if self.may_negotiate() && !self.outbound.is_empty() {
            // A driver that polls in a loop retries the handshake without
            // having to know it stalled.
            self.drain_outbound()?;
        }
        if self.negotiation.state() == State::Closed {
            // The session is over. Frames still arriving on a closing carrier
            // are not worth interpreting, and interpreting them would report
            // the second thing that went wrong rather than the first: a peer
            // whose HELLO was refused would show up as an application frame
            // before negotiation on the next call.
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
                    if let Some(event) = self.accept_control(&bytes)? {
                        return Ok(Some(event));
                    }
                }
                Event::Disconnected(connection) => {
                    self.negotiation.carrier_closed()?;
                    return Ok(Some(Event::Disconnected(connection)));
                }
                record @ Event::Reliable { .. } => {
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
        self.require_ready()?;
        self.adapter.send_control(frame).map_err(transport_error)
    }

    /// Submits an application record on a reliable lane.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        self.require_ready()?;
        self.adapter
            .send_reliable(stream, record)
            .map_err(transport_error)
    }

    /// Submits an already shared record without another copy.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.require_ready()?;
        self.adapter
            .send_reliable_shared(stream, record)
            .map_err(transport_error)
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
        // Closed. Whatever the backend already holds may still go out, but no
        // more negotiation frames are handed to it.
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
        }
    }

    /// Applies what the peer advertised to the backend.
    ///
    /// Without this the exchange is a state enum: the peer's control-frame
    /// maximum is the bound on what this endpoint may send, and ignoring it
    /// means sending frames the peer is entitled to close the session over.
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
    /// Reports a backend refusal that is not capacity. A full queue is not an
    /// error: the frames stay queued and the next `flush` or `poll` retries
    /// them.
    fn submit(&mut self, frames: Vec<Vec<u8>>) -> Result<(), Error> {
        self.outbound.extend(frames);
        self.drain_outbound()
    }

    /// Hands queued negotiation frames to the backend in order.
    ///
    /// # Errors
    /// Reports the first refusal that is not capacity, keeping that frame and
    /// everything after it queued either way.
    fn drain_outbound(&mut self) -> Result<(), Error> {
        while let Some(frame) = self.outbound.front() {
            match self.adapter.send_control(frame) {
                Ok(()) => {
                    self.outbound.pop_front();
                }
                // Backpressure. The frame stays at the head and the exchange
                // resumes when the backend has room, rather than the peer
                // waiting for something nothing will send again.
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

    /// Returns the next carrier event a closed session still owes its caller.
    ///
    /// Lifecycle only: the caller has to learn the carrier ended, and nothing
    /// else on a closed session means anything.
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

    fn require_ready(&self) -> Result<(), Error> {
        if self.negotiation.is_ready() {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::NotReady {
                state: self.negotiation.state(),
            },
            error_code::MALFORMED_FRAME,
        ))
    }
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
        receive_limit: Option<usize>,
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

        fn control_receive_limit(&self) -> Option<usize> {
            self.receive_limit
        }

        fn close(&mut self, code: u16) -> Result<(), TransportError> {
            self.closed.push(code);
            Ok(())
        }
    }

    fn control(bytes: &[u8]) -> Event {
        Event::Control(vot_transport_api::shared_payload(bytes))
    }

    fn record(lane: u64, payload: &[u8]) -> Event {
        Event::Reliable {
            stream: StreamId(lane),
            sequence: lane,
            bytes: vot_transport_api::shared_payload(payload),
        }
    }

    /// Runs the exchange to completion, returning both endpoints.
    fn negotiated() -> (Session<Loopback>, Session<Loopback>) {
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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

        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        // SETTINGS_ACK.
        let answer = server.adapter.sent.clone();
        assert_eq!(answer.len(), 2);
        let (first, _) = vot_codec::decode_one(&answer[0], limits).unwrap();
        let (second, _) = vot_codec::decode_one(&answer[1], limits).unwrap();
        assert_eq!(first.frame_type(), frame_type::SETTINGS);
        assert_eq!(second.frame_type(), frame_type::SETTINGS_ACK);

        for frame in answer {
            client.adapter.events.push_back(control(&frame));
        }
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.is_ready());
        assert_eq!(client.peer_settings(), Some(Settings::default()));
    }

    #[test]
    fn the_data_plane_is_refused_until_the_exchange_finishes() {
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
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
        client.send_reliable(StreamId(1), b"record").unwrap();
        assert_eq!(client.adapter.records.len(), 1);
    }

    #[test]
    fn records_that_arrive_early_are_held_rather_than_refused() {
        // The two endpoints reach readiness at different moments and QUIC
        // orders nothing between the negotiation stream and an application
        // lane, so a conforming peer can have records in flight already.
        // Closing the session over them would punish it for the protocol's own
        // shape.
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        client.begin().unwrap();
        client.adapter.events.push_back(control(&frame));
        assert!(matches!(
            client.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence { .. }
        ));

        // SETTINGS before HELLO leaves the server with limits from a peer it
        // has not identified.
        let mut early = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
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

        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        let mut server = Session::server(Loopback::default(), peer, BTreeSet::new());
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
        );
        let mut answering = Session::server(Loopback::default(), peer, BTreeSet::new());
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
            .send_reliable_shared(StreamId(3), vot_transport_api::shared_payload(b"shared"))
            .unwrap();
        assert_eq!(
            client.adapter().records,
            vec![(StreamId(3), b"shared".to_vec())]
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
        );
        refusing.negotiation.state = State::Ready;
        let error = refusing.send_reliable(StreamId(1), b"record").unwrap_err();
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
            );
            session.negotiation.state = State::Ready;
            assert_eq!(
                session
                    .send_reliable(StreamId(1), b"record")
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
        server.begin().unwrap();
        server
            .set_pending_limits(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES, 8)
            .unwrap();
        for lane in 0..4 {
            server.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.pending_bytes, 4 * 1024);

        let mut exact = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
        exact.begin().unwrap();
        exact.pending_byte_limit = 2 * 1024;
        for lane in 0..2 {
            exact.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(exact.poll().unwrap(), None, "the bound itself is allowed");
        assert_eq!(exact.pending_bytes, 2 * 1024);

        exact.adapter.events.push_back(record(2, b"x"));
        let error = exact.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::RESOURCE_LIMIT);
        assert_eq!(
            error.kind(),
            &ErrorKind::PendingRecordsExhausted {
                bytes: 2 * 1024,
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        let mut early = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        early.begin().unwrap();
        assert!(early.send_reliable(StreamId(1), b"record").is_err());
        assert!(early.send_control(b"frame").is_err());
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
        );
        refusing.negotiation.state = State::Ready;
        assert!(refusing.send_reliable(StreamId(1), b"record").is_err());
        assert!(refusing.adapter().closed.is_empty());

        // Nor does a carrier that has already gone; there is nothing to close.
        let mut gone = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
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
            let mut session =
                Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
                receive_limit: Some(64 * 1024),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
        );
        let error = mismatched.begin().unwrap_err();
        assert_eq!(error.close_code(), error_code::INVALID_SETTING);
        assert_eq!(
            error.kind(),
            &ErrorKind::ReceiveLimitMismatch {
                advertised: Settings::default().max_control_frame_payload,
                backend: 64 * 1024,
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
                receive_limit: Some(64 * 1024),
                ..Loopback::default()
            },
            Settings {
                max_control_frame_payload: 64 * 1024,
                ..Settings::default()
            },
            BTreeSet::new(),
        );
        agreed.begin().unwrap();
        assert_eq!(agreed.adapter().sent.len(), 2);

        // A backend that reassembles nothing has nothing to disagree with.
        let mut silent = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        silent.begin().unwrap();
        assert_eq!(silent.adapter().sent.len(), 2);
    }

    #[test]
    fn a_closed_session_stops_interpreting_and_still_reports_the_carrier() {
        // Polling a failed session again used to report whatever the next frame
        // looked like against a closed state, which named the second thing that
        // went wrong rather than the first.
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        );
        polling.begin().unwrap();
        assert_eq!(polling.unsent_negotiation_frames(), 2);
        polling.adapter.control_capacity = None;
        assert_eq!(polling.poll().unwrap(), None);
        assert_eq!(polling.unsent_negotiation_frames(), 0);
        assert_eq!(polling.adapter().sent.len(), 2);

        // The server's answer is a pair too, and stalls the same way.
        let mut server = Session::server(
            Loopback {
                control_capacity: Some(1),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
        );
        server.begin().unwrap();
        for frame in polling.adapter().sent.clone() {
            server.adapter.events.push_back(control(&frame));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert!(server.is_ready());
        assert_eq!(server.adapter().sent.len(), 1, "only SETTINGS fitted");
        assert_eq!(server.unsent_negotiation_frames(), 1);
        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.adapter().sent.len(), 2);
        assert_eq!(
            vot_codec::decode_one(&server.adapter().sent[1], limits)
                .unwrap()
                .0
                .frame_type(),
            frame_type::SETTINGS_ACK
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
    fn beginning_twice_is_refused() {
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        client.begin().unwrap();
        assert!(matches!(
            client.begin().unwrap_err().kind(),
            ErrorKind::OutOfSequence { .. }
        ));
        assert_eq!(client.adapter.sent.len(), 2, "nothing was sent twice");
    }
}
