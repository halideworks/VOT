//! The `spec/wire.md` section 1 exchange, and the gate it puts in front of the
//! data plane. See `docs/session.md`.
//!
//! `Ready` means negotiated, not authenticated. `AUTH_CONTEXT`,
//! `SESSION_OPEN`, and `SESSION_ACCEPT` are unimplemented, so every frame the
//! registry marks `auth: yes` is not yet conforming.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

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
    /// The carrier ended before the exchange finished.
    Interrupted { state: State },
    /// The application tried to use the data plane before `Ready`.
    NotReady { state: State },
    /// The peer sent more before readiness than this endpoint will hold.
    PendingRecordsExhausted { bytes: usize, count: usize },
    /// Negotiation frames have not all reached the backend yet.
    HandshakeUnsent { remaining: usize },
    /// A record larger than the peer said it would accept.
    RecordExceedsPeerLimit { bytes: u64, limit: u64 },
    /// A record larger than this endpoint said it would accept.
    RecordExceedsLocalLimit { bytes: u64, limit: u64 },
    /// The backend refused something the session needed.
    Transport(TransportError),
    /// The backend would reassemble control frames larger than this endpoint
    /// is about to say it accepts.
    ReceiveLimitMismatch { advertised: u64, backend: usize },
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
            | Self::PendingRecordsExhausted { .. }
            // The peer sent past the limit it was given.
            | Self::RecordExceedsLocalLimit { .. } => true,
            // Local. Closing over these would blame the peer for something it
            // did not do, or turn backpressure into a teardown.
            Self::NotReady { .. }
            | Self::Transport(_)
            | Self::Interrupted { .. }
            | Self::ReceiveLimitMismatch { .. }
            | Self::HandshakeUnsent { .. }
            | Self::RecordExceedsPeerLimit { .. } => false,
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

/// The exchange as a state machine, with no carrier and no buffers.
/// [`Session`] connects it to a transport.
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
    /// Absent until its `SETTINGS` arrive; guessing a default would be the
    /// assumption negotiation exists to remove.
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
                // Answer and acknowledgement together: nothing further to ask.
                let reply = vec![self.settings_frame()?, settings_ack_frame()?];
                self.state = State::Ready;
                Ok(Accepted::Consumed { reply })
            }
        }
    }

    /// Accepts `SETTINGS_ACK`. No payload check: the registry gives it a
    /// maximum of zero bytes, so the codec has already refused a longer one.
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
        // spec/wire.md section 1: frames needing a session are invalid until
        // there is one. A state violation, not an authentication failure: no
        // authentication policy has run.
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
/// Owns the adapter so an application cannot reach past the gate.
pub struct Session<A> {
    adapter: A,
    negotiation: Negotiation,
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
                    if let Some(event) = self.accept_control(&bytes)? {
                        return Ok(Some(event));
                    }
                }
                Event::Disconnected(connection) => {
                    self.negotiation.carrier_closed()?;
                    return Ok(Some(Event::Disconnected(connection)));
                }
                record @ Event::Reliable { .. } => {
                    self.admit_record(&record)?;
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
        self.adapter.send_control(frame).map_err(transport_error)
    }

    /// Submits an application record on a reliable lane.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable(&mut self, stream: StreamId, record: &[u8]) -> Result<(), Error> {
        self.require_sendable()?;
        self.require_within_peer_record_limit(record)?;
        self.adapter
            .send_reliable(stream, record)
            .map_err(transport_error)
    }

    /// Submits an already shared record without another copy.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_reliable_shared(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        self.require_sendable()?;
        self.require_within_peer_record_limit(&record)?;
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
        }
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

    /// Refuses a record whose payload is larger than the peer said it accepts.
    ///
    /// The declared payload, not the wire length: a conforming record carries
    /// the type and length varints on top of the negotiated maximum.
    fn require_within_peer_record_limit(&self, record: &[u8]) -> Result<(), Error> {
        let Some(peer) = self.negotiation.peer_settings() else {
            return Ok(());
        };
        let payload = declared_payload(record, peer.max_data_record_payload)?;
        if payload <= peer.max_data_record_payload {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::RecordExceedsPeerLimit {
                bytes: payload,
                limit: peer.max_data_record_payload,
            },
            error_code::FRAME_TOO_LARGE,
        ))
    }

    /// Refuses a record whose payload is larger than this endpoint advertised.
    ///
    /// The adapters bound records by the protocol ceiling, which is what a
    /// session advertising less than that would otherwise hand the application
    /// instead of refusing.
    fn admit_record(&self, event: &Event) -> Result<(), Error> {
        let Event::Reliable { bytes, .. } = event else {
            return Ok(());
        };
        let limit = self.negotiation.local_settings().max_data_record_payload;
        let payload = declared_payload(bytes, limit)?;
        if payload <= limit {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::RecordExceedsLocalLimit {
                bytes: payload,
                limit,
            },
            error_code::FRAME_TOO_LARGE,
        ))
    }
}

/// The payload length a record declares, from its envelope.
///
/// `limit` bounds the decode so an unknown type cannot claim more than this
/// endpoint would accept anyway.
fn declared_payload(record: &[u8], limit: u64) -> Result<u64, Error> {
    let limits = vot_codec::DecodeLimits {
        max_unknown_payload: usize::try_from(limit).unwrap_or(usize::MAX),
        max_frames: 1,
    };
    let envelope = vot_codec::peek_envelope(record, limits).map_err(decode_error)?;
    u64::try_from(envelope.payload_length).map_err(|_| {
        Error::new(
            ErrorKind::Decode(DecodeError::LengthOverflow(u64::MAX)),
            error_code::FRAME_TOO_LARGE,
        )
    })
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
            );
            session.negotiation.state = State::Ready;
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
        let mut server = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
        server.begin().unwrap();
        server
            .set_pending_limits(vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES, 8)
            .unwrap();
        for lane in 0..4 {
            server.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.pending_bytes, 4 * record_wire_len(1024));

        let mut exact = Session::server(Loopback::default(), Settings::default(), BTreeSet::new());
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
        assert!(
            refusing
                .send_reliable(StreamId(1), &data_record(b"record"))
                .is_err()
        );
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
    fn an_application_frame_cannot_overtake_a_queued_acknowledgement() {
        // A server is ready when it produces SETTINGS_ACK, not when the backend
        // takes it. An application frame sent in between would reach a peer
        // still in SettingsExchanged, which closes for NotNegotiated.
        let mut client = Session::client(Loopback::default(), Settings::default(), BTreeSet::new());
        let mut server = Session::server(
            Loopback {
                control_capacity: Some(1),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
        );
        client.begin().unwrap();
        server.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.poll().unwrap();
        assert!(server.is_ready());
        assert_eq!(server.unsent_negotiation_frames(), 1, "the ACK did not fit");

        for send in [
            server.send_control(b"application"),
            server.send_reliable(StreamId(1), &data_record(b"record")),
        ] {
            assert_eq!(
                send.unwrap_err().kind(),
                &ErrorKind::HandshakeUnsent { remaining: 1 }
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
        server.send_control(b"application").unwrap();
        assert_eq!(server.adapter().sent.len(), 3);
    }

    #[test]
    fn a_record_larger_than_the_peer_accepts_is_refused() {
        // The adapter only knows the protocol ceiling. Sending past what the
        // peer advertised is a session the peer is entitled to end.
        let peer = Settings {
            max_data_record_payload: 64 * 1024,
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

        client
            .send_reliable(StreamId(1), &data_record(&vec![0; 64 * 1024]))
            .unwrap();
        let error = client
            .send_reliable(StreamId(1), &data_record(&vec![0; 64 * 1024 + 1]))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert_eq!(
            error.kind(),
            &ErrorKind::RecordExceedsPeerLimit {
                bytes: 64 * 1024 + 1,
                limit: 64 * 1024,
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
        let mut server = Session::server(Loopback::default(), local, BTreeSet::new());
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
            &ErrorKind::RecordExceedsLocalLimit {
                bytes: 64 * 1024 + 1,
                limit: 64 * 1024,
            }
        );
        // The peer sent past what it was given, so the carrier is closed.
        assert_eq!(server.adapter().closed, vec![error_code::FRAME_TOO_LARGE]);
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
