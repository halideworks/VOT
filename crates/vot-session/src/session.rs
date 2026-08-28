//! `TransportAdapter` orchestration behind the negotiation gate.

use super::{
    Accepted, AuthContext, Authentication, BTreeSet, Binding, EndpointRole, Error, ErrorKind,
    Event, ExtensionPolicy, Lane, Negotiation, Payload, PendingEvents, PresentationError,
    SessionAccept, SessionOpen, SessionReject, Settings, Side, State, StreamId, TransportAdapter,
    TransportError, VecDeque, check_frame, error_code, lane_allowed, no_capability,
    transport_error,
};
use vot_transport_api::ChannelBinding;

const RETIRED_NONCE_ONLY_CAPABILITY_FORMAT: u64 = 0x0001;
const CHANNEL_BOUND_CAPABILITY_FORMAT: u64 = 0x0002;

/// A negotiation running over a transport, gating the data plane behind it.
/// Owns the adapter so an application cannot reach past the gate.
pub struct Session<A> {
    pub(super) adapter: A,
    pub(super) negotiation: Negotiation,
    /// Named by the caller, because no policy exists to establish it.
    pub(super) authentication: Authentication,
    /// Negotiation frames the backend has not accepted yet, at most four (the
    /// server's whole reply). A full queue is backpressure, not a lost
    /// handshake.
    pub(super) outbound: VecDeque<Vec<u8>>,
    /// Records the peer sent before this endpoint reached `Ready`. Held here
    /// rather than in the adapter, whose single queue would block the control
    /// frames readiness is waiting for.
    pub(super) pending: PendingEvents,
    /// Lanes this endpoint has sent on, bounded by the peer's advertised
    /// `RELIABLE_LANE_LIMIT`.
    pub(super) lanes: BTreeSet<StreamId>,
    /// Whether the peer's control-frame limit reached the backend.
    pub(super) control_limit_applied: bool,
    /// Carrier-derived authentication material, latched once for this session.
    channel_binding: Option<ChannelBinding>,
    /// Whether this authentication policy requires carrier-derived material.
    binding_required: bool,
    required_extensions: BTreeSet<u64>,
    expected_granted_scope: Option<Vec<u8>>,
}

impl<A: TransportAdapter> Session<A> {
    /// A connecting session, which opens the negotiation stream. See
    /// [`Authentication`] for why it must be named.
    pub fn client(
        adapter: A,
        local: Settings,
        extensions: BTreeSet<u64>,
        authentication: Authentication,
    ) -> Self {
        let negotiation = if matches!(authentication, Authentication::Presenting) {
            Negotiation::presenting_client(local, extensions)
        } else {
            Negotiation::client(local, extensions)
        };
        Self::new(adapter, negotiation, authentication)
    }

    /// An accepting session, which answers on the stream the client opened.
    /// See [`Authentication`] for why it must be named.
    pub fn server(
        adapter: A,
        local: Settings,
        extensions: BTreeSet<u64>,
        authentication: Authentication,
    ) -> Self {
        let challenge = match &authentication {
            Authentication::Capability { challenge } => challenge.clone(),
            // A client's stance, which `begin` refuses on a server rather than
            // advertising a challenge this endpoint never built.
            Authentication::NotRequired { nonce } => no_capability(*nonce),
            Authentication::Presenting => no_capability([0; 32]),
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
            pending: PendingEvents::default(),
            lanes: BTreeSet::new(),
            control_limit_applied: false,
            channel_binding: None,
            binding_required: false,
            required_extensions: BTreeSet::new(),
            expected_granted_scope: None,
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
        self.pending.byte_limit = bytes;
        self.pending.count_limit = count;
        Ok(())
    }

    /// How far the exchange has got.
    #[must_use]
    pub const fn state(&self) -> State {
        self.negotiation.state()
    }

    /// Whether `extension` is in the negotiated set, so a frame that requires
    /// it may be sent and will be accepted. False until the peer's `HELLO`
    /// has arrived.
    #[must_use]
    pub fn extension_negotiated(&self, extension: u64) -> bool {
        self.negotiation.extension_is_negotiated(extension)
    }

    /// Requires a client-offered extension to appear in the server's answer.
    pub fn require_extension(&mut self, extension: u64) {
        self.required_extensions.insert(extension);
    }

    /// Requires the server to grant exactly `scope` before the data plane opens.
    pub fn require_granted_scope(&mut self, scope: Vec<u8>) {
        self.expected_granted_scope = Some(scope);
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
    /// Some backends work through methods the adapter contract does not cover.
    /// This is for a driver, not an application: it reaches past the readiness
    /// gate, and an application that sends through here is doing what
    /// [`send_reliable`](Self::send_reliable) exists to refuse.
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
        self.begin_inner()
    }

    fn begin_inner(&mut self) -> Result<(), Error> {
        self.check_authentication_role()?;
        self.check_local_authentication_policy()?;
        self.binding_required = matches!(
            &self.authentication,
            Authentication::Capability { challenge }
                if challenge.binding == Binding::ProofOfPossession
        );
        self.check_receive_limit()?;
        let frames = self.negotiation.begin()?;
        self.submit(frames)
    }

    fn check_local_authentication_policy(&self) -> Result<(), Error> {
        let Authentication::Capability { challenge } = &self.authentication else {
            return Ok(());
        };
        let advertises_retired = challenge
            .formats
            .contains(&RETIRED_NONCE_ONLY_CAPABILITY_FORMAT);
        let leaves_active_unbound = challenge.formats.contains(&CHANNEL_BOUND_CAPABILITY_FORMAT)
            && challenge.binding != Binding::ProofOfPossession;
        if advertises_retired || leaves_active_unbound {
            return Err(Error::new(
                ErrorKind::AuthContextInvalid,
                error_code::MALFORMED_FRAME,
            ));
        }
        Ok(())
    }

    /// Refuses a stance that means nothing for this endpoint's role.
    /// A server given a client's stance would advertise a nonce no caller
    /// chose; a client given a server's would ignore the challenge.
    fn check_authentication_role(&self) -> Result<(), Error> {
        let role = self.negotiation.role;
        let fits = match (&self.authentication, role) {
            // NotRequired is the one stance both roles can act on: a server
            // advertises no format, and a client refuses a challenge that asks
            // for one.
            (Authentication::NotRequired { .. }, _)
            | (Authentication::Capability { .. }, EndpointRole::Server)
            | (Authentication::Presenting, EndpointRole::Client) => true,
            (Authentication::Capability { .. } | Authentication::Presenting, _) => false,
        };
        if fits {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::AuthenticationRoleMismatch { role },
            error_code::MALFORMED_FRAME,
        ))
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
            self.channel_binding = None;
            self.binding_required = false;
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
            && let Some(event) = self.take_pending()?
        {
            return Ok(Some(event));
        }
        while let Some(event) = self.adapter.poll() {
            match event {
                Event::Connected(connection) => {
                    self.latch_required_channel_binding()?;
                    return Ok(Some(Event::Connected(connection)));
                }
                Event::Control(bytes) => {
                    self.check_inbound(&bytes, Lane::Control)?;
                    let accepted = self.accept_control(&bytes)?;
                    // A rejection is an application decision even when the
                    // carrier closes immediately behind it. Give the caller
                    // a turn to read `last_refusal` before lifecycle handling.
                    if self.negotiation.last_refusal().is_some() {
                        return Ok(None);
                    }
                    if let (Some(expected), Some(granted)) =
                        (&self.expected_granted_scope, self.negotiation.granted())
                        && &granted.granted_scope != expected
                    {
                        let error = Error::new(
                            ErrorKind::GrantedScopeMismatch,
                            error_code::AUTHORIZATION_FAILED,
                        );
                        return Err(self.fail(error));
                    }
                    if self.negotiation.peer_hello().is_some()
                        && let Some(extension) = self
                            .required_extensions
                            .iter()
                            .find(|extension| {
                                !self.negotiation.extension_is_negotiated(**extension)
                            })
                            .copied()
                    {
                        let _ = self.adapter.close(error_code::EXPERIMENT_NOT_NEGOTIATED);
                        self.negotiation.abandon();
                        return Err(Error::new(
                            ErrorKind::RequiredExtensionUnavailable { extension },
                            error_code::EXPERIMENT_NOT_NEGOTIATED,
                        ));
                    }
                    if let Some(event) = accepted {
                        return Ok(Some(event));
                    }
                }
                Event::Disconnected(connection) => {
                    self.channel_binding = None;
                    self.binding_required = false;
                    self.negotiation.carrier_closed()?;
                    return Ok(Some(Event::Disconnected(connection)));
                }
                record @ Event::Reliable { .. } => {
                    // No lane count here: a session never sees a stream close,
                    // so counting would reject a peer that closed one and opened
                    // another. The transport handles lane accounting.
                    if let Event::Reliable { bytes, .. } = &record {
                        self.check_inbound(bytes, Lane::Reliable)?;
                    }
                    if self.negotiation.is_ready() {
                        return Ok(Some(record));
                    }
                    self.hold(record)?;
                }
                // Unreliable, so never held: one that arrives before the
                // session is ready or without DATAGRAM_FEC negotiated is
                // dropped, as spec/fec.md section 12 has the receiver drop
                // any symbol it has no state for.
                Event::Datagram(bytes) => {
                    if self.negotiation.is_ready()
                        && self
                            .negotiation
                            .extension_is_negotiated(vot_codec::extension_id::DATAGRAM_FEC)
                    {
                        return Ok(Some(Event::Datagram(bytes)));
                    }
                }
                other => return Ok(Some(other)),
            }
            if self.negotiation.is_ready()
                && let Some(event) = self.take_pending()?
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

    /// Submits an already shared application control frame without another copy.
    ///
    /// # Errors
    /// Refuses before `Ready`, and propagates a backend refusal.
    pub fn send_control_shared(&mut self, frame: Payload) -> Result<(), Error> {
        self.require_sendable()?;
        self.check_outbound(&frame, Lane::Control)?;
        self.adapter
            .send_control_shared(frame)
            .map_err(transport_error)
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
        // stream, so counting it would spend a lane on nothing.
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

    /// Submits an unreliable datagram, the experimental symbol path.
    ///
    /// # Errors
    /// Refuses before `Ready` and propagates a backend refusal. Whether the
    /// peer negotiated the extension the datagram serves is the caller's to
    /// check with [`Self::extension_negotiated`]; the carrier drops what the
    /// peer's session will not take.
    pub fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
        self.require_sendable()?;
        self.adapter
            .send_datagram(context, payload)
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
                // Applied at Negotiated, not Authenticated: the peer's limit is
                // known as soon as its SETTINGS arrive, and the exchange itself
                // sends frames under it.
                let negotiated = self.negotiation.state().is_negotiated();
                self.submit(reply)?;
                if negotiated {
                    self.apply_peer_limits();
                }
                Ok(None)
            }
            // The caller's policy decides. Nothing is sent and nothing moves
            // until it answers through grant, refuse, or present.
            Accepted::AuthorizationRequired => {
                self.latch_required_channel_binding()?;
                Ok(None)
            }
            Accepted::PresentationRequired => {
                if self
                    .negotiation
                    .pending_presentation()
                    .is_some_and(|challenge| challenge.binding == Binding::ProofOfPossession)
                {
                    self.binding_required = true;
                    self.latch_required_channel_binding()?;
                }
                Ok(None)
            }
        }
    }

    fn latch_required_channel_binding(&mut self) -> Result<(), Error> {
        if self.binding_required && self.channel_binding.is_none() {
            match self.adapter.channel_binding() {
                Ok(binding) => self.channel_binding = Some(binding),
                Err(transport) => {
                    let error = transport_error(transport);
                    self.channel_binding = None;
                    let _ = self.adapter.close(error.close_code());
                    self.negotiation.abandon();
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// The carrier material bound to this authentication exchange, when required.
    #[must_use]
    pub const fn channel_binding(&self) -> Option<ChannelBinding> {
        self.channel_binding
    }

    /// The request awaiting the caller's policy, and the challenge it answered.
    #[must_use]
    pub const fn pending_authorization(&self) -> Option<(&AuthContext, &SessionOpen)> {
        if matches!(self.negotiation.state(), State::Closed) {
            None
        } else {
            self.negotiation.pending_authorization()
        }
    }

    /// The challenge awaiting a capability from the caller.
    #[must_use]
    pub const fn pending_presentation(&self) -> Option<&AuthContext> {
        if matches!(self.negotiation.state(), State::Closed) {
            None
        } else {
            self.negotiation.pending_presentation()
        }
    }

    /// Attempts section 1.1 still allows this session.
    #[must_use]
    pub const fn attempts_remaining(&self) -> usize {
        self.negotiation.attempts_remaining()
    }

    /// What the server authorized, once it has accepted an attempt.
    #[must_use]
    pub const fn granted(&self) -> Option<&SessionAccept> {
        self.negotiation.granted()
    }

    /// Why the last attempt was refused.
    #[must_use]
    pub const fn last_refusal(&self) -> Option<&SessionReject> {
        self.negotiation.last_refusal()
    }

    /// Presents the caller's capability and sends the request.
    ///
    /// # Errors
    /// Reports a request section 1.1 does not allow, and a backend refusal.
    pub fn present(&mut self, request: SessionOpen) -> Result<(), Error> {
        if request.capability_format == RETIRED_NONCE_ONLY_CAPABILITY_FORMAT {
            return Err(Error::new(
                ErrorKind::PresentationInvalid(PresentationError::FormatRetired {
                    format: request.capability_format,
                }),
                error_code::AUTHENTICATION_FAILED,
            ));
        }
        let reply = self.negotiation.present(request)?;
        self.submit(reply)
    }

    /// Authorizes the pending request and sends the acceptance.
    ///
    /// # Errors
    /// Reports nothing pending, an unencodable scope, or a backend refusal.
    pub fn grant(&mut self, granted_scope: Vec<u8>) -> Result<(), Error> {
        let reply = self.negotiation.grant(granted_scope)?;
        self.submit(reply)
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
        self.pending.try_hold(record)
    }

    /// Lifecycle events only. The caller still has to learn the carrier
    /// ended; nothing else on a closed session means anything.
    fn drain_lifecycle(&mut self) -> Option<Event> {
        while let Some(event) = self.adapter.poll() {
            match event {
                Event::Control(_) | Event::Reliable { .. } | Event::Datagram(_) => {}
                lifecycle => return Some(lifecycle),
            }
        }
        None
    }

    fn take_pending(&mut self) -> Result<Option<Event>, Error> {
        let Some(event) = self.pending.pop_front() else {
            return Ok(None);
        };
        if let Event::Reliable { bytes, .. } = &event {
            self.check_inbound(bytes, Lane::Reliable)?;
        }
        Ok(Some(event))
    }

    /// Whether the application may put a frame on the carrier.
    ///
    /// Readiness is not enough: a server becomes ready when it produces
    /// `SETTINGS_ACK`, not when the backend takes it, so an application frame
    /// sent while the acknowledgement is queued would overtake it.
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
            ExtensionPolicy::Negotiated(&self.negotiation),
            lane,
            Side::Peer,
            self.negotiation.role,
            self.is_ready(),
        )
    }

    /// Checks a frame the peer sent against the limits this endpoint
    /// advertised, which the adapters bound only by the protocol ceiling.
    fn check_inbound(&self, frame: &[u8], lane: Lane) -> Result<(), Error> {
        check_frame(
            frame,
            &self.negotiation.local_settings(),
            ExtensionPolicy::Negotiated(&self.negotiation),
            lane,
            Side::Local,
            self.negotiation.role,
            self.is_ready(),
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
