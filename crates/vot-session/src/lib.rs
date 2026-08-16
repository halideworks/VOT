//! The `spec/wire.md` section 1 and 1.1 negotiation and authentication
//! exchange. See `docs/session.md`.
//!
//! The state machine owns the sequence; the caller decides what a capability
//! is worth through [`Accepted::AuthorizationRequired`] (server) and
//! [`Accepted::PresentationRequired`] (client).

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use vot_codec::frames::{AuthContext, Binding, SessionAccept, SessionOpen, SessionReject};
use vot_codec::{
    DecodeError, DecodedFrame, EndpointRole, Hello, HelloError, Settings, SettingsError,
    error_code, frame_type,
};
use vot_transport_api::{Error as TransportError, Event, Payload, StreamId, TransportAdapter};

mod authentication;
mod error;
mod frame_policy;
mod negotiation;
mod pending;
mod session;

pub use authentication::*;
pub use error::*;
pub use frame_policy::*;
pub use negotiation::*;
pub use pending::*;
pub use session::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
        channel_binding: Option<vot_transport_api::ChannelBinding>,
        channel_binding_error: Option<TransportError>,
        channel_binding_queries: Cell<usize>,
    }

    impl TransportAdapter for Loopback {
        fn channel_binding(&self) -> Result<vot_transport_api::ChannelBinding, TransportError> {
            self.channel_binding_queries
                .set(self.channel_binding_queries.get() + 1);
            if let Some(error) = self.channel_binding_error {
                return Err(error);
            }
            self.channel_binding.ok_or(TransportError::Unsupported)
        }

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

        let answer = server.adapter.sent.clone();
        assert_eq!(answer.len(), 4);
        let types: Vec<u64> = answer
            .iter()
            .map(|frame| vot_codec::decode_one(frame, limits).unwrap().0.frame_type())
            .collect();
        assert_eq!(
            types,
            vec![
                frame_type::HELLO,
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
        challenge_frame(nonce, Binding::None, formats)
    }

    /// The same, for a challenge whose binding is what is under test.
    fn auth_context_of(binding: Binding, formats: Vec<u64>) -> Vec<u8> {
        challenge_frame(&[3; 32], binding, formats)
    }

    fn challenge_frame(nonce: &[u8], binding: Binding, formats: Vec<u64>) -> Vec<u8> {
        let context = vot_codec::frames::AuthContext {
            nonce: nonce.to_vec(),
            binding,
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
        let (client, server, answer) = negotiated_pair();
        assert_eq!(server.state(), State::Authenticated);
        assert_eq!(client.state(), State::Authenticated);
        assert!(server.is_ready() && client.is_ready());

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
            formats: vec![3, 4],
        }
    }

    fn proof_demanding(nonce: [u8; 32]) -> AuthContext {
        AuthContext {
            nonce: nonce.to_vec(),
            binding: Binding::ProofOfPossession,
            formats: vec![2],
        }
    }

    #[test]
    fn a_server_cannot_advertise_retired_or_unbound_active_authentication() {
        for challenge in [
            AuthContext {
                nonce: vec![3; 32],
                binding: Binding::None,
                formats: vec![1],
            },
            AuthContext {
                nonce: vec![3; 32],
                binding: Binding::None,
                formats: vec![2],
            },
        ] {
            let mut server = Session::server(
                Loopback::default(),
                Settings::default(),
                BTreeSet::new(),
                Authentication::Capability { challenge },
            );
            let error = server.begin().unwrap_err();
            assert_eq!(error.kind(), &ErrorKind::AuthContextInvalid);
            assert_eq!(server.adapter().channel_binding_queries.get(), 0);
            assert!(server.adapter().sent.is_empty());
        }
    }

    #[test]
    fn a_bound_server_latches_only_after_the_carrier_connects() {
        let binding = vot_transport_api::ChannelBinding::from_bytes([0x27; 32]);
        let adapter = Loopback {
            channel_binding: Some(binding),
            ..Loopback::default()
        };
        let mut server = Session::server(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: proof_demanding([3; 32]),
            },
        );

        server.begin().unwrap();
        assert_eq!(server.adapter().channel_binding_queries.get(), 0);
        assert_eq!(server.channel_binding(), None);

        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));
        assert_eq!(
            server.poll().unwrap(),
            Some(Event::Connected(vot_transport_api::ConnectionId(7)))
        );
        assert_eq!(server.channel_binding(), Some(binding));
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);

        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));
        assert!(server.poll().unwrap().is_some());
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);
    }

    #[test]
    fn beginning_twice_after_binding_does_not_erase_it() {
        let binding = vot_transport_api::ChannelBinding::from_bytes([0x27; 32]);
        let adapter = Loopback {
            channel_binding: Some(binding),
            ..Loopback::default()
        };
        let mut server = Session::server(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: proof_demanding([3; 32]),
            },
        );
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));
        assert!(server.poll().unwrap().is_some());
        assert_eq!(server.channel_binding(), Some(binding));

        assert!(server.begin().is_err());
        assert_eq!(server.channel_binding(), Some(binding));
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);
    }

    #[test]
    fn a_backend_begin_failure_keeps_the_handshake_for_retry() {
        let mut client = Session::client(
            Loopback {
                refuse_control: Some(TransportError::Backend),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [3; 32] },
        );

        let error = client.begin().unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::Transport(TransportError::Backend));
        assert_eq!(client.unsent_negotiation_frames(), 2);
        assert!(client.adapter().sent.is_empty());

        client.adapter.refuse_control = None;
        client.flush().unwrap();
        assert_eq!(client.unsent_negotiation_frames(), 0);
        assert_eq!(client.adapter().sent.len(), 2);
        assert_eq!(client.state(), State::HelloSent);
    }

    #[test]
    fn a_bound_server_fails_closed_when_connected_without_binding() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: proof_demanding([3; 32]),
            },
        );
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));

        let error = server.poll().unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::Transport(TransportError::Unsupported)
        );
        assert_eq!(server.channel_binding(), None);
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);
        assert_eq!(server.state(), State::Closed);
        assert_eq!(server.pending_authorization(), None);
        assert!(server.grant(Vec::new()).is_err());
        assert_eq!(server.poll().unwrap(), None);
        assert_eq!(server.adapter().closed, vec![error.close_code()]);
    }

    #[test]
    fn backend_binding_failure_cannot_be_resumed_by_a_server() {
        let adapter = Loopback {
            channel_binding_error: Some(TransportError::Backend),
            ..Loopback::default()
        };
        let mut server = Session::server(
            adapter,
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: proof_demanding([3; 32]),
            },
        );
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));

        let error = server.poll().unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::Transport(TransportError::Backend));
        assert_eq!(server.state(), State::Closed);
        assert_eq!(server.pending_authorization(), None);
        assert!(server.grant(Vec::new()).is_err());
        assert_eq!(server.poll().unwrap(), None);
    }

    #[test]
    fn presenting_client_binding_failures_are_terminal() {
        for transport_error in [TransportError::Unsupported, TransportError::Backend] {
            let client_adapter = Loopback {
                channel_binding_error: Some(transport_error),
                ..Loopback::default()
            };
            let server_adapter = Loopback {
                channel_binding: Some(vot_transport_api::ChannelBinding::from_bytes([0x27; 32])),
                ..Loopback::default()
            };
            let mut client = Session::client(
                client_adapter,
                Settings::default(),
                BTreeSet::new(),
                Authentication::Presenting,
            );
            let mut server = Session::server(
                server_adapter,
                Settings::default(),
                BTreeSet::new(),
                Authentication::Capability {
                    challenge: proof_demanding([3; 32]),
                },
            );
            client.begin().unwrap();
            server.begin().unwrap();
            pump(&mut client, &mut server);
            for frame in std::mem::take(&mut server.adapter.sent) {
                client.adapter.events.push_back(control(&frame));
            }

            let error = client.poll().unwrap_err();
            assert_eq!(error.kind(), &ErrorKind::Transport(transport_error));
            assert_eq!(client.state(), State::Closed);
            assert_eq!(client.pending_presentation(), None);
            let mut open = request([7; 16], 4);
            open.binding_proof = vec![4; 64];
            assert!(client.present(open).is_err());
            assert_eq!(client.poll().unwrap(), None);
            assert_eq!(client.adapter().closed, vec![error.close_code()]);
        }
    }

    #[test]
    fn an_open_session_does_not_query_binding_when_connected() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [3; 32] },
        );
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));

        assert!(server.poll().unwrap().is_some());
        assert_eq!(server.adapter().channel_binding_queries.get(), 0);
        assert_eq!(server.channel_binding(), None);
    }

    #[test]
    fn a_recoverable_send_failure_preserves_the_latched_binding() {
        let binding = vot_transport_api::ChannelBinding::from_bytes([0x27; 32]);
        let mut client = Session::client(
            Loopback {
                channel_binding: Some(binding),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::Presenting,
        );
        let mut server = Session::server(
            Loopback {
                channel_binding: Some(binding),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: proof_demanding([3; 32]),
            },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        server
            .adapter
            .events
            .push_back(Event::Connected(vot_transport_api::ConnectionId(7)));
        assert!(server.poll().unwrap().is_some());
        assert_eq!(server.channel_binding(), Some(binding));

        for frame in std::mem::take(&mut client.adapter.sent) {
            server.adapter.events.push_back(control(&frame));
        }
        server.adapter.refuse_control = Some(TransportError::Backend);
        let error = server.poll().unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::Transport(TransportError::Backend));
        assert_eq!(server.channel_binding(), Some(binding));
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);

        server.adapter.refuse_control = None;
        assert_eq!(server.poll().unwrap(), None);
        for frame in std::mem::take(&mut server.adapter.sent) {
            client.adapter.events.push_back(control(&frame));
        }
        assert_eq!(client.poll().unwrap(), None);
        assert_eq!(client.channel_binding(), Some(binding));

        let mut open = request([7; 16], 2);
        open.binding_proof = vec![4; 64];
        client.present(open).unwrap();
        pump(&mut client, &mut server);
        assert!(server.pending_authorization().is_some());
        assert_eq!(server.channel_binding(), Some(binding));
        assert_eq!(server.adapter().channel_binding_queries.get(), 1);
    }

    #[test]
    fn a_presenting_client_refuses_a_retired_format_even_when_offered() {
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Presenting,
        );
        client.negotiation.state = State::Negotiated;
        client
            .adapter
            .events
            .push_back(control(&auth_context_of(Binding::None, vec![1])));
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.pending_presentation().is_some());

        let error = client.present(request([7; 16], 1)).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::PresentationInvalid(PresentationError::FormatRetired { format: 1 })
        );
        assert!(client.adapter().sent.is_empty());
        assert_eq!(client.attempts_remaining(), MAX_AUTHENTICATION_ATTEMPTS);
    }

    /// A request a client presents, and a server reads.
    fn request(session_id: [u8; 16], capability_format: u64) -> SessionOpen {
        SessionOpen {
            session_id,
            capability_format,
            capability: vec![9; 32],
            requested_scope: Vec::new(),
            binding_proof: Vec::new(),
        }
    }

    /// A `SESSION_OPEN` frame.
    fn session_open(session_id: [u8; 16], capability_format: u64) -> Vec<u8> {
        let mut frame = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::SessionOpen(request(session_id, capability_format)),
            &mut frame,
        )
        .unwrap();
        frame
    }

    /// One of the server's answers, as a frame.
    fn answer_frame(frame: &vot_codec::frames::TypedFrame) -> Vec<u8> {
        let mut encoded = Vec::new();
        vot_codec::frames::encode(frame, &mut encoded).unwrap();
        encoded
    }

    /// Hands everything one endpoint submitted to the other, and polls it.
    fn pump(from: &mut Session<Loopback>, to: &mut Session<Loopback>) {
        for frame in std::mem::take(&mut from.adapter.sent) {
            to.adapter.events.push_back(control(&frame));
        }
        assert_eq!(to.poll().unwrap(), None);
    }

    /// A pair whose server asks for a capability, driven to the point where the
    /// client has read the challenge and presented nothing.
    fn demanding_pair(
        client_settings: Settings,
        server_settings: Settings,
    ) -> (Session<Loopback>, Session<Loopback>) {
        let mut client = Session::client(
            Loopback::default(),
            client_settings,
            BTreeSet::new(),
            Authentication::Presenting,
        );
        let mut server = Session::server(
            Loopback::default(),
            server_settings,
            BTreeSet::new(),
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        );
        client.begin().unwrap();
        server.begin().unwrap();
        pump(&mut client, &mut server);
        pump(&mut server, &mut client);
        assert_eq!(client.state(), State::Negotiated);
        assert!(!client.is_ready() && !server.is_ready());
        (client, server)
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
        let mut server = demanding_server();
        assert_eq!(server.pending_authorization(), None);
        assert_eq!(
            server.accept_control(&session_open([7; 16], 4)).unwrap(),
            Accepted::AuthorizationRequired
        );
        let (challenge, open) = server
            .pending_authorization()
            .expect("a request is pending");
        assert_eq!(challenge.nonce, vec![3; 32], "the challenge it answered");
        assert_eq!(open.session_id, [7; 16]);
        assert_eq!(open.capability_format, 4);
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
        let mut server = demanding_server();
        let limits = vot_codec::DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 1,
        };
        for attempt in 0..MAX_AUTHENTICATION_ATTEMPTS {
            let id = [u8::try_from(attempt).unwrap(); 16];
            assert_eq!(
                server.accept_control(&session_open(id, 3)).unwrap(),
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
            .accept_control(&session_open([9; 16], 3))
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
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        );
        let mut client = Session::client(
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
        assert_eq!(
            server.state(),
            State::Negotiated,
            "a challenge asking for a capability does not conclude the exchange"
        );
        assert!(
            server.control_limit_applied(),
            "the peer's limit is known once its SETTINGS arrive"
        );
        assert!(!server.is_ready(), "and the data plane stays shut");
        assert_eq!(
            server
                .send_reliable(StreamId(1), &data_record(b"early"))
                .unwrap_err()
                .close_code(),
            error_code::MALFORMED_FRAME
        );
        std::mem::take(&mut server.adapter.sent);

        server
            .adapter
            .events
            .push_back(control(&session_open([7; 16], 3)));
        assert_eq!(server.poll().unwrap(), None);
        assert!(!server.is_ready(), "a request is not a grant");
        assert!(
            server.adapter().sent.is_empty(),
            "nothing goes out until the caller answers"
        );
        let (challenge, open) = server.pending_authorization().expect("pending");
        assert_eq!(challenge.formats, vec![3, 4]);
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
            .push_back(control(&session_open([8; 16], 3)));
        assert_eq!(server.poll().unwrap(), None);
        server.grant(b"scope".to_vec()).unwrap();
        assert!(server.is_ready(), "the exchange concluded");
        assert_eq!(server.adapter().sent.len(), 2);

        assert!(server.grant(Vec::new()).is_err());
        assert!(
            server
                .refuse(error_code::AUTHENTICATION_FAILED, String::new())
                .is_err()
        );
    }

    #[test]
    fn a_challenge_is_answered_with_the_capability_the_caller_presents() {
        let (mut client, mut server) = demanding_pair(Settings::default(), Settings::default());
        let challenge = client
            .pending_presentation()
            .expect("the client was asked for a capability");
        assert_eq!(
            challenge.nonce,
            vec![3; 32],
            "the nonce a proof of possession would be over"
        );
        assert_eq!(challenge.formats, vec![3, 4]);
        assert_eq!(client.attempts_remaining(), MAX_AUTHENTICATION_ATTEMPTS);
        assert!(client.granted().is_none() && client.last_refusal().is_none());

        client.present(request([7; 16], 4)).unwrap();
        assert_eq!(client.attempts_remaining(), MAX_AUTHENTICATION_ATTEMPTS - 1);
        assert_eq!(
            client.pending_presentation(),
            None,
            "the answer to this attempt decides whether another is needed"
        );
        assert!(!client.is_ready(), "a request is not a conclusion");

        pump(&mut client, &mut server);
        let (_, open) = server.pending_authorization().expect("the request arrived");
        assert_eq!(open.session_id, [7; 16]);
        assert_eq!(open.capability_format, 4);
        server.grant(b"read:objects".to_vec()).unwrap();
        assert!(server.is_ready());

        pump(&mut server, &mut client);
        assert_eq!(client.state(), State::Authenticated);
        assert!(client.is_ready(), "the client read the concluding frame");
        assert_eq!(
            client.granted().map(|accept| accept.granted_scope.clone()),
            Some(b"read:objects".to_vec()),
            "the scope the server authorized, which the caller has no other way to learn"
        );
        assert!(client.last_refusal().is_none());
        client
            .send_reliable(StreamId(1), &data_record(b"payload"))
            .unwrap();
    }

    #[test]
    fn a_refused_attempt_is_followed_by_another_until_the_bound_is_reached() {
        let (mut client, mut server) = demanding_pair(Settings::default(), Settings::default());
        for attempt in 0..MAX_AUTHENTICATION_ATTEMPTS {
            let id = [u8::try_from(attempt).unwrap(); 16];
            assert!(
                client.pending_presentation().is_some(),
                "attempt {attempt} may be made"
            );
            client.present(request(id, 3)).unwrap();
            pump(&mut client, &mut server);
            server
                .refuse(error_code::AUTHORIZATION_FAILED, "not enough".to_owned())
                .unwrap();
            pump(&mut server, &mut client);

            assert_eq!(client.state(), State::Negotiated, "and not closed");
            let refusal = client.last_refusal().expect("the refusal is reported");
            assert_eq!(refusal.session_id, id);
            assert_eq!(refusal.reason, u64::from(error_code::AUTHORIZATION_FAILED));
            assert_eq!(refusal.detail, "not enough");
            assert!(client.granted().is_none());
            assert_eq!(
                client.attempts_remaining(),
                MAX_AUTHENTICATION_ATTEMPTS - attempt - 1
            );
        }

        assert_eq!(client.attempts_remaining(), 0);
        let error = client.present(request([9; 16], 3)).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::PresentationInvalid(PresentationError::AttemptsSpent {
                attempts: MAX_AUTHENTICATION_ATTEMPTS
            })
        );
        assert!(
            !error.kind().is_peer_fault(),
            "the caller's, not the peer's"
        );
        assert!(client.adapter().sent.is_empty(), "and nothing went out");
        assert_eq!(client.state(), State::Negotiated);
    }

    #[test]
    fn a_request_section_1_1_forbids_never_reaches_the_carrier() {
        let mut plain = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        plain.begin().unwrap();
        assert_eq!(
            plain.present(request([7; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::NothingToAnswer {
                state: State::HelloSent
            }),
            "a client that presents nothing has nothing to present"
        );

        let (mut client, _) = demanding_pair(Settings::default(), Settings::default());
        let format = client
            .present(request([7; 16], 9))
            .unwrap_err()
            .kind()
            .clone();
        assert_eq!(
            format,
            ErrorKind::PresentationInvalid(PresentationError::FormatNotOffered { format: 9 })
        );
        assert_eq!(
            client.attempts_remaining(),
            MAX_AUTHENTICATION_ATTEMPTS,
            "a refused request spends no attempt"
        );
        assert!(client.adapter().sent.is_empty());

        let mut signed = request([7; 16], 3);
        signed.binding_proof = vec![4; 8];
        assert_eq!(
            client.present(signed).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::BindingProof {
                binding: Binding::None,
                proof_bytes: 8
            })
        );

        client.present(request([7; 16], 3)).unwrap();
        assert_eq!(
            client.present(request([8; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::NothingToAnswer {
                state: State::Negotiated
            }),
            "one attempt at a time"
        );
        client
            .negotiation
            .accept_control(&answer_frame(
                &vot_codec::frames::TypedFrame::SessionReject(SessionReject {
                    session_id: [7; 16],
                    reason: u64::from(error_code::AUTHENTICATION_FAILED),
                    detail: String::new(),
                }),
            ))
            .unwrap();
        assert_eq!(
            client.present(request([7; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::IdentifierReused)
        );
    }

    #[test]
    fn the_binding_proof_rule_holds_in_both_directions() {
        let mut server = Negotiation::server(
            Settings::default(),
            BTreeSet::new(),
            AuthContext {
                nonce: vec![3; 32],
                binding: Binding::ProofOfPossession,
                formats: vec![3],
            },
        );
        server.state = State::Negotiated;
        let error = server
            .accept_control(&session_open([7; 16], 3))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::BindingProofMismatch {
                binding: Binding::ProofOfPossession,
                proof_bytes: 0
            }
        );
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);
        assert!(error.kind().is_peer_fault(), "the peer built the request");
        assert_eq!(
            server.pending_authorization(),
            None,
            "and no policy is asked to weigh it"
        );

        let mut none = demanding_server();
        let mut open = request([7; 16], 3);
        open.binding_proof = vec![4; 8];
        let mut frame = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::SessionOpen(open),
            &mut frame,
        )
        .unwrap();
        assert_eq!(
            none.accept_control(&frame).unwrap_err().kind(),
            &ErrorKind::BindingProofMismatch {
                binding: Binding::None,
                proof_bytes: 8
            }
        );

        let mut client = Negotiation::presenting_client(Settings::default(), BTreeSet::new());
        client.state = State::Negotiated;
        client
            .accept_control(&auth_context_of(Binding::ProofOfPossession, vec![3]))
            .unwrap();
        assert_eq!(
            client.present(request([7; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::BindingProof {
                binding: Binding::ProofOfPossession,
                proof_bytes: 0
            })
        );
        let mut proved = request([7; 16], 3);
        proved.binding_proof = vec![4; 64];
        client.present(proved).unwrap();
    }

    #[test]
    fn an_answer_naming_another_attempt_is_refused() {
        let (mut client, _) = demanding_pair(Settings::default(), Settings::default());
        client.present(request([7; 16], 3)).unwrap();
        let mut mismatched = client.negotiation.clone();
        let error = mismatched
            .accept_control(&answer_frame(
                &vot_codec::frames::TypedFrame::SessionAccept(SessionAccept {
                    session_id: [8; 16],
                    granted_scope: Vec::new(),
                }),
            ))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::SessionIdentifierMismatch);
        assert_eq!(error.close_code(), error_code::AUTHENTICATION_FAILED);
        assert!(error.kind().is_peer_fault());
        assert!(!mismatched.is_ready(), "and the data plane stays shut");

        let mut rejected = client.negotiation.clone();
        assert!(
            rejected
                .accept_control(&answer_frame(
                    &vot_codec::frames::TypedFrame::SessionReject(SessionReject {
                        session_id: [8; 16],
                        reason: u64::from(error_code::AUTHENTICATION_FAILED),
                        detail: String::new(),
                    },)
                ))
                .is_err()
        );
        assert!(
            rejected.pending_presentation().is_none(),
            "the attempt this client is waiting on was not cleared"
        );
        assert!(
            rejected.last_refusal().is_none(),
            "and nothing was recorded as its answer"
        );

        let mut unasked = demanding_server();
        assert_eq!(
            unasked
                .accept_control(&answer_frame(
                    &vot_codec::frames::TypedFrame::SessionAccept(SessionAccept {
                        session_id: [7; 16],
                        granted_scope: Vec::new(),
                    },)
                ))
                .unwrap_err()
                .kind(),
            &ErrorKind::OutOfSequence {
                frame_type: frame_type::SESSION_ACCEPT,
                state: State::Negotiated
            }
        );

        let mut holding = demanding_server();
        holding.accept_control(&session_open([7; 16], 3)).unwrap();
        for reply in [
            vot_codec::frames::TypedFrame::SessionAccept(SessionAccept {
                session_id: [7; 16],
                granted_scope: Vec::new(),
            }),
            vot_codec::frames::TypedFrame::SessionReject(SessionReject {
                session_id: [7; 16],
                reason: u64::from(error_code::AUTHENTICATION_FAILED),
                detail: String::new(),
            }),
        ] {
            let error = holding.accept_control(&answer_frame(&reply)).unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::OutOfSequence {
                    frame_type: reply.frame_type(),
                    state: State::Negotiated
                }
            );
        }
        assert!(!holding.is_ready(), "and it did not authenticate itself");
        assert!(
            holding.pending_authorization().is_some(),
            "the request it holds is still its own to answer"
        );

        let mut malformed = client.negotiation.clone();
        let error = malformed
            .accept_control(&frame_of(frame_type::SESSION_ACCEPT, 3))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::SessionAnswerInvalid {
                frame_type: frame_type::SESSION_ACCEPT
            }
        );
        assert!(error.kind().is_peer_fault());
    }

    #[test]
    fn a_client_that_can_present_asks_for_nothing_until_it_is_asked() {
        let mut client = Negotiation::presenting_client(Settings::default(), BTreeSet::new());
        client.begin().unwrap();
        client
            .accept_control(&server_hello_of(BTreeSet::new()))
            .unwrap();
        client
            .accept_control(&settings_of(Settings::default()))
            .unwrap();
        client
            .accept_control(&frame_of(frame_type::SETTINGS_ACK, 0))
            .unwrap();
        assert_eq!(client.state(), State::Negotiated);
        assert_eq!(
            client.pending_presentation(),
            None,
            "negotiated is not the same as asked"
        );

        assert_eq!(
            client.accept_control(&auth_context(&[7; 16], Vec::new())),
            Ok(Accepted::Consumed { reply: Vec::new() })
        );
        assert_eq!(
            client.state(),
            State::Authenticated,
            "a challenge advertising no format concludes the exchange"
        );
        assert_eq!(client.pending_presentation(), None);
        assert_eq!(
            client.present(request([7; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::NothingToAnswer {
                state: State::Authenticated
            }),
            "and there is nothing to present to a server that asked for nothing"
        );
    }

    #[test]
    fn a_second_challenge_cannot_replace_the_one_an_attempt_answers() {
        let (mut client, _) = demanding_pair(Settings::default(), Settings::default());
        let error = client
            .negotiation
            .accept_control(&auth_context_of(Binding::None, vec![4]))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::OutOfSequence {
                frame_type: frame_type::AUTH_CONTEXT,
                state: State::Negotiated
            }
        );
        assert_eq!(
            client
                .pending_presentation()
                .map(|challenge| challenge.formats.clone()),
            Some(vec![3, 4]),
            "the challenge it was asked with"
        );
    }

    #[test]
    fn a_frame_the_peer_will_not_carry_is_refused_before_it_is_sent() {
        let narrow = Settings {
            max_control_frame_payload: 1024,
            ..Settings::default()
        };
        let (mut client, mut server) = demanding_pair(Settings::default(), narrow);
        let mut large = request([7; 16], 3);
        large.capability = vec![9; 4096];
        let error = client.present(large).unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::FrameExceedsLimit {
                frame_type: frame_type::SESSION_OPEN,
                bytes: 4127,
                limit: 1024,
                side: Side::Peer
            }
        );
        assert!(
            !error.kind().is_peer_fault(),
            "the peer's limit, so this endpoint would be the one breaking it"
        );
        assert_eq!(client.attempts_remaining(), MAX_AUTHENTICATION_ATTEMPTS);
        assert!(client.adapter().sent.is_empty());

        client.present(request([7; 16], 3)).unwrap();
        pump(&mut client, &mut server);
        let mut narrow_client = server.negotiation.clone();
        narrow_client.peer_settings = Some(Settings {
            max_control_frame_payload: 1024,
            ..Settings::default()
        });
        assert_eq!(
            narrow_client
                .grant(vec![0; 2048])
                .unwrap_err()
                .kind()
                .clone(),
            ErrorKind::FrameExceedsLimit {
                frame_type: frame_type::SESSION_ACCEPT,
                bytes: 2073,
                limit: 1024,
                side: Side::Peer
            }
        );
        assert!(
            narrow_client.pending_authorization().is_some(),
            "an answer that cannot go out leaves the request to answer again"
        );
        assert!(!narrow_client.is_ready());
    }

    #[test]
    fn a_stance_the_role_cannot_act_on_is_refused() {
        let mut server = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Presenting,
        );
        let error = server.begin().unwrap_err();
        assert_eq!(
            error.kind(),
            &ErrorKind::AuthenticationRoleMismatch {
                role: EndpointRole::Server
            }
        );
        assert!(!error.kind().is_peer_fault(), "the caller's own doing");
        assert_eq!(server.state(), State::Connecting, "and nothing began");

        let mut accepting = demanding_server();
        assert_eq!(accepting.pending_presentation(), None);
        assert_eq!(
            accepting.present(request([7; 16], 3)).unwrap_err().kind(),
            &ErrorKind::PresentationInvalid(PresentationError::NothingToAnswer {
                state: State::Negotiated
            })
        );

        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        );
        assert_eq!(
            client.begin().unwrap_err().kind(),
            &ErrorKind::AuthenticationRoleMismatch {
                role: EndpointRole::Client
            }
        );

        for authentication in [
            Authentication::NotRequired { nonce: [1; 32] },
            Authentication::Presenting,
        ] {
            Session::client(
                Loopback::default(),
                Settings::default(),
                BTreeSet::new(),
                authentication,
            )
            .begin()
            .unwrap();
        }
        for authentication in [
            Authentication::NotRequired { nonce: [1; 32] },
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        ] {
            Session::server(
                Loopback::default(),
                Settings::default(),
                BTreeSet::new(),
                authentication,
            )
            .begin()
            .unwrap();
        }
    }

    #[test]
    fn a_grant_the_backend_has_no_room_for_does_not_open_the_data_plane() {
        let mut server = Session::server(
            Loopback {
                control_capacity: Some(0),
                ..Loopback::default()
            },
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: demanding([3; 32]),
            },
        );
        server.begin().unwrap();
        server.negotiation.state = State::Negotiated;
        server
            .adapter
            .events
            .push_back(control(&session_open([7; 16], 3)));
        assert_eq!(server.poll().unwrap(), None);
        server.grant(b"scope".to_vec()).unwrap();

        assert!(server.is_ready(), "the exchange concluded on this side");
        assert!(server.adapter().sent.is_empty(), "and nothing went out");
        let remaining = server.unsent_negotiation_frames();
        assert!(remaining > 0);
        assert_eq!(
            server
                .send_reliable(StreamId(1), &data_record(b"record"))
                .unwrap_err()
                .kind(),
            &ErrorKind::HandshakeUnsent { remaining }
        );

        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.unsent_negotiation_frames(), 0);
        server
            .send_reliable(StreamId(1), &data_record(b"record"))
            .unwrap();
    }

    #[test]
    fn an_empty_format_list_means_the_same_thing_whichever_variant_names_it() {
        let mut named = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::Capability {
                challenge: no_capability([9; 32]),
            },
        );
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        named.begin().unwrap();
        for frame in std::mem::take(&mut client.adapter.sent) {
            named.adapter.events.push_back(control(&frame));
        }
        assert_eq!(named.poll().unwrap(), None);
        assert!(named.is_ready(), "the exchange concluded at the challenge");
        assert_eq!(named.pending_authorization(), None);
    }

    #[test]
    fn a_request_this_endpoint_never_invited_is_refused() {
        let mut reused = demanding_server();
        reused.accept_control(&session_open([7; 16], 3)).unwrap();
        reused
            .refuse(error_code::AUTHENTICATION_FAILED, String::new())
            .unwrap();
        let error = reused
            .accept_control(&session_open([7; 16], 3))
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

        let mut oversized = demanding_server();
        let mut envelope = Vec::new();
        vot_codec::encode_varint(frame_type::SESSION_OPEN, &mut envelope).unwrap();
        vot_codec::encode_varint(64 * 1024 + 1, &mut envelope).unwrap();
        let error = oversized.accept_control(&envelope).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Decode(DecodeError::FrameTooLarge { .. })
            ),
            "{:?}",
            error.kind()
        );

        let mut open_to_nobody =
            Negotiation::server(Settings::default(), BTreeSet::new(), no_capability([1; 32]));
        open_to_nobody.state = State::Negotiated;
        assert!(
            open_to_nobody
                .accept_control(&session_open([7; 16], 3))
                .is_err()
        );

        let mut busy = demanding_server();
        busy.accept_control(&session_open([7; 16], 3)).unwrap();
        assert!(busy.accept_control(&session_open([8; 16], 3)).is_err());

        let mut client = Negotiation::client(Settings::default(), BTreeSet::new());
        client.state = State::Negotiated;
        assert!(client.accept_control(&session_open([7; 16], 3)).is_err());

        let mut early = demanding_server();
        early.state = State::HelloSent;
        assert!(early.accept_control(&session_open([7; 16], 3)).is_err());
        let mut done = demanding_server();
        done.state = State::Authenticated;
        assert!(done.accept_control(&session_open([7; 16], 3)).is_err());
    }

    #[test]
    fn an_answer_with_nothing_pending_is_refused() {
        let mut server = demanding_server();
        assert!(server.grant(Vec::new()).is_err());
        assert!(
            server
                .refuse(error_code::AUTHENTICATION_FAILED, String::new())
                .is_err()
        );
        assert_eq!(server.state(), State::Negotiated);

        server.accept_control(&session_open([7; 16], 3)).unwrap();
        let error = server
            .refuse(error_code::MALFORMED_FRAME, String::new())
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::SessionAnswerUnencodable);
        assert!(
            !error.kind().is_peer_fault(),
            "the caller's answer, not the peer's request"
        );
        assert!(server.pending_authorization().is_some());
        let scope = vec![0; 4097];
        assert_eq!(
            server.grant(scope).unwrap_err().kind(),
            &ErrorKind::SessionAnswerUnencodable
        );
        assert!(server.pending_authorization().is_some());
        assert_eq!(server.state(), State::Negotiated, "and not authenticated");
        server
            .refuse(error_code::AUTHORIZATION_FAILED, String::new())
            .unwrap();
        assert_eq!(server.pending_authorization(), None);
    }

    #[test]
    fn a_challenge_asking_for_a_capability_is_refused() {
        let mut client = Negotiation::client(Settings::default(), BTreeSet::new());
        client.state = State::Negotiated;
        let error = client
            .accept_control(&auth_context(&[7; 16], vec![3, 4]))
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

        let mut early = Negotiation::client(Settings::default(), BTreeSet::new());
        early.state = State::HelloSent;
        assert!(
            early
                .accept_control(&auth_context(&[7; 16], Vec::new()))
                .is_err()
        );

        let mut done = Negotiation::client(Settings::default(), BTreeSet::new());
        done.state = State::Negotiated;
        done.accept_control(&auth_context(&[7; 16], Vec::new()))
            .unwrap();
        assert_eq!(done.state(), State::Authenticated);
        assert!(
            done.accept_control(&auth_context(&[7; 16], Vec::new()))
                .is_err()
        );

        let mut malformed = Negotiation::client(Settings::default(), BTreeSet::new());
        malformed.state = State::Negotiated;
        let error = malformed
            .accept_control(&frame_of(frame_type::AUTH_CONTEXT, 3))
            .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::AuthContextInvalid);
        assert_eq!(error.close_code(), error_code::MALFORMED_FRAME);
    }

    #[test]
    fn an_answer_to_a_request_this_endpoint_never_made_is_refused() {
        for frame in [
            vot_codec::frames::TypedFrame::SessionAccept(SessionAccept {
                session_id: [7; 16],
                granted_scope: Vec::new(),
            }),
            vot_codec::frames::TypedFrame::SessionReject(SessionReject {
                session_id: [7; 16],
                reason: u64::from(error_code::AUTHENTICATION_FAILED),
                detail: String::new(),
            }),
        ] {
            let mut encoded = Vec::new();
            vot_codec::frames::encode(&frame, &mut encoded).unwrap();
            for state in [State::Negotiated, State::Authenticated] {
                let mut client = Negotiation::client(Settings::default(), BTreeSet::new());
                client.state = state;
                let error = client.accept_control(&encoded).unwrap_err();
                assert_eq!(
                    error.kind(),
                    &ErrorKind::OutOfSequence {
                        frame_type: frame.frame_type(),
                        state
                    }
                );
            }
        }
    }

    #[test]
    fn the_application_may_not_send_the_exchange_itself() {
        let (mut client, _server, _answer) = negotiated_pair();
        let mut accept = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::SessionAccept(SessionAccept {
                session_id: [7; 16],
                granted_scope: Vec::new(),
            }),
            &mut accept,
        )
        .unwrap();
        let mut reject = Vec::new();
        vot_codec::frames::encode(
            &vot_codec::frames::TypedFrame::SessionReject(SessionReject {
                session_id: [7; 16],
                reason: u64::from(error_code::AUTHENTICATION_FAILED),
                detail: String::new(),
            }),
            &mut reject,
        )
        .unwrap();
        for frame in [
            auth_context(&[7; 16], Vec::new()),
            session_open([7; 16], 3),
            accept,
            reject,
            frame_of(frame_type::HELLO, 0),
        ] {
            let error = client.send_control(&frame).unwrap_err();
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::NegotiationFrameFromApplication { .. }
                ),
                "{:?}",
                error.kind()
            );
        }

        client.send_control(&frame_of(frame_type::PING, 0)).unwrap();
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
        server.adapter.events.push_back(control(&sent[0]));
        server.adapter.events.push_back(record(7, b"early"));
        server.adapter.events.push_back(control(&sent[1]));
        server.adapter.events.push_back(record(8, b"also early"));

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

        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        // The server-role HELLO is what a client expects; a client-role one
        // there is the wrong role.
        let mut client_role = Vec::new();
        vot_codec::encode_hello(
            &Hello {
                endpoint_role: EndpointRole::Client,
                ..wrong_role
            },
            &mut client_role,
        )
        .unwrap();
        let mut misdirected = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &client_role, &mut misdirected).unwrap();
        client.adapter.events.push_back(control(&misdirected));
        assert!(
            matches!(
                client.poll().unwrap_err().kind(),
                ErrorKind::Hello(HelloError::RoleMismatch { .. })
            ),
            "a client-role HELLO at a client is the wrong role"
        );
        // And the server's SETTINGS before its HELLO is out of order.
        let mut unanswered = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        unanswered.begin().unwrap();
        unanswered
            .adapter
            .events
            .push_back(control(&settings_of(Settings::default())));
        assert!(matches!(
            unanswered.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence {
                frame_type: frame_type::SETTINGS,
                ..
            }
        ));
        // Once per direction: a second server HELLO at a client is refused.
        let mut answered = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        answered.begin().unwrap();
        answered
            .adapter
            .events
            .push_back(control(&server_hello_of(BTreeSet::new())));
        assert_eq!(answered.poll().unwrap(), None);
        answered
            .adapter
            .events
            .push_back(control(&server_hello_of(BTreeSet::new())));
        assert!(matches!(
            answered.poll().unwrap_err().kind(),
            ErrorKind::OutOfSequence {
                frame_type: frame_type::HELLO,
                ..
            }
        ));

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

        let (mut client, _server) = negotiated();
        client.adapter.events.push_back(control(&frame));
        assert_eq!(client.poll().unwrap(), Some(control(&frame)));
    }

    #[test]
    fn an_unknown_optional_frame_does_not_end_the_exchange() {
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

        let mut ack = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS_ACK, &[], &mut ack).unwrap();
        client.adapter.events.push_back(control(&ack));
        assert_eq!(client.poll().unwrap(), None);
        assert!(client.is_ready());

        let fat = [u8::try_from(frame_type::SETTINGS_ACK).unwrap(), 0x01, b'x'];
        client.adapter.events.push_back(control(&fat));
        assert_eq!(
            client.poll().unwrap_err().close_code(),
            error_code::FRAME_TOO_LARGE
        );
    }

    #[test]
    fn every_submission_path_reaches_the_backend() {
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
        assert_eq!(server.pending.bytes, 4 * record_wire_len(1024));

        let mut exact = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        exact.begin().unwrap();
        exact.pending.byte_limit = 2 * record_wire_len(1024);
        for lane in 0..2 {
            exact.adapter.events.push_back(record(lane, &payload));
        }
        assert_eq!(exact.poll().unwrap(), None, "the bound itself is allowed");
        assert_eq!(exact.pending.bytes, 2 * record_wire_len(1024));

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

        assert_eq!(
            DEFAULT_PENDING_RECORD_BYTES,
            4 * vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES
        );
        assert_eq!(DEFAULT_PENDING_RECORD_COUNT, 64);
    }

    #[test]
    fn a_repeated_negotiation_frame_is_refused_at_every_point() {
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
        assert!(mismatched.adapter().closed.is_empty());

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
        assert_eq!(server.adapter().sent.len(), 1, "only HELLO fitted");
        assert_eq!(server.unsent_negotiation_frames(), 3);
        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.adapter().sent.len(), 4);
        let held: Vec<u64> = server.adapter().sent[1..]
            .iter()
            .map(|frame| vot_codec::decode_one(frame, limits).unwrap().0.frame_type())
            .collect();
        assert_eq!(
            held,
            vec![
                frame_type::SETTINGS,
                frame_type::SETTINGS_ACK,
                frame_type::AUTH_CONTEXT
            ],
            "in the order the exchange gives them"
        );

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

        client.adapter.control_capacity = None;
        assert_eq!(client.poll().unwrap(), None);
        client.flush().unwrap();
        assert_eq!(client.unsent_negotiation_frames(), 2, "still queued");
        assert!(
            client.adapter().sent.is_empty(),
            "a closed session sends no more of the handshake"
        );
        assert!(client.adapter().flushes > 0);
    }

    #[test]
    fn an_application_frame_cannot_overtake_a_queued_acknowledgement() {
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
            3,
            "the SETTINGS, ACK, and challenge did not fit"
        );

        for send in [
            server.send_control(&frame_of(frame_type::PING, 0)),
            server.send_reliable(StreamId(1), &data_record(b"record")),
        ] {
            assert_eq!(
                send.unwrap_err().kind(),
                &ErrorKind::HandshakeUnsent { remaining: 3 }
            );
        }
        assert_eq!(
            server.adapter().sent.len(),
            1,
            "nothing overtook the acknowledgement"
        );
        assert!(server.adapter().records.is_empty());

        server.adapter.control_capacity = None;
        server.flush().unwrap();
        assert_eq!(server.unsent_negotiation_frames(), 0);
        server.send_control(&frame_of(frame_type::PING, 0)).unwrap();
        assert_eq!(server.adapter().sent.len(), 5);
    }

    #[test]
    fn a_record_larger_than_the_peer_accepts_is_refused() {
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
        assert_eq!(server.adapter().closed, vec![error_code::FRAME_TOO_LARGE]);
    }

    /// One encoded frame of `frame_type` carrying `payload` bytes.
    fn frame_of(frame_type: u64, payload: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type, &vec![0; payload], &mut frame).unwrap();
        frame
    }

    /// One encoded server `HELLO` answering with `extensions`.
    fn server_hello_of(extensions: BTreeSet<u64>) -> Vec<u8> {
        let mut payload = Vec::new();
        vot_codec::encode_hello(
            &vot_codec::Hello {
                draft_revision: vot_codec::DRAFT_REVISION,
                endpoint_role: vot_codec::EndpointRole::Server,
                extensions,
            },
            &mut payload,
        )
        .unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::HELLO, &payload, &mut frame).unwrap();
        frame
    }

    fn settings_of(settings: Settings) -> Vec<u8> {
        let mut payload = Vec::new();
        vot_codec::encode_settings(&settings, &mut payload).unwrap();
        let mut frame = Vec::new();
        vot_codec::encode_frame(frame_type::SETTINGS, &payload, &mut frame).unwrap();
        frame
    }

    #[test]
    fn every_negotiated_payload_limit_is_applied_in_both_directions() {
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
            let nothing = Negotiation::client(Settings::default(), BTreeSet::new());
            for side in [Side::Local, Side::Peer] {
                check_frame(
                    &frame_of(frame_type, limit),
                    &settings,
                    ExtensionPolicy::Negotiated(&nothing),
                    lane,
                    side,
                )
                .unwrap();
                let error = check_frame(
                    &frame_of(frame_type, limit + 1),
                    &settings,
                    ExtensionPolicy::Negotiated(&nothing),
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
                assert_eq!(error.kind().is_peer_fault(), side == Side::Local);
            }
        }

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

        client
            .send_control(&frame_of(frame_type::MANIFEST_PAGE, 64 * 1024))
            .unwrap();
        let error = client
            .send_control(&frame_of(frame_type::MANIFEST_PAGE, 64 * 1024 + 1))
            .unwrap_err();
        assert_eq!(error.close_code(), error_code::FRAME_TOO_LARGE);
        assert!(!error.kind().is_peer_fault());
        assert!(client.adapter().closed.is_empty());

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
        let peer = Settings {
            reliable_lane_limit: 1,
            ..Settings::default()
        };
        let (mut client, _server) = negotiated_with(Settings::default(), peer);
        client.adapter.refuse_sends = Some(TransportError::OutboundQueueFull);
        let record = data_record(b"record");
        assert!(client.send_reliable(StreamId(1), &record).is_err());

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
        assert!(!error.kind().is_peer_fault());
        assert!(
            client.adapter().closed.is_empty(),
            "a local refusal does not close the carrier"
        );
        assert!(!client.extension_negotiated(vot_codec::extension_id::DATAGRAM_FEC));
        assert!(client.negotiation.usable_extensions().is_empty());
        assert!(server.negotiation.usable_extensions().is_empty());

        server.adapter.events.push_back(control(&credit));
        let error = server.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::EXPERIMENT_NOT_NEGOTIATED);
        assert!(error.kind().is_peer_fault());

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

        // Both ends hold the same set once the server's HELLO has answered,
        // and both may send under it (ADR-0041).
        let fec = BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]);
        assert_eq!(server.negotiation.negotiated_extensions(), fec);
        assert_eq!(client.negotiation.negotiated_extensions(), fec);
        assert_eq!(server.negotiation.usable_extensions(), fec);
        assert_eq!(client.negotiation.usable_extensions(), fec);
        assert!(server.extension_negotiated(vot_codec::extension_id::DATAGRAM_FEC));
        assert!(client.extension_negotiated(vot_codec::extension_id::DATAGRAM_FEC));
        assert!(!client.extension_negotiated(vot_codec::extension_id::VCRC));
        client.send_control(&credit).unwrap();
        server.send_control(&credit).unwrap();

        // The negotiated side accepts the frame inbound: membership answers
        // true only through the intersection.
        server.adapter.events.push_back(control(&credit));
        assert!(
            matches!(server.poll().unwrap(), Some(Event::Control(_))),
            "a negotiated experimental frame is delivered"
        );

        // One-sided advertisement is not negotiation: the client offered the
        // extension, this server did not, and the intersection is empty.
        let mut unextended = Session::server(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        unextended.begin().unwrap();
        let mut offering = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::from([vot_codec::extension_id::DATAGRAM_FEC]),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        offering.begin().unwrap();
        for frame in std::mem::take(&mut offering.adapter.sent) {
            unextended.adapter.events.push_back(control(&frame));
        }
        unextended.poll().unwrap();
        assert!(unextended.negotiation.negotiated_extensions().is_empty());
        unextended.adapter.events.push_back(control(&credit));
        let error = unextended.poll().unwrap_err();
        assert_eq!(error.close_code(), error_code::EXPERIMENT_NOT_NEGOTIATED);
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn a_drifted_pending_byte_total_fails_the_recomputation() {
        let mut pending = PendingEvents::default();
        pending
            .try_hold(Event::Reliable {
                stream: StreamId(1),
                sequence: 1,
                bytes: vot_transport_api::shared_payload(b"record"),
            })
            .unwrap();
        // The only way bytes and events can disagree is a bug; simulate one.
        pending.bytes += 1;
        pending.assert_accounted();
    }

    #[test]
    fn a_lane_carries_the_payload_and_the_control_stream_describes_it() {
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
        let mut client = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        client.begin().unwrap();
        assert_eq!(client.adapter().sent.len(), 2);

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
        let (mut client, _server) = negotiated();
        for frame_type in [
            frame_type::HELLO,
            frame_type::SETTINGS,
            frame_type::SETTINGS_ACK,
            frame_type::AUTH_CONTEXT,
            frame_type::SESSION_OPEN,
            frame_type::SESSION_ACCEPT,
            frame_type::SESSION_REJECT,
        ] {
            let error = client.send_control(&frame_of(frame_type, 0)).unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::NegotiationFrameFromApplication { frame_type }
            );
            assert!(!error.kind().is_peer_fault());
            assert!(client.adapter().closed.is_empty());
        }
        assert!(client.adapter().sent.is_empty(), "none reached the backend");

        let mut fresh = Session::client(
            Loopback::default(),
            Settings::default(),
            BTreeSet::new(),
            Authentication::NotRequired { nonce: [0x5a; 32] },
        );
        fresh.begin().unwrap();
        assert_eq!(fresh.adapter().sent.len(), 2);

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
