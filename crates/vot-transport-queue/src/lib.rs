//! Bounded queue for backend adapters: submissions out, events in.
//! Shared across backends; each keeps its own native event type.

use std::collections::VecDeque;

use vot_transport_api::{
    Error, Event, Payload, ReceiveLimits, StreamId, effective_send_limit, validate_control_frame,
    validate_control_payload_limit, validate_data_record,
};

/// What a driver has been handed to put on the carrier.
///
/// Submissions are held in order, and a driver takes them one at a time. VOT
/// frame bytes are never rewritten on the way through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Control(Payload),
    Reliable { stream: StreamId, bytes: Payload },
    Datagram { context: u64, bytes: Payload },
    ReceiveCredit(u64),
}

impl Command {
    /// The bytes this submission takes out of the queue's budget.
    ///
    /// Credit carries no payload, so it costs nothing but a slot.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Control(bytes) | Self::Reliable { bytes, .. } | Self::Datagram { bytes, .. } => {
                bytes.len()
            }
            Self::ReceiveCredit(_) => 0,
        }
    }

    /// The VOT bytes this submission carries, for a driver that logs or checks
    /// them.
    #[must_use]
    pub fn vot_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Control(bytes) | Self::Reliable { bytes, .. } | Self::Datagram { bytes, .. } => {
                Some(bytes)
            }
            Self::ReceiveCredit(_) => None,
        }
    }
}

/// The default number of submissions or events held at once.
pub const DEFAULT_COUNT_LIMIT: usize = 64;

/// The default bytes held at once in either direction.
pub const DEFAULT_BYTE_LIMIT: usize = 4 * 1024 * 1024;

/// The bytes an inbound queue can hold, which is what an endpoint may advertise.
pub const INBOUND_BYTE_CAPACITY: usize = DEFAULT_BYTE_LIMIT;

fn event_payload_len(event: &Event) -> usize {
    match event {
        Event::Control(bytes) | Event::Reliable { bytes, .. } => bytes.len(),
        Event::Connected(_)
        | Event::Disconnected(_)
        | Event::Acknowledged(_)
        | Event::DatagramState { .. } => 0,
    }
}

/// Submissions out, events in, both bounded by count and bytes.
#[derive(Clone, Debug)]
pub struct Queue {
    commands: VecDeque<Command>,
    command_bytes: usize,
    command_count_limit: usize,
    command_byte_limit: usize,
    /// The peer's bound on what this endpoint sends.
    control_send_limit: usize,
    /// What this endpoint accepts, which is what it advertised. Separate from
    /// the send bound, which is the peer's.
    control_receive_limit: usize,
    /// What this endpoint advertised, once it has been configured.
    receive_limits: Option<ReceiveLimits>,
    events: VecDeque<Event>,
    event_bytes: usize,
    event_count_limit: usize,
    event_byte_limit: usize,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            commands: VecDeque::new(),
            command_bytes: 0,
            command_count_limit: DEFAULT_COUNT_LIMIT,
            command_byte_limit: DEFAULT_BYTE_LIMIT,
            control_send_limit: vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            control_receive_limit: vot_transport_api::MAX_CONTROL_FRAME_PAYLOAD,
            receive_limits: None,
            events: VecDeque::new(),
            event_bytes: 0,
            event_count_limit: DEFAULT_COUNT_LIMIT,
            event_byte_limit: DEFAULT_BYTE_LIMIT,
        }
    }
}

impl Queue {
    /// A queue with explicit bounds in both directions.
    ///
    /// # Errors
    /// Rejects a zero count or byte limit: a queue that can hold nothing
    /// refuses every submission, which a caller reads as backpressure that
    /// never clears.
    pub fn with_limits(count: usize, bytes: usize) -> Result<Self, Error> {
        if count == 0 || bytes == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            command_count_limit: count,
            command_byte_limit: bytes,
            event_count_limit: count,
            event_byte_limit: bytes,
            ..Self::default()
        })
    }

    /// Applies what this endpoint advertised. Must be in force before the
    /// peer's first frame.
    pub const fn set_receive_limits(&mut self, limits: ReceiveLimits) {
        self.control_receive_limit = limits.control_payload();
        self.receive_limits = Some(limits);
    }

    #[must_use]
    pub const fn receive_limits(&self) -> Option<ReceiveLimits> {
        self.receive_limits
    }

    /// Applies the peer's send bound, clamped to the outbound queue capacity.
    ///
    /// # Errors
    /// Rejects a limit outside the protocol's range.
    pub fn set_control_send_limit(&mut self, limit: usize) -> Result<(), Error> {
        validate_control_payload_limit(limit)?;
        self.control_send_limit = effective_send_limit(limit, self.command_byte_limit);
        Ok(())
    }

    #[must_use]
    pub const fn control_send_limit(&self) -> usize {
        self.control_send_limit
    }

    /// Submissions taken but not yet handed to the carrier.
    ///
    /// A driver watches this to know whether a failed flush left work behind.
    #[must_use]
    pub fn pending_commands(&self) -> usize {
        self.commands.len()
    }

    /// Takes a control frame, against the peer's bound rather than this
    /// endpoint's.
    ///
    /// # Errors
    /// Rejects a frame past the peer's limit or a full outbound queue.
    pub fn send_control(&mut self, frame: Payload) -> Result<(), Error> {
        validate_control_frame(&frame, self.control_send_limit)?;
        self.enqueue(Command::Control(frame))
    }

    /// Takes one reliable record on a lane.
    ///
    /// # Errors
    /// Rejects a record past the protocol's bound or a full outbound queue.
    pub fn send_reliable(&mut self, stream: StreamId, record: Payload) -> Result<(), Error> {
        validate_data_record(&record)?;
        self.enqueue(Command::Reliable {
            stream,
            bytes: record,
        })
    }

    /// Takes one unreliable datagram.
    ///
    /// # Errors
    /// Rejects a payload past the datagram bound or a full outbound queue.
    pub fn send_datagram(&mut self, context: u64, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > vot_transport_api::MAX_DATAGRAM_BYTES {
            return Err(Error::RecordTooLarge);
        }
        self.enqueue(Command::Datagram {
            context,
            bytes: vot_transport_api::shared_payload(payload),
        })
    }

    /// Takes an absolute receive credit for the carrier to apply.
    ///
    /// # Errors
    /// Rejects a full outbound queue.
    pub fn set_receive_credit(&mut self, bytes: u64) -> Result<(), Error> {
        self.enqueue(Command::ReceiveCredit(bytes))
    }

    /// Checks a batch of records against the protocol and the queue without
    /// changing anything.
    ///
    /// The queue's own capacity is part of the answer, so a batch that passes
    /// this cannot be accepted only in part.
    ///
    /// # Errors
    /// Rejects an oversized record, arithmetic overflow, or a batch the queue
    /// cannot hold whole.
    pub fn preflight_reliable_batch(&self, records: &[Payload]) -> Result<(), Error> {
        let next_bytes = records
            .iter()
            .try_fold(self.command_bytes, |bytes, record| {
                validate_data_record(record)?;
                bytes
                    .checked_add(record.len())
                    .ok_or(Error::ArithmeticOverflow)
            })?;
        let next_count = self
            .commands
            .len()
            .checked_add(records.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if next_count > self.command_count_limit || next_bytes > self.command_byte_limit {
            Err(Error::OutboundQueueFull)
        } else {
            Ok(())
        }
    }

    /// Hands back the next submission, releasing what it held.
    pub fn next_command(&mut self) -> Option<Command> {
        let command = self.commands.pop_front()?;
        self.command_bytes = self.command_bytes.saturating_sub(command.payload_len());
        Some(command)
    }

    /// Gives a driver one submission at a time. Failed submissions stay queued.
    ///
    /// # Errors
    /// Returns the first error the driver reports.
    pub fn drain_commands<F, E>(&mut self, mut submit: F) -> Result<(), E>
    where
        F: FnMut(Command) -> Result<(), E>,
    {
        while let Some(command) = self.commands.front().cloned() {
            submit(command)?;
            let Some(command) = self.commands.pop_front() else {
                break;
            };
            self.command_bytes = self.command_bytes.saturating_sub(command.payload_len());
        }
        Ok(())
    }

    /// Whether an event fits the advertised bounds. Separate from admission so
    /// a backend can refuse before counting.
    ///
    /// # Errors
    /// Rejects a control frame or record past what this endpoint accepts.
    pub fn validate_event(&self, event: &Event) -> Result<(), Error> {
        match event {
            Event::Control(bytes) => validate_control_frame(bytes, self.control_receive_limit),
            Event::Reliable { bytes, .. } => validate_data_record(bytes),
            Event::Connected(_)
            | Event::Disconnected(_)
            | Event::Acknowledged(_)
            | Event::DatagramState { .. } => Ok(()),
        }
    }

    /// Delivers an event after enforcing the protocol and memory bounds.
    ///
    /// # Errors
    /// Rejects an oversized payload, arithmetic overflow, or a full inbound
    /// queue.
    pub fn admit_event(&mut self, event: Event) -> Result<(), Error> {
        let next_bytes = self.admit(&event)?;
        self.accept(event, next_bytes);
        Ok(())
    }

    /// Delivers an event, handing it back when the inbound queue is full.
    ///
    /// # Errors
    /// Returns the event alongside the reason it was refused.
    pub fn try_admit_event(&mut self, event: Event) -> Result<(), (Event, Error)> {
        match self.admit(&event) {
            Ok(next_bytes) => {
                self.accept(event, next_bytes);
                Ok(())
            }
            Err(error) => Err((event, error)),
        }
    }

    /// Hands back the next event, releasing what it held.
    pub fn poll(&mut self) -> Option<Event> {
        let event = self.events.pop_front()?;
        self.event_bytes = self.event_bytes.saturating_sub(event_payload_len(&event));
        Some(event)
    }

    /// Events delivered but not yet taken.
    #[must_use]
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    /// Checks an event against the protocol and memory bounds, returning the
    /// queue size it would produce.
    fn admit(&self, event: &Event) -> Result<usize, Error> {
        self.validate_event(event)?;
        let next_bytes = self
            .event_bytes
            .checked_add(event_payload_len(event))
            .ok_or(Error::ArithmeticOverflow)?;
        if self.events.len() >= self.event_count_limit || next_bytes > self.event_byte_limit {
            return Err(Error::InboundQueueFull);
        }
        Ok(next_bytes)
    }

    /// Takes the space an admitted event was measured for.
    fn accept(&mut self, event: Event, next_bytes: usize) {
        self.events.push_back(event);
        self.event_bytes = next_bytes;
    }

    fn enqueue(&mut self, command: Command) -> Result<(), Error> {
        let next_bytes = self
            .command_bytes
            .checked_add(command.payload_len())
            .ok_or(Error::ArithmeticOverflow)?;
        if self.commands.len() >= self.command_count_limit || next_bytes > self.command_byte_limit {
            return Err(Error::OutboundQueueFull);
        }
        self.commands.push_back(command);
        self.command_bytes = next_bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use vot_transport_api::{ConnectionId, DatagramSendState, TransportAck, shared_payload};

    use super::*;

    /// A control frame of exactly this many wire bytes. Stated as bytes, not
    /// an encoding, to avoid duplicating codec rules.
    fn frame(wire_len: usize) -> Payload {
        shared_payload(&vec![0; wire_len])
    }

    #[test]
    fn a_queue_that_can_hold_nothing_is_not_a_queue() {
        assert!(matches!(
            Queue::with_limits(0, 1),
            Err(Error::InvalidConfiguration)
        ));
        assert!(matches!(
            Queue::with_limits(1, 0),
            Err(Error::InvalidConfiguration)
        ));
        assert!(Queue::with_limits(1, 1).is_ok());
    }

    #[test]
    fn submissions_come_back_in_the_order_they_were_taken() {
        let mut queue = Queue::default();
        queue.send_control(frame(4)).expect("a control frame");
        queue
            .send_reliable(StreamId(2), shared_payload(b"record"))
            .expect("a record");
        queue.send_datagram(7, b"datagram").expect("a datagram");
        queue.set_receive_credit(4_096).expect("credit");
        assert_eq!(queue.pending_commands(), 4);

        assert!(matches!(queue.next_command(), Some(Command::Control(_))));
        assert_eq!(
            queue.next_command(),
            Some(Command::Reliable {
                stream: StreamId(2),
                bytes: shared_payload(b"record"),
            })
        );
        assert_eq!(
            queue.next_command(),
            Some(Command::Datagram {
                context: 7,
                bytes: shared_payload(b"datagram"),
            })
        );
        assert_eq!(queue.next_command(), Some(Command::ReceiveCredit(4_096)));
        assert_eq!(queue.next_command(), None);
        assert_eq!(queue.pending_commands(), 0);
    }

    #[test]
    fn a_submission_the_driver_could_not_take_stays_at_the_head() {
        let mut queue = Queue::default();
        queue
            .send_reliable(StreamId(1), shared_payload(b"first"))
            .expect("a record");
        queue
            .send_reliable(StreamId(1), shared_payload(b"second"))
            .expect("a record");

        let result: Result<(), &str> = queue.drain_commands(|_| Err("the carrier refused"));
        assert_eq!(result, Err("the carrier refused"));
        assert_eq!(queue.pending_commands(), 2);
        assert_eq!(
            queue.next_command(),
            Some(Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"first"),
            })
        );

        let mut taken = Vec::new();
        let result: Result<(), &str> = queue.drain_commands(|command| {
            taken.push(command);
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(taken.len(), 1);
        assert_eq!(queue.pending_commands(), 0);
    }

    #[test]
    fn a_full_queue_refuses_by_count_and_by_bytes() {
        let mut queue = Queue::with_limits(2, 1_024).expect("a bounded queue");
        queue
            .send_reliable(StreamId(1), shared_payload(b"one"))
            .expect("a record");
        queue
            .send_reliable(StreamId(1), shared_payload(b"two"))
            .expect("a record");
        assert_eq!(
            queue.send_reliable(StreamId(1), shared_payload(b"three")),
            Err(Error::OutboundQueueFull),
            "the count is reached"
        );

        let mut wide = Queue::with_limits(8, 16).expect("a bounded queue");
        wide.send_reliable(StreamId(1), shared_payload(&[0; 16]))
            .expect("a record at the byte limit");
        assert_eq!(
            wide.send_reliable(StreamId(1), shared_payload(b"x")),
            Err(Error::OutboundQueueFull),
            "the bytes are reached"
        );
        assert!(wide.next_command().is_some());
        assert!(
            wide.send_reliable(StreamId(1), shared_payload(b"x"))
                .is_ok()
        );
    }

    #[test]
    fn credit_costs_a_slot_and_no_bytes() {
        let mut queue = Queue::with_limits(2, 1).expect("a bounded queue");
        queue.set_receive_credit(1).expect("credit");
        queue.set_receive_credit(2).expect("credit");
        assert_eq!(
            queue.set_receive_credit(3),
            Err(Error::OutboundQueueFull),
            "the count is what bounds credit"
        );
        assert_eq!(Command::ReceiveCredit(1).payload_len(), 0);
        assert_eq!(Command::ReceiveCredit(1).vot_bytes(), None);
    }

    #[test]
    fn what_a_submission_carries_is_the_bytes_it_was_given() {
        assert_eq!(
            Command::Control(shared_payload(b"frame")).vot_bytes(),
            Some(b"frame".as_slice())
        );
        assert_eq!(
            Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"record"),
            }
            .vot_bytes(),
            Some(b"record".as_slice())
        );
        assert_eq!(
            Command::Datagram {
                context: 1,
                bytes: shared_payload(b"gram"),
            }
            .vot_bytes(),
            Some(b"gram".as_slice())
        );
        assert_eq!(Command::Control(shared_payload(b"frame")).payload_len(), 5);
        assert_eq!(
            Command::Reliable {
                stream: StreamId(1),
                bytes: shared_payload(b"record"),
            }
            .payload_len(),
            6
        );
        assert_eq!(
            Command::Datagram {
                context: 1,
                bytes: shared_payload(b"gram"),
            }
            .payload_len(),
            4
        );
    }

    #[test]
    fn a_record_or_datagram_past_its_bound_is_never_taken() {
        let mut queue = Queue::default();
        assert_eq!(
            queue.send_reliable(
                StreamId(1),
                shared_payload(&vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1])
            ),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(
            queue.send_datagram(1, &vec![0; vot_transport_api::MAX_DATAGRAM_BYTES + 1]),
            Err(Error::RecordTooLarge)
        );
        assert_eq!(queue.pending_commands(), 0, "nothing refused was taken");

        assert!(
            queue
                .send_datagram(1, &vec![0; vot_transport_api::MAX_DATAGRAM_BYTES])
                .is_ok()
        );
    }

    #[test]
    fn the_send_bound_is_the_peers_and_the_receive_bound_is_this_endpoints() {
        const ENVELOPE: usize = vot_transport_api::MAX_FRAME_ENVELOPE_BYTES;
        let mut queue = Queue::default();
        let advertised = ReceiveLimits::advertised(
            &vot_codec::Settings {
                max_control_frame_payload: 16_384,
                reliable_lane_limit: 4,
                ..vot_codec::Settings::default()
            },
            INBOUND_BYTE_CAPACITY,
        )
        .expect("limits the queue can hold");
        queue.set_receive_limits(advertised);
        assert_eq!(queue.receive_limits(), Some(advertised));

        let peer = vot_transport_api::MIN_CONTROL_FRAME_PAYLOAD;
        queue
            .set_control_send_limit(peer)
            .expect("the peer's limit");
        assert_eq!(queue.control_send_limit(), peer);
        assert!(
            queue.send_control(frame(peer + ENVELOPE)).is_ok(),
            "a frame at the peer's bound"
        );
        assert_eq!(
            queue.send_control(frame(peer + ENVELOPE + 1)),
            Err(Error::RecordTooLarge),
            "and one byte more"
        );

        assert_eq!(
            queue.validate_event(&Event::Control(frame(16_384 + ENVELOPE))),
            Ok(())
        );
        assert_eq!(
            queue.validate_event(&Event::Control(frame(16_384 + ENVELOPE + 1))),
            Err(Error::RecordTooLarge)
        );

        assert_eq!(
            queue.set_control_send_limit(vot_transport_api::MIN_CONTROL_FRAME_PAYLOAD - 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            queue.set_control_send_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD + 1),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(queue.control_send_limit(), peer, "and nothing changed");
    }

    #[test]
    fn the_send_bound_is_clamped_to_what_the_queue_can_hold() {
        let mut queue = Queue::with_limits(4, 64 * 1024).expect("a bounded queue");
        queue
            .set_control_send_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD)
            .expect("the peer's limit");
        assert_eq!(
            queue.control_send_limit(),
            64 * 1024 - vot_transport_api::MAX_FRAME_ENVELOPE_BYTES,
            "what the queue holds, not what the peer allows"
        );
        assert!(queue.send_control(frame(64 * 1024)).is_ok());

        let mut narrow = Queue::with_limits(1, 8).expect("a bounded queue");
        narrow
            .set_control_send_limit(vot_codec::HARD_MAX_FRAME_PAYLOAD)
            .expect("the peer's limit");
        assert_eq!(
            narrow.control_send_limit(),
            vot_transport_api::MIN_CONTROL_FRAME_PAYLOAD
        );
    }

    #[test]
    fn the_default_bounds_are_what_an_endpoint_advertises_against() {
        assert_eq!(DEFAULT_COUNT_LIMIT, 64);
        assert_eq!(DEFAULT_BYTE_LIMIT, 4_194_304);
        assert_eq!(INBOUND_BYTE_CAPACITY, DEFAULT_BYTE_LIMIT);
    }

    #[test]
    fn a_batch_at_each_bound_is_taken_and_one_past_it_is_not() {
        let queue = Queue::with_limits(3, 32).expect("a bounded queue");
        assert_eq!(
            queue.preflight_reliable_batch(&[
                shared_payload(&[0; 8]),
                shared_payload(&[0; 8]),
                shared_payload(&[0; 8]),
            ]),
            Ok(()),
            "a batch of exactly the slots there are"
        );
        assert_eq!(
            queue.preflight_reliable_batch(&[
                shared_payload(b"a"),
                shared_payload(b"b"),
                shared_payload(b"c"),
                shared_payload(b"d"),
            ]),
            Err(Error::OutboundQueueFull),
            "and one slot more"
        );
        assert_eq!(
            queue.preflight_reliable_batch(&[shared_payload(&[0; 16]), shared_payload(&[0; 16])]),
            Ok(()),
            "a batch of exactly the bytes there are"
        );
        assert_eq!(
            queue.preflight_reliable_batch(&[shared_payload(&[0; 16]), shared_payload(&[0; 17])]),
            Err(Error::OutboundQueueFull),
            "and one byte more"
        );
    }

    #[test]
    fn a_batch_is_checked_whole_and_changes_nothing() {
        let mut queue = Queue::with_limits(3, 1_024).expect("a bounded queue");
        let records = vec![shared_payload(b"one"), shared_payload(b"two")];
        assert_eq!(queue.preflight_reliable_batch(&records), Ok(()));
        assert_eq!(queue.pending_commands(), 0, "a check takes nothing");

        queue
            .send_reliable(StreamId(1), shared_payload(b"first"))
            .expect("a record");
        queue
            .send_reliable(StreamId(1), shared_payload(b"second"))
            .expect("a record");
        assert_eq!(
            queue.preflight_reliable_batch(&records),
            Err(Error::OutboundQueueFull)
        );

        let fresh = Queue::default();
        assert_eq!(
            fresh.preflight_reliable_batch(&[
                shared_payload(b"one"),
                shared_payload(&vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1]),
            ]),
            Err(Error::RecordTooLarge)
        );
    }

    #[test]
    fn events_come_back_in_the_order_they_arrived() {
        let mut queue = Queue::default();
        for event in [
            Event::Connected(ConnectionId(1)),
            Event::Control(frame(4)),
            Event::Reliable {
                stream: StreamId(2),
                sequence: 1,
                bytes: shared_payload(b"record"),
            },
            Event::Acknowledged(TransportAck::new(2, 1)),
            Event::DatagramState {
                context: 3,
                state: DatagramSendState::Sent,
            },
            Event::Disconnected(ConnectionId(1)),
        ] {
            queue.admit_event(event).expect("an event");
        }
        assert_eq!(queue.pending_events(), 6);
        assert_eq!(queue.poll(), Some(Event::Connected(ConnectionId(1))));
        assert!(matches!(queue.poll(), Some(Event::Control(_))));
        assert!(matches!(queue.poll(), Some(Event::Reliable { .. })));
        assert_eq!(
            queue.poll(),
            Some(Event::Acknowledged(TransportAck::new(2, 1)))
        );
        assert_eq!(
            queue.poll(),
            Some(Event::DatagramState {
                context: 3,
                state: DatagramSendState::Sent,
            })
        );
        assert_eq!(queue.poll(), Some(Event::Disconnected(ConnectionId(1))));
        assert_eq!(queue.poll(), None);
    }

    #[test]
    fn an_event_the_queue_cannot_hold_is_handed_back_rather_than_dropped() {
        let mut queue = Queue::with_limits(1, 1_024).expect("a bounded queue");
        queue
            .admit_event(Event::Connected(ConnectionId(1)))
            .expect("an event");

        let refused = Event::Reliable {
            stream: StreamId(1),
            sequence: 1,
            bytes: shared_payload(b"record"),
        };
        assert_eq!(
            queue.try_admit_event(refused.clone()),
            Err((refused.clone(), Error::InboundQueueFull))
        );
        assert_eq!(
            queue.admit_event(refused.clone()),
            Err(Error::InboundQueueFull)
        );

        assert_eq!(queue.poll(), Some(Event::Connected(ConnectionId(1))));
        assert_eq!(queue.try_admit_event(refused.clone()), Ok(()));
        assert_eq!(queue.poll(), Some(refused));
    }

    #[test]
    fn an_inbound_queue_is_bounded_by_bytes_as_well_as_by_count() {
        let mut queue = Queue::with_limits(8, 8).expect("a bounded queue");
        queue
            .admit_event(Event::Reliable {
                stream: StreamId(1),
                sequence: 1,
                bytes: shared_payload(&[0; 8]),
            })
            .expect("an event at the byte limit");
        assert_eq!(
            queue.admit_event(Event::Reliable {
                stream: StreamId(1),
                sequence: 2,
                bytes: shared_payload(b"x"),
            }),
            Err(Error::InboundQueueFull)
        );
        assert_eq!(queue.admit_event(Event::Connected(ConnectionId(1))), Ok(()));

        assert!(matches!(queue.poll(), Some(Event::Reliable { .. })));
        assert_eq!(
            queue.admit_event(Event::Reliable {
                stream: StreamId(1),
                sequence: 2,
                bytes: shared_payload(b"x"),
            }),
            Ok(())
        );
    }

    /// A naive queue that recomputes its byte total from scratch on every
    /// question, so it cannot share the production queue's bookkeeping bugs.
    struct NaiveBoundedQueue {
        costs: Vec<usize>,
        count_limit: usize,
        byte_limit: usize,
    }

    impl NaiveBoundedQueue {
        const fn new(count_limit: usize, byte_limit: usize) -> Self {
            Self {
                costs: Vec::new(),
                count_limit,
                byte_limit,
            }
        }

        fn bytes(&self) -> usize {
            self.costs.iter().sum()
        }

        fn fits(&self, more: &[usize]) -> bool {
            self.costs.len() + more.len() <= self.count_limit
                && self.bytes() + more.iter().sum::<usize>() <= self.byte_limit
        }

        fn push(&mut self, cost: usize) -> bool {
            let fits = self.fits(&[cost]);
            if fits {
                self.costs.push(cost);
            }
            fits
        }

        fn pop(&mut self) -> Option<usize> {
            if self.costs.is_empty() {
                None
            } else {
                Some(self.costs.remove(0))
            }
        }
    }

    #[test]
    fn the_production_queue_matches_a_naive_model_over_a_long_script() {
        // Characterization for the accounting refactor: every accept, refusal,
        // and release the production queue makes must match a model that
        // recomputes its totals from scratch. The script is generated by a
        // fixed linear congruence, so it is deterministic and bounded by its
        // own counter.
        const COUNT_LIMIT: usize = 4;
        const BYTE_LIMIT: usize = 64;
        let mut queue = Queue::with_limits(COUNT_LIMIT, BYTE_LIMIT).expect("a bounded queue");
        let mut commands = NaiveBoundedQueue::new(COUNT_LIMIT, BYTE_LIMIT);
        let mut events = NaiveBoundedQueue::new(COUNT_LIMIT, BYTE_LIMIT);
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let mut step = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as usize
        };

        for round in 0..4_000 {
            match step() % 10 {
                0 | 1 => {
                    let len = step() % 40;
                    let accepted = queue
                        .send_reliable(StreamId(1), shared_payload(&vec![0; len]))
                        .is_ok();
                    assert_eq!(accepted, commands.push(len), "round {round} send {len}");
                }
                2 => {
                    let accepted = queue.set_receive_credit(1).is_ok();
                    assert_eq!(accepted, commands.push(0), "round {round} credit");
                }
                3 => {
                    let lens = [step() % 40, step() % 40];
                    let records: Vec<Payload> = lens
                        .iter()
                        .map(|len| shared_payload(&vec![0; *len]))
                        .collect();
                    assert_eq!(
                        queue.preflight_reliable_batch(&records).is_ok(),
                        commands.fits(&lens),
                        "round {round} preflight {lens:?}"
                    );
                }
                4 => {
                    let popped = queue.next_command().map(|command| command.payload_len());
                    assert_eq!(popped, commands.pop(), "round {round} pop");
                }
                5 => {
                    // A driver that refuses leaves the head in place.
                    let result: Result<(), ()> = queue.drain_commands(|_| Err(()));
                    assert_eq!(result.is_err(), !commands.costs.is_empty(), "round {round}");
                }
                6 => {
                    // A driver that takes one submission then refuses.
                    let mut taken = 0;
                    let _: Result<(), ()> = queue.drain_commands(|_| {
                        if taken == 0 {
                            taken += 1;
                            Ok(())
                        } else {
                            Err(())
                        }
                    });
                    if taken == 1 {
                        commands.pop();
                    }
                }
                7 | 8 => {
                    let len = step() % 40;
                    let accepted = queue
                        .try_admit_event(Event::Reliable {
                            stream: StreamId(1),
                            sequence: round,
                            bytes: shared_payload(&vec![0; len]),
                        })
                        .is_ok();
                    assert_eq!(accepted, events.push(len), "round {round} admit {len}");
                }
                _ => {
                    let popped = queue.poll().map(|event| event_payload_len(&event));
                    assert_eq!(popped, events.pop(), "round {round} poll");
                }
            }
            assert_eq!(
                queue.pending_commands(),
                commands.costs.len(),
                "round {round}"
            );
            assert_eq!(queue.pending_events(), events.costs.len(), "round {round}");
        }
        assert!(
            queue.pending_commands() + queue.pending_events() > 0,
            "the script ended with work in flight, so refusals were exercised"
        );
    }

    #[test]
    fn a_malformed_event_is_refused_before_it_is_counted() {
        let queue = Queue::default();
        assert_eq!(
            queue.validate_event(&Event::Reliable {
                stream: StreamId(1),
                sequence: 1,
                bytes: shared_payload(&vec![0; vot_transport_api::MAX_DATA_RECORD_WIRE_BYTES + 1]),
            }),
            Err(Error::RecordTooLarge)
        );
        for event in [
            Event::Connected(ConnectionId(1)),
            Event::Disconnected(ConnectionId(1)),
            Event::Acknowledged(TransportAck::new(1, 1)),
            Event::DatagramState {
                context: 1,
                state: DatagramSendState::Canceled,
            },
        ] {
            assert_eq!(queue.validate_event(&event), Ok(()), "{event:?}");
        }
    }
}
