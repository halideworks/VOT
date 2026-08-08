//! Shared fixtures for the wire-engine tests: a recording fake carrier,
//! the bundles the engines answer from, and the pump that moves frames
//! between two endpoints the way a carrier would.

use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;

use vot_codec::DecodeLimits;
use vot_codec::frames::{self, TypedFrame};
use vot_session::Authentication;
use vot_transport_api::{
    Event, MAX_CONTROL_FRAME_PAYLOAD, StreamId, TransportAdapter, shared_payload,
};

use crate::tests::temporary;
use crate::{PackageSummary, build_bundle};

/// A recording fake carrier: what a session sends is captured, what a test
/// pushes into `events` is what the session receives.
#[derive(Default)]
pub(crate) struct Loopback {
    pub(crate) control: Vec<Vec<u8>>,
    pub(crate) records: Vec<(StreamId, Vec<u8>)>,
    pub(crate) events: VecDeque<Event>,
    pub(crate) refuse_sends: usize,
    pub(crate) fail_sends_with: Option<vot_transport_api::Error>,
    pub(crate) closed: Option<u16>,
    /// What the carrier reports when a driving loop waits on it.
    pub(crate) on_wait: VecDeque<Event>,
    /// A rendezvous for concurrency tests. A wait blocks until the expected
    /// number of carriers are waiting at once.
    pub(crate) rendezvous: Option<std::sync::Arc<Rendezvous>>,
}

/// The gate [`Loopback::rendezvous`] carriers meet at.
pub(crate) struct Rendezvous {
    pub(crate) expected: usize,
    state: std::sync::Mutex<usize>,
    arrived: std::sync::Condvar,
}

impl Rendezvous {
    pub(crate) fn expecting(expected: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            expected,
            state: std::sync::Mutex::new(0),
            arrived: std::sync::Condvar::new(),
        })
    }

    /// Blocks until `expected` waiters arrive, or panics after a bound.
    fn meet(&self) {
        let mut waiting = self.state.lock().expect("the gate");
        *waiting += 1;
        if *waiting >= self.expected {
            self.arrived.notify_all();
            return;
        }
        let deadline = std::time::Duration::from_secs(10);
        let (guard, outcome) = self
            .arrived
            .wait_timeout_while(waiting, deadline, |count| *count < self.expected)
            .expect("the gate");
        drop(guard);
        assert!(
            !outcome.timed_out(),
            "the rendezvous never filled: sessions were driven one at a time"
        );
    }
}

impl Loopback {
    fn refuse_send(&mut self) -> Result<(), vot_transport_api::Error> {
        if let Some(error) = self.fail_sends_with.take() {
            return Err(error);
        }
        if self.refuse_sends > 0 {
            self.refuse_sends -= 1;
            return Err(vot_transport_api::Error::OutboundQueueFull);
        }
        Ok(())
    }
}

impl TransportAdapter for Loopback {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), vot_transport_api::Error> {
        self.refuse_send()?;
        self.control.push(frame.to_vec());
        Ok(())
    }

    fn send_reliable(
        &mut self,
        stream: StreamId,
        record: &[u8],
    ) -> Result<(), vot_transport_api::Error> {
        self.refuse_send()?;
        self.records.push((stream, record.to_vec()));
        Ok(())
    }

    fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), vot_transport_api::Error> {
        Ok(())
    }

    fn wait_for_event(&mut self, _bound: std::time::Duration) {
        if let Some(gate) = self.rendezvous.take() {
            gate.meet();
        }
        if let Some(event) = self.on_wait.pop_front() {
            self.events.push_back(event);
        }
    }

    fn close(&mut self, code: u16) -> Result<(), vot_transport_api::Error> {
        if self.closed.is_none() {
            self.closed = Some(code);
        }
        Ok(())
    }
}

pub(crate) fn not_required() -> Authentication {
    Authentication::NotRequired { nonce: [7; 32] }
}

/// One end's inbox of a [`Duplex`]: the events, and the signal a waiting
/// end parks on.
pub(crate) struct DuplexQueue {
    events: std::sync::Mutex<VecDeque<Event>>,
    arrived: std::sync::Condvar,
}

impl DuplexQueue {
    fn push(&self, event: Event) {
        let mut events = self.events.lock().expect("the inbox");
        events.push_back(event);
        drop(events);
        self.arrived.notify_all();
    }
}

/// Thread-safe carrier pair. What one end sends, the other polls.
/// Dropping an end hangs up.
pub(crate) struct Duplex {
    inbox: std::sync::Arc<DuplexQueue>,
    outbox: std::sync::Arc<DuplexQueue>,
    sequence: u64,
    closed: bool,
}

/// A connected pair of [`Duplex`] ends.
pub(crate) fn duplex_pair() -> (Duplex, Duplex) {
    let queue = || {
        std::sync::Arc::new(DuplexQueue {
            events: std::sync::Mutex::new(VecDeque::new()),
            arrived: std::sync::Condvar::new(),
        })
    };
    let (left, right) = (queue(), queue());
    (
        Duplex {
            inbox: std::sync::Arc::clone(&left),
            outbox: std::sync::Arc::clone(&right),
            sequence: 0,
            closed: false,
        },
        Duplex {
            inbox: right,
            outbox: left,
            sequence: 0,
            closed: false,
        },
    )
}

impl Duplex {
    fn hang_up(&mut self) {
        if !self.closed {
            self.closed = true;
            self.outbox
                .push(Event::Disconnected(vot_transport_api::ConnectionId(1)));
        }
    }
}

impl Drop for Duplex {
    fn drop(&mut self) {
        self.hang_up();
    }
}

impl TransportAdapter for Duplex {
    fn send_control(&mut self, frame: &[u8]) -> Result<(), vot_transport_api::Error> {
        self.outbox.push(Event::Control(shared_payload(frame)));
        Ok(())
    }

    fn send_reliable(
        &mut self,
        stream: StreamId,
        record: &[u8],
    ) -> Result<(), vot_transport_api::Error> {
        self.sequence += 1;
        self.outbox.push(Event::Reliable {
            stream,
            sequence: self.sequence,
            bytes: shared_payload(record),
        });
        Ok(())
    }

    fn poll(&mut self) -> Option<Event> {
        self.inbox.events.lock().expect("the inbox").pop_front()
    }

    fn set_receive_credit(&mut self, _bytes: u64) -> Result<(), vot_transport_api::Error> {
        Ok(())
    }

    fn wait_for_event(&mut self, bound: std::time::Duration) {
        let events = self.inbox.events.lock().expect("the inbox");
        if events.is_empty() {
            let _ = self.inbox.arrived.wait_timeout(events, bound);
        }
    }

    fn close(&mut self, _code: u16) -> Result<(), vot_transport_api::Error> {
        self.hang_up();
        Ok(())
    }
}

pub(crate) fn built_bundle(name: &str, files: &[(&str, Vec<u8>)]) -> (PathBuf, PackageSummary) {
    let source = temporary(&format!("{name}-source"));
    let bundle = temporary(&format!("{name}-bundle"));
    fs::create_dir_all(&source).unwrap();
    for (file, bytes) in files {
        let path = source.join(file);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
    let summary = build_bundle(&source, &bundle).unwrap();
    fs::remove_dir_all(&source).unwrap();
    (bundle, summary)
}

/// Bytes that differ across group boundaries, so a wrong slice is caught.
pub(crate) fn patterned(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from((index / 251) % 256).unwrap())
        .collect()
}

pub(crate) fn control_event(frame: &TypedFrame) -> Event {
    let mut wire = Vec::new();
    frames::encode(frame, &mut wire).unwrap();
    Event::Control(shared_payload(&wire))
}

pub(crate) fn decode_control(bytes: &[u8]) -> TypedFrame {
    let limits = DecodeLimits {
        max_unknown_payload: MAX_CONTROL_FRAME_PAYLOAD,
        max_frames: 1,
    };
    let (frame, consumed) = frames::decode(bytes, limits).unwrap();
    assert_eq!(consumed, bytes.len());
    frame
}

/// Moves everything `from` sent into `to`'s inbound events.
pub(crate) fn pump(from: &mut Loopback, to: &mut Loopback, next_sequence: &mut u64) -> bool {
    let mut moved = false;
    for frame in std::mem::take(&mut from.control) {
        to.events.push_back(Event::Control(shared_payload(&frame)));
        moved = true;
    }
    for (stream, bytes) in std::mem::take(&mut from.records) {
        *next_sequence += 1;
        to.events.push_back(Event::Reliable {
            stream,
            sequence: *next_sequence,
            bytes: shared_payload(&bytes),
        });
        moved = true;
    }
    moved
}

/// Incompressible bytes for tests that exercise byte budgets.
pub(crate) fn noise(length: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

/// Moves records ahead of control frames (simulates data lane outrunning
/// control). Relative order within each kind is preserved.
pub(crate) fn pump_records_first(from: &mut Loopback, to: &mut Loopback, next_sequence: &mut u64) {
    for (stream, bytes) in std::mem::take(&mut from.records) {
        *next_sequence += 1;
        to.events.push_back(Event::Reliable {
            stream,
            sequence: *next_sequence,
            bytes: shared_payload(&bytes),
        });
    }
    for frame in std::mem::take(&mut from.control) {
        to.events.push_back(Event::Control(shared_payload(&frame)));
    }
}

/// Removes temporary paths. Paths outlive the process; this prevents
/// disk accumulation.
pub(crate) fn discard(paths: &[&std::path::Path]) {
    for path in paths {
        let _ = fs::remove_dir_all(path);
        let _ = fs::remove_file(path);
    }
}
