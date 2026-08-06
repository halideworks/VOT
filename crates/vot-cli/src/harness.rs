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
    ///
    /// A fake carrier otherwise never delivers anything a pass did not
    /// already put there, so a loop that waits for one can only be tested
    /// against a loop that never needed to.
    pub(crate) on_wait: VecDeque<Event>,
    /// A rendezvous other carriers share, for tests whose subject is
    /// concurrency itself: a wait blocks until the expected number of
    /// carriers are waiting at once, so a loop that drives sessions one
    /// after another deadlocks where a concurrent one passes. Bounded,
    /// because a deadlock should fail the test rather than hang it.
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

    /// Blocks until `expected` waiters have arrived, or panics after a
    /// bound: the sequential loop this exists to reject would otherwise
    /// hold the suite forever.
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
    // The source has served its purpose; only the bundle is answered from,
    // and what a test leaves behind it leaves behind for every mutant.
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

/// Moves everything `from` sent into `to`'s inbound events, the way a
/// carrier would: control frames in order, records as reliable events with
/// per-call sequence numbers. Returns whether anything moved.
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

/// Removes what a test wrote.
///
/// `temporary` paths outlive the process that made them, and a mutation
/// run is this suite over and over: a bundle left behind per run per
/// mutant fills a CI runner's disk long before the mutants are through.
pub(crate) fn discard(paths: &[&std::path::Path]) {
    for path in paths {
        let _ = fs::remove_dir_all(path);
        let _ = fs::remove_file(path);
    }
}
