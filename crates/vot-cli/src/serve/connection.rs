//! One serving connection: replay memory and outbound accounting.

use super::{
    Error, ErrorKind, Fault, Payload, RECORD_LANE, Session, TransportAdapter, VecDeque, error_code,
    is_backpressure,
};

/// Outbound budget. Bounds the queue against a peer pipelining faster than it drains.
pub(crate) const OUTBOUND_BUDGET_BYTES: u64 = 2 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// Request identities remembered for replay detection. An exact duplicate is
/// re-answered; a duplicate identifier with different content is a protocol error.
pub(crate) const REMEMBERED_REQUESTS: usize = 64;

/// Per-session serving state, fresh for every accepted carrier.
pub struct ServeConnection {
    pub(crate) announced: bool,
    pub(crate) replay: ReplayWindow,
    pub(crate) outbound: OutboundQueue,
    /// Owed manifest pages as `(next, end)`. Paced rather than queued at once;
    /// a request may name thousands of pages.
    pub(crate) manifest_cursor: Option<(u64, u64)>,
    pub(crate) budget: u64,
    pub(crate) closed: Option<u16>,
    /// Answers queued this session, only ever increasing.
    pub(crate) progress: u64,
    /// Answers the carrier has taken, which the outbound budget may hide.
    pub(crate) handed_over: u64,
    /// The datagram FEC sending state: what the peer's credit lets this end
    /// open and send. Used only while `fec_negotiated`.
    pub(crate) fec: FecSender,
    /// Whether the session negotiated `DATAGRAM_FEC`, refreshed each pass.
    pub(crate) fec_negotiated: bool,
}

impl Default for ServeConnection {
    fn default() -> Self {
        Self {
            announced: false,
            replay: ReplayWindow::default(),
            outbound: OutboundQueue::default(),
            manifest_cursor: None,
            budget: OUTBOUND_BUDGET_BYTES,
            closed: None,
            progress: 0,
            handed_over: 0,
            fec: FecSender::default(),
            fec_negotiated: false,
        }
    }
}

/// One epoch this serve opened for one bundle: what to re-send reliably when
/// the receiver reports a generation abandoned or the epoch refused.
#[derive(Clone, Debug)]
pub(crate) struct OpenedEpoch {
    pub(crate) root: [u8; 32],
    pub(crate) bundle_id: [u8; 16],
    pub(crate) plan: vot_fec::EpochPlan,
    /// Generations still owed an outcome; the epoch closes when empty.
    pub(crate) live: std::collections::BTreeSet<u32>,
    /// When this epoch was first seen with its symbols all on the carrier
    /// and nothing heard about it since. Cleared by anything the receiver
    /// says about it, so it measures one epoch's own silence.
    pub(crate) quiet_since: Option<std::time::Instant>,
}

/// The sender side of datagram FEC for one connection.
#[derive(Debug, Default)]
pub(crate) struct FecSender {
    pub(crate) sender: vot_fec::Sender,
    pub(crate) epochs: std::collections::BTreeMap<u32, OpenedEpoch>,
}

pub(crate) struct Remembered {
    pub(crate) frame_type: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) digest: [u8; 32],
}

pub(crate) enum Outbound {
    Control(Payload),
    Record(Payload),
    /// One FEC symbol datagram, in the same queue so the outbound budget and
    /// the backlog see it.
    Datagram(Payload),
}

impl Outbound {
    /// The answer's bytes, whichever lane carries it.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Control(frame) => frame.len(),
            Self::Record(record) => record.len(),
            Self::Datagram(symbol) => symbol.len(),
        }
    }

    /// Hands the answer to its lane: control frames as control, records
    /// shared on the record lane, symbols to the datagram path.
    pub(crate) fn send<A: TransportAdapter>(
        &self,
        session: &mut Session<A>,
    ) -> Result<(), vot_session::Error> {
        match self {
            Self::Control(frame) => session.send_control(frame),
            Self::Record(record) => session.send_reliable_shared(RECORD_LANE, record.clone()),
            Self::Datagram(symbol) => session.send_datagram(0, symbol),
        }
    }
}

/// The queued answers and the bytes they hold, kept exactly together.
#[derive(Default)]
pub(crate) struct OutboundQueue {
    queue: VecDeque<Outbound>,
    bytes: u64,
}

impl OutboundQueue {
    pub(crate) fn push(&mut self, outbound: Outbound) {
        self.bytes = self.bytes.saturating_add(outbound.len() as u64);
        self.queue.push_back(outbound);
        debug_assert_eq!(
            self.bytes,
            self.queue.iter().map(|held| held.len() as u64).sum::<u64>(),
            "outbound bytes drifted from the queue"
        );
    }

    pub(crate) fn front(&self) -> Option<&Outbound> {
        self.queue.front()
    }

    /// Retires the front answer once the carrier took it.
    pub(crate) fn pop_sent(&mut self) {
        if let Some(sent) = self.queue.pop_front() {
            self.bytes = self.bytes.saturating_sub(sent.len() as u64);
        }
        debug_assert_eq!(
            self.bytes,
            self.queue.iter().map(|held| held.len() as u64).sum::<u64>(),
            "outbound bytes drifted from the queue"
        );
    }

    /// Answer bytes queued and not yet taken.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Answers still queued.
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Request identities this session remembers, FIFO at a fixed bound.
#[derive(Default)]
pub(crate) struct ReplayWindow {
    remembered: VecDeque<Remembered>,
}

impl ReplayWindow {
    /// Admits a request as new or an exact replay, which is re-answered.
    /// The same identity over different bytes is the replay that is refused.
    pub(crate) fn admit(
        &mut self,
        frame_type: u64,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Fault> {
        let digest = *blake3::hash(bytes).as_bytes();
        if let Some(seen) = self
            .remembered
            .iter()
            .find(|seen| seen.frame_type == frame_type && seen.request_id == request_id)
        {
            if seen.digest == digest {
                // Rebuild reproduces it: the bundle identity derives from the request bytes.
                return Ok(());
            }
            return Err(Fault::Peer(error_code::REPLAY_REJECTED));
        }
        if self.remembered.len() == REMEMBERED_REQUESTS {
            self.remembered.pop_front();
        }
        self.remembered.push_back(Remembered {
            frame_type,
            request_id,
            digest,
        });
        Ok(())
    }
}

impl ServeConnection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer bytes queued but not yet accepted by the carrier.
    #[must_use]
    pub fn pending_answer_bytes(&self) -> u64 {
        self.outbound.bytes()
    }

    /// Whether answers are still owed: queued frames or unpaged manifest pages.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.outbound.is_empty() || self.manifest_cursor.is_some()
    }

    /// Records the close and drops pending answers.
    pub(crate) fn close_with(&mut self, code: u16) {
        self.closed = Some(code);
        self.outbound = OutboundQueue::default();
        self.manifest_cursor = None;
    }

    /// Admits a request as new or an exact replay, which is re-answered.
    pub(crate) fn admit_request(
        &mut self,
        frame_type: u64,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Fault> {
        self.replay.admit(frame_type, request_id, bytes)
    }

    /// Queued plus handed-over answers, only ever increasing. Both are needed:
    /// the outbound budget can stall queuing while the carrier still drains,
    /// or vice versa.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.progress.saturating_add(self.handed_over)
    }

    /// One booked answer, whichever lane: progress and bytes move together.
    fn queue(&mut self, outbound: Outbound) {
        self.progress = self.progress.saturating_add(1);
        self.outbound.push(outbound);
    }

    pub(crate) fn queue_control(&mut self, frame: Payload) {
        self.queue(Outbound::Control(frame));
    }

    pub(crate) fn queue_record(&mut self, record: Payload) {
        self.queue(Outbound::Record(record));
    }

    pub(crate) fn queue_datagram(&mut self, symbol: Payload) {
        self.queue(Outbound::Datagram(symbol));
    }

    /// Hands queued answers to the session until the carrier refuses one.
    pub(crate) fn drain<A: TransportAdapter>(
        &mut self,
        session: &mut Session<A>,
    ) -> Result<(), Error> {
        while let Some(outbound) = self.outbound.front() {
            match outbound.send(session) {
                Ok(()) => {
                    // The loop's progress depends on the front leaving here:
                    // were it kept, a taken answer would be sent forever.
                    let held = self.outbound.len();
                    self.outbound.pop_sent();
                    debug_assert_eq!(
                        self.outbound.len(),
                        held - 1,
                        "a sent answer must leave the queue"
                    );
                    // Progress even under a stalled budget.
                    self.handed_over = self.handed_over.saturating_add(1);
                }
                // Backpressure: retry next pass.
                Err(error) if is_backpressure(&error) => break,
                Err(error) if matches!(error.kind(), ErrorKind::FrameExceedsLimit { .. }) => {
                    // Peer limits too small for this server's answers.
                    let _ = session.driver().close(error_code::FRAME_TOO_LARGE);
                    self.close_with(error_code::FRAME_TOO_LARGE);
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
