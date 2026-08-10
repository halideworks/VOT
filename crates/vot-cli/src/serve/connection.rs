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
    pub(crate) remembered: VecDeque<Remembered>,
    pub(crate) pending: VecDeque<Outbound>,
    pub(crate) pending_bytes: u64,
    /// Owed manifest pages as `(next, end)`. Paced rather than queued at once;
    /// a request may name thousands of pages.
    pub(crate) manifest_cursor: Option<(u64, u64)>,
    pub(crate) budget: u64,
    pub(crate) closed: Option<u16>,
    /// Answers queued this session, only ever increasing.
    pub(crate) progress: u64,
    /// Answers the carrier has taken, which the outbound budget may hide.
    pub(crate) handed_over: u64,
}

impl Default for ServeConnection {
    fn default() -> Self {
        Self {
            announced: false,
            remembered: VecDeque::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            manifest_cursor: None,
            budget: OUTBOUND_BUDGET_BYTES,
            closed: None,
            progress: 0,
            handed_over: 0,
        }
    }
}

pub(crate) struct Remembered {
    pub(crate) frame_type: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) digest: [u8; 32],
}

pub(crate) enum Outbound {
    Control(Payload),
    Record(Payload),
}

impl ServeConnection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer bytes queued but not yet accepted by the carrier.
    #[must_use]
    pub fn pending_answer_bytes(&self) -> u64 {
        self.pending_bytes
    }

    /// Whether answers are still owed: queued frames or unpaged manifest pages.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.pending.is_empty() || self.manifest_cursor.is_some()
    }

    /// Records the close and drops pending answers.
    pub(crate) fn close_with(&mut self, code: u16) {
        self.closed = Some(code);
        self.pending.clear();
        self.pending_bytes = 0;
        self.manifest_cursor = None;
    }

    /// Admits a request as new or an exact replay, which is re-answered.
    pub(crate) fn admit_request(
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

    /// Queued plus handed-over answers, only ever increasing. Both are needed:
    /// the outbound budget can stall queuing while the carrier still drains,
    /// or vice versa.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.progress.saturating_add(self.handed_over)
    }

    pub(crate) fn queue_control(&mut self, frame: Payload) {
        self.progress = self.progress.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(frame.len() as u64);
        self.pending.push_back(Outbound::Control(frame));
    }

    pub(crate) fn queue_record(&mut self, record: Payload) {
        self.progress = self.progress.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(record.len() as u64);
        self.pending.push_back(Outbound::Record(record));
    }

    /// Hands queued answers to the session until the carrier refuses one.
    pub(crate) fn drain<A: TransportAdapter>(
        &mut self,
        session: &mut Session<A>,
    ) -> Result<(), Error> {
        while let Some(outbound) = self.pending.front() {
            let result = match outbound {
                Outbound::Control(frame) => session.send_control(frame),
                Outbound::Record(record) => {
                    session.send_reliable_shared(RECORD_LANE, record.clone())
                }
            };
            match result {
                Ok(()) => {
                    if let Some(sent) = self.pending.pop_front() {
                        let bytes = match sent {
                            Outbound::Control(frame) => frame.len(),
                            Outbound::Record(record) => record.len(),
                        };
                        self.pending_bytes = self.pending_bytes.saturating_sub(bytes as u64);
                    }
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
