//! One serving connection: replay memory and outbound accounting.

use super::{
    Error, ErrorKind, Fault, Payload, RECORD_LANE, Session, TransportAdapter, VecDeque, error_code,
    is_backpressure,
};
use vot_transport_api::PathStats;

/// Outbound budget. Bounds the queue against a peer pipelining faster than it drains.
pub(crate) const OUTBOUND_BUDGET_BYTES: u64 = 2 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// Request identities remembered for replay detection. An exact duplicate is
/// re-answered; a duplicate identifier with different content is a protocol error.
pub(crate) const REMEMBERED_REQUESTS: usize = 64;

/// Packets in one loss decision. Smaller observations are accumulated so
/// service-loop cadence cannot turn a handful of drops into a path verdict.
const FEC_SAMPLE_PACKETS: u64 = 8192;

/// Packets in the first decision only. A transfer a few seconds long is
/// mostly issued before a full sample closes, so the first verdict comes
/// from a cover's worth of packets and the steady cadence takes over from
/// there (ADR-0042). Closing early on a detected loss instead was
/// measured seeding the smoothed rate at a fraction of the truth,
/// because detection trails sending by about a round trip and the close
/// divides a fresh loss count by every packet the seeded flight already
/// sent; one such run never engaged at all.
const FIRST_FEC_SAMPLE_PACKETS: u64 = 256;

#[derive(Clone, Copy, Debug)]
struct PathCounters {
    lost: u64,
    spurious: u64,
    sent: u64,
}

/// Recent path loss, activation hysteresis, and the repair count it supports.
#[derive(Debug)]
pub(crate) struct FecPolicy {
    previous: Option<PathCounters>,
    sample_lost: u64,
    sample_sent: u64,
    coding: bool,
    repair_symbols: usize,
    /// Whether a sample has closed yet; the first closes early (ADR-0042).
    decided: bool,
    /// Smoothed loss rate in [`RATE_ONE`]ths, an exponential average over
    /// the closed windows. The verdict reads this rather than one window:
    /// loss detection bunches real drops into some windows and starves
    /// others, and per-window hysteresis was measured flapping a steadily
    /// lossy path off half the time.
    smoothed_loss: u64,
}

impl Default for FecPolicy {
    fn default() -> Self {
        Self {
            previous: None,
            sample_lost: 0,
            sample_sent: 0,
            coding: false,
            repair_symbols: super::server::FEC_REPAIR_SYMBOLS,
            decided: false,
            smoothed_loss: 0,
        }
    }
}

/// The fixed-point unit the smoothed loss rate is held in. Wide enough
/// that the engagement edge is exact at the sample sizes the windows
/// close at: at 1/1024 a five-percent verdict over 8192 packets sat
/// between representable values.
const RATE_ONE: u64 = 65_536;

/// The smoothing weight's denominator: each closed window moves the
/// average a quarter of the way to its own rate. Four steady windows
/// carry most of a change through, so a real shift in the path lands in
/// about half a second of full-rate sending, while a single starved or
/// bunched window moves the verdict by at most a quarter of its error.
const RATE_SMOOTHING: u64 = 4;

/// The most a first lossy window may seed the smoothed rate with: a
/// tenth, well past the engagement rate.
const SEED_CEILING: u64 = RATE_ONE / 10;

impl FecPolicy {
    /// Adds the packets since the preceding carrier sample. Counter resets
    /// start a new baseline; missing telemetry leaves the last decision intact.
    pub(crate) fn observe(&mut self, stats: Option<PathStats>) {
        let Some(PathStats {
            lost_packets: Some(lost),
            spurious_lost_packets: Some(spurious),
            packets_sent: Some(sent),
            ..
        }) = stats
        else {
            return;
        };
        let counters = PathCounters {
            lost,
            spurious,
            sent,
        };
        let Some(previous) = self.previous.replace(counters) else {
            return;
        };
        let (Some(lost), Some(spurious), Some(sent)) = (
            counters.lost.checked_sub(previous.lost),
            counters.spurious.checked_sub(previous.spurious),
            counters.sent.checked_sub(previous.sent),
        ) else {
            // A counter reset is a new baseline: what the old counters'
            // windows smoothed into the rate describes a path this one no
            // longer is.
            self.sample_lost = 0;
            self.sample_sent = 0;
            self.smoothed_loss = 0;
            return;
        };
        self.sample_lost = self
            .sample_lost
            .saturating_add(lost.saturating_sub(spurious));
        self.sample_sent = self.sample_sent.saturating_add(sent);
        let threshold = if self.decided {
            FEC_SAMPLE_PACKETS
        } else {
            FIRST_FEC_SAMPLE_PACKETS
        };
        if self.sample_sent < threshold {
            return;
        }
        self.decided = true;

        // The window's own rate folds into the smoothed one, and every
        // verdict below reads the smoothed rate: engagement at 4%, the
        // off-hysteresis at 2.5%, and the repair count, so one bunched or
        // starved window cannot flip what a steady path deserves.
        let window_rate = (self.sample_lost.saturating_mul(RATE_ONE)) / self.sample_sent.max(1);
        // Seeded whole by the first lossy window: until then there is
        // nothing to smooth, and quartering the first real observation
        // would hold engagement back three windows for no information.
        self.smoothed_loss = if self.smoothed_loss == 0 {
            // Capped: a genuinely lossy path still engages on its first
            // sample, but the raw rate of one freak 256-packet startup
            // burst was reviewed locking an otherwise clean path into
            // coding for up to thirteen windows of decay; from the
            // ceiling it is back under the off-hysteresis within five.
            window_rate.min(SEED_CEILING)
        } else {
            self.smoothed_loss - self.smoothed_loss / RATE_SMOOTHING + window_rate / RATE_SMOOTHING
        };

        let rate = u128::from(self.smoothed_loss);
        // Three times the expected losses across a generation's symbols,
        // plus one: at that margin a generation losing past its repair is
        // rarer than one in ten thousand at the loss rates this engages
        // for, so covered bytes stop paying retransmission round trips
        // (ADR-0042). The floor of two keeps one unlucky drop from
        // touching the reliable path on a barely lossy sample.
        self.repair_symbols = usize::try_from(
            (rate * 3 * vot_fec::MAX_SYMBOLS as u128).div_ceil(u128::from(RATE_ONE)) + 1,
        )
        .unwrap_or(super::server::FEC_REPAIR_SYMBOLS)
        .clamp(2, super::server::FEC_REPAIR_SYMBOLS);
        // Engagement sits a margin under the loss rates it serves, not at
        // them: at exactly 5% the smoothed estimate of a 5% path converges
        // onto the threshold and the verdict becomes a coin flip per
        // window, measured coding anywhere from zero to 1,536 of 4,096
        // generations across identical cells.
        self.coding = if self.coding {
            self.smoothed_loss * 40 >= RATE_ONE
        } else {
            self.smoothed_loss * 25 >= RATE_ONE
        };
        self.sample_lost = 0;
        self.sample_sent = 0;
    }

    pub(crate) const fn coding(&self) -> bool {
        self.coding
    }

    pub(crate) const fn repair_symbols(&self) -> usize {
        self.repair_symbols
    }
}

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
    /// Requests read while answers are backpressured. Kept in wire order so
    /// carrier-state events behind them can still be drained.
    pub(crate) deferred: VecDeque<Payload>,
    /// The datagram FEC sending state: what the peer's credit lets this end
    /// open and send. Used only while `fec_negotiated`.
    pub(crate) fec: FecSender,
    /// Whether the session negotiated both `DATAGRAM_FEC` and
    /// `FEC_COVER_EPOCHS`, refreshed each pass. The second declares a
    /// receiver that joins an epoch's generations to bundles by offset,
    /// which the cover-sized epochs this serve opens require, so a peer
    /// offering only the first is answered reliably.
    pub(crate) fec_negotiated: bool,
    /// Whether this path currently justifies coding new range answers.
    pub(crate) fec_coding: bool,
    /// Recent carrier loss and the FEC decision derived from it.
    pub(crate) fec_policy: FecPolicy,
    /// Per-epoch silence budget, derived from the path's smoothed round trip
    /// each service pass; the fixed default until the carrier reports one.
    pub(crate) quiet_grace: std::time::Duration,
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
            deferred: VecDeque::new(),
            fec: FecSender::default(),
            fec_negotiated: false,
            fec_coding: true,
            fec_policy: FecPolicy::default(),
            quiet_grace: super::server::EPOCH_QUIET_GRACE,
        }
    }
}

/// One epoch this serve opened across one requested cover: what to re-send
/// reliably when the receiver reports a generation abandoned or the epoch
/// refused.
#[derive(Clone, Debug)]
pub(crate) struct OpenedEpoch {
    pub(crate) root: [u8; 32],
    /// The piece bundles the epoch's generations belong to, ascending:
    /// each piece's first generation and its bundle identifier. A
    /// generation's record rides under the last piece at or before it,
    /// indexed relative to that piece.
    pub(crate) pieces: Vec<(u32, [u8; 16])>,
    /// Repair symbols the first pass transmitted per generation. The
    /// geometry declares the spec's whole repair count, so the ESIs past
    /// this are the reserve a symbol repair draws from (ADR-0042).
    pub(crate) transmitted_repairs: usize,
    /// Whether this epoch already spent its one symbol-repair rung. The
    /// second quiet deadline falls through to the reliable resend.
    pub(crate) symbol_repaired: bool,
    /// Generations already answered a targeted repair for, once each.
    pub(crate) repaired: std::collections::BTreeSet<u32>,
    /// The outbound mark this epoch's own symbol passes sit behind: the
    /// first pass, and the ladder's reserve rung. Written only by those,
    /// never by a targeted repair, so one repair's queued bytes cannot
    /// gate the sibling states that arrive in the same dispatch pass out
    /// of theirs.
    pub(crate) symbols_queued_through: u64,
    pub(crate) plan: vot_fec::EpochPlan,
    /// Generations still owed an outcome; the epoch closes when empty.
    pub(crate) live: std::collections::BTreeSet<u32>,
    /// The outbound mark this epoch's symbols sit behind. The carrier has
    /// taken all of them once it has taken this many bytes, which is what
    /// makes silence about the epoch mean the receiver is not answering
    /// rather than that this end has not handed them over yet.
    pub(crate) queued_through: u64,
    /// When this epoch's silence budget runs out, fixed from the grace in
    /// force when it was first seen with its symbols all on the carrier and
    /// nothing heard about it. Cleared by anything the receiver says about
    /// it, so it measures one epoch's own silence, and a later change in the
    /// path's grace never shortens a budget already partly spent.
    pub(crate) quiet_until: Option<std::time::Instant>,
}

impl OpenedEpoch {
    /// Repair ESIs the first pass held back for a symbol repair.
    pub(crate) fn reserve_repairs(&self) -> usize {
        self.plan
            .geometry()
            .repair_count()
            .saturating_sub(self.transmitted_repairs)
    }
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
            Self::Control(frame) => session.send_control_shared(frame.clone()),
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
    /// Bytes the carrier has taken over this connection's life, only ever
    /// going up. What is queued behind a given answer is `taken` at the
    /// moment it was queued plus [`Self::bytes`], so a caller can say when
    /// that answer has left this end without holding the answer itself.
    taken: u64,
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
            self.taken = self.taken.saturating_add(sent.len() as u64);
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

    /// Bytes the carrier has taken over this connection's life.
    pub(crate) fn taken(&self) -> u64 {
        self.taken
    }

    /// The mark an answer queued now would sit behind: everything already
    /// taken plus everything still waiting.
    pub(crate) fn queued_through(&self) -> u64 {
        self.taken.saturating_add(self.bytes)
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

    /// Whether answers are still owed: queued frames, deferred requests, or
    /// unpaged manifest pages.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.outbound.is_empty() || self.manifest_cursor.is_some() || !self.deferred.is_empty()
    }

    /// Records the close and drops pending answers.
    pub(crate) fn close_with(&mut self, code: u16) {
        self.closed = Some(code);
        self.outbound = OutboundQueue::default();
        self.manifest_cursor = None;
        self.deferred.clear();
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
