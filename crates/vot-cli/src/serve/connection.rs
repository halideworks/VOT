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

/// Generations whose fate is known in one decode sample.
///
/// Counted as they resolve rather than as they are coded, so both halves
/// of the ratio come off the same stream of reports. An outcome reaches
/// this end well after the generation was coded, by `GEN_DONE` or by the
/// epoch's quiet retirement, and counting the coding instead put the two
/// halves on different clocks: whichever way the mismatch was resolved it
/// misjudged the sample that spans a change of verdict, once by charging
/// an old attempt's failures to a fresh denominator and once by closing a
/// sample before any of its own outcomes had arrived.
///
/// Small, because the whole cost of this verdict is how long it takes to
/// reach: outcomes arrive in lumps at epoch retirement, and the smoothing
/// below is what absorbs the noise a short sample carries. Measured on the
/// 4 GiB shaped cell, 128 gave 63.07 s and 48 gives 61.42 against 68.22
/// unjudged and 56.10 with coding off, and the genuinely lossy cell is
/// unmoved between them.
pub(crate) const FEC_DECODE_SAMPLE: u64 = 48;

/// The share of coded generations that may fail before coding is judged
/// to be making the path worse: a quarter, of the smoothed rate.
///
/// Measured, this separates the two cases with room on both sides. A path
/// whose loss is exogenous decodes every coded generation it engages for,
/// 100% across every emulated cell and a real 12 GiB transfer at 5% loss.
/// A path whose loss is the sender's own queue overflowing decoded 39-40%
/// of coded, because the repair symbols queue behind the sources they
/// were sent to repair.
///
/// Read against the smoothed rate rather than one sample, for the reason
/// the loss verdict is: failures do not arrive spread out. A generation
/// that never gathers enough symbols owes no `GEN_DONE`, so its epoch's
/// quiet retirement reports the whole epoch at once, and a sample sees
/// either none of that or half of it. Measured on a genuinely lossy
/// 4 GiB transfer whose overall failure rate was 1.9%, nine of 359 raw
/// samples crossed a quarter on their own, and acting on them cost that
/// arm coding it should have kept.
const DECODE_FAILURE_SHARE: u64 = 4;

/// Closed loss windows the first decode failure holds coding off for.
///
/// Coding cannot be judged while it is off, because a generation that is
/// never coded never reports, so the off-hysteresis on the loss rate
/// cannot be what governs re-entry: the loss that engaged coding is still
/// there, and the verdict would flap engage, fail, disengage, re-engage
/// for the length of the transfer. A counted hold bounds that duty cycle
/// instead, and the first one is short so a path that has genuinely
/// changed is retried rather than written off on one bad sample.
const DECODE_FAILURE_HOLD_WINDOWS: u32 = 4;

/// Doublings the hold may take across repeated failures on one
/// connection.
///
/// A fixed hold is not enough on its own, because this end learns a
/// generation's fate well after it coded it: the receiver owes no
/// `GEN_DONE` for a generation that never gathered enough symbols to
/// decode, so the whole truth arrives at the epoch's quiet retirement. A
/// path that keeps failing therefore pays a fresh sample plus that lag
/// for every retry, and a fixed hold buys one retry per hold for the
/// length of the transfer. Doubling bounds the retries a connection can
/// spend in total, and at the cap the hold outlasts any transfer, so a
/// path that has failed five samples is left alone.
const DECODE_FAILURE_BACKOFF_CAP: u32 = 4;

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
    /// Generations resolved toward the current decode decision, and how
    /// many of them the receiver could not decode from symbols.
    resolved_sample: u64,
    failed_sample: u64,
    /// The share of coded generations failing, in [`RATE_ONE`]ths,
    /// smoothed across samples the way the loss rate is.
    smoothed_failure: u64,
    /// Loss windows still owed to a decode failure before coding may be
    /// reconsidered, and how many samples have failed on this connection,
    /// which is what lengthens the next hold.
    hold: u32,
    decode_failures: u32,
    /// The last unaided window rates, where the next one goes, and their
    /// mean: the path's own rate, measured only when this end is adding
    /// nothing to it.
    recent: [u32; PROBE_WINDOWS],
    recent_at: usize,
    recent_len: usize,
    unaided_loss: u64,
    /// The pause cadence: coded windows since the last pause, how many
    /// to allow before the next, and how many windows of the current
    /// pause remain.
    coded_since_probe: u32,
    probe_interval: u32,
    pausing: u32,
    /// Closed windows so far, only to skip the opening ramp.
    windows_closed: u32,
    /// Consecutive looks that have said this path does not need coding,
    /// and whether enough of them have agreed.
    quiet_looks: u8,
    quiet_path: bool,
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
            resolved_sample: 0,
            failed_sample: 0,
            smoothed_failure: 0,
            hold: 0,
            decode_failures: 0,
            recent: [0; PROBE_WINDOWS],
            recent_at: 0,
            recent_len: 0,
            unaided_loss: 0,
            coded_since_probe: 0,
            probe_interval: PROBE_FIRST_INTERVAL,
            pausing: 0,
            windows_closed: 0,
            quiet_looks: 0,
            quiet_path: false,
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

/// Unaided windows the path's own rate is averaged over.
///
/// A trailing window rather than a mean over the connection, because a
/// mean that never forgets is carried over the bar by the ramp it opened
/// with: traced on a real 12 GiB transfer with coding off throughout,
/// the running mean climbs to 4.11% at windows seventeen through
/// twenty-one before decaying to 2.4% by window forty.
const PROBE_WINDOWS: usize = 16;

/// Unaided windows that must be in hand before the probe will judge.
const PROBE_MIN_WINDOWS: usize = 4;

/// Coded windows before the first pause, doubling to
/// [`PROBE_MAX_INTERVAL`] each time the pause says to carry on.
///
/// Every observable this end can read while coding runs is downstream of
/// coding's own traffic: loss, delay, drops, decode outcomes, and
/// whether decoding needed repair are all endogenous to the engagement
/// they would judge, which is why five in-band discriminators died the
/// same death on real paths. The only measurement that means anything is
/// one taken with nothing added to the path, so the policy stops adding
/// for a moment and looks. That is what a delay-targeting rate
/// controller does continuously and is the reason it never traps itself.
pub(crate) const PROBE_FIRST_INTERVAL: u32 = 8;

/// The longest a settled answer goes unchecked.
const PROBE_MAX_INTERVAL: u32 = 64;

/// Windows one pause lasts.
///
/// The cost is arithmetic and bounded, which is what separates this from
/// an open-ended experiment on a path where coding may be winning:
/// pausing four windows in sixty-four leaves about 6% of a transfer
/// uncoded, so on a path where coding wins 6% the probe costs about 0.4%
/// of the wall, against the 30% it recovers on a path where coding is
/// wrong.
const PROBE_PAUSE_WINDOWS: u32 = 6;

/// Looks that must agree before coding is taken away.
///
/// One, because the two errors are not the same size. A look that wrongly
/// says quiet costs almost nothing and corrects itself: coding stops, and
/// with nothing being added the unaided evidence then arrives every
/// window and puts it back within a few of them. A look that wrongly says
/// carry on costs the 30% this exists to remove, and on a path whose
/// engagement flaps it may be the last look for a long time, because the
/// count toward the next one only advances while coding.
const PROBE_AGREEING_LOOKS: u8 = 1;

/// The rate a look must read under for the path to be judged not to need
/// coding: the engagement rate, so the question is whether this path
/// would engage on its own merits when measured with nothing added.
pub(crate) const PROBE_BAR: u64 = RATE_ONE / 25;

/// Whether a measured rate is under the bar. Pure, so both sides of the
/// edge are pinned by a table test rather than by whichever cell happens
/// to straddle it.
pub(crate) const fn under_probe_bar(rate: u64) -> bool {
    rate < PROBE_BAR
}

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
            self.smoothed_failure = 0;
            self.recent = [0; PROBE_WINDOWS];
            self.recent_at = 0;
            self.recent_len = 0;
            self.unaided_loss = 0;
            self.coded_since_probe = 0;
            self.probe_interval = PROBE_FIRST_INTERVAL;
            self.pausing = 0;
            self.windows_closed = 0;
            self.quiet_looks = 0;
            self.quiet_path = false;
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
        self.observe_unaided(window_rate);
        self.run_probe();

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
        let engaged = if let Some(remaining) = self.hold.checked_sub(1) {
            // A decode failure is serving out its hold. The loss that
            // engaged coding is still on the path and would re-engage it
            // every window, so nothing about the loss rate is consulted
            // until the hold is spent.
            self.hold = remaining;
            false
        } else if self.coding {
            self.smoothed_loss * 40 >= RATE_ONE
        } else {
            self.smoothed_loss * 25 >= RATE_ONE
        };
        // A pause is a measurement, and the last one has the final word
        // on whether this path wants coding at all.
        let engaged = engaged && self.pausing == 0 && !self.quiet_path;
        if engaged && !self.coding {
            // An engagement is judged on its own outcomes. What is still
            // resolving from the last one arrives for generations coded
            // before it ended, and describes a path this may no longer be.
            // The smoothed rate goes with them: it only ever decays a
            // quarter a sample and it is above the bar by construction at
            // a disengage, so carrying it would spend the retry's first
            // clean sample crossing the bar again, however well the
            // retried path decodes. What bounds the retries is the hold
            // and its doubling, not this.
            self.resolved_sample = 0;
            self.failed_sample = 0;
            self.smoothed_failure = 0;
        }
        self.coding = engaged;
        self.sample_lost = 0;
        self.sample_sent = 0;
    }

    /// Takes a closed window into the unaided rate, if this end was
    /// adding nothing to the path while it ran.
    ///
    /// The opening window is the amplification-shaped ramp and describes
    /// no path, and a coded window describes coding as much as the path,
    /// so neither is evidence.
    fn observe_unaided(&mut self, window_rate: u64) {
        if self.coding || self.windows_closed == 0 {
            self.windows_closed = self.windows_closed.saturating_add(1);
            return;
        }
        self.windows_closed = self.windows_closed.saturating_add(1);
        self.recent[self.recent_at] = u32::try_from(window_rate).unwrap_or(u32::MAX);
        self.recent_at = (self.recent_at + 1) % PROBE_WINDOWS;
        self.recent_len = self.recent_len.saturating_add(1).min(PROBE_WINDOWS);
        let total: u64 = self.recent[..self.recent_len]
            .iter()
            .map(|rate| u64::from(*rate))
            .sum();
        self.unaided_loss = total / self.recent_len as u64;
    }

    /// Runs the pause cadence: counts coded windows toward the next
    /// look, spends a pause, and reads the verdict when one ends.
    fn run_probe(&mut self) {
        if self.pausing > 0 {
            self.pausing -= 1;
            if self.pausing == 0 {
                if self.judged_quiet() {
                    // One look is an estimate. Coding is taken away only
                    // when consecutive looks agree.
                    self.quiet_looks = self.quiet_looks.saturating_add(1);
                    self.quiet_path = self.quiet_looks >= PROBE_AGREEING_LOOKS;
                } else {
                    // The look said carry on, so the next one is further
                    // off; a settled answer is not worth re-asking at
                    // the same rate.
                    self.quiet_looks = 0;
                    self.probe_interval = self
                        .probe_interval
                        .saturating_mul(2)
                        .min(PROBE_MAX_INTERVAL);
                }
            }
            return;
        }
        if self.quiet_path {
            // Nothing is being added, so the evidence keeps arriving on
            // its own and a path that turns lossy is served again
            // without a pause to discover it.
            if self.recent_len >= PROBE_MIN_WINDOWS && !under_probe_bar(self.unaided_loss) {
                self.quiet_path = false;
                self.quiet_looks = 0;
                self.coded_since_probe = 0;
                self.probe_interval = PROBE_FIRST_INTERVAL;
            }
            return;
        }
        if !self.coding {
            return;
        }
        self.coded_since_probe = self.coded_since_probe.saturating_add(1);
        if self.coded_since_probe >= self.probe_interval {
            self.coded_since_probe = 0;
            self.pausing = PROBE_PAUSE_WINDOWS;
            // The look is over this pause's own windows and nothing
            // older, so the verdict cannot be carried by history from
            // before the engagement it is judging.
            self.recent_at = 0;
            self.recent_len = 0;
            self.unaided_loss = 0;
        }
    }

    /// Whether the unaided look says this path does not need coding.
    /// The bar is the engagement rate, not the disengagement rate below
    /// it: the question a look asks is whether this path would engage
    /// coding on its own merits, measured honestly. Both edges sit
    /// there, and what keeps the verdict from flapping is agreement
    /// between looks rather than a gap between bars, because a gap wide
    /// enough to matter would sit on top of the five percent paths this
    /// serves and make *their* verdict the coin flip instead.
    const fn judged_quiet(&self) -> bool {
        self.recent_len >= PROBE_MIN_WINDOWS && under_probe_bar(self.unaided_loss)
    }

    /// Counts a coded generation the receiver decoded from symbols.
    pub(crate) fn note_decoded(&mut self) {
        self.note_resolved(false);
    }

    /// Counts a coded generation the receiver could not decode from
    /// symbols, which this end is repairing reliably instead.
    pub(crate) fn note_repaired(&mut self) {
        self.note_resolved(true);
    }

    /// Takes one generation's outcome, and judges the sample once it is
    /// full.
    ///
    /// Loss the sender caused itself is loss coding cannot answer: the
    /// repair symbols are more packets into the same overflowing queue, so
    /// they drop with the sources they were sent to repair and the coded
    /// arm pays its overhead for generations that decode anyway. Measured
    /// against a shaped bottleneck with no injected loss, the automatic
    /// policy engaged on every run, put 41% more packets into the queue
    /// (20,658 drops against 14,667), decoded 40% of what it coded, and
    /// cost 6.3% of the wall at 256 MB and 14% at 4 GiB. Nothing the
    /// sender can see about the path separates that from a lossy link:
    /// delay does not move (RTT sat within 1.3% of its minimum in the
    /// shaped cell, inside the range the clean and lossy cells both
    /// occupy) and neither does the normalized loss-event count. What
    /// separates them is whether the coding works, so that is what this
    /// reads.
    fn note_resolved(&mut self, failed: bool) {
        self.resolved_sample = self.resolved_sample.saturating_add(1);
        if failed {
            self.failed_sample = self.failed_sample.saturating_add(1);
        }
        if self.resolved_sample < FEC_DECODE_SAMPLE {
            return;
        }
        let sample_rate =
            (self.failed_sample.saturating_mul(RATE_ONE)) / self.resolved_sample.max(1);
        self.resolved_sample = 0;
        self.failed_sample = 0;
        // A sample that resolves while coding is off is the previous
        // attempt's tail arriving, and it is not weighed at all: it is the
        // evidence that ended that attempt, and an epoch's quiet
        // retirement reports every generation still under it at once, so
        // the tail is whole samples of near-total failure by construction.
        // Folded, it would end the next engagement on the last one's
        // record, however well the retried path decodes.
        if !self.coding {
            return;
        }
        self.smoothed_failure = self.smoothed_failure - self.smoothed_failure / RATE_SMOOTHING
            + sample_rate / RATE_SMOOTHING;
        if self.smoothed_failure.saturating_mul(DECODE_FAILURE_SHARE) < RATE_ONE {
            return;
        }
        self.coding = false;
        self.hold = DECODE_FAILURE_HOLD_WINDOWS
            .saturating_mul(1 << self.decode_failures.min(DECODE_FAILURE_BACKOFF_CAP));
        self.decode_failures = self.decode_failures.saturating_add(1);
    }

    pub(crate) const fn coding(&self) -> bool {
        self.coding
    }

    /// Whether the last unaided look said this path does not need
    /// coding.
    #[cfg(test)]
    pub(crate) const fn quiet_path(&self) -> bool {
        self.quiet_path
    }

    /// The path's own rate in [`RATE_ONE`]ths, from unaided windows.
    #[cfg(test)]
    pub(crate) const fn unaided_loss(&self) -> u64 {
        self.unaided_loss
    }

    #[cfg(test)]
    pub(crate) const fn probe_state(&self) -> (u32, usize, u32, u32) {
        (
            self.pausing,
            self.recent_len,
            self.coded_since_probe,
            self.probe_interval,
        )
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
